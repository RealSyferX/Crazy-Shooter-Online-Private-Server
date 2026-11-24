"""
SQLite3 persistence layer for CSG Private Server.
Handles accounts, roles, inventory, equipped KFXItemList loadout, emails,
relations (friends / blacklist), quests, rankings, and launcher news.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from .crypto import md5_upper
from .gamedata import GameData


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS accounts (
    account_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_md5 TEXT NOT NULL,
    email TEXT DEFAULT '',
    is_gm INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS roles (
    role_id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL UNIQUE,
    role_name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    sex INTEGER DEFAULT 1,
    body_type INTEGER DEFAULT 1,
    head_type INTEGER DEFAULT 6554721,
    coat_type INTEGER DEFAULT 6620247,
    trousers_type INTEGER DEFAULT 6685803,
    major_weapon_id INTEGER DEFAULT 65537,
    kill_count INTEGER DEFAULT 0,
    death_count INTEGER DEFAULT 0,
    victory_count INTEGER DEFAULT 0,
    deuce_count INTEGER DEFAULT 0,
    defeated_count INTEGER DEFAULT 0,
    head_kill_count INTEGER DEFAULT 0,
    knife_kill_count INTEGER DEFAULT 0,
    special_kill_count INTEGER DEFAULT 0,
    level INTEGER DEFAULT 1,
    honor_point INTEGER DEFAULT 0,
    honor_place INTEGER DEFAULT 1,
    honor_place_last INTEGER DEFAULT 1,
    faction_id INTEGER DEFAULT 0,
    faction_name TEXT DEFAULT '',
    faction_role_id INTEGER DEFAULT 0,
    faction_icon_id INTEGER DEFAULT 0,
    money_point INTEGER DEFAULT 25000,
    game_cash INTEGER DEFAULT 500000,
    constellation INTEGER DEFAULT 0,
    area TEXT DEFAULT '',
    qq INTEGER DEFAULT 0,
    introduce TEXT DEFAULT '',
    skills_json TEXT DEFAULT '{}',
    created_at INTEGER NOT NULL,
    FOREIGN KEY(account_id) REFERENCES accounts(account_id)
);

CREATE TABLE IF NOT EXISTS inventory (
    item_id INTEGER PRIMARY KEY AUTOINCREMENT,
    role_id INTEGER NOT NULL,
    item_type INTEGER NOT NULL,
    left_days INTEGER DEFAULT 30,
    item_get_type INTEGER DEFAULT 1,
    created_at INTEGER NOT NULL,
    FOREIGN KEY(role_id) REFERENCES roles(role_id)
);

CREATE TABLE IF NOT EXISTS loadouts (
    role_id INTEGER PRIMARY KEY,
    loadout_json TEXT NOT NULL,
    FOREIGN KEY(role_id) REFERENCES roles(role_id)
);

CREATE TABLE IF NOT EXISTS emails (
    email_id INTEGER PRIMARY KEY AUTOINCREMENT,
    recv_role_id INTEGER NOT NULL,
    send_role_id INTEGER NOT NULL,
    send_role_name TEXT NOT NULL,
    email_type INTEGER DEFAULT 1,
    is_locked INTEGER DEFAULT 0,
    is_read INTEGER DEFAULT 0,
    title TEXT DEFAULT '',
    content TEXT DEFAULT '',
    item_id INTEGER DEFAULT 0,
    item_type INTEGER DEFAULT 0,
    item_days INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL,
    FOREIGN KEY(recv_role_id) REFERENCES roles(role_id)
);

CREATE TABLE IF NOT EXISTS relations (
    role_id INTEGER NOT NULL,
    target_role_id INTEGER NOT NULL,
    relation_type INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY(role_id, target_role_id),
    FOREIGN KEY(role_id) REFERENCES roles(role_id),
    FOREIGN KEY(target_role_id) REFERENCES roles(role_id)
);

CREATE TABLE IF NOT EXISTS quests (
    role_id INTEGER NOT NULL,
    task_id INTEGER NOT NULL,
    step INTEGER DEFAULT 1,
    status INTEGER DEFAULT 0,
    PRIMARY KEY(role_id, task_id),
    FOREIGN KEY(role_id) REFERENCES roles(role_id)
);

CREATE TABLE IF NOT EXISTS news (
    news_id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
"""


def empty_item_tuple() -> tuple[int, int, int, int]:
    return (0, 0, 0, 0)


class Database:
    def __init__(self, db_path: Path | str, gamedata: GameData, default_gp: int = 500000, default_csp: int = 25000):
        self.db_path = Path(db_path)
        self.gamedata = gamedata
        self.default_gp = default_gp
        self.default_csp = default_csp
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        with self._lock:
            self.conn.executescript(SCHEMA_SQL)
            # Migrate legacy roles that stored KFXItem body IDs (589825/589875) instead of PawnList.csv RoleID (1/2)
            self.conn.execute("UPDATE roles SET body_type = 2, sex = 2 WHERE body_type IN (589875, 589876, 589926)")
            self.conn.execute("UPDATE roles SET body_type = 1, sex = 1 WHERE body_type NOT IN (1, 2)")
            # Migrate legacy starter inventory rows that stored raw 365 days instead of permanent Default (-1, get_type=0)
            self.conn.execute("UPDATE inventory SET left_days = -1, item_get_type = 0 WHERE left_days = 365 AND item_get_type = 1")
            # Seed initial launcher news if empty
            cnt = self.conn.execute("SELECT COUNT(*) FROM news").fetchone()[0]
            if cnt == 0:
                self.conn.execute(
                    "INSERT INTO news (title, content, created_at) VALUES (?, ?, ?)",
                    (
                        "CSG Local Private Server Online",
                        "Clean-room Bishop, Realm, Shop, Inventory, Room, Chat, Mail & UE2 Match Server ready.",
                        int(time.time()),
                    ),
                )
            self.conn.commit()

    def close(self) -> None:
        with self._lock:
            self.conn.close()

    # ------------------------------------------------------------------
    # Accounts
    # ------------------------------------------------------------------
    def count_accounts(self) -> int:
        with self._lock:
            return int(self.conn.execute("SELECT COUNT(*) FROM accounts").fetchone()[0])

    def get_account_by_username(self, username: str) -> dict[str, Any] | None:
        with self._lock:
            row = self.conn.execute("SELECT * FROM accounts WHERE username = ?", (username,)).fetchone()
            return dict(row) if row else None

    def get_account_by_id(self, account_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self.conn.execute("SELECT * FROM accounts WHERE account_id = ?", (account_id,)).fetchone()
            return dict(row) if row else None

    def create_account(
        self,
        username: str,
        password_plain_or_md5: str,
        email: str = "",
        is_gm: bool = False,
        *,
        already_md5: bool = False,
    ) -> dict[str, Any]:
        pw_hash = password_plain_or_md5.upper() if already_md5 else md5_upper(password_plain_or_md5)
        now = int(time.time())
        with self._lock:
            cur = self.conn.execute(
                "INSERT INTO accounts (username, password_md5, email, is_gm, created_at) VALUES (?, ?, ?, ?, ?)",
                (username.strip(), pw_hash, email.strip(), 1 if is_gm else 0, now),
            )
            self.conn.commit()
            return self.get_account_by_id(cur.lastrowid)  # type: ignore[return-value]

    def verify_account(self, username: str, password_md5_upper: str, auto_register: bool = False) -> tuple[dict[str, Any] | None, str]:
        acc = self.get_account_by_username(username)
        if acc is None:
            if not auto_register:
                return None, "account_not_found"
            acc = self.create_account(username, password_md5_upper, already_md5=True)
            return acc, "auto_registered"
        if acc["password_md5"].upper() != password_md5_upper.upper():
            return None, "wrong_password"
        return acc, "ok"

    # ------------------------------------------------------------------
    # Roles
    # ------------------------------------------------------------------
    def get_role_by_account(self, account_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self.conn.execute("SELECT * FROM roles WHERE account_id = ?", (account_id,)).fetchone()
            return dict(row) if row else None

    def get_role_by_id(self, role_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self.conn.execute("SELECT * FROM roles WHERE role_id = ?", (role_id,)).fetchone()
            return dict(row) if row else None

    def get_role_by_name(self, role_name: str) -> dict[str, Any] | None:
        with self._lock:
            row = self.conn.execute("SELECT * FROM roles WHERE role_name = ?", (role_name,)).fetchone()
            return dict(row) if row else None

    def list_roles(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM roles ORDER BY honor_point DESC, role_id ASC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]

    def create_role(
        self,
        account_id: int,
        role_name: str,
        body_type: int,
        head_type: int,
        coat_type: int,
        trousers_type: int,
    ) -> dict[str, Any] | None:
        role_name = role_name.strip()
        if not role_name or len(role_name) > 30:
            return None
        starter = self.gamedata.starter_items_for_role(body_type, head_type, coat_type, trousers_type)
        now = int(time.time())
        with self._lock:
            if self.get_role_by_account(account_id) is not None:
                return None
            if self.get_role_by_name(role_name) is not None:
                return None

            cur = self.conn.execute(
                """
                INSERT INTO roles (
                    account_id, role_name, sex, body_type, head_type, coat_type, trousers_type,
                    major_weapon_id, money_point, game_cash, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    account_id,
                    role_name,
                    starter["sex"],
                    starter["body"],
                    starter["head"],
                    starter["coat"],
                    starter["trousers"],
                    starter["major"][0],
                    self.default_csp,
                    self.default_gp,
                    now,
                ),
            )
            role_id = int(cur.lastrowid)

            # Grant starter inventory items as permanent Default items (left_days=-1, item_get_type=0)
            # Do NOT insert PawnList body_type (1/2) into inventory — it is not in KFXItem.csv.
            def grant(item_type: int) -> int:
                if item_type <= 0:
                    return 0
                c = self.conn.execute(
                    "INSERT INTO inventory (role_id, item_type, left_days, item_get_type, created_at) VALUES (?, ?, ?, ?, ?)",
                    (role_id, item_type, -1, 0, now),
                )
                return int(c.lastrowid)

            loadout = {
                "body": 0,
                "head": grant(starter["head"]),
                "coat": grant(starter["coat"]),
                "trousers": grant(starter["trousers"]),
                "major": [grant(t) for t in starter["major"]],
                "minor": [grant(t) for t in starter["minor"]],
                "knife": [grant(t) for t in starter["knife"]],
                "grenade": [grant(t) for t in starter["grenade"]],
                "armor": grant(starter["armor"]),
                "shoes": grant(starter["shoes"]),
                "baggage_cards": [0] * 20,
            }
            for extra_type in starter["extra_items"]:
                grant(extra_type)

            self.conn.execute(
                "INSERT INTO loadouts (role_id, loadout_json) VALUES (?, ?)",
                (role_id, json.dumps(loadout)),
            )

            # Auto-accept initial newbie quests
            for q in self.gamedata.quests.values():
                if q.get("is_first_step") and q.get("auto_accept"):
                    self.conn.execute(
                        "INSERT OR IGNORE INTO quests (role_id, task_id, step, status) VALUES (?, ?, ?, 0)",
                        (role_id, q["id"], q["id_step"]),
                    )

            # Welcome mail
            self.conn.execute(
                """
                INSERT INTO emails (recv_role_id, send_role_id, send_role_name, email_type, title, content, created_at)
                VALUES (?, 0, 'CSG System', 1, 'Welcome to CSG!', ?, ?)
                """,
                (
                    role_id,
                    f"Welcome {role_name}! You received {self.default_gp} GP, {self.default_csp} CSP, and starter weapons.",
                    now,
                ),
            )
            self.conn.commit()
            return self.get_role_by_id(role_id)

    def update_role_profile(self, role_id: int, constellation: int, area: str, qq: int, introduce: str) -> None:
        with self._lock:
            self.conn.execute(
                "UPDATE roles SET constellation=?, area=?, qq=?, introduce=? WHERE role_id=?",
                (constellation, area[:31], qq, introduce[:63], role_id),
            )
            self.conn.commit()

    def update_role_currency(self, role_id: int, delta_gp: int = 0, delta_csp: int = 0) -> dict[str, Any] | None:
        with self._lock:
            role = self.get_role_by_id(role_id)
            if not role:
                return None
            new_gp = max(0, int(role["game_cash"]) + delta_gp)
            new_csp = max(0, int(role["money_point"]) + delta_csp)
            self.conn.execute(
                "UPDATE roles SET game_cash=?, money_point=? WHERE role_id=?",
                (new_gp, new_csp, role_id),
            )
            self.conn.commit()
            return self.get_role_by_id(role_id)

    def add_match_stats(
        self,
        role_id: int,
        *,
        kills: int = 0,
        deaths: int = 0,
        victory: int = 0,
        deuce: int = 0,
        defeated: int = 0,
        head_kills: int = 0,
        knife_kills: int = 0,
        special_kills: int = 0,
        honor_gain: int = 0,
        gp_gain: int = 0,
    ) -> dict[str, Any] | None:
        with self._lock:
            role = self.get_role_by_id(role_id)
            if not role:
                return None
            new_honor = int(role["honor_point"]) + honor_gain
            new_level = self.gamedata.level_for_honor(new_honor)
            self.conn.execute(
                """
                UPDATE roles SET
                    kill_count = kill_count + ?,
                    death_count = death_count + ?,
                    victory_count = victory_count + ?,
                    deuce_count = deuce_count + ?,
                    defeated_count = defeated_count + ?,
                    head_kill_count = head_kill_count + ?,
                    knife_kill_count = knife_kill_count + ?,
                    special_kill_count = special_kill_count + ?,
                    honor_point = ?,
                    level = ?,
                    game_cash = game_cash + ?
                WHERE role_id = ?
                """,
                (
                    kills, deaths, victory, deuce, defeated,
                    head_kills, knife_kills, special_kills,
                    new_honor, new_level, gp_gain, role_id,
                ),
            )
            self.conn.commit()
            return self.get_role_by_id(role_id)

    # ------------------------------------------------------------------
    # Inventory & Loadout
    # ------------------------------------------------------------------
    def get_inventory(self, role_id: int) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM inventory WHERE role_id = ? ORDER BY item_id ASC", (role_id,)
            ).fetchall()
            return [dict(r) for r in rows]

    def get_item_by_id(self, role_id: int, item_id: int) -> dict[str, Any] | None:
        if item_id <= 0:
            return None
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM inventory WHERE role_id = ? AND item_id = ?", (role_id, item_id)
            ).fetchone()
            return dict(row) if row else None

    def add_item(
        self,
        role_id: int,
        item_type: int,
        left_days: int = 30,
        get_type: int = 1,
        *,
        raw_left_value: int | None = None,
    ) -> dict[str, Any]:
        """
        Insert an owned item into inventory.
        left_days is interpreted as a KFXItem.csv PriceTime/GameCashTime value (days, -1=permanent,
        or use count for use_type==2) and converted to wire nItemLeftDays (seconds / uses / -1),
        unless raw_left_value is explicitly provided.
        """
        now = int(time.time())
        left_val = int(raw_left_value) if raw_left_value is not None else self.gamedata.item_time_to_left_value(item_type, left_days)
        with self._lock:
            cur = self.conn.execute(
                "INSERT INTO inventory (role_id, item_type, left_days, item_get_type, created_at) VALUES (?, ?, ?, ?, ?)",
                (role_id, item_type, left_val, get_type, now),
            )
            self.conn.commit()
            return self.get_item_by_id(role_id, int(cur.lastrowid))  # type: ignore[return-value]

    def get_loadout(self, role_id: int) -> dict[str, Any]:
        with self._lock:
            row = self.conn.execute("SELECT loadout_json FROM loadouts WHERE role_id = ?", (role_id,)).fetchone()
            if row:
                return json.loads(row["loadout_json"])
            return {
                "body": 0, "head": 0, "coat": 0, "trousers": 0,
                "major": [0] * 5, "minor": [0] * 5, "knife": [0] * 5, "grenade": [0] * 5,
                "armor": 0, "shoes": 0, "baggage_cards": [0] * 20,
            }

    def get_resolved_loadout(self, role_id: int) -> dict[str, Any]:
        """Return each loadout slot resolved to a 4-tuple (item_id, item_type, left_days, get_type)."""
        raw = self.get_loadout(role_id)
        inv_map = {int(it["item_id"]): it for it in self.get_inventory(role_id)}
        role = self.get_role_by_id(role_id)
        body_id = self.gamedata.normalize_body_type(int(role["body_type"])) if role else 1

        def resolve(iid: int) -> tuple[int, int, int, int]:
            it = inv_map.get(int(iid))
            if not it:
                return (0, 0, 0, 0)
            return (int(it["item_id"]), int(it["item_type"]), int(it["left_days"]), int(it["item_get_type"]))

        return {
            # BodyType.nItemType is PawnList.csv RoleID (1=Male, 2=Female), permanent default
            "body": (0, body_id, -1, 0),
            "head": resolve(raw.get("head", 0)),
            "coat": resolve(raw.get("coat", 0)),
            "trousers": resolve(raw.get("trousers", 0)),
            "major": [resolve(x) for x in (raw.get("major") or [0] * 5)[:5]],
            "minor": [resolve(x) for x in (raw.get("minor") or [0] * 5)[:5]],
            "knife": [resolve(x) for x in (raw.get("knife") or [0] * 5)[:5]],
            "grenade": [resolve(x) for x in (raw.get("grenade") or [0] * 5)[:5]],
            "armor": resolve(raw.get("armor", 0)),
            "shoes": resolve(raw.get("shoes", 0)),
            "baggage_cards": [resolve(x) for x in (raw.get("baggage_cards") or [0] * 20)[:20]],
        }

    def set_loadout_from_indices(
        self,
        role_id: int,
        head_idx: int,
        coat_idx: int,
        trousers_idx: int,
        major_idx: list[int],
        minor_idx: list[int],
        grenade_idx: list[int],
        knife_idx: list[int],
        armor_idx: int,
        shoes_idx: int,
        baggage_idx: list[int],
    ) -> dict[str, Any]:
        """
        KFXClient::execSetUsingItemList sends 0-based indices into the client's m_sPlayerOwnerItem
        array (or -1 / 0xFFFFFFFF if slot empty). Map each valid index to the owned item_id.
        """
        inv = self.get_inventory(role_id)
        cur = self.get_loadout(role_id)

        def pick(idx: int, fallback: int = 0) -> int:
            if 0 <= idx < len(inv):
                return int(inv[idx]["item_id"])
            if idx == -1 or idx == 0xFFFFFFFF:
                return 0
            return fallback

        new_loadout = {
            "body": cur.get("body", 0),
            "head": pick(head_idx, cur.get("head", 0)),
            "coat": pick(coat_idx, cur.get("coat", 0)),
            "trousers": pick(trousers_idx, cur.get("trousers", 0)),
            "major": [pick(i) for i in major_idx[:5]],
            "minor": [pick(i) for i in minor_idx[:5]],
            "grenade": [pick(i) for i in grenade_idx[:5]],
            "knife": [pick(i) for i in knife_idx[:5]],
            "armor": pick(armor_idx),
            "shoes": pick(shoes_idx),
            "baggage_cards": [pick(i) for i in baggage_idx[:20]],
        }
        # Also mirror primary appearance & major weapon onto roles table for room display
        inv_map = {int(it["item_id"]): int(it["item_type"]) for it in inv}
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO loadouts (role_id, loadout_json) VALUES (?, ?)",
                (role_id, json.dumps(new_loadout)),
            )
            head_t = inv_map.get(new_loadout["head"], 0)
            coat_t = inv_map.get(new_loadout["coat"], 0)
            trou_t = inv_map.get(new_loadout["trousers"], 0)
            maj_t = inv_map.get(new_loadout["major"][0], 0) if new_loadout["major"] else 0
            self.conn.execute(
                """
                UPDATE roles SET
                    head_type = CASE WHEN ? > 0 THEN ? ELSE head_type END,
                    coat_type = CASE WHEN ? > 0 THEN ? ELSE coat_type END,
                    trousers_type = CASE WHEN ? > 0 THEN ? ELSE trousers_type END,
                    major_weapon_id = CASE WHEN ? > 0 THEN ? ELSE major_weapon_id END
                WHERE role_id = ?
                """,
                (head_t, head_t, coat_t, coat_t, trou_t, trou_t, maj_t, maj_t, role_id),
            )
            self.conn.commit()
        return new_loadout

    def buy_item(self, role_id: int, item_type: int, item_time: int, buy_type: int) -> tuple[int, dict[str, Any] | None, dict[str, Any] | None]:
        """
        Purchase an item. Returns (result_code, new_item, updated_role).
        KFXGUI.int ErrorMsgs codes: 1=success, 218=invalid/failed, 254=insufficient funds.
        """
        price_info = self.gamedata.get_item_price(item_type, item_time, buy_type)
        if not price_info:
            return 218, None, self.get_role_by_id(role_id)
        currency, price = price_info
        with self._lock:
            role = self.get_role_by_id(role_id)
            if not role:
                return 218, None, None
            if currency == "csp":
                if int(role["money_point"]) < price:
                    return 254, None, role
                self.conn.execute("UPDATE roles SET money_point = money_point - ? WHERE role_id = ?", (price, role_id))
            else:
                if int(role["game_cash"]) < price:
                    return 254, None, role
                self.conn.execute("UPDATE roles SET game_cash = game_cash - ? WHERE role_id = ?", (price, role_id))
            item = self.add_item(role_id, item_type, left_days=item_time, get_type=1)
            self.conn.commit()
            return 1, item, self.get_role_by_id(role_id)

    # ------------------------------------------------------------------
    # Emails
    # ------------------------------------------------------------------
    def list_emails(self, role_id: int) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM emails WHERE recv_role_id = ? ORDER BY email_id DESC LIMIT 50", (role_id,)
            ).fetchall()
            return [dict(r) for r in rows]

    def get_email(self, role_id: int, email_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM emails WHERE recv_role_id = ? AND email_id = ?", (role_id, email_id)
            ).fetchone()
            if row:
                self.conn.execute("UPDATE emails SET is_read = 1 WHERE email_id = ?", (email_id,))
                self.conn.commit()
                return dict(row)
            return None

    def send_email(
        self,
        send_role_id: int,
        send_role_name: str,
        recv_role_id: int,
        email_type: int,
        title: str,
        content: str,
        item_id: int = 0,
        item_type: int = 0,
        item_days: int = 0,
    ) -> int:
        now = int(time.time())
        with self._lock:
            cur = self.conn.execute(
                """
                INSERT INTO emails (
                    recv_role_id, send_role_id, send_role_name, email_type,
                    title, content, item_id, item_type, item_days, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (recv_role_id, send_role_id, send_role_name, email_type, title[:63], content[:511], item_id, item_type, item_days, now),
            )
            self.conn.commit()
            return int(cur.lastrowid)

    def takeout_email_item(self, role_id: int, email_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM emails WHERE recv_role_id = ? AND email_id = ?", (role_id, email_id)
            ).fetchone()
            if not row or int(row["item_type"]) <= 0:
                return None
            raw_left = int(row["item_days"])
            item = self.add_item(
                role_id,
                int(row["item_type"]),
                left_days=7,
                get_type=2,
                raw_left_value=raw_left if raw_left != 0 else None,
            )
            self.conn.execute("UPDATE emails SET item_id = 0, item_type = 0, item_days = 0 WHERE email_id = ?", (email_id,))
            self.conn.commit()
            return item

    def delete_email(self, role_id: int, email_id: int) -> bool:
        with self._lock:
            cur = self.conn.execute("DELETE FROM emails WHERE recv_role_id = ? AND email_id = ?", (role_id, email_id))
            self.conn.commit()
            return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Relations (Friends & Blacklist)
    # ------------------------------------------------------------------
    def list_relations(self, role_id: int) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                """
                SELECT rel.relation_type, r.role_id, r.role_name, r.level, r.sex, r.faction_id, r.faction_icon_id
                FROM relations rel
                JOIN roles r ON r.role_id = rel.target_role_id
                WHERE rel.role_id = ?
                """,
                (role_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    def add_relation(self, role_id: int, target_role_id: int, relation_type: int) -> bool:
        if role_id == target_role_id:
            return False
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO relations (role_id, target_role_id, relation_type, created_at) VALUES (?, ?, ?, ?)",
                (role_id, target_role_id, relation_type, int(time.time())),
            )
            self.conn.commit()
            return True

    def delete_relation(self, role_id: int, target_role_id: int) -> int | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT relation_type FROM relations WHERE role_id = ? AND target_role_id = ?",
                (role_id, target_role_id),
            ).fetchone()
            if not row:
                return None
            rel_type = int(row["relation_type"])
            self.conn.execute(
                "DELETE FROM relations WHERE role_id = ? AND target_role_id = ?", (role_id, target_role_id)
            )
            self.conn.commit()
            return rel_type

    # ------------------------------------------------------------------
    # Quests & News
    # ------------------------------------------------------------------
    def get_quests(self, role_id: int) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute("SELECT * FROM quests WHERE role_id = ?", (role_id,)).fetchall()
            return [dict(r) for r in rows]

    def upsert_quest(self, role_id: int, task_id: int, step: int, status: int) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO quests (role_id, task_id, step, status) VALUES (?, ?, ?, ?)",
                (role_id, task_id, step, status),
            )
            self.conn.commit()

    def list_news(self, limit: int = 10) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute("SELECT * FROM news ORDER BY news_id DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]

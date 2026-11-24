#!/usr/bin/env python3
"""
Admin CLI for CSG Private Server (manage accounts, roles, GP/CSP, items, GM flag).

Examples:
  python tools/admin_cli.py create-account syferx mypass123 --gm
  python tools/admin_cli.py list-accounts
  python tools/admin_cli.py grant-currency SyferX --gp 1000000 --csp 50000
  python tools/admin_cli.py grant-item SyferX 65541 --days 365
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from server.database import Database
from server.gamedata import GameData


def open_db() -> tuple[Database, GameData]:
    cfg = json.loads((BASE_DIR / "config.json").read_text(encoding="utf-8"))
    gd = GameData(BASE_DIR / "data")
    db_path = Path(cfg.get("database_path", "csg.db"))
    if not db_path.is_absolute():
        db_path = BASE_DIR / db_path
    db = Database(db_path, gd, int(cfg.get("default_gp", 500000)), int(cfg.get("default_csp", 25000)))
    return db, gd


def main() -> None:
    parser = argparse.ArgumentParser(description="CSG Private Server Admin CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_ca = sub.add_parser("create-account", help="Create a new user account")
    p_ca.add_argument("username")
    p_ca.add_argument("password")
    p_ca.add_argument("--email", default="")
    p_ca.add_argument("--gm", action="store_true")

    sub.add_parser("list-accounts", help="List all accounts and roles")

    p_gc = sub.add_parser("grant-currency", help="Add GP and/or CSP to a role")
    p_gc.add_argument("role_name")
    p_gc.add_argument("--gp", type=int, default=0)
    p_gc.add_argument("--csp", type=int, default=0)

    p_gi = sub.add_parser("grant-item", help="Grant an item by KFXItem.csv item_type ID")
    p_gi.add_argument("role_name")
    p_gi.add_argument("item_type", type=int)
    p_gi.add_argument("--days", type=int, default=30)

    args = parser.parse_args()
    db, gd = open_db()
    try:
        if args.cmd == "create-account":
            if db.get_account_by_username(args.username):
                print(f"[ERR] Account '{args.username}' already exists.")
                return
            acc = db.create_account(args.username, args.password, args.email, is_gm=args.gm)
            print(f"[OK] Created account id={acc['account_id']} username={acc['username']} gm={acc['is_gm']}")

        elif args.cmd == "list-accounts":
            rows = db.conn.execute(
                """
                SELECT a.account_id, a.username, a.is_gm, r.role_id, r.role_name, r.level, r.game_cash, r.money_point
                FROM accounts a LEFT JOIN roles r ON r.account_id = a.account_id
                ORDER BY a.account_id ASC
                """
            ).fetchall()
            if not rows:
                print("(no accounts)")
                return
            for r in rows:
                print(
                    f"acc#{r['account_id']:3d} user={r['username']:16s} gm={r['is_gm']} "
                    f"role={str(r['role_name'] or '-'):16s} lv={r['level'] or 0:2d} "
                    f"GP={r['game_cash'] or 0:8d} CSP={r['money_point'] or 0:6d}"
                )

        elif args.cmd == "grant-currency":
            role = db.get_role_by_name(args.role_name)
            if not role:
                print(f"[ERR] Role '{args.role_name}' not found.")
                return
            upd = db.update_role_currency(int(role["role_id"]), delta_gp=args.gp, delta_csp=args.csp)
            print(f"[OK] {upd['role_name']}: GP={upd['game_cash']} CSP={upd['money_point']}")

        elif args.cmd == "grant-item":
            role = db.get_role_by_name(args.role_name)
            if not role:
                print(f"[ERR] Role '{args.role_name}' not found.")
                return
            info = gd.get_item(args.item_type)
            it = db.add_item(int(role["role_id"]), args.item_type, left_days=args.days, get_type=2)
            iname = info["name"] if info else f"Type#{args.item_type}"
            print(f"[OK] Granted {iname} (item_id={it['item_id']}, days={it['left_days']}) to {role['role_name']}")
    finally:
        db.close()


if __name__ == "__main__":
    main()

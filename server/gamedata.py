"""
Loads extracted CSO Malaysia game data tables (maps, modes, items, levels, quests).
"""
from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Any


class GameData:
    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.maps: dict[int, dict[str, Any]] = {}
        self.modes: dict[int, dict[str, Any]] = {}
        self.items: dict[int, dict[str, Any]] = {}
        self.levels: list[dict[str, Any]] = []
        self.quests: dict[int, dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        for m in json.loads((self.data_dir / "maps.json").read_text(encoding="utf-8")):
            self.maps[int(m["id"])] = m
        for g in json.loads((self.data_dir / "gamemodes.json").read_text(encoding="utf-8")):
            self.modes[int(g["id"])] = g
        for it in json.loads((self.data_dir / "items.json").read_text(encoding="utf-8")):
            self.items[int(it["item_type"])] = it
        self.levels = sorted(
            json.loads((self.data_dir / "levels.json").read_text(encoding="utf-8")),
            key=lambda x: int(x["level"]),
        )
        for q in json.loads((self.data_dir / "quests.json").read_text(encoding="utf-8")):
            self.quests[int(q["id"])] = q

    def get_map(self, map_id: int) -> dict[str, Any]:
        return self.maps.get(map_id) or next(iter(self.maps.values()))

    def maps_for_mode(self, game_mode: int) -> list[int]:
        """Return all map IDs permitted for game_mode per KFXMapMode.csv."""
        allowed = [mid for mid, m in self.maps.items() if game_mode in m.get("allowed_modes", [])]
        return allowed if allowed else list(self.maps.keys())

    def pick_map_for_mode(self, game_mode: int, preferred_map_id: int = 0, *, reroll: bool = False) -> int:
        """
        Return a valid map_id for game_mode per KFXMapMode.csv.
        Keeps preferred_map_id when valid (unless reroll=True); otherwise picks randomly
        from the maps allowed for game_mode (handles SetRoomInfo map_id=0 Random).
        """
        allowed = self.maps_for_mode(game_mode)
        if not reroll and preferred_map_id in allowed:
            return preferred_map_id
        return random.choice(allowed)

    def get_mode(self, mode_id: int) -> dict[str, Any]:
        return self.modes.get(mode_id) or next(iter(self.modes.values()))

    def get_item(self, item_type: int) -> dict[str, Any] | None:
        return self.items.get(item_type)

    def get_item_price(self, item_type: int, item_time: int, buy_type: int) -> tuple[str, int] | None:
        """
        Return (currency, price) where currency is 'csp' (MoneyPoint) or 'gp' (GameCash).
        Verified in KFXGUI.u (KFXGUIPurchasePricePanel / InShopState):
          - buy_type == 0: CSP (MoneyPoint / PricePoint0..7)
          - buy_type == 1: GP (GameCash / GameCash0..3)
        Falls back cleanly if the requested duration is present in only one table.
        """
        it = self.items.get(item_type)
        if not it:
            return None
        tkey = str(item_time)
        csp_map: dict[str, int] = it.get("csp_prices", {})
        gp_map: dict[str, int] = it.get("gp_prices", {})

        # buy_type == 0 -> CSP (MoneyPoint), buy_type == 1 -> GP (GameCash)
        if buy_type == 0:
            if tkey in csp_map:
                return ("csp", csp_map[tkey])
            if csp_map:
                return ("csp", next(iter(csp_map.values())))
            if tkey in gp_map:
                return ("gp", gp_map[tkey])
            if gp_map:
                return ("gp", next(iter(gp_map.values())))
        else:
            if tkey in gp_map:
                return ("gp", gp_map[tkey])
            if gp_map:
                return ("gp", next(iter(gp_map.values())))
            if tkey in csp_map:
                return ("csp", csp_map[tkey])
            if csp_map:
                return ("csp", next(iter(csp_map.values())))
        return ("gp", 1000)

    def item_time_to_left_value(self, item_type: int, item_time: int) -> int:
        """
        Convert a KFXItem.csv PriceTime/GameCashTime value into the wire nItemLeftDays value:
          - use_type == 2 (consumables/bugles): remaining use count
          - use_type == 1 (timed items): -1 for permanent (item_time < 0), else seconds (days * 86400)
        """
        it = self.items.get(item_type)
        use_type = int(it.get("use_type", 1)) if it else 1
        if use_type == 2:
            if item_time > 0:
                return int(item_time)
            return max(1, int(it.get("use_count", 1)) if it else 1)
        if item_time < 0:
            return -1
        days = int(item_time) if item_time > 0 else 7
        return days * 86400

    @staticmethod
    def normalize_body_type(body_type: int) -> int:
        """
        PawnList.csv RoleID: 1 = Male, 2 = Female.
        Also maps legacy KFXItem female body IDs (589875/589876/589926) -> 2, else 1.
        """
        if body_type in (2, 589875, 589876, 589926):
            return 2
        return 1

    def level_for_honor(self, honor_point: int) -> int:
        lvl = 1
        for row in self.levels:
            if honor_point >= int(row["honor_point"]):
                lvl = int(row["level"])
            else:
                break
        return lvl

    def starter_items_for_role(
        self,
        body_type: int,
        head_type: int,
        coat_type: int,
        trousers_type: int,
    ) -> dict[str, Any]:
        """
        Build a valid starter kit matching the character's chosen appearance + iconic starter weapons:
          - Body is PawnList.csv RoleID (1=Male, 2=Female) — NOT a KFXItem.csv ID
          - Head, Coat, Trousers (chosen at CreateRole, or verified KFXGUICreatePlayerPanel defaults)
          - AK47 (65537), M4A1 (65538), MP5 (65539)
          - GLOCK (131078), Desert Eagle (131079)
          - Melon Knife (196616)
          - Explosive Bang (262156), Flash Bang (262155), Smoke Bomb (262157)
        """
        body = self.normalize_body_type(body_type)
        is_female = body == 2
        default_head = 6559724 if is_female else 6554721
        default_coat = 6625247 if is_female else 6620247
        default_trousers = 6690803 if is_female else 6685803
        head = head_type if head_type in self.items else (default_head if default_head in self.items else self._first_inv(12, 2 if is_female else 1, 6554725))
        coat = coat_type if coat_type in self.items else (default_coat if default_coat in self.items else self._first_inv(13, 2 if is_female else 1, 6620251))
        trousers = trousers_type if trousers_type in self.items else (default_trousers if default_trousers in self.items else self._first_inv(14, 2 if is_female else 1, 6686007))

        return {
            "sex": 2 if is_female else 1,
            "body": body,
            "head": head,
            "coat": coat,
            "trousers": trousers,
            "major": [65537, 65538, 65539, 0, 0],
            "minor": [131078, 131079, 0, 0, 0],
            "knife": [196616, 0, 0, 0, 0],
            "grenade": [262156, 262155, 262157, 0, 0],
            "armor": 0,
            "shoes": 0,
            "baggage_cards": [0] * 20,
            "extra_items": [65541, 65540],  # AWP + XM1014 in bag
        }

    def _first_inv(self, inv_type: int, sex: int, fallback: int) -> int:
        for it in self.items.values():
            if it["inventory_type"] == inv_type and it["sex"] in (0, sex):
                return it["item_type"]
        return fallback

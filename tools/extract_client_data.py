#!/usr/bin/env python3
"""
Extract game data tables (XOR 0x9D CSVs) and the 5,679-dword KSG cipher table
from the CSO Malaysia client installation into C:\\Users\\Administrator\\Documents\\CSG\\data\\.
"""
from __future__ import annotations

import csv
import io
import json
import os
import struct
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
CONFIG_PATH = BASE_DIR / "config.json"

KSG_TABLE_VA = 0x10006080
KSG_COUNT_VA = 0x1000B93C
KSG_EXPECTED_COUNT = 5679


def load_client_dir() -> Path:
    if len(sys.argv) > 1:
        return Path(sys.argv[1])
    if CONFIG_PATH.exists():
        cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        if cfg.get("client_dir"):
            return Path(cfg["client_dir"])
    return Path(r"C:\Program Files (x86)\CSO Malaysia")


def decode_kfx_csv(path: Path) -> list[dict[str, str]]:
    raw = path.read_bytes()
    dec = bytes(b ^ 0x9D for b in raw[3:]) if raw.startswith(b"KFX") else raw
    text = None
    for enc in ("utf-8-sig", "gb18030", "latin1"):
        try:
            text = dec.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    if text is None:
        text = dec.decode("latin1", errors="replace")
    return list(csv.DictReader(io.StringIO(text)))


def to_int(val: str | None, default: int = 0) -> int:
    if val is None:
        return default
    s = str(val).strip()
    if not s:
        return default
    try:
        return int(s)
    except ValueError:
        try:
            return int(float(s))
        except ValueError:
            return default


def extract_ksg_table(dll_path: Path, out_bin: Path) -> int:
    data = dll_path.read_bytes()
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_off:pe_off + 4] != b"PE\x00\x00":
        raise RuntimeError(f"Invalid PE header in {dll_path}")
    num_sec = struct.unpack_from("<H", data, pe_off + 6)[0]
    opt_sz = struct.unpack_from("<H", data, pe_off + 20)[0]
    image_base = struct.unpack_from("<I", data, pe_off + 24 + 28)[0]
    sec_off = pe_off + 24 + opt_sz

    def va_to_off(va: int) -> int:
        rva = va - image_base
        for i in range(num_sec):
            off = sec_off + i * 40
            vsz, sva, rsz, sra = struct.unpack_from("<IIII", data, off + 8)
            if sva <= rva < sva + max(vsz, rsz):
                return sra + (rva - sva)
        raise RuntimeError(f"VA 0x{va:08x} not found in PE sections")

    tbl_off = va_to_off(KSG_TABLE_VA)
    cnt_off = va_to_off(KSG_COUNT_VA)
    count = struct.unpack_from("<I", data, cnt_off)[0]
    if count != KSG_EXPECTED_COUNT:
        raise RuntimeError(f"Unexpected KSG table count {count} (expected {KSG_EXPECTED_COUNT})")
    table_bytes = data[tbl_off:tbl_off + count * 4]
    if len(table_bytes) != count * 4:
        raise RuntimeError("Truncated KSG table read")
    out_bin.write_bytes(table_bytes)
    return count


def main() -> None:
    client_dir = load_client_dir()
    sys_dir = client_dir / "System"
    if not sys_dir.exists():
        raise SystemExit(f"Client System directory not found: {sys_dir}")

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Extract KSG cipher table
    dll_path = sys_dir / "KFXClientNetwork.dll"
    ksg_bin = DATA_DIR / "ksg_table.bin"
    cnt = extract_ksg_table(dll_path, ksg_bin)
    print(f"[OK] Extracted KSG cipher table: {cnt} dwords -> {ksg_bin}")

    # 2. Extract Maps (KFXMapInfo.csv + KFXMapMode.csv)
    map_modes_raw = decode_kfx_csv(sys_dir / "KFXMapMode.csv")
    map_modes_by_id: dict[int, list[int]] = {}
    for row in map_modes_raw:
        mid = to_int(row.get("id"))
        allowed = [m for m in range(1, 6) if to_int(row.get(str(m))) == 1]
        map_modes_by_id[mid] = allowed

    maps = []
    for row in decode_kfx_csv(sys_dir / "KFXMapInfo.csv"):
        mid = to_int(row.get("id"))
        if mid <= 0:
            continue
        maps.append({
            "id": mid,
            "name": row.get("Name", "").strip(),
            "map_file": row.get("MapName", "").strip(),
            "max_players": to_int(row.get("PlayerCount"), 16),
            "balance": to_int(row.get("Balance"), 1),
            "default_mode": to_int(row.get("DefMode"), 1),
            "allowed_modes": map_modes_by_id.get(mid, [1, 2, 3]),
            "info": row.get("Info", "").strip(),
        })
    (DATA_DIR / "maps.json").write_text(json.dumps(maps, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[OK] Extracted {len(maps)} maps -> {DATA_DIR / 'maps.json'}")

    # 3. Extract Game Modes (KFXGameMode.csv)
    modes = []
    for row in decode_kfx_csv(sys_dir / "KFXGameMode.csv"):
        gid = to_int(row.get("id"))
        if gid <= 0:
            continue
        modes.append({
            "id": gid,
            "name": row.get("Name", "").strip(),
            "game_class": row.get("GameMode", "").strip(),
            "default_player_limit": to_int(row.get("DefPlayerLimit"), 16),
            "default_kill_limit": to_int(row.get("DefKillLimit"), 100),
            "default_time_limit": to_int(row.get("DefTimeLimit"), 20),
            "default_sub_time_limit": to_int(row.get("DefSubTimeLimit"), 3),
            "default_bout_limit": to_int(row.get("DefBoutLimit"), 5),
            "default_point_limit": to_int(row.get("DefPointLimit"), 0),
            "intro": row.get("ModeIntro", "").strip(),
        })
    (DATA_DIR / "gamemodes.json").write_text(json.dumps(modes, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[OK] Extracted {len(modes)} game modes -> {DATA_DIR / 'gamemodes.json'}")

    # 4. Extract Items (KFXItem.csv)
    items = []
    for row in decode_kfx_csv(sys_dir / "KFXItem.csv"):
        item_type = to_int(row.get("ID"))
        if item_type <= 0:
            continue
        csp_prices: dict[str, int] = {}
        for i in range(8):
            t = to_int(row.get(f"PriceTime{i}"), 0)
            p = to_int(row.get(f"PricePoint{i}"), 0)
            if t != 0 and p > 0:
                csp_prices[str(t)] = p
        gp_prices: dict[str, int] = {}
        for i in range(4):
            t = to_int(row.get(f"GameCashTime{i}"), 0)
            p = to_int(row.get(f"GameCash{i}"), 0)
            if t != 0 and p > 0:
                gp_prices[str(t)] = p
        items.append({
            "item_type": item_type,
            "type_high": to_int(row.get("TypeIDHigh")),
            "type_low": to_int(row.get("TypeIDLow")),
            "name": row.get("Name", "").strip(),
            "sex": to_int(row.get("sex")),
            "inventory_type": to_int(row.get("InventoryType")),
            "use_type": to_int(row.get("useType")),
            "use_count": to_int(row.get("useCount")),
            "level_limit": to_int(row.get("LevelLimit")),
            "can_buy_with_gp": to_int(row.get("CanBuyWithMoney")) == 1,
            "csp_prices": csp_prices,
            "gp_prices": gp_prices,
        })
    (DATA_DIR / "items.json").write_text(json.dumps(items, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[OK] Extracted {len(items)} items -> {DATA_DIR / 'items.json'}")

    # 5. Extract Level Table (LevelUpgradeTable.csv)
    levels = []
    for row in decode_kfx_csv(sys_dir / "LevelUpgradeTable.csv"):
        lid = to_int(row.get("id"))
        if lid <= 0:
            continue
        levels.append({
            "level": lid,
            "name": row.get("Name", "").strip(),
            "icon": row.get("LevelIcon", "").strip(),
            "honor_point": to_int(row.get("HonorPoint")),
            "honor_upgrade": to_int(row.get("HonorUpgrade")),
        })
    (DATA_DIR / "levels.json").write_text(json.dumps(levels, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[OK] Extracted {len(levels)} levels -> {DATA_DIR / 'levels.json'}")

    # 6. Extract Quests (KFXQuest.csv)
    quests = []
    for row in decode_kfx_csv(sys_dir / "KFXQuest.csv"):
        qid = to_int(row.get("ID"))
        if qid <= 0:
            continue
        bonuses = []
        for i in range(1, 11):
            bid = to_int(row.get(f"BonusID{i}"))
            btm = to_int(row.get(f"Time{i}"))
            if bid > 0:
                bonuses.append({"item_type": bid, "days": btm})
        female_bonuses = []
        for i in range(1, 11):
            bid = to_int(row.get(f"FemaleBonusID{i}"))
            btm = to_int(row.get(f"FemaleTime{i}"))
            if bid > 0:
                female_bonuses.append({"item_type": bid, "days": btm})
        quests.append({
            "id": qid,
            "id_class": to_int(row.get("IDClass")),
            "id_type": to_int(row.get("IDType")),
            "id_step": to_int(row.get("IDStep")),
            "class_name": row.get("ClassName", "").strip(),
            "type_name": row.get("TypeName", "").strip(),
            "step_name": row.get("StepName", "").strip(),
            "is_first_step": to_int(row.get("IsFirstStep")) == 1,
            "step_count": to_int(row.get("StepCount")),
            "auto_accept": to_int(row.get("AutoAccept")) == 1,
            "auto_bonus": to_int(row.get("AutoBonus")) == 1,
            "random_bonus": to_int(row.get("RandomBonus")) == 1,
            "bonus_exp": to_int(row.get("BonusExp")),
            "bonuses": bonuses,
            "female_bonuses": female_bonuses,
        })
    (DATA_DIR / "quests.json").write_text(json.dumps(quests, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[OK] Extracted {len(quests)} quests -> {DATA_DIR / 'quests.json'}")


if __name__ == "__main__":
    main()

"""UE2.5 (UT2004 build 3369 / CSO Malaysia) CHTYPE_Actor Channel Replication,
Actor Spawning, Dirty-Property Delta Serialization, and RPC Encode/Decode.

Binary-verified against retail Core.dll, Engine.dll, Engine.u, KFXGame.u,
and KFXWeapons.u (PackageVersion=129, LicenseeMode=29, EngineVersion=3369):
- Initial Actor Bunch (`bOpen=1, bClose=0, bReliable=1`, `CHTYPE_Actor=2`):
  1. `Archetype` via `PackageMap.serialize_object`:
     - Static/NoDelete map actor: `bIsDynamic=0, WriteInt(ExportObjIdx, MaxObjectIndex)`.
       NO Location or Rotation follows.
     - Dynamic actor (`UClass*`): `bIsDynamic=0, WriteInt(ClassObjIdx, MaxObjectIndex)`,
       followed by compressed `Location` (`FVector`), followed by compressed `Rotation`
       (`FRotator`) ONLY when `ClassNetCache.b_net_initial_rotation == True`.
  2. Followed immediately by Property/RPC stream (no trailing terminator bit;
     reader loops `ReadInt(ClassCache.max_index)` until `at_end()` / `is_error()`).
- Owning `KFX*Player` MUST replicate `Actor.bNetOwner=True` (`RepIndex 18`) in its
  initial `bOpen=1` bunch so `UNetConnection::HandleClientPlayer(PC)` binds the
  viewport and dismisses the loading screen.
- Property wire format:
  - `WriteInt(RepIndex, ClassCache.max_index)`
  - If `ArrayDim != 1`: 1 raw byte (8 bits) `ElementIndex`
  - Value via exact `UProperty::NetSerializeItem` (`Enum` uses `ceil_log2(Num)` bits!)
- RPC wire format:
  - `WriteInt(BaseFuncRepIndex, ClassCache.max_index)`
  - For each non-return `CPF_Parm` parameter in order:
    - `BoolProperty`: 1 bit directly (NO presence bit)
    - All other types (required AND optional): 1-bit `bNonZero`; if `1`, value follows.
"""

from __future__ import annotations

import csv
import io
import logging
import math
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union

from .bitstream import (
    CHTYPE_ACTOR,
    MAX_CHANNELS,
    MAX_PACKET_BITS,
    BitReader,
    BitWriter,
    InBunch,
    OutBunch,
    UE2ConnectionState,
)
from .packagemap import (
    ClassNetCache,
    NetFieldEntry,
    PackageMap,
    RpcParamInfo,
    StructFieldInfo,
)

log = logging.getLogger("ue2.replication")

# ---------------------------------------------------------------------------
# UE2.5 Network / Physics Constants
# ---------------------------------------------------------------------------

# ENetRole (5 values -> 3 bits on wire)
ROLE_NONE: int = 0
ROLE_DUMB_PROXY: int = 1
ROLE_SIMULATED_PROXY: int = 2
ROLE_AUTONOMOUS_PROXY: int = 3
ROLE_AUTHORITY: int = 4

# EPhysics (17 values in CSO Malaysia Engine.u -> 5 bits on wire)
PHYS_NONE: int = 0
PHYS_WALKING: int = 1
PHYS_FALLING: int = 2
PHYS_SWIMMING: int = 3
PHYS_FLYING: int = 4
PHYS_ROTATING: int = 5
PHYS_PROJECTILE: int = 6
PHYS_INTERPOLATING: int = 7
PHYS_MOVING_BRUSH: int = 8
PHYS_SPIDER: int = 9
PHYS_TRAILER: int = 10
PHYS_LADDER: int = 11
PHYS_ROOT_MOTION: int = 12
PHYS_KARMA: int = 13
PHYS_KARMA_RAGDOLL: int = 14
PHYS_HOVERING: int = 15
PHYS_CINEMATICS: int = 16

# Safe per-bunch payload bit budget (UE2.5 has NO partial bunches; max datagram = 4095 bits)
SAFE_BUNCH_BITS: int = 3200

# Combat message & damage type static class paths (verified in KFXGame.u / KFXWeapons.u)
COMBAT_MSG_NORMAL = "KFXGame.KFXCombatMessage_Normal"
COMBAT_MSG_HEADSHOT = "KFXGame.KFXCombatMessage_KillHead"
COMBAT_MSG_SUICIDE = "KFXGame.KFXCombatMessage_Suicide"
COMBAT_MSG_AUTOAIM = "KFXGame.KFXCombatMessage_AutoAim"

DMG_TYPE_INSTANT = "KFXWeapons.KFXDmgTypeInstant"
DMG_TYPE_DELAYED = "KFXWeapons.KFXDmgTypeDelayed"
DMG_TYPE_C4 = "KFXGame.KFXDmgTypeC4"

# Game mode -> exact CSO Malaysia KFXGame class names (verified from KFXGame.u)
GAME_MODE_CLASSES: Dict[int, Dict[str, Any]] = {
    1: {
        "game_class": "KFXGame.KFXMeleeGame",
        "pc_class": "KFXGame.KFXMeleePlayer",
        "hud_class": "KFXGame.KFXMeleeHUD",
        "scoreboard_class": "KFXGame.KFXMeleeGameScoreBoard",
        "gri_class": "KFXGame.KFXMeleeGameReplicationInfo",
        "pri_class": "KFXGame.KFXMeleePlayerReplicationInfo",
        "team_class": "KFXGame.KFXTeamInfo",
        "pawn_class": "KFXGame.KFXPawn",
        "team_game": True,
        "game_name": "Team Death",
    },
    2: {
        "game_class": "KFXGame.KFXSingleGame",
        "pc_class": "KFXGame.KFXSinglePlayer",
        "hud_class": "KFXGame.KFXSingleHUD",
        "scoreboard_class": "KFXGame.KFXSingleGameScoreBoard",
        "gri_class": "KFXGame.KFXSingleGameReplicationInfo",
        "pri_class": "KFXGame.KFXSinglePlayerReplicationInfo",
        "team_class": "KFXGame.KFXTeamInfo",
        "pawn_class": "KFXGame.KFXPawn",
        "team_game": False,
        "game_name": "Death Match",
    },
    3: {
        "game_class": "KFXGame.KFXRoundGame",
        "pc_class": "KFXGame.KFXRoundPlayer",
        "hud_class": "KFXGame.KFXRoundHUD",
        "scoreboard_class": "KFXGame.KFXRoundGameScoreBoard",
        "gri_class": "KFXGame.KFXRoundGameReplicationInfo",
        "pri_class": "KFXGame.KFXRoundPlayerReplicationInfo",
        "team_class": "KFXGame.KFXTeamInfo",
        "pawn_class": "KFXGame.KFXPawn",
        "team_game": True,
        "game_name": "Team Match",
    },
    4: {
        "game_class": "KFXGame.KFXBombGame",
        "pc_class": "KFXGame.KFXBombPlayer",
        "hud_class": "KFXGame.KFXBombHUD",
        "scoreboard_class": "KFXGame.KFXBombGameScoreBoard",
        "gri_class": "KFXGame.KFXBombGameReplicationInfo",
        "pri_class": "KFXGame.KFXBombPlayerReplicationInfo",
        "team_class": "KFXGame.KFXTeamInfo",
        "pawn_class": "KFXGame.KFXPawn",
        "team_game": True,
        "game_name": "Bomb Match",
    },
    5: {
        "game_class": "KFXGame.KFXOccupyGame",
        "pc_class": "KFXGame.KFXOccupyPlayer",
        "hud_class": "KFXGame.KFXOccupyHUD",
        "scoreboard_class": "KFXGame.KFXOccupyGameScoreBoard",
        "gri_class": "KFXGame.KFXOccupyGameReplicationInfo",
        "pri_class": "KFXGame.KFXOccupyPlayerReplicationInfo",
        "team_class": "KFXGame.KFXTeamInfo",
        "pawn_class": "KFXGame.KFXPawn",
        "team_game": True,
        "game_name": "Occupation Match",
    },
}

# WeaponClass.csv ID -> UClass
_WEAPON_CLASS_ID_TO_UCLASS: Dict[int, str] = {
    1: "KFXWeapons.KFXWeapRifle",
    2: "KFXWeapons.KFXWeapPistal",
    3: "KFXWeapons.KFXWeapMelee",
    4: "KFXWeapons.KFXWeapSniper",
    5: "KFXWeapons.KFXWeapToss",
    6: "KFXWeapons.KFXWeapCFour",
    7: "KFXWeapons.KFXWeapRocket",
    8: "KFXWeapons.KFXWeapMachinegun",
    9: "KFXWeapons.KFXWeapGreenMG",
    10: "KFXWeapons.KFXWeapRocketBase",
    11: "KFXWeapons.KFXWeapApplyProp",
    12: "KFXWeapons.KFXWeapMine",
    13: "KFXWeapons.KFXWeapEG",
    14: "KFXWeapons.KFXWeapEPO",
    15: "KFXWeapons.KFXWeapX",
    16: "KFXWeapons.KFXWeapGRX",
}

# Verified WeaponID -> (UClass, Accessory0) from retail System\WeaponAttribute.csv + WeaponClass.csv
# (All 62 weapons verified; e.g. M249=13 NOT 10 Hammer!)
WEAPON_CLASS_MAP: Dict[int, Tuple[str, int]] = {
    1: ("KFXWeapons.KFXWeapCFour", 16),          # C4
    101: ("KFXWeapons.KFXWeapApplyProp", 5),     # Prop item
    102: ("KFXWeapons.KFXWeapRocketBase", 21),   # Freeze rocket
    103: ("KFXWeapons.KFXWeapRocketBase", 21),   # 5x rocket
    104: ("KFXWeapons.KFXWeapToss", 27),         # Slow grenade
    105: ("KFXWeapons.KFXWeapRocketBase", 21),   # Pig rocket
    106: ("KFXWeapons.KFXWeapRocketBase", 21),   # Turtle rocket
    65537: ("KFXWeapons.KFXWeapRifle", 1),       # AK47
    65538: ("KFXWeapons.KFXWeapRifle", 7),       # M4A1
    65539: ("KFXWeapons.KFXWeapRifle", 8),       # MP5
    65540: ("KFXWeapons.KFXWeapRifle", 2),       # XM1014
    65541: ("KFXWeapons.KFXWeapSniper", 3),      # AWP
    65542: ("KFXWeapons.KFXWeapMachinegun", 13), # M249 (Accessory0=13; 10 is Hammer!)
    65543: ("KFXWeapons.KFXWeapMachinegun", 14), # M60
    65544: ("KFXWeapons.KFXWeapRifle", 15),      # M3
    65545: ("KFXWeapons.KFXWeapRifle", 18),      # MP7
    65546: ("KFXWeapons.KFXWeapSniper", 19),     # M24
    65547: ("KFXWeapons.KFXWeapRocket", 20),     # Bazooka
    65548: ("KFXWeapons.KFXWeapRocket", 21),     # RPG7
    65549: ("KFXWeapons.KFXWeapRifle", 24),      # AUG
    65550: ("KFXWeapons.KFXWeapSniper", 25),     # G3
    65551: ("KFXWeapons.KFXWeapGreenMG", 26),    # M134
    65552: ("KFXWeapons.KFXWeapRifle", 28),      # P90
    65553: ("KFXWeapons.KFXWeapRocket", 29),     # MGL140
    65554: ("KFXWeapons.KFXWeapRifle", 32),      # QBZ-95
    65555: ("KFXWeapons.KFXWeapRifle", 34),      # XM8
    65556: ("KFXWeapons.KFXWeapRifle", 35),      # SCAR
    65557: ("KFXWeapons.KFXWeapSniper", 37),     # Type 85 Sniper
    65589: ("KFXWeapons.KFXWeapSniper", 3),      # AWP s1
    65590: ("KFXWeapons.KFXWeapRifle", 24),      # AUG s1
    65591: ("KFXWeapons.KFXWeapSniper", 25),     # G3 s1
    65592: ("KFXWeapons.KFXWeapRocket", 20),     # Bazooka s1
    65593: ("KFXWeapons.KFXWeapMachinegun", 14), # M60 s1
    65594: ("KFXWeapons.KFXWeapSniper", 19),     # M24 s1
    65595: ("KFXWeapons.KFXWeapRifle", 2),       # XM1014 s1
    65596: ("KFXWeapons.KFXWeapRifle", 15),      # M3 s1
    65597: ("KFXWeapons.KFXWeapRifle", 1),       # AK47 s1
    65598: ("KFXWeapons.KFXWeapRifle", 7),       # M4A1 s1
    65599: ("KFXWeapons.KFXWeapRifle", 8),       # MP5 s1
    65600: ("KFXWeapons.KFXWeapRifle", 18),      # MP7 s1
    65601: ("KFXWeapons.KFXWeapRifle", 28),      # P90 s1
    65602: ("KFXWeapons.KFXWeapRifle", 42),      # Golden QBZ-95
    65603: ("KFXWeapons.KFXWeapSniper", 43),     # Camo AWP
    65604: ("KFXWeapons.KFXWeapRifle", 44),      # AK47 variant
    65605: ("KFXWeapons.KFXWeapRifle", 45),      # M4A1 variant
    131078: ("KFXWeapons.KFXWeapPistal", 4),     # Glock (exact KFX spelling: Pistal!)
    131079: ("KFXWeapons.KFXWeapPistal", 9),     # DEagle
    131080: ("KFXWeapons.KFXWeapPistal", 31),    # Mauser / C96
    131081: ("KFXWeapons.KFXWeapPistal", 36),    # M500
    131082: ("KFXWeapons.KFXWeapPistal", 38),    # Type 54 Pistol
    196616: ("KFXWeapons.KFXWeapMelee", 6),      # Melon Knife
    196617: ("KFXWeapons.KFXWeapMelee", 10),     # Hammer
    196618: ("KFXWeapons.KFXWeapMelee", 22),     # Dagger
    196619: ("KFXWeapons.KFXWeapMelee", 23),     # Axe
    196620: ("KFXWeapons.KFXWeapMelee", 30),     # Broadsword
    262154: ("KFXWeapons.KFXWeapToss", 5),       # Pig Bomb
    262155: ("KFXWeapons.KFXWeapToss", 12),      # Flashbang
    262156: ("KFXWeapons.KFXWeapToss", 11),      # HE Grenade
    262157: ("KFXWeapons.KFXWeapToss", 17),      # Smoke
    262158: ("KFXWeapons.KFXWeapToss", 27),      # Turtle Bomb
    262159: ("KFXWeapons.KFXWeapToss", 33),      # Cat Bomb
    262160: ("KFXWeapons.KFXWeapToss", 41),      # Snowman Bomb
}

_WEAPON_CSV_CACHE: Dict[str, Dict[int, Tuple[str, List[int]]]] = {}


def _load_weapon_visual_table(game_dir: Optional[str]) -> Dict[int, Tuple[str, List[int]]]:
    """Load `WeaponID -> (UClass, [Accessory0..Accessory6])` from retail WeaponAttribute.csv."""
    if not game_dir:
        return {}
    key = os.path.abspath(game_dir).lower()
    cached = _WEAPON_CSV_CACHE.get(key)
    if cached is not None:
        return cached
    table: Dict[int, Tuple[str, List[int]]] = {}
    try:
        sys_dir = Path(game_dir) / "System"
        cls_map = dict(_WEAPON_CLASS_ID_TO_UCLASS)
        wcls_path = sys_dir / "WeaponClass.csv"
        if wcls_path.is_file():
            raw = wcls_path.read_bytes()
            dec = bytes(b ^ 0x9D for b in raw[3:]) if raw[:3] == b"KFX" else raw
            for row in csv.DictReader(io.StringIO(dec.decode("gbk", errors="replace"))):
                cid_s = (row.get("ID") or "").strip()
                cname = (row.get("Class") or "").strip()
                if cid_s.isdigit() and cname:
                    cls_map[int(cid_s)] = cname
        wattr_path = sys_dir / "WeaponAttribute.csv"
        if wattr_path.is_file():
            raw = wattr_path.read_bytes()
            dec = bytes(b ^ 0x9D for b in raw[3:]) if raw[:3] == b"KFX" else raw
            for row in csv.DictReader(io.StringIO(dec.decode("gbk", errors="replace"))):
                wid_s = (row.get("ID") or "").strip()
                if not wid_s.isdigit():
                    continue
                wid = int(wid_s)
                cid = int((row.get("Class") or "1").strip() or "1")
                ucls = cls_map.get(cid, "KFXWeapons.KFXWeapRifle")
                accs: List[int] = []
                for idx in range(7):
                    av = (row.get(f"Accessory{idx}") or "0").strip()
                    accs.append(int(av) if av.lstrip("-").isdigit() else 0)
                table[wid] = (ucls, accs)
    except Exception as exc:
        log.debug("Could not load WeaponAttribute.csv from %s: %s", game_dir, exc)
    _WEAPON_CSV_CACHE[key] = table
    return table

# Properties prioritized first in bOpen=1 bunches so client binding (HandleClientPlayer)
# always receives critical actor identity/owner fields in the very first bunch.
_INITIAL_PROP_PRIORITY: Dict[str, int] = {
    "bnetowner": 0,
    "role": 1,
    "remoterole": 2,
    "owner": 3,
    "instigator": 4,
    "controller": 5,
    "playerreplicationinfo": 6,
    "gamereplicationinfo": 7,
    "team": 8,
    "teamindex": 9,
    "teams": 10,
    "pawn": 11,
    "location": 12,
    "rotation": 13,
    "velocity": 14,
    "physics": 15,
    "drawscale": 16,
    "collisionheight": 17,
    "collisionradius": 18,
    "defprepivot": 19,
    "prepivot": 20,
    "health": 21,
    "healthmax": 22,
    "playername": 23,
    "playerid": 24,
    "thirdpersonactor": 25,
    "kfxweaponid": 26,
    "inventory": 27,
}

# Movement properties that MUST NOT be echoed back to the owning client's
# ROLE_AutonomousProxy pawn after initial spawn (bNetInitial). Echoing them back
# overwrites UE2 client-side prediction with stale server state and causes severe
# rubber-banding / sluggish walking! (Matches Engine.u Actor/Pawn replication.)
_OWNER_SKIP_PAWN_MOVEMENT_PROPS: frozenset[str] = frozenset({
    "location",
    "rotation",
    "velocity",
    "physics",
    "base",
    "viewpitch",
    "pawnposition",
    "biscrouched",
    "biswalking",
})

# Properties that must always replicate reliably when dirty (lifecycle/combat/scoreboard)
_RELIABLE_DELTA_PROPS: frozenset[str] = frozenset({
    "bnetowner",
    "role",
    "remoterole",
    "owner",
    "instigator",
    "controller",
    "inventory",
    "pawn",
    "playerreplicationinfo",
    "gamereplicationinfo",
    "team",
    "teams",
    "teamindex",
    "teamname",
    "score",
    "deaths",
    "playername",
    "playerid",
    "teamid",
    "breadytoplay",
    "bdeadstatus",
    "bisspectator",
    "bonlyspectator",
    "bheadkill",
    "fxkills",
    "fxdeaths",
    "fxlevel",
    "winner",
    "bmatchhasbegun",
    "bstopcountdown",
    "fxremainingtime",
    "fxtimelimit",
    "fxkilledlimit",
    "fxmapid",
    "health",
    "healthmax",
    "kfxarmorpoints",
    "btearoff",
    "tearoffmomentum",
    "hitdamagetype",
    "takehitlocation",
    "kfxdmgrepinfo",
    "kfxhitweaponid",
    "kfxpendingstate",
    "kfxavatar",
    "biscrouched",
    "thirdpersonactor",
    "kfxreload",
    "kfxammocount",
    "bisreload",
    "kfxweaponid",
    "kfxaccessory",
    "flashcount",
    "firingmode",
    "spawnhitcount",
    "hitlocs",
    "fxdbplayerinfo",
})


def get_mode_classes(game_mode: Union[int, str] = 1) -> Dict[str, Any]:
    """Return exact CSO Malaysia class names for a game mode ID (1..5) or game class string."""
    if isinstance(game_mode, int):
        return GAME_MODE_CLASSES.get(game_mode, GAME_MODE_CLASSES[1])
    low = str(game_mode).lower()
    for cfg in GAME_MODE_CLASSES.values():
        if cfg["game_class"].lower() == low or cfg["game_class"].split(".")[-1].lower() == low:
            return cfg
    return GAME_MODE_CLASSES[1]


def get_weapon_class(weapon_id: int, game_dir: Optional[str] = None) -> Tuple[str, int]:
    """Return `(KFXWeapons.KFXWeap*, accessory0)` for a WeaponID."""
    wid = int(weapon_id)
    if game_dir:
        csv_table = _load_weapon_visual_table(game_dir)
        entry = csv_table.get(wid)
        if entry is not None:
            return (entry[0], entry[1][0] if entry[1] else 0)
    if wid in WEAPON_CLASS_MAP:
        return WEAPON_CLASS_MAP[wid]
    major = (wid >> 16) & 0xFFFF
    if major == 1:
        return ("KFXWeapons.KFXWeapRifle", 1)
    if major == 2:
        return ("KFXWeapons.KFXWeapPistal", 4)
    if major == 3:
        return ("KFXWeapons.KFXWeapMelee", 6)
    if major == 4:
        return ("KFXWeapons.KFXWeapToss", 11)
    return ("KFXWeapons.KFXWeapRifle", 1)


def get_weapon_accessories(weapon_id: int, game_dir: Optional[str] = None) -> List[int]:
    """Return all 7 `KFXAccessory[0..6]` IDs for a WeaponID from WeaponAttribute.csv."""
    wid = int(weapon_id)
    if game_dir:
        csv_table = _load_weapon_visual_table(game_dir)
        entry = csv_table.get(wid)
        if entry is not None:
            return list(entry[1])
    _, acc0 = get_weapon_class(wid)
    return [acc0, 0, 0, 0, 0, 0, 0]


# ---------------------------------------------------------------------------
# ServerMove View Packing Helpers (verified against Engine.u bytecode)
# ---------------------------------------------------------------------------

def pack_server_move_view(pitch: int, yaw: int) -> int:
    """Pack UE2 rotator `(Pitch, Yaw)` (0..65535) into ServerMove's `int View`.

    Exact Engine.u PlayerController.CallServerMove formula:
      View = (32767 & (Pitch // 2)) * 32768 + (32767 & (Yaw // 2))
    """
    p = ((int(pitch) & 0xFFFF) >> 1) & 0x7FFF
    y = ((int(yaw) & 0xFFFF) >> 1) & 0x7FFF
    return (p << 15) | y


def unpack_server_move_view(view: int, client_roll: int = 0) -> Tuple[int, int, int]:
    """Unpack ServerMove's `int View` + `byte ClientRoll` into UE2 `(Pitch, Yaw, Roll)`."""
    v = int(view) & 0xFFFFFFFF
    pitch = ((v >> 15) & 0x7FFF) * 2
    yaw = (v & 0x7FFF) * 2
    roll = (int(client_roll) & 0xFF) * 256
    return (pitch, yaw, roll)


def rotator_to_view_pitch_byte(pitch: int) -> int:
    """Encode UE2 Pawn.ViewPitch byte: `(Pitch & 0xFFFF) >> 8`."""
    return (int(pitch) & 0xFFFF) >> 8


def unpack_dual_server_move_compress(pending_compress: int) -> Dict[str, bool]:
    """Unpack DualServerMove's `PendingCompress` byte into move 0 & current flags."""
    pc = int(pending_compress) & 0xFF
    return {
        "NewbRun0": bool(pc & 0x01),
        "NewbDuck0": bool(pc & 0x02),
        "NewbJumpStatus0": bool(pc & 0x04),
        "NewbDoubleJump0": bool(pc & 0x08),
        "NewbRun": bool(pc & 0x10),
        "NewbDuck": bool(pc & 0x20),
        "NewbJumpStatus": bool(pc & 0x40),
        "NewbDoubleJump": bool(pc & 0x80),
    }


# ---------------------------------------------------------------------------
# Object Reference Wrappers
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ActorRef:
    """Reference to a server-side ReplicatedActor by its match-local `actor_id`."""
    actor_id: int


@dataclass(frozen=True)
class ChannelRef:
    """Direct reference to a wire Actor Channel index (`0` = None, `1..1022` = channel)."""
    ch_index: int


@dataclass(frozen=True)
class StaticRef:
    """Explicit reference to a static package export (by full name or global index)."""
    ref: Union[str, int, Tuple[str, int]]


@dataclass(frozen=True)
class NetObjectRef:
    """Decoded UE2 ObjectProperty / ClassProperty reference."""
    is_dynamic: bool
    channel_index: int = 0
    static_index: int = -1
    full_name: Optional[str] = None
    actor_id: Optional[int] = None

    @property
    def is_none(self) -> bool:
        return self.is_dynamic and self.channel_index == 0


# ---------------------------------------------------------------------------
# Default / Zero-Check Helpers & UProperty::NetSerializeItem Wire Codec
# ---------------------------------------------------------------------------

def default_value_for_type(
    prop_type: str,
    *,
    struct_name: Optional[str] = None,
    struct_fields: Optional[Sequence[StructFieldInfo]] = None,
    pkgmap: Optional[PackageMap] = None,
) -> Any:
    """Return zero/default Python value for a UE2 property or RPC parameter type."""
    if prop_type == "BoolProperty":
        return False
    if prop_type in ("ByteProperty", "IntProperty"):
        return 0
    if prop_type == "FloatProperty":
        return 0.0
    if prop_type == "NameProperty":
        return "None"
    if prop_type == "StrProperty":
        return ""
    if prop_type in ("ObjectProperty", "ClassProperty"):
        return None
    if prop_type == "StructProperty":
        sn = struct_name or ""
        if sn == "Vector":
            return (0.0, 0.0, 0.0)
        if sn == "Rotator":
            return (0, 0, 0)
        if sn == "CompressedPosition":
            return ((0.0, 0.0, 0.0), (0, 0, 0), (0.0, 0.0, 0.0))
        if sn == "Quat":
            return (0.0, 0.0, 0.0, 1.0)
        if sn == "Plane":
            return (0.0, 0.0, 0.0, 0.0)
        if sn == "Coords":
            return ((0.0, 0.0, 0.0), (1.0, 0.0, 0.0), (0.0, 1.0, 0.0), (0.0, 0.0, 1.0))
        fields = list(struct_fields) if struct_fields else (
            pkgmap.get_struct_fields(sn) if (pkgmap and sn) else []
        )
        out: Dict[str, Any] = {}
        for sf in fields:
            elem_def = default_value_for_type(
                sf.prop_type, struct_name=sf.struct_name, pkgmap=pkgmap
            )
            if sf.array_dim > 1:
                out[sf.name] = [elem_def for _ in range(sf.array_dim)]
            else:
                out[sf.name] = elem_def
        return out
    return None


def _resolve_object_for_wire(
    value: Any,
    pkgmap: PackageMap,
    actor_to_channel: Optional[Dict[int, int]] = None,
) -> Tuple[Optional[int], Optional[int]]:
    """Resolve a Python object reference into `(static_index, channel_index)`.

    Returns `(static_idx, None)` for static package exports, or `(None, ch_idx)`
    for dynamic actors / None (with `ch_idx == 0` meaning NULL).
    """
    if value is None:
        return (None, 0)
    if isinstance(value, ReplicatedActor):
        if value.is_static and value.static_index >= 0:
            return (value.static_index, None)
        ch = (actor_to_channel or {}).get(value.actor_id, 0)
        return (None, ch)
    if isinstance(value, ActorRef):
        ch = (actor_to_channel or {}).get(value.actor_id, 0)
        return (None, ch)
    if isinstance(value, ChannelRef):
        return (None, value.ch_index)
    if isinstance(value, StaticRef):
        if isinstance(value.ref, int):
            if 0 <= value.ref < pkgmap.max_object_index:
                return (value.ref, None)
            return (None, 0)
        idx = pkgmap.object_to_index(value.ref)
        return (idx, None) if idx >= 0 else (None, 0)
    if isinstance(value, NetObjectRef):
        if value.is_dynamic:
            if value.actor_id is not None and actor_to_channel is not None:
                return (None, actor_to_channel.get(value.actor_id, value.channel_index))
            return (None, value.channel_index)
        if 0 <= value.static_index < pkgmap.max_object_index:
            return (value.static_index, None)
        if value.full_name:
            idx = pkgmap.object_to_index(value.full_name)
            if idx >= 0:
                return (idx, None)
        return (None, 0)
    if isinstance(value, str):
        if not value or value.lower() == "none":
            return (None, 0)
        idx = pkgmap.object_to_index(value)
        return (idx, None) if idx >= 0 else (None, 0)
    if isinstance(value, tuple) and len(value) == 2 and isinstance(value[0], str):
        idx = pkgmap.object_to_index(value)
        return (idx, None) if idx >= 0 else (None, 0)
    if isinstance(value, int):
        # Raw integer: if it matches an actor_id in actor_to_channel, map it; else treat as channel index
        if actor_to_channel is not None and value in actor_to_channel:
            return (None, actor_to_channel[value])
        if 0 <= value < MAX_CHANNELS:
            return (None, value)
        return (None, 0)
    return (None, 0)


def _extract_struct_field_value(
    struct_val: Any,
    sf: StructFieldInfo,
    idx: int,
    pkgmap: PackageMap,
) -> Any:
    """Extract field `sf` from a dict, list/tuple, or attribute-bearing object."""
    if struct_val is None:
        val = None
    elif isinstance(struct_val, dict):
        if sf.name in struct_val:
            val = struct_val[sf.name]
        else:
            low = sf.name.lower()
            val = None
            for k, v in struct_val.items():
                if str(k).lower() == low:
                    val = v
                    break
    elif isinstance(struct_val, (list, tuple)):
        val = struct_val[idx] if idx < len(struct_val) else None
    else:
        val = getattr(struct_val, sf.name, None)

    if val is None:
        elem_def = default_value_for_type(sf.prop_type, struct_name=sf.struct_name, pkgmap=pkgmap)
        return [elem_def for _ in range(sf.array_dim)] if sf.array_dim > 1 else elem_def
    return val


def is_value_non_zero(
    prop_type: str,
    value: Any,
    pkgmap: PackageMap,
    *,
    struct_name: Optional[str] = None,
    struct_fields: Optional[Sequence[StructFieldInfo]] = None,
    actor_to_channel: Optional[Dict[int, int]] = None,
) -> bool:
    """Match Core.dll/Engine.dll `appMemcmp(Parm, ZeroMem, Size) != 0` check for RPC params."""
    if value is None:
        return False
    if prop_type == "BoolProperty":
        return bool(value)
    if prop_type in ("ByteProperty", "IntProperty"):
        return int(value) != 0
    if prop_type == "FloatProperty":
        fv = float(value)
        return fv != 0.0 and not math.isnan(fv)
    if prop_type == "NameProperty":
        s = str(value)
        return bool(s) and s.lower() != "none"
    if prop_type == "StrProperty":
        return len(str(value)) > 0
    if prop_type in ("ObjectProperty", "ClassProperty"):
        static_idx, ch_idx = _resolve_object_for_wire(value, pkgmap, actor_to_channel)
        if static_idx is not None and static_idx >= 0:
            return True
        return bool(ch_idx and ch_idx > 0)
    if prop_type == "StructProperty":
        sn = struct_name or ""
        if sn == "Vector":
            return any(float(c) != 0.0 for c in value[:3])
        if sn == "Rotator":
            return any(int(c) != 0 for c in value[:3])
        if sn == "CompressedPosition":
            if isinstance(value, dict):
                loc = value.get("Location", (0.0, 0.0, 0.0))
                rot = value.get("Rotation", (0, 0, 0))
                vel = value.get("Velocity", (0.0, 0.0, 0.0))
            else:
                loc, rot, vel = value[0], value[1], value[2]
            return (
                any(float(c) != 0.0 for c in loc[:3])
                or any(int(c) != 0 for c in rot[:3])
                or any(float(c) != 0.0 for c in vel[:3])
            )
        if sn in ("Quat", "Plane"):
            return any(float(c) != 0.0 for c in value[:4])
        fields = list(struct_fields) if struct_fields else (
            pkgmap.get_struct_fields(sn) if sn else []
        )
        for i, sf in enumerate(fields):
            fv = _extract_struct_field_value(value, sf, i, pkgmap)
            if sf.array_dim > 1:
                items = list(fv) if isinstance(fv, (list, tuple)) else []
                for item in items[: sf.array_dim]:
                    if is_value_non_zero(
                        sf.prop_type,
                        item,
                        pkgmap,
                        struct_name=sf.struct_name,
                        actor_to_channel=actor_to_channel,
                    ):
                        return True
            else:
                if is_value_non_zero(
                    sf.prop_type,
                    fv,
                    pkgmap,
                    struct_name=sf.struct_name,
                    actor_to_channel=actor_to_channel,
                ):
                    return True
        return False
    return bool(value)


def serialize_value(
    writer: BitWriter,
    pkgmap: PackageMap,
    prop_type: str,
    value: Any,
    *,
    enum_name: Optional[str] = None,
    enum_bits: int = 8,
    struct_name: Optional[str] = None,
    struct_fields: Optional[Sequence[StructFieldInfo]] = None,
    actor_to_channel: Optional[Dict[int, int]] = None,
) -> None:
    """Exact UE2.5 Core.dll UProperty::NetSerializeItem encoder."""
    if prop_type == "BoolProperty":
        writer.write_bit(1 if value else 0)
    elif prop_type == "ByteProperty":
        if enum_name:
            bits = enum_bits if enum_bits > 0 else pkgmap.get_enum_bits(enum_name)
            writer.write_bits(int(value) if value is not None else 0, bits)
        else:
            writer.write_byte(int(value) if value is not None else 0)
    elif prop_type == "IntProperty":
        writer.write_int32(int(value) if value is not None else 0)
    elif prop_type == "FloatProperty":
        writer.write_float(float(value) if value is not None else 0.0)
    elif prop_type == "NameProperty":
        pkgmap.serialize_name(writer, str(value) if value is not None else "None")
    elif prop_type == "StrProperty":
        writer.write_fstring(str(value) if value is not None else "")
    elif prop_type in ("ObjectProperty", "ClassProperty"):
        static_idx, ch_idx = _resolve_object_for_wire(value, pkgmap, actor_to_channel)
        if static_idx is not None:
            pkgmap.serialize_object(writer, static_index=static_idx)
        else:
            pkgmap.serialize_object(writer, channel_index=ch_idx or 0)
    elif prop_type == "ArrayProperty":
        # Core.dll UArrayProperty::NetSerializeItem is a 0-bit no-op
        return
    elif prop_type == "StructProperty":
        sn = struct_name or ""
        if sn == "Vector":
            vec = value if value is not None else (0.0, 0.0, 0.0)
            writer.write_compressed_vector((float(vec[0]), float(vec[1]), float(vec[2])))
        elif sn == "Rotator":
            rot = value if value is not None else (0, 0, 0)
            writer.write_compressed_rotator((int(rot[0]), int(rot[1]), int(rot[2])))
        elif sn == "CompressedPosition":
            if isinstance(value, dict):
                loc = value.get("Location", (0.0, 0.0, 0.0))
                rot = value.get("Rotation", (0, 0, 0))
                vel = value.get("Velocity", (0.0, 0.0, 0.0))
            elif value is not None:
                loc, rot, vel = value[0], value[1], value[2]
            else:
                loc, rot, vel = (0.0, 0.0, 0.0), (0, 0, 0), (0.0, 0.0, 0.0)
            writer.write_compressed_position(loc, rot, vel)
        elif sn == "Quat":
            q = value if value is not None else (0.0, 0.0, 0.0, 1.0)
            writer.write_compressed_quat((float(q[0]), float(q[1]), float(q[2]), float(q[3])))
        elif sn == "Plane":
            pl = value if value is not None else (0.0, 0.0, 0.0, 0.0)
            writer.write_compressed_plane((float(pl[0]), float(pl[1]), float(pl[2]), float(pl[3])))
        elif sn == "Coords":
            cs = value if value is not None else (
                (0.0, 0.0, 0.0), (1.0, 0.0, 0.0), (0.0, 1.0, 0.0), (0.0, 0.0, 1.0)
            )
            for v in cs[:4]:
                writer.write_compressed_vector(v)
        else:
            fields = list(struct_fields) if struct_fields else (
                pkgmap.get_struct_fields(sn) if sn else []
            )
            for i, sf in enumerate(fields):
                fv = _extract_struct_field_value(value, sf, i, pkgmap)
                if sf.array_dim > 1:
                    items = list(fv) if isinstance(fv, (list, tuple)) else []
                    elem_def = default_value_for_type(
                        sf.prop_type, struct_name=sf.struct_name, pkgmap=pkgmap
                    )
                    for ai in range(sf.array_dim):
                        item = items[ai] if ai < len(items) else elem_def
                        serialize_value(
                            writer,
                            pkgmap,
                            sf.prop_type,
                            item,
                            enum_name=sf.enum_name,
                            enum_bits=sf.enum_bits,
                            struct_name=sf.struct_name,
                            actor_to_channel=actor_to_channel,
                        )
                else:
                    serialize_value(
                        writer,
                        pkgmap,
                        sf.prop_type,
                        fv,
                        enum_name=sf.enum_name,
                        enum_bits=sf.enum_bits,
                        struct_name=sf.struct_name,
                        actor_to_channel=actor_to_channel,
                    )
    else:
        raise ValueError(f"Unsupported UE2 NetSerializeItem property type: {prop_type!r}")


def deserialize_value(
    reader: BitReader,
    pkgmap: PackageMap,
    prop_type: str,
    *,
    enum_name: Optional[str] = None,
    enum_bits: int = 8,
    struct_name: Optional[str] = None,
    struct_fields: Optional[Sequence[StructFieldInfo]] = None,
    channel_to_actor: Optional[Dict[int, int]] = None,
) -> Any:
    """Exact UE2.5 Core.dll UProperty::NetSerializeItem decoder."""
    if prop_type == "BoolProperty":
        return bool(reader.read_bit())
    if prop_type == "ByteProperty":
        if enum_name:
            bits = enum_bits if enum_bits > 0 else pkgmap.get_enum_bits(enum_name)
            return reader.read_bits(bits)
        return reader.read_byte()
    if prop_type == "IntProperty":
        return reader.read_int32()
    if prop_type == "FloatProperty":
        return reader.read_float()
    if prop_type == "NameProperty":
        return pkgmap.deserialize_name(reader)
    if prop_type == "StrProperty":
        return reader.read_fstring()
    if prop_type in ("ObjectProperty", "ClassProperty"):
        is_dyn, idx = pkgmap.deserialize_object(reader)
        if reader.is_error():
            return None
        if is_dyn:
            if idx == 0:
                return None
            aid = (channel_to_actor or {}).get(idx)
            return NetObjectRef(is_dynamic=True, channel_index=idx, actor_id=aid)
        obj_info = pkgmap.index_to_object(idx)
        return NetObjectRef(
            is_dynamic=False,
            static_index=idx,
            full_name=obj_info[1] if obj_info else None,
        )
    if prop_type == "ArrayProperty":
        return []
    if prop_type == "StructProperty":
        sn = struct_name or ""
        if sn == "Vector":
            return reader.read_compressed_vector()
        if sn == "Rotator":
            return reader.read_compressed_rotator()
        if sn == "CompressedPosition":
            return reader.read_compressed_position()
        if sn == "Quat":
            return reader.read_compressed_quat()
        if sn == "Plane":
            return reader.read_compressed_plane()
        if sn == "Coords":
            return tuple(reader.read_compressed_vector() for _ in range(4))
        fields = list(struct_fields) if struct_fields else (
            pkgmap.get_struct_fields(sn) if sn else []
        )
        out: Dict[str, Any] = {}
        for sf in fields:
            if sf.array_dim > 1:
                arr = []
                for _ in range(sf.array_dim):
                    arr.append(
                        deserialize_value(
                            reader,
                            pkgmap,
                            sf.prop_type,
                            enum_name=sf.enum_name,
                            enum_bits=sf.enum_bits,
                            struct_name=sf.struct_name,
                            channel_to_actor=channel_to_actor,
                        )
                    )
                    if reader.is_error():
                        break
                out[sf.name] = arr
            else:
                out[sf.name] = deserialize_value(
                    reader,
                    pkgmap,
                    sf.prop_type,
                    enum_name=sf.enum_name,
                    enum_bits=sf.enum_bits,
                    struct_name=sf.struct_name,
                    channel_to_actor=channel_to_actor,
                )
            if reader.is_error():
                break
        return out
    raise ValueError(f"Unsupported UE2 NetSerializeItem property type: {prop_type!r}")


# ---------------------------------------------------------------------------
# Property & RPC Bunch Builders and Decoders
# ---------------------------------------------------------------------------

@dataclass
class DecodedRPC:
    """Parsed UE2.5 RPC call from an Actor channel bunch."""
    name: str
    rep_index: int
    args: Dict[str, Any]
    ch_index: int
    is_reliable: bool = False
    actor_id: Optional[int] = None
    actor_kind: str = ""
    role_id: Optional[int] = None
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DecodedActorBunch:
    """Parsed UE2.5 CHTYPE_Actor bunch (initial spawn header + properties + RPCs)."""
    ch_index: int
    is_open: bool = False
    is_close: bool = False
    spawn_class: Optional[str] = None
    spawn_object_index: int = -1
    is_static_actor: bool = False
    spawn_location: Optional[Tuple[float, float, float]] = None
    spawn_rotation: Optional[Tuple[int, int, int]] = None
    properties: List[Tuple[str, int, Any]] = field(default_factory=list)
    rpcs: List[DecodedRPC] = field(default_factory=list)


def encode_property_into_writer(
    writer: BitWriter,
    pkgmap: PackageMap,
    class_cache: ClassNetCache,
    prop_name: str,
    value: Any,
    *,
    elem_index: int = 0,
    actor_to_channel: Optional[Dict[int, int]] = None,
) -> NetFieldEntry:
    """Encode a single `CPF_Net` property update into `writer`."""
    entry = class_cache.get_field(prop_name)
    if entry is None or not entry.is_property:
        raise KeyError(
            f"Replicated property {prop_name!r} not found in ClassNetCache for {class_cache.full_name}"
        )
    writer.write_int(entry.rep_index, class_cache.max_index)
    if entry.array_dim != 1:
        writer.write_byte(elem_index & 0xFF)
    serialize_value(
        writer,
        pkgmap,
        entry.prop_type,
        value,
        enum_name=entry.enum_name,
        enum_bits=entry.enum_bits,
        struct_name=entry.struct_name,
        struct_fields=entry.struct_fields,
        actor_to_channel=actor_to_channel,
    )
    return entry


def _bind_rpc_arguments(
    params: Sequence[RpcParamInfo],
    args: Sequence[Any],
    kwargs: Optional[Dict[str, Any]],
    pkgmap: PackageMap,
) -> List[Any]:
    """Bind positional/keyword arguments to a function's `RpcParamInfo` list."""
    kw_lower: Dict[str, Any] = {k.lower(): v for k, v in (kwargs or {}).items()}
    bound: List[Any] = []
    for idx, parm in enumerate(params):
        if idx < len(args):
            bound.append(args[idx])
        elif parm.name.lower() in kw_lower:
            bound.append(kw_lower[parm.name.lower()])
        else:
            bound.append(
                default_value_for_type(
                    parm.prop_type, struct_name=parm.struct_name, pkgmap=pkgmap
                )
            )
    return bound


def encode_rpc_into_writer(
    writer: BitWriter,
    pkgmap: PackageMap,
    class_cache: ClassNetCache,
    func_name: str,
    args: Sequence[Any] = (),
    kwargs: Optional[Dict[str, Any]] = None,
    *,
    actor_to_channel: Optional[Dict[int, int]] = None,
) -> NetFieldEntry:
    """Encode a UE2.5 RPC call into `writer` (matches AActor::ProcessRemoteFunction)."""
    entry = class_cache.get_field(func_name)
    if entry is None or not entry.is_function:
        raise KeyError(
            f"Replicated RPC {func_name!r} not found in ClassNetCache for {class_cache.full_name}"
        )
    writer.write_int(entry.rep_index, class_cache.max_index)
    bound_values = _bind_rpc_arguments(entry.params, args, kwargs, pkgmap)
    for parm, val in zip(entry.params, bound_values):
        if parm.prop_type == "BoolProperty":
            # BoolProperty RPC parms have NO presence bit (Core/Engine.dll 0x104c2bb1)
            writer.write_bit(1 if val else 0)
        else:
            non_zero = is_value_non_zero(
                parm.prop_type,
                val,
                pkgmap,
                struct_name=parm.struct_name,
                actor_to_channel=actor_to_channel,
            )
            writer.write_bit(1 if non_zero else 0)
            if non_zero:
                serialize_value(
                    writer,
                    pkgmap,
                    parm.prop_type,
                    val,
                    enum_name=parm.enum_name,
                    enum_bits=parm.enum_bits,
                    struct_name=parm.struct_name,
                    actor_to_channel=actor_to_channel,
                )
    return entry


def build_rpc_bunch(
    ch_index: int,
    pkgmap: PackageMap,
    class_cache: ClassNetCache,
    func_name: str,
    args: Sequence[Any] = (),
    kwargs: Optional[Dict[str, Any]] = None,
    *,
    actor_to_channel: Optional[Dict[int, int]] = None,
    force_reliable: Optional[bool] = None,
) -> OutBunch:
    """Build a standalone `OutBunch` carrying one encoded RPC call."""
    entry = class_cache.get_field(func_name)
    if entry is None or not entry.is_function:
        raise KeyError(
            f"Replicated RPC {func_name!r} not found in ClassNetCache for {class_cache.full_name}"
        )
    reliable = entry.is_reliable if force_reliable is None else bool(force_reliable)
    bunch = OutBunch(
        ch_index=ch_index,
        ch_type=CHTYPE_ACTOR,
        b_open=False,
        b_close=False,
        b_reliable=reliable,
    )
    encode_rpc_into_writer(
        bunch,
        pkgmap,
        class_cache,
        func_name,
        args=args,
        kwargs=kwargs,
        actor_to_channel=actor_to_channel,
    )
    return bunch


def _encode_single_prop_bits(
    pkgmap: PackageMap,
    class_cache: ClassNetCache,
    prop_name: str,
    elem_index: int,
    value: Any,
    actor_to_channel: Optional[Dict[int, int]],
) -> BitWriter:
    tmp = BitWriter(max_bits=MAX_PACKET_BITS)
    encode_property_into_writer(
        tmp,
        pkgmap,
        class_cache,
        prop_name,
        value,
        elem_index=elem_index,
        actor_to_channel=actor_to_channel,
    )
    return tmp


def build_actor_open_bunches(
    ch_index: int,
    pkgmap: PackageMap,
    class_cache: ClassNetCache,
    *,
    spawn_location: Tuple[float, float, float] = (0.0, 0.0, 0.0),
    spawn_rotation: Tuple[int, int, int] = (0, 0, 0),
    static_actor_index: Optional[int] = None,
    properties: Optional[Sequence[Tuple[str, int, Any]]] = None,
    actor_to_channel: Optional[Dict[int, int]] = None,
    max_bunch_bits: int = SAFE_BUNCH_BITS,
) -> List[OutBunch]:
    """Build reliable initial spawn bunch(es) (`bOpen=1, bReliable=1`) for an Actor channel.

    Automatically splits overflow properties into follow-up reliable bunches so no
    single bunch ever exceeds the UE2.5 512B MTU.
    """
    first = OutBunch(
        ch_index=ch_index,
        ch_type=CHTYPE_ACTOR,
        b_open=True,
        b_close=False,
        b_reliable=True,
    )
    if static_actor_index is not None and static_actor_index >= 0:
        # Static/NoDelete map actor (e.g. LevelInfo0): NO Location or Rotation
        pkgmap.serialize_object(first, static_index=static_actor_index)
    else:
        # Dynamic actor spawn: UClass static index + compressed Location + optional Rotation
        pkgmap.serialize_object(first, static_index=class_cache.class_object_index)
        first.write_compressed_vector(spawn_location)
        if class_cache.b_net_initial_rotation:
            first.write_compressed_rotator(spawn_rotation)

    bunches: List[OutBunch] = [first]
    if not properties:
        return bunches

    # Prioritize critical identity/ownership properties into the very first bOpen=1 bunch
    ordered = sorted(
        properties,
        key=lambda item: (_INITIAL_PROP_PRIORITY.get(item[0].lower(), 100), item[1]),
    )
    cur = first
    for prop_name, elem_idx, val in ordered:
        entry = class_cache.get_field(prop_name)
        if entry is None or not entry.is_property:
            continue
        encoded = _encode_single_prop_bits(
            pkgmap, class_cache, prop_name, elem_idx, val, actor_to_channel
        )
        if encoded.is_error():
            log.warning(
                "Property %s.%s[%d] exceeded max bit buffer; skipping",
                class_cache.class_name, prop_name, elem_idx,
            )
            continue
        if cur.num_bits > 0 and (cur.num_bits + encoded.num_bits) > max_bunch_bits:
            cur = OutBunch(
                ch_index=ch_index,
                ch_type=CHTYPE_ACTOR,
                b_open=False,
                b_close=False,
                b_reliable=True,
            )
            bunches.append(cur)
        cur.write_bits_bytes(encoded.buf, encoded.num_bits)

    return bunches


def build_actor_delta_bunches(
    ch_index: int,
    pkgmap: PackageMap,
    class_cache: ClassNetCache,
    properties: Sequence[Tuple[str, int, Any]],
    *,
    reliable: bool = False,
    actor_to_channel: Optional[Dict[int, int]] = None,
    max_bunch_bits: int = SAFE_BUNCH_BITS,
) -> List[OutBunch]:
    """Build one or more delta property bunches for an already-open Actor channel."""
    if not properties:
        return []
    bunches: List[OutBunch] = []
    cur: Optional[OutBunch] = None
    for prop_name, elem_idx, val in properties:
        entry = class_cache.get_field(prop_name)
        if entry is None or not entry.is_property:
            continue
        encoded = _encode_single_prop_bits(
            pkgmap, class_cache, prop_name, elem_idx, val, actor_to_channel
        )
        if encoded.is_error():
            continue
        if cur is None or (cur.num_bits > 0 and cur.num_bits + encoded.num_bits > max_bunch_bits):
            cur = OutBunch(
                ch_index=ch_index,
                ch_type=CHTYPE_ACTOR,
                b_open=False,
                b_close=False,
                b_reliable=reliable,
            )
            bunches.append(cur)
        cur.write_bits_bytes(encoded.buf, encoded.num_bits)
    return bunches


def build_actor_close_bunch(ch_index: int, *, reliable: bool = True) -> OutBunch:
    """Build an Actor channel close bunch (`bClose=1`) destroying the actor on the client."""
    return OutBunch(
        ch_index=ch_index,
        ch_type=CHTYPE_ACTOR,
        b_open=False,
        b_close=True,
        b_reliable=reliable,
    )


def decode_actor_bunch(
    bunch: Union[InBunch, BitReader],
    pkgmap: PackageMap,
    class_cache: Optional[ClassNetCache] = None,
    *,
    is_open_initial: Optional[bool] = None,
    channel_to_actor: Optional[Dict[int, int]] = None,
) -> DecodedActorBunch:
    """Decode an incoming UE2.5 `CHTYPE_Actor` bunch (exact Engine.dll ReceivedBunch).

    Works for both S2C bunches (initial spawn + properties + S2C RPCs) and C2S
    bunches (C2S RPCs like `ServerMove`, `ServerStartFire`, `ServerChangedWeapon`).
    """
    ch_index = bunch.ch_index if isinstance(bunch, InBunch) else 0
    b_open = bunch.b_open if isinstance(bunch, InBunch) else False
    b_close = bunch.b_close if isinstance(bunch, InBunch) else False
    reader = bunch.reader() if isinstance(bunch, InBunch) else bunch.clone()

    open_init = b_open if is_open_initial is None else bool(is_open_initial)
    result = DecodedActorBunch(ch_index=ch_index, is_open=b_open, is_close=b_close)

    if reader.num_bits == 0:
        return result

    cache = class_cache
    if open_init:
        is_dyn, obj_idx = pkgmap.deserialize_object(reader)
        if reader.is_error() or is_dyn:
            return result
        result.spawn_object_index = obj_idx
        obj_info = pkgmap.index_to_object(obj_idx)
        if obj_info is None:
            return result
        pkg_name, full_name, export_idx = obj_info
        pkg = pkgmap.get_package(pkg_name)
        is_uclass = (pkg is not None and pkg.exports[export_idx].class_index == 0)
        if is_uclass:
            result.spawn_class = full_name
            result.is_static_actor = False
            if cache is None:
                try:
                    cache = pkgmap.get_class_cache(full_name)
                except KeyError:
                    return result
            result.spawn_location = reader.read_compressed_vector()
            if cache.b_net_initial_rotation:
                result.spawn_rotation = reader.read_compressed_rotator()
            else:
                result.spawn_rotation = (0, 0, 0)
        else:
            # Static/NoDelete map actor (e.g. LevelInfo0)
            result.is_static_actor = True
            if pkg is not None:
                cls_short = pkg.get_export_class_name(export_idx)
                result.spawn_class = cls_short
                if cache is None:
                    try:
                        cache = pkgmap.get_class_cache(cls_short)
                    except KeyError:
                        return result

    if cache is None:
        return result

    max_index = cache.max_index
    while not reader.at_end():
        rep_index = reader.read_int(max_index)
        if reader.is_error():
            break
        entry = cache.get_field(rep_index)
        if entry is None:
            log.debug(
                "Unknown RepIndex %d for %s on ch=%d", rep_index, cache.full_name, ch_index
            )
            break
        if entry.is_property:
            elem_idx = 0
            if entry.array_dim != 1:
                elem_idx = reader.read_byte()
                if reader.is_error():
                    break
            val = deserialize_value(
                reader,
                pkgmap,
                entry.prop_type,
                enum_name=entry.enum_name,
                enum_bits=entry.enum_bits,
                struct_name=entry.struct_name,
                struct_fields=entry.struct_fields,
                channel_to_actor=channel_to_actor,
            )
            if reader.is_error():
                break
            result.properties.append((entry.name, elem_idx, val))
        elif entry.is_function:
            rpc_args: Dict[str, Any] = {}
            ok = True
            for parm in entry.params:
                if parm.prop_type == "BoolProperty":
                    pval: Any = bool(reader.read_bit())
                else:
                    has_val = bool(reader.read_bit())
                    if reader.is_error():
                        ok = False
                        break
                    if has_val:
                        pval = deserialize_value(
                            reader,
                            pkgmap,
                            parm.prop_type,
                            enum_name=parm.enum_name,
                            enum_bits=parm.enum_bits,
                            struct_name=parm.struct_name,
                            channel_to_actor=channel_to_actor,
                        )
                    else:
                        pval = default_value_for_type(
                            parm.prop_type, struct_name=parm.struct_name, pkgmap=pkgmap
                        )
                if reader.is_error():
                    ok = False
                    break
                rpc_args[parm.name] = pval
            if not ok:
                break
            result.rpcs.append(
                DecodedRPC(
                    name=entry.name,
                    rep_index=rep_index,
                    args=rpc_args,
                    ch_index=ch_index,
                    is_reliable=entry.is_reliable,
                )
            )
    return result


# ---------------------------------------------------------------------------
# Authoritative Server-Side ReplicatedActor & Per-Client Channel View
# ---------------------------------------------------------------------------

class ReplicatedActor:
    """Server-side authoritative actor whose properties replicate via CHTYPE_Actor."""

    def __init__(
        self,
        actor_id: int,
        class_name: str,
        kind: str = "actor",
        *,
        owner_client_id: Optional[Any] = None,
        owner_role_id: Optional[int] = None,
        only_relevant_to_owner: bool = False,
        preferred_channel: Optional[int] = None,
        is_static: bool = False,
        static_index: int = -1,
        spawn_location: Tuple[float, float, float] = (0.0, 0.0, 0.0),
        spawn_rotation: Tuple[int, int, int] = (0, 0, 0),
    ) -> None:
        self.actor_id: int = actor_id
        self.class_name: str = class_name
        self.kind: str = kind
        self.owner_client_id: Optional[Any] = owner_client_id
        self.owner_role_id: Optional[int] = owner_role_id
        self.only_relevant_to_owner: bool = only_relevant_to_owner
        self.preferred_channel: Optional[int] = preferred_channel
        self.is_static: bool = is_static
        self.static_index: int = static_index
        self.spawn_location: Tuple[float, float, float] = spawn_location
        self.spawn_rotation: Tuple[int, int, int] = spawn_rotation
        self.destroyed: bool = False

        # Shared properties: (prop_name, elem_index) -> value
        self.props: Dict[Tuple[str, int], Any] = {}
        self.prop_versions: Dict[Tuple[str, int], int] = {}
        self._version_seq: int = 0

        # Per-perspective overrides (e.g. Role/bNetOwner/Owner/Controller/Inventory)
        self.owner_props: Dict[Tuple[str, int], Any] = {}
        self.owner_prop_versions: Dict[Tuple[str, int], int] = {}
        self.non_owner_props: Dict[Tuple[str, int], Any] = {}
        self.non_owner_prop_versions: Dict[Tuple[str, int], int] = {}

    def is_relevant_to(self, client_id: Any) -> bool:
        if self.destroyed:
            return False
        if self.only_relevant_to_owner:
            return self.owner_client_id == client_id
        return True

    def is_owned_by(self, client_id: Any) -> bool:
        return self.owner_client_id is not None and self.owner_client_id == client_id

    def set_prop(
        self,
        name: str,
        value: Any,
        elem_index: int = 0,
        *,
        force: bool = False,
    ) -> bool:
        key = (name, elem_index)
        if not force and key in self.props and self.props[key] == value:
            return False
        self._version_seq += 1
        self.props[key] = value
        self.prop_versions[key] = self._version_seq
        return True

    def set_owner_prop(
        self,
        name: str,
        value: Any,
        elem_index: int = 0,
        *,
        force: bool = False,
    ) -> bool:
        key = (name, elem_index)
        if not force and key in self.owner_props and self.owner_props[key] == value:
            return False
        self._version_seq += 1
        self.owner_props[key] = value
        self.owner_prop_versions[key] = self._version_seq
        return True

    def set_non_owner_prop(
        self,
        name: str,
        value: Any,
        elem_index: int = 0,
        *,
        force: bool = False,
    ) -> bool:
        key = (name, elem_index)
        if not force and key in self.non_owner_props and self.non_owner_props[key] == value:
            return False
        self._version_seq += 1
        self.non_owner_props[key] = value
        self.non_owner_prop_versions[key] = self._version_seq
        return True

    def set_props(self, mapping: Dict[str, Any], *, force: bool = False) -> None:
        for k, v in mapping.items():
            self.set_prop(k, v, 0, force=force)

    def get_prop(self, name: str, elem_index: int = 0, default: Any = None) -> Any:
        return self.props.get((name, elem_index), default)

    def mark_dirty(self, name: str, elem_index: int = 0) -> None:
        key = (name, elem_index)
        if key in self.props:
            self._version_seq += 1
            self.prop_versions[key] = self._version_seq

    def effective_props_for(
        self, client_id: Any
    ) -> Dict[Tuple[str, int], Tuple[Any, int]]:
        """Return `(prop_name, elem_idx) -> (value, version)` tailored to `client_id`."""
        merged: Dict[Tuple[str, int], Tuple[Any, int]] = {
            k: (v, self.prop_versions[k]) for k, v in self.props.items()
        }
        if self.is_owned_by(client_id):
            for k, v in self.owner_props.items():
                merged[k] = (v, self.owner_prop_versions[k])
        else:
            for k, v in self.non_owner_props.items():
                merged[k] = (v, self.non_owner_prop_versions[k])
        return merged


class ClientReplicationView:
    """Per-client Actor channel allocator (`1..MAX_CHANNELS-1`) & dirty-state tracker."""

    def __init__(
        self,
        client_id: Any,
        conn: UE2ConnectionState,
        role_id: int,
        player_name: str,
        team_id: int,
    ) -> None:
        self.client_id: Any = client_id
        self.conn: UE2ConnectionState = conn
        self.role_id: int = role_id
        self.player_name: str = player_name
        self.team_id: int = team_id

        self.joined: bool = False
        self.actor_to_channel: Dict[int, int] = {}
        self.channel_to_actor: Dict[int, int] = {}
        self.channel_classes: Dict[int, ClassNetCache] = {}
        self.sent_versions: Dict[int, Dict[Tuple[str, int], int]] = {}
        self.actor_last_version: Dict[int, int] = {}
        self._next_ch: int = 2  # Ch 0 = Control; Ch 1 = GRI/LevelInfo; Ch 2..1022 = dynamic

        # Primary actor IDs belonging to this client's player
        self.pc_actor_id: Optional[int] = None
        self.pri_actor_id: Optional[int] = None
        self.pawn_actor_id: Optional[int] = None
        self.weapon_actor_id: Optional[int] = None
        self.attachment_actor_id: Optional[int] = None

    def allocate_channel(
        self,
        actor_id: int,
        preferred_channel: Optional[int] = None,
    ) -> int:
        """Allocate a free Actor channel index in `1..MAX_CHANNELS-1`."""
        existing = self.actor_to_channel.get(actor_id)
        if existing is not None:
            return existing

        if (
            preferred_channel is not None
            and 1 <= preferred_channel < MAX_CHANNELS
            and preferred_channel not in self.channel_to_actor
        ):
            ch = preferred_channel
        else:
            ch = -1
            for offset in range(MAX_CHANNELS - 1):
                cand = ((self._next_ch - 1 + offset) % (MAX_CHANNELS - 1)) + 1
                if cand not in self.channel_to_actor:
                    ch = cand
                    self._next_ch = (cand % (MAX_CHANNELS - 1)) + 1
                    break
            if ch < 0:
                raise RuntimeError("No free UE2 Actor channels available (all 1022 in use)")

        self.actor_to_channel[actor_id] = ch
        self.channel_to_actor[ch] = actor_id
        self.sent_versions.setdefault(actor_id, {})
        return ch

    def free_channel(self, ch_index: int) -> Optional[int]:
        """Release an Actor channel and reset its reliable sequence counters."""
        actor_id = self.channel_to_actor.pop(ch_index, None)
        if actor_id is not None:
            self.actor_to_channel.pop(actor_id, None)
            self.sent_versions.pop(actor_id, None)
            self.actor_last_version.pop(actor_id, None)
        self.channel_classes.pop(ch_index, None)
        self.conn.reset_channel(ch_index)
        return actor_id

    def get_channel(self, actor_id: int) -> Optional[int]:
        return self.actor_to_channel.get(actor_id)

    def get_actor_id(self, ch_index: int) -> Optional[int]:
        return self.channel_to_actor.get(ch_index)


# ---------------------------------------------------------------------------
# High-Level Match Replication Manager
# ---------------------------------------------------------------------------

# Verified PawnList.csv / PawnAvatar.csv defaults (Male=1, Female=2)
DEFAULT_MALE_AVATAR: Tuple[int, int, int] = (1111, 1121, 1131)    # body, head, legs
DEFAULT_FEMALE_AVATAR: Tuple[int, int, int] = (6111, 6121, 6131)  # body, head, legs


def resolve_kfx_avatar(
    body_type: int = 1,
    coat_type: int = 0,
    head_type: int = 0,
    trousers_type: int = 0,
) -> Tuple[int, int, int, int]:
    """Resolve Realm DB avatar/item fields into valid `PawnList.csv` / `PawnAvatar.csv` IDs.

    Returns `(pawn_role_id, nBodyID, nHeadID, nLegsID)`:
    - `pawn_role_id`: `2` (Standard Female) if `body_type == 2`, else `1` (Standard Male).
      (`KFXPawnBase` looks up `KFXPendingState.nRoleID` in `PawnList.csv`, NOT the DB player ID!)
    - `KFXItem.csv` 32-bit IDs (e.g. `head_type=6554721`, `coat_type=6620247`,
      `trousers_type=6685803`) carry their `PawnAvatar.csv` ID in the low 16 bits
      (`& 0xFFFF` -> `1121`, `1111`, `1131`).
    - Direct `PawnAvatar.csv` IDs (`>= 1000`) are kept as-is; `0` or gender codes `< 1000`
      fall back to `(1111, 1121, 1131)` (male) or `(6111, 6121, 6131)` (female) so `CS.exe`
      always resolves a valid skeletal mesh in `KFXPawnBase.KFXChangeState.BeginState`.
    """
    bt = int(body_type or 0)
    ct = int(coat_type or 0)
    ht = int(head_type or 0)
    tt = int(trousers_type or 0)

    ct_low = ct & 0xFFFF
    is_female = (bt == 2) or (6000 <= ct_low < 7000 and bt != 1)
    pawn_role_id = 2 if is_female else 1
    def_body, def_head, def_legs = DEFAULT_FEMALE_AVATAR if is_female else DEFAULT_MALE_AVATAR

    def _extract_avatar_id(raw_val: int, fallback: int) -> int:
        if raw_val <= 0:
            return fallback
        low16 = raw_val & 0xFFFF
        return low16 if low16 >= 1000 else fallback

    raw_body = ct if (ct > 0 and ct_low >= 1000) else bt
    avatar_body = _extract_avatar_id(raw_body, def_body)
    avatar_head = _extract_avatar_id(ht, def_head)
    avatar_legs = _extract_avatar_id(tt, def_legs)
    return (pawn_role_id, avatar_body, avatar_head, avatar_legs)


def _build_default_kfx_player_info(
    *,
    player_id: int,
    session_id: int,
    player_name: str,
    role_id: int,
    team_id: int,
    level: int = 1,
    body_type: int = 1,
    coat_type: int = 0,
    head_type: int = 0,
    legs_type: int = 0,
    weapon_id: int = 65537,
    loadout: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build KFXGame.KFXPlayerInfo struct dict for `KFXPlayer.fxDBPlayerInfo`."""
    pawn_role_id, avatar_body, avatar_head, avatar_legs = resolve_kfx_avatar(
        body_type=body_type,
        coat_type=coat_type,
        head_type=head_type,
        trousers_type=legs_type,
    )
    lo = loadout or {}
    majors = list(lo.get("major_weapons", [weapon_id, 65538, 65539, 65541, 0]))[:5]
    minors = list(lo.get("minor_weapons", [131078, 131079, 0, 0, 0]))[:5]
    melees = list(lo.get("melee_weapons", [196616, 0, 0, 0, 0]))[:5]
    grenades = list(lo.get("grenades", [262156, 262155, 262157, 0, 0]))[:5]
    bag_props = list(lo.get("bag_props", [0] * 20))[:20]

    while len(majors) < 5:
        majors.append(0)
    while len(minors) < 5:
        minors.append(0)
    while len(melees) < 5:
        melees.append(0)
    while len(grenades) < 5:
        grenades.append(0)
    while len(bag_props) < 20:
        bag_props.append(0)

    return {
        "PlayerID": int(player_id),
        "SessionID": int(session_id),
        "PlayerName": str(player_name),
        "RoleID": int(pawn_role_id),
        "TeamID": int(team_id),
        "nLevel": int(level),
        "AvatarBody": int(avatar_body),
        "AvatarHead": int(avatar_head),
        "AvatarLegs": int(avatar_legs),
        "nMajorWeapons": majors,
        "nMinorWeapons": minors,
        "nMeleeWeapons": melees,
        "nGrenades": grenades,
        "nArmorID": int(lo.get("armor_id", 0)),
        "nShoesID": int(lo.get("shoes_id", 0)),
        "nBagProps": bag_props,
        "nVipLevel": int(lo.get("vip_level", 0)),
        "nNetBarMode": int(lo.get("netbar_mode", 0)),
        "nKillCount": 0,
        "nDeathCount": 0,
        "nHeadKillCount": 0,
        "nKnifeKillCount": 0,
        "nSpeicalKillCount": 0,
        "nGameResult": 0,
        "nExperience": 0,
        "GameCash": 0,
    }


class ReplicationManager:
    """Manages UE2.5 Actor spawning, delta replication, and RPC dispatch for a match."""

    def __init__(
        self,
        pkgmap: PackageMap,
        *,
        game_mode: int = 1,
        map_id: int = 1,
        time_limit: int = 15,
        goal_score: int = 50,
        respawn_delay: float = 3.0,
        server_name: str = "CSG Multiplayer Server",
        rpc_handler: Optional[Any] = None,
    ) -> None:
        self.pkgmap: PackageMap = pkgmap
        self.game_mode: int = int(game_mode)
        self.mode_classes: Dict[str, Any] = get_mode_classes(self.game_mode)
        self.map_id: int = int(map_id)
        self.time_limit: int = int(time_limit)
        self.goal_score: int = int(goal_score)
        self.respawn_delay: float = float(respawn_delay)
        self.server_name: str = server_name
        self.rpc_handler: Optional[Any] = rpc_handler

        self._next_actor_id: int = 1
        self._next_player_id: int = 1
        self.actors: Dict[int, ReplicatedActor] = {}
        self.clients: Dict[Any, ClientReplicationView] = {}
        self.role_to_client: Dict[int, Any] = {}

        # Per-role counters for KFX FX replication triggers
        self._weap_flash_count: Dict[int, int] = {}
        self._dmg_flash_count: Dict[int, int] = {}
        self._state_revision: Dict[int, int] = {}

        # Resolve map's static LevelInfo0 index so walking SimulatedProxy pawns have Base=LevelInfo0
        # (enables smooth 60FPS APawn::physWalking velocity extrapolation on remote clients!)
        li_idx = self.pkgmap.object_to_index("LevelInfo0")
        self._level_info_ref: Optional[StaticRef] = StaticRef(li_idx) if li_idx >= 0 else None

        # Create match-global actors: TeamInfo[0], TeamInfo[1], and KFX*GameReplicationInfo
        self.team_actors: Dict[int, ReplicatedActor] = {}
        self.gri_actor: ReplicatedActor = self._create_global_match_actors()

    def _alloc_actor_id(self) -> int:
        aid = self._next_actor_id
        self._next_actor_id += 1
        return aid

    def _create_global_match_actors(self) -> ReplicatedActor:
        team_cls = self.mode_classes["team_class"]
        # Blue Team (TeamIndex = 0) & Red Team (TeamIndex = 1)
        team_specs = [
            (0, "Blue", {"B": 255, "G": 80, "R": 40, "A": 255}),
            (1, "Red", {"B": 40, "G": 60, "R": 255, "A": 255}),
        ]
        for idx, tname, color in team_specs:
            t_actor = ReplicatedActor(
                self._alloc_actor_id(),
                team_cls,
                kind="team",
                preferred_channel=2 + idx,
            )
            t_actor.set_props({
                "Role": ROLE_SIMULATED_PROXY,
                "RemoteRole": ROLE_AUTHORITY,
                "TeamIndex": idx,
                "TeamName": tname,
                "Score": 0.0,
                "TeamColor": color,
                "fxCurrWinRound": 0,
            })
            self.actors[t_actor.actor_id] = t_actor
            self.team_actors[idx] = t_actor

        # KFX*GameReplicationInfo (preferred Channel 1)
        gri_cls = self.mode_classes["gri_class"]
        gri = ReplicatedActor(
            self._alloc_actor_id(),
            gri_cls,
            kind="gri",
            preferred_channel=1,
        )
        time_sec = self.time_limit * 60 if self.time_limit <= 60 else self.time_limit
        gri.set_props({
            "Role": ROLE_SIMULATED_PROXY,
            "RemoteRole": ROLE_AUTHORITY,
            "GameClass": self.mode_classes["game_class"],
            "GameName": self.mode_classes["game_name"],
            "ShortName": self.mode_classes["game_name"],
            "ServerName": self.server_name,
            "bTeamGame": bool(self.mode_classes["team_game"]),
            "bMatchHasBegun": True,
            "bStopCountDown": False,
            "TimeLimit": self.time_limit,
            "RemainingTime": time_sec,
            "RemainingMinute": time_sec,
            "ElapsedTime": 0,
            "GoalScore": self.goal_score,
            "MinNetPlayers": 1,
            "fxMapID": self.map_id,
            "fxTimeLimit": time_sec,
            "fxRemainingTime": time_sec,
            "fxKilledLimit": self.goal_score,
            "fxPlayerRestartDelay": self.respawn_delay,
            "fxElapsedTime": 0,
        })
        gri.set_prop("Teams", ActorRef(self.team_actors[0].actor_id), elem_index=0)
        gri.set_prop("Teams", ActorRef(self.team_actors[1].actor_id), elem_index=1)
        self.actors[gri.actor_id] = gri
        return gri

    # ------------------------------------------------------------------
    # Actor Creation Helpers
    # ------------------------------------------------------------------

    def spawn_actor(
        self,
        class_name: str,
        kind: str = "actor",
        *,
        owner_client_id: Optional[Any] = None,
        owner_role_id: Optional[int] = None,
        only_relevant_to_owner: bool = False,
        preferred_channel: Optional[int] = None,
        spawn_location: Tuple[float, float, float] = (0.0, 0.0, 0.0),
        spawn_rotation: Tuple[int, int, int] = (0, 0, 0),
        initial_props: Optional[Dict[str, Any]] = None,
    ) -> ReplicatedActor:
        actor = ReplicatedActor(
            self._alloc_actor_id(),
            class_name,
            kind=kind,
            owner_client_id=owner_client_id,
            owner_role_id=owner_role_id,
            only_relevant_to_owner=only_relevant_to_owner,
            preferred_channel=preferred_channel,
            spawn_location=spawn_location,
            spawn_rotation=spawn_rotation,
        )
        if initial_props:
            actor.set_props(initial_props)
        self.actors[actor.actor_id] = actor
        return actor

    def destroy_actor(self, actor_id: int) -> None:
        """Mark an actor destroyed and queue channel-close bunches to every client viewing it."""
        actor = self.actors.get(actor_id)
        if actor is None:
            return
        actor.destroyed = True
        for view in self.clients.values():
            ch = view.get_channel(actor_id)
            if ch is not None:
                view.conn.queue_bunch(build_actor_close_bunch(ch, reliable=True))
                view.free_channel(ch)

    def _create_pawn_and_weapon_actors(
        self,
        view: ClientReplicationView,
        *,
        spawn_location: Tuple[float, float, float],
        spawn_rotation: Tuple[int, int, int],
        health: int = 100,
        health_max: float = 100.0,
        armor: int = 0,
        body_type: int = 1,
        coat_type: int = 0,
        head_type: int = 0,
        trousers_type: int = 0,
        weapon_id: int = 65537,
        clip_ammo: int = 30,
        reserve_ammo: int = 60,
    ) -> Tuple[ReplicatedActor, ReplicatedActor, ReplicatedActor]:
        role_id = view.role_id
        team_id = view.team_id
        pawn_role_id, avatar_body, avatar_head, avatar_legs = resolve_kfx_avatar(
            body_type=body_type,
            coat_type=coat_type,
            head_type=head_type,
            trousers_type=trousers_type,
        )
        rev = (self._state_revision.get(role_id, 0) + 1) & 0xFF
        if rev == 0:
            rev = 1
        self._state_revision[role_id] = rev

        # UE2.5 Pawn body orientation MUST have Pitch=0, Roll=0 (yaw-only!).
        # Vertical aim goes exclusively into `ViewPitch`, otherwise looking up/down
        # tilts the entire 3D character mesh horizontally into mid-air!
        body_spawn_rot = (0, int(spawn_rotation[1]) & 0xFFFF, 0)

        # 1. KFXPawn (relevant to all clients)
        pawn = self.spawn_actor(
            self.mode_classes["pawn_class"],
            kind="pawn",
            owner_client_id=view.client_id,
            owner_role_id=role_id,
            only_relevant_to_owner=False,
            spawn_location=spawn_location,
            spawn_rotation=body_spawn_rot,
        )
        # 2. KFXWeapAttachment (3rd-person weapon mesh, relevant to all clients)
        game_dir = getattr(self.pkgmap, "game_dir", None)
        weap_cls, _ = get_weapon_class(weapon_id, game_dir=game_dir)
        accessories = get_weapon_accessories(weapon_id, game_dir=game_dir)
        attach = self.spawn_actor(
            "KFXGame.KFXWeapAttachment",
            kind="attachment",
            owner_client_id=view.client_id,
            owner_role_id=role_id,
            only_relevant_to_owner=False,
            spawn_location=spawn_location,
        )
        # 3. KFXWeap* (1st-person inventory weapon, relevant ONLY to owning client)
        weapon = self.spawn_actor(
            weap_cls,
            kind="weapon",
            owner_client_id=view.client_id,
            owner_role_id=role_id,
            only_relevant_to_owner=True,
            spawn_location=spawn_location,
        )

        # Configure Pawn shared + owner/non-owner perspective properties.
        # Exact physical/movement constants from retail System\PawnAttribute.csv
        # (id=1 Male / id=2 Female: DrawScale=0.85, CollisionHeight=92, CollisionRadius=55,
        # GroundSpeed=520, AirSpeed=650, WaterSpeed=400, JumpZ=763, MaxFallSpeed=1456,
        # WalkingPct=0.67, CrouchedPct=0.40, Pivot=0,0,0) so feet sit flush on floors
        # and movement physics match the retail CSO Malaysia client identically!
        pawn.set_props({
            "Location": spawn_location,
            "Rotation": body_spawn_rot,
            "Velocity": (0.0, 0.0, 0.0),
            "Physics": PHYS_WALKING,
            "Base": self._level_info_ref,
            "RemoteRole": ROLE_AUTHORITY,
            "DrawScale": 0.85,
            "CollisionHeight": 92.0,
            "CollisionRadius": 55.0,
            "DefPrePivot": (0.0, 0.0, 0.0),
            "PrePivot": (0.0, 0.0, 0.0),
            "Health": int(health),
            "HealthMax": float(health_max),
            "bIsCrouched": False,
            "bIsWalking": False,
            "bSimulateGravity": True,
            "bCollideActors": True,
            "bCollideWorld": True,
            "bBlockActors": True,
            "bProjTarget": True,
            "GroundSpeed": 520.0,
            "AirSpeed": 650.0,
            "WaterSpeed": 400.0,
            "JumpZ": 763.0,
            "MaxFallSpeed": 1456.0,
            "WalkingPct": 0.67,
            "CrouchedPct": 0.40,
            "AccelRate": 1024.0,
            "MaxMultiJump": 1,
            "DoubleJumpZ": 464,
            "DoubleJumpZThresh": 1000.0,
            "DodgeSpeedZ": 208.0,
            "DodgeSpeedFactor": 2.0,
            "ViewPitch": rotator_to_view_pitch_byte(spawn_rotation[0]),
            "PawnPosition": (spawn_location, body_spawn_rot, (0.0, 0.0, 0.0)),
            "PlayerReplicationInfo": ActorRef(view.pri_actor_id) if view.pri_actor_id else None,
            "KFXPendingState": {
                "Revision": rev,
                "TeamID": int(team_id) & 0xFF,
                "nRoleID": int(pawn_role_id),
            },
            "KFXAvatar": {
                "nBodyID": int(avatar_body),
                "nHeadID": int(avatar_head),
                "nLegsID": int(avatar_legs),
            },
            "KFXArmorPoints": int(armor),
            "bCanMove": True,
            "bCanFire": True,
            "bCanUseWeapon": True,
            "KFXSpeedScale": 1.0,
            "bTearOff": False,
        })
        pawn.set_owner_prop("Role", ROLE_AUTONOMOUS_PROXY)
        pawn.set_owner_prop("bNetOwner", True)
        if view.pc_actor_id is not None:
            pawn.set_owner_prop("Owner", ActorRef(view.pc_actor_id))
            pawn.set_owner_prop("Controller", ActorRef(view.pc_actor_id))
        pawn.set_owner_prop("Inventory", ActorRef(weapon.actor_id))

        pawn.set_non_owner_prop("Role", ROLE_SIMULATED_PROXY)
        pawn.set_non_owner_prop("bNetOwner", False)
        pawn.set_non_owner_prop("Owner", None)
        pawn.set_non_owner_prop("Controller", None)
        pawn.set_non_owner_prop("Inventory", None)

        # Configure KFXWeapAttachment (all WeaponAttribute.csv accessories)
        attach.set_props({
            "Role": ROLE_SIMULATED_PROXY,
            "RemoteRole": ROLE_AUTHORITY,
            "Owner": ActorRef(pawn.actor_id),
            "Instigator": ActorRef(pawn.actor_id),
            "KFXWeaponID": int(weapon_id),
            "FiringMode": 0,
            "FlashCount": 0,
            "SpawnHitCount": 0,
            "KFXOnlyEffect": False,
        })
        for acc_idx, acc_val in enumerate(accessories):
            if acc_idx == 0 or acc_val > 0:
                attach.set_prop("KFXAccessory", int(acc_val), elem_index=acc_idx)

        # Configure KFXWeap*
        weapon.set_props({
            "Role": ROLE_SIMULATED_PROXY,
            "RemoteRole": ROLE_AUTHORITY,
            "bNetOwner": True,
            "Owner": ActorRef(pawn.actor_id),
            "Instigator": ActorRef(pawn.actor_id),
            "ThirdPersonActor": ActorRef(attach.actor_id),
            "bIsReload": False,
        })
        weapon.set_prop("KFXReload", int(clip_ammo), elem_index=0)
        weapon.set_prop("KFXAmmoCount", int(reserve_ammo), elem_index=0)

        view.pawn_actor_id = pawn.actor_id
        view.attachment_actor_id = attach.actor_id
        view.weapon_actor_id = weapon.actor_id

        # Link PC -> Pawn
        if view.pc_actor_id is not None and view.pc_actor_id in self.actors:
            self.actors[view.pc_actor_id].set_prop("Pawn", ActorRef(pawn.actor_id))

        return pawn, weapon, attach

    # ------------------------------------------------------------------
    # Player Registration, Initial Spawn (JOIN), Respawn & Disconnect
    # ------------------------------------------------------------------

    def register_client(
        self,
        client_id: Any,
        conn: UE2ConnectionState,
        *,
        role_id: int,
        player_name: str,
        team_id: int = 0,
        player_id: Optional[int] = None,
        session_id: int = 0,
        level: int = 1,
        body_type: int = 0,
        head_type: int = 0,
        coat_type: int = 0,
        trousers_type: int = 0,
        weapon_id: int = 65537,
        clip_ammo: int = 30,
        reserve_ammo: int = 60,
        health: int = 100,
        armor: int = 0,
        spawn_location: Tuple[float, float, float] = (0.0, 0.0, 0.0),
        spawn_rotation: Tuple[int, int, int] = (0, 0, 0),
        loadout: Optional[Dict[str, Any]] = None,
    ) -> ClientReplicationView:
        """Create a client view and spawn its PC, PRI, Pawn, Weapon, and WeapAttachment actors."""
        if player_id is None:
            player_id = self._next_player_id
            self._next_player_id += 1

        team_idx = 1 if int(team_id) == 1 else 0
        view = ClientReplicationView(
            client_id=client_id,
            conn=conn,
            role_id=int(role_id),
            player_name=str(player_name),
            team_id=team_idx,
        )
        self.clients[client_id] = view
        self.role_to_client[int(role_id)] = client_id

        # 1. KFX*PlayerReplicationInfo (relevant to ALL clients)
        pri = self.spawn_actor(
            self.mode_classes["pri_class"],
            kind="pri",
            owner_client_id=client_id,
            owner_role_id=int(role_id),
            only_relevant_to_owner=False,
        )
        team_actor = self.team_actors[team_idx]
        pri.set_props({
            "Role": ROLE_SIMULATED_PROXY,
            "RemoteRole": ROLE_AUTHORITY,
            "PlayerName": str(player_name),
            "Team": ActorRef(team_actor.actor_id),
            "TeamID": team_idx,
            "PlayerID": int(player_id),
            "Score": 0.0,
            "Deaths": 0.0,
            "Ping": 5,
            "bReadyToPlay": True,
            "bIsSpectator": False,
            "bOnlySpectator": False,
            "bWaitingPlayer": False,
            "bOutOfLives": False,
            "bAdmin": False,
            "bBot": False,
            "fxKills": 0,
            "fxDeaths": 0,
            "bDeadStatus": False,
            "bEnableTransWeapon": True,
            "fxLevel": int(level),
            "bHeadKill": False,
        })
        view.pri_actor_id = pri.actor_id

        # 2. KFX*Player (PlayerController — relevant ONLY to owning client!)
        pc = self.spawn_actor(
            self.mode_classes["pc_class"],
            kind="pc",
            owner_client_id=client_id,
            owner_role_id=int(role_id),
            only_relevant_to_owner=True,
            spawn_location=spawn_location,
            spawn_rotation=spawn_rotation,
        )
        db_info = _build_default_kfx_player_info(
            player_id=player_id,
            session_id=session_id,
            player_name=player_name,
            role_id=role_id,
            team_id=team_idx,
            level=level,
            body_type=body_type,
            coat_type=coat_type,
            head_type=head_type,
            legs_type=trousers_type,
            weapon_id=weapon_id,
            loadout=loadout,
        )
        pc.set_props({
            "bNetOwner": True,
            "Role": ROLE_AUTONOMOUS_PROXY,
            "RemoteRole": ROLE_AUTHORITY,
            "PlayerReplicationInfo": ActorRef(pri.actor_id),
            "GameReplicationInfo": ActorRef(self.gri_actor.actor_id),
            "Location": spawn_location,
            "Rotation": spawn_rotation,
            "fxDBPlayerInfo": db_info,
        })
        view.pc_actor_id = pc.actor_id
        pri.set_owner_prop("Owner", ActorRef(pc.actor_id))

        # 3. KFXPawn + KFXWeap* + KFXWeapAttachment
        self._create_pawn_and_weapon_actors(
            view,
            spawn_location=spawn_location,
            spawn_rotation=spawn_rotation,
            health=health,
            armor=armor,
            body_type=body_type,
            coat_type=coat_type,
            head_type=head_type,
            trousers_type=trousers_type,
            weapon_id=weapon_id,
            clip_ammo=clip_ammo,
            reserve_ammo=reserve_ammo,
        )
        return view

    def _open_actor_on_client(
        self,
        view: ClientReplicationView,
        actor: ReplicatedActor,
    ) -> int:
        """Open an Actor channel on `view` and queue its reliable initial spawn bunch(es)."""
        if actor.actor_id in view.actor_to_channel:
            return view.actor_to_channel[actor.actor_id]

        cache = self.pkgmap.get_class_cache(actor.class_name)
        ch = view.allocate_channel(actor.actor_id, preferred_channel=actor.preferred_channel)
        view.channel_classes[ch] = cache

        eff = actor.effective_props_for(view.client_id)
        props_to_send: List[Tuple[str, int, Any]] = []
        sent_ver = view.sent_versions.setdefault(actor.actor_id, {})
        for (prop_name, elem_idx), (val, ver) in eff.items():
            props_to_send.append((prop_name, elem_idx, val))
            sent_ver[(prop_name, elem_idx)] = ver
        view.actor_last_version[actor.actor_id] = actor._version_seq

        bunches = build_actor_open_bunches(
            ch,
            self.pkgmap,
            cache,
            spawn_location=actor.spawn_location,
            spawn_rotation=actor.spawn_rotation,
            static_actor_index=actor.static_index if actor.is_static else None,
            properties=props_to_send,
            actor_to_channel=view.actor_to_channel,
        )
        for b in bunches:
            view.conn.queue_bunch(b)
        return ch

    def spawn_initial_actors_for_client(
        self,
        client_id: Any,
        *,
        weapon_id: int = 65537,
        spawn_rotation: Optional[Tuple[int, int, int]] = None,
    ) -> int:
        """Execute the full post-JOIN UE2.5 actor spawn & S2C RPC sequence for `client_id`.

        Spawns in strict dependency order (TeamInfo -> GRI -> PRIs -> PC -> Pawns ->
        WeapAttachments -> Weapon), sends critical S2C RPCs (`KFXClientInit`,
        `ClientWeaponSet`, `ClientSetHUD`, `ClientGotoState`, `ClientReStart`,
        `ClientSetRotation`, `ClientSwitchToBestWeapon`), and replicates the newly
        joined player's actors to all other already-joined clients.

        Returns the number of actor channels opened on this client.
        """
        view = self.clients[client_id]
        view.joined = True

        # Determine spawn order respecting object-reference DAG
        kind_order = {
            "team": 0,
            "gri": 1,
            "pri": 2,
            "pc": 3,
            "pawn": 4,
            "attachment": 5,
            "weapon": 6,
            "projectile": 7,
            "actor": 8,
        }
        relevant = [
            a for a in self.actors.values() if a.is_relevant_to(client_id)
        ]
        relevant.sort(key=lambda a: (kind_order.get(a.kind, 9), a.actor_id))

        # Pre-allocate channels for all relevant actors BEFORE encoding properties so
        # forward references (e.g. Pawn.Inventory -> Weapon, PC.Pawn -> Pawn) resolve
        # to their exact channel indices on the very first open bunch!
        for actor in relevant:
            if actor.actor_id not in view.actor_to_channel:
                ch = view.allocate_channel(actor.actor_id, preferred_channel=actor.preferred_channel)
                view.channel_classes[ch] = self.pkgmap.get_class_cache(actor.class_name)

        opened_count = 0
        for actor in relevant:
            ch = view.actor_to_channel[actor.actor_id]
            cache = view.channel_classes[ch]
            eff = actor.effective_props_for(client_id)
            props_to_send: List[Tuple[str, int, Any]] = []
            sent_ver = view.sent_versions.setdefault(actor.actor_id, {})
            for (prop_name, elem_idx), (val, ver) in eff.items():
                props_to_send.append((prop_name, elem_idx, val))
                sent_ver[(prop_name, elem_idx)] = ver
            view.actor_last_version[actor.actor_id] = actor._version_seq

            bunches = build_actor_open_bunches(
                ch,
                self.pkgmap,
                cache,
                spawn_location=actor.spawn_location,
                spawn_rotation=actor.spawn_rotation,
                static_actor_index=actor.static_index if actor.is_static else None,
                properties=props_to_send,
                actor_to_channel=view.actor_to_channel,
            )
            for b in bunches:
                view.conn.queue_bunch(b)
            opened_count += 1

        # Determine actual weapon_id & spawn_rotation from created actors
        if view.attachment_actor_id and view.attachment_actor_id in self.actors:
            w_id = self.actors[view.attachment_actor_id].get_prop("KFXWeaponID", 0, weapon_id)
            weapon_id = int(w_id)
        if spawn_rotation is None:
            if view.pawn_actor_id and view.pawn_actor_id in self.actors:
                spawn_rotation = self.actors[view.pawn_actor_id].spawn_rotation
            else:
                spawn_rotation = (0, 0, 0)

        # Critical S2C Weapon RPCs (KFXClientInit MUST precede ClientWeaponSet!)
        if view.weapon_actor_id is not None:
            self.send_kfx_client_init_weapon(client_id, weapon_id)
            self.send_client_weapon_set(client_id, b_possibly_switch=True)

        # Critical S2C PlayerController RPCs (dismisses HUD/Spectating and starts ServerMove!)
        self.send_client_set_hud(client_id)
        self.send_client_goto_state(client_id, "PlayerWalking", "Begin")
        if view.pawn_actor_id is not None:
            self.send_client_restart(client_id, view.pawn_actor_id)
        self.send_client_set_rotation(client_id, spawn_rotation)
        self.send_client_switch_to_best_weapon(client_id)

        # Replicate this new player's shared actors (PRI, Pawn, WeapAttachment) to all other joined clients
        for other_cid, other_view in self.clients.items():
            if other_cid == client_id or not other_view.joined:
                continue
            self._sync_new_actors_to_client(other_view)

        return opened_count

    def _sync_new_actors_to_client(self, view: ClientReplicationView) -> int:
        """Open channels on `view` for any relevant actors not yet replicated to it."""
        kind_order = {"team": 0, "gri": 1, "pri": 2, "pc": 3, "pawn": 4, "attachment": 5, "weapon": 6}
        missing = [
            a
            for a in self.actors.values()
            if a.is_relevant_to(view.client_id) and a.actor_id not in view.actor_to_channel
        ]
        if not missing:
            return 0
        missing.sort(key=lambda a: (kind_order.get(a.kind, 9), a.actor_id))
        # Pre-allocate channels so cross-actor refs resolve immediately
        for actor in missing:
            ch = view.allocate_channel(actor.actor_id, preferred_channel=actor.preferred_channel)
            view.channel_classes[ch] = self.pkgmap.get_class_cache(actor.class_name)
        for actor in missing:
            ch = view.actor_to_channel[actor.actor_id]
            cache = view.channel_classes[ch]
            eff = actor.effective_props_for(view.client_id)
            props_to_send = []
            sent_ver = view.sent_versions.setdefault(actor.actor_id, {})
            for (prop_name, elem_idx), (val, ver) in eff.items():
                props_to_send.append((prop_name, elem_idx, val))
                sent_ver[(prop_name, elem_idx)] = ver
            view.actor_last_version[actor.actor_id] = actor._version_seq
            for b in build_actor_open_bunches(
                ch,
                self.pkgmap,
                cache,
                spawn_location=actor.spawn_location,
                spawn_rotation=actor.spawn_rotation,
                static_actor_index=actor.static_index if actor.is_static else None,
                properties=props_to_send,
                actor_to_channel=view.actor_to_channel,
            ):
                view.conn.queue_bunch(b)
        return len(missing)

    def remove_client(self, client_id: Any) -> None:
        """Clean up a disconnected client and destroy all of its owned actors across peers."""
        view = self.clients.pop(client_id, None)
        if view is None:
            return
        self.role_to_client.pop(view.role_id, None)
        owned_ids = [
            aid
            for aid in (
                view.weapon_actor_id,
                view.attachment_actor_id,
                view.pawn_actor_id,
                view.pc_actor_id,
                view.pri_actor_id,
            )
            if aid is not None
        ]
        for aid in owned_ids:
            self.destroy_actor(aid)
            self.actors.pop(aid, None)

    def respawn_player_pawn(
        self,
        role_id: int,
        spawn_location: Tuple[float, float, float],
        spawn_rotation: Tuple[int, int, int],
        *,
        health: int = 100,
        health_max: float = 100.0,
        armor: int = 0,
        body_type: Optional[int] = None,
        coat_type: Optional[int] = None,
        head_type: Optional[int] = None,
        trousers_type: Optional[int] = None,
        weapon_id: Optional[int] = None,
        clip_ammo: int = 30,
        reserve_ammo: int = 60,
    ) -> Optional[ReplicatedActor]:
        """Respawn a player's KFXPawn + weapon at a team PlayerStart and replicate to all clients."""
        cid = self.role_to_client.get(role_id)
        if cid is None or cid not in self.clients:
            return None
        view = self.clients[cid]

        # Preserve previous resolved PawnList role / PawnAvatar IDs if caller omitted them
        old_pawn = self.actors.get(view.pawn_actor_id) if view.pawn_actor_id else None
        if old_pawn is not None:
            old_av = old_pawn.get_prop("KFXAvatar", 0, {}) or {}
            old_st = old_pawn.get_prop("KFXPendingState", 0, {}) or {}
            if body_type is None:
                body_type = int(old_st.get("nRoleID", 1))
            if coat_type is None:
                coat_type = int(old_av.get("nBodyID", 0))
            if head_type is None:
                head_type = int(old_av.get("nHeadID", 0))
            if trousers_type is None:
                trousers_type = int(old_av.get("nLegsID", 0))
        if weapon_id is None:
            old_att = self.actors.get(view.attachment_actor_id) if view.attachment_actor_id else None
            weapon_id = int(old_att.get_prop("KFXWeaponID", 0, 65537)) if old_att else 65537

        # Destroy old pawn/weapon/attachment channels cleanly across all clients
        for old_aid in (view.weapon_actor_id, view.attachment_actor_id, view.pawn_actor_id):
            if old_aid is not None:
                self.destroy_actor(old_aid)
                self.actors.pop(old_aid, None)

        # Spawn fresh pawn, weapon, attachment
        pawn, _weap, _att = self._create_pawn_and_weapon_actors(
            view,
            spawn_location=spawn_location,
            spawn_rotation=spawn_rotation,
            health=health,
            health_max=health_max,
            armor=armor,
            body_type=body_type if body_type is not None else 1,
            coat_type=coat_type or 0,
            head_type=head_type or 0,
            trousers_type=trousers_type or 0,
            weapon_id=weapon_id,
            clip_ammo=clip_ammo,
            reserve_ammo=reserve_ammo,
        )

        # Mark PRI alive
        if view.pri_actor_id and view.pri_actor_id in self.actors:
            self.actors[view.pri_actor_id].set_prop("bDeadStatus", False)

        # Open new actor channels immediately on all joined clients & send respawn RPCs to owner
        for cview in self.clients.values():
            if cview.joined:
                self._sync_new_actors_to_client(cview)

        if view.joined:
            # Flush PC.Pawn reference update reliably before ClientReStart
            self._replicate_actor_dirty_to_client(view, self.actors[view.pc_actor_id], force_reliable=True)
            self.send_kfx_client_init_weapon(cid, weapon_id)
            self.send_client_weapon_set(cid, b_possibly_switch=True)
            self.send_client_goto_state(cid, "PlayerWalking", "Begin")
            self.send_client_restart(cid, pawn.actor_id)
            self.send_client_set_rotation(cid, spawn_rotation)
            self.send_client_switch_to_best_weapon(cid)

        return pawn

    # ------------------------------------------------------------------
    # State Update Helpers (called by combat.py / host.py)
    # ------------------------------------------------------------------

    def get_client_by_role(self, role_id: int) -> Optional[ClientReplicationView]:
        cid = self.role_to_client.get(role_id)
        return self.clients.get(cid) if cid is not None else None

    def _resolve_view(self, client_or_role_id: Any) -> Optional[ClientReplicationView]:
        """Resolve a ClientReplicationView by either `client_id` or `role_id`."""
        view = self.clients.get(client_or_role_id)
        if view is not None:
            return view
        if isinstance(client_or_role_id, int):
            return self.get_client_by_role(client_or_role_id)
        return None

    def switch_player_weapon(
        self,
        role_id: int,
        new_weapon_id: int,
        *,
        clip_ammo: int = 30,
        reserve_ammo: int = 60,
        ack_id: Optional[int] = None,
    ) -> Optional[ReplicatedActor]:
        """Swap a player's active KFXWeap* + KFXWeapAttachment and sync to all clients."""
        view = self.get_client_by_role(role_id)
        if view is None or view.pawn_actor_id is None:
            return None
        pawn = self.actors.get(view.pawn_actor_id)
        if pawn is None or pawn.destroyed:
            return None

        # Destroy previous weapon & 3P attachment
        for old_aid in (view.weapon_actor_id, view.attachment_actor_id):
            if old_aid is not None:
                self.destroy_actor(old_aid)
                self.actors.pop(old_aid, None)

        game_dir = getattr(self.pkgmap, "game_dir", None)
        weap_cls, _ = get_weapon_class(new_weapon_id, game_dir=game_dir)
        accessories = get_weapon_accessories(new_weapon_id, game_dir=game_dir)
        loc = pawn.get_prop("Location", 0, pawn.spawn_location)
        attach = self.spawn_actor(
            "KFXGame.KFXWeapAttachment",
            kind="attachment",
            owner_client_id=view.client_id,
            owner_role_id=role_id,
            only_relevant_to_owner=False,
            spawn_location=loc,
        )
        attach.set_props({
            "Role": ROLE_SIMULATED_PROXY,
            "RemoteRole": ROLE_AUTHORITY,
            "Owner": ActorRef(pawn.actor_id),
            "Instigator": ActorRef(pawn.actor_id),
            "KFXWeaponID": int(new_weapon_id),
            "FiringMode": 0,
            "FlashCount": 0,
            "SpawnHitCount": 0,
            "KFXOnlyEffect": False,
        })
        for acc_idx, acc_val in enumerate(accessories):
            if acc_idx == 0 or acc_val > 0:
                attach.set_prop("KFXAccessory", int(acc_val), elem_index=acc_idx)

        weapon = self.spawn_actor(
            weap_cls,
            kind="weapon",
            owner_client_id=view.client_id,
            owner_role_id=role_id,
            only_relevant_to_owner=True,
            spawn_location=loc,
        )
        weapon.set_props({
            "Role": ROLE_SIMULATED_PROXY,
            "RemoteRole": ROLE_AUTHORITY,
            "bNetOwner": True,
            "Owner": ActorRef(pawn.actor_id),
            "Instigator": ActorRef(pawn.actor_id),
            "ThirdPersonActor": ActorRef(attach.actor_id),
            "bIsReload": False,
        })
        weapon.set_prop("KFXReload", int(clip_ammo), elem_index=0)
        weapon.set_prop("KFXAmmoCount", int(reserve_ammo), elem_index=0)

        view.attachment_actor_id = attach.actor_id
        view.weapon_actor_id = weapon.actor_id
        pawn.set_owner_prop("Inventory", ActorRef(weapon.actor_id), force=True)

        for cview in self.clients.values():
            if cview.joined:
                self._sync_new_actors_to_client(cview)

        if view.joined:
            self._replicate_actor_dirty_to_client(view, pawn, force_reliable=True)
            self.send_kfx_client_init_weapon(view.client_id, new_weapon_id, weapon.actor_id)
            self.send_client_weapon_set(view.client_id, True, weapon.actor_id)
            if ack_id is not None:
                self.send_kfx_change_weapon_ack(view.client_id, ack_id)
        return weapon

    def get_pawn_actor(self, role_id: int) -> Optional[ReplicatedActor]:
        view = self.get_client_by_role(role_id)
        if view is None or view.pawn_actor_id is None:
            return None
        return self.actors.get(view.pawn_actor_id)

    def get_pri_actor(self, role_id: int) -> Optional[ReplicatedActor]:
        view = self.get_client_by_role(role_id)
        if view is None or view.pri_actor_id is None:
            return None
        return self.actors.get(view.pri_actor_id)

    def get_pc_actor(self, role_id: int) -> Optional[ReplicatedActor]:
        view = self.get_client_by_role(role_id)
        if view is None or view.pc_actor_id is None:
            return None
        return self.actors.get(view.pc_actor_id)

    def get_weapon_actor(self, role_id: int) -> Optional[ReplicatedActor]:
        view = self.get_client_by_role(role_id)
        if view is None or view.weapon_actor_id is None:
            return None
        return self.actors.get(view.weapon_actor_id)

    def get_attachment_actor(self, role_id: int) -> Optional[ReplicatedActor]:
        view = self.get_client_by_role(role_id)
        if view is None or view.attachment_actor_id is None:
            return None
        return self.actors.get(view.attachment_actor_id)

    def update_pawn_state(
        self,
        role_id: int,
        *,
        location: Optional[Tuple[float, float, float]] = None,
        rotation: Optional[Tuple[int, int, int]] = None,
        velocity: Optional[Tuple[float, float, float]] = None,
        physics: Optional[int] = None,
        health: Optional[int] = None,
        health_max: Optional[float] = None,
        armor: Optional[int] = None,
        crouched: Optional[bool] = None,
        view_pitch: Optional[int] = None,
        hit_weapon_id: Optional[int] = None,
        tear_off: Optional[bool] = None,
        tear_off_momentum: Optional[Tuple[float, float, float]] = None,
        hit_damage_type: Optional[str] = None,
        take_hit_location: Optional[Tuple[float, float, float]] = None,
        sync_compressed_position: bool = True,
    ) -> Optional[ReplicatedActor]:
        pawn = self.get_pawn_actor(role_id)
        if pawn is None:
            return None
        moved = False
        if location is not None:
            loc = (float(location[0]), float(location[1]), float(location[2]))
            pawn.spawn_location = loc
            if pawn.set_prop("Location", loc):
                moved = True
        if rotation is not None:
            full_pitch = int(rotation[0]) & 0xFFFF
            yaw = int(rotation[1]) & 0xFFFF
            # UE2.5 Pawn.Rotation MUST stay upright (Pitch=0, Roll=0); vertical look angle
            # replicates via Pawn.ViewPitch so looking up/down bends upper torso/head only!
            body_rot = (0, yaw, 0)
            pawn.spawn_rotation = body_rot
            if pawn.set_prop("Rotation", body_rot):
                moved = True
            if view_pitch is None:
                pawn.set_prop("ViewPitch", rotator_to_view_pitch_byte(full_pitch))
        if velocity is not None:
            vel = (float(velocity[0]), float(velocity[1]), float(velocity[2]))
            if pawn.set_prop("Velocity", vel):
                moved = True
        if physics is not None:
            phys_val = int(physics)
            if phys_val <= 0:
                phys_val = PHYS_WALKING
            pawn.set_prop("Physics", phys_val)
            # Keep Base=LevelInfo0 when walking so SimulatedProxy APawn::physWalking
            # extrapolates smoothly at 60+ FPS between UDP updates!
            pawn.set_prop("Base", self._level_info_ref if phys_val == PHYS_WALKING else None)
        if health is not None:
            pawn.set_prop("Health", int(health))
        if health_max is not None:
            pawn.set_prop("HealthMax", float(health_max))
        if armor is not None:
            pawn.set_prop("KFXArmorPoints", int(armor))
        if crouched is not None:
            pawn.set_prop("bIsCrouched", bool(crouched))
        if view_pitch is not None:
            pawn.set_prop("ViewPitch", int(view_pitch) & 0xFF)
        if hit_weapon_id is not None:
            pawn.set_prop("KFXHitWeaponID", int(hit_weapon_id))
        if tear_off is not None:
            pawn.set_prop("bTearOff", bool(tear_off))
        if tear_off_momentum is not None:
            pawn.set_prop("TearOffMomentum", tuple(float(c) for c in tear_off_momentum[:3]))
        if hit_damage_type is not None:
            pawn.set_prop("HitDamageType", StaticRef(hit_damage_type))
        if take_hit_location is not None:
            pawn.set_prop("TakeHitLocation", tuple(float(c) for c in take_hit_location[:3]))
        if sync_compressed_position and moved:
            cur_loc = pawn.get_prop("Location", 0, (0.0, 0.0, 0.0))
            cur_rot = pawn.get_prop("Rotation", 0, (0, 0, 0))
            cur_vel = pawn.get_prop("Velocity", 0, (0.0, 0.0, 0.0))
            pawn.set_prop("PawnPosition", (cur_loc, cur_rot, cur_vel))
        return pawn

    def update_pri_state(
        self,
        role_id: int,
        *,
        kills: Optional[int] = None,
        deaths: Optional[int] = None,
        score: Optional[float] = None,
        ping: Optional[int] = None,
        dead_status: Optional[bool] = None,
        head_kill: Optional[bool] = None,
        team_id: Optional[int] = None,
        ready: Optional[bool] = None,
        player_name: Optional[str] = None,
    ) -> Optional[ReplicatedActor]:
        pri = self.get_pri_actor(role_id)
        if pri is None:
            return None
        if kills is not None:
            pri.set_prop("fxKills", int(kills))
            if score is None:
                pri.set_prop("Score", float(kills))
        if score is not None:
            pri.set_prop("Score", float(score))
        if deaths is not None:
            pri.set_prop("fxDeaths", int(deaths))
            pri.set_prop("Deaths", float(deaths))
        if ping is not None:
            pri.set_prop("Ping", max(0, min(255, int(ping))))
        if dead_status is not None:
            pri.set_prop("bDeadStatus", bool(dead_status))
        if head_kill is not None:
            pri.set_prop("bHeadKill", bool(head_kill))
        if team_id is not None:
            tidx = 1 if int(team_id) == 1 else 0
            pri.set_prop("TeamID", tidx)
            pri.set_prop("Team", ActorRef(self.team_actors[tidx].actor_id))
            view = self.get_client_by_role(role_id)
            if view is not None:
                view.team_id = tidx
        if ready is not None:
            pri.set_prop("bReadyToPlay", bool(ready))
        if player_name is not None:
            pri.set_prop("PlayerName", str(player_name))
        return pri

    def update_gri_state(
        self,
        *,
        remaining_time: Optional[int] = None,
        elapsed_time: Optional[int] = None,
        blue_score: Optional[float] = None,
        red_score: Optional[float] = None,
        winner_team: Optional[int] = None,
        match_begun: Optional[bool] = None,
        stop_countdown: Optional[bool] = None,
    ) -> None:
        if remaining_time is not None:
            rt = max(0, int(remaining_time))
            self.gri_actor.set_prop("RemainingTime", rt)
            self.gri_actor.set_prop("RemainingMinute", rt)
            self.gri_actor.set_prop("fxRemainingTime", rt)
        if elapsed_time is not None:
            et = max(0, int(elapsed_time))
            self.gri_actor.set_prop("ElapsedTime", et)
            self.gri_actor.set_prop("fxElapsedTime", et)
        if match_begun is not None:
            self.gri_actor.set_prop("bMatchHasBegun", bool(match_begun))
        if stop_countdown is not None:
            self.gri_actor.set_prop("bStopCountDown", bool(stop_countdown))
        if blue_score is not None:
            self.team_actors[0].set_prop("Score", float(blue_score))
        if red_score is not None:
            self.team_actors[1].set_prop("Score", float(red_score))
        if winner_team is not None and winner_team in self.team_actors:
            self.gri_actor.set_prop("Winner", ActorRef(self.team_actors[winner_team].actor_id))

    def update_weapon_state(
        self,
        role_id: int,
        *,
        clip_ammo: Optional[int] = None,
        reserve_ammo: Optional[int] = None,
        is_reload: Optional[bool] = None,
    ) -> Optional[ReplicatedActor]:
        weap = self.get_weapon_actor(role_id)
        if weap is None:
            return None
        if clip_ammo is not None:
            weap.set_prop("KFXReload", int(clip_ammo), elem_index=0)
        if reserve_ammo is not None:
            weap.set_prop("KFXAmmoCount", int(reserve_ammo), elem_index=0)
        if is_reload is not None:
            weap.set_prop("bIsReload", bool(is_reload))
        return weap

    def trigger_weapon_fire_effect(
        self,
        role_id: int,
        *,
        firing_mode: int = 0,
        hit_locations: Optional[Sequence[Tuple[float, float, float]]] = None,
        is_reload: bool = False,
    ) -> Optional[ReplicatedActor]:
        """Trigger 3rd-person muzzle flash / impact decals on `KFXWeapAttachment`."""
        att = self.get_attachment_actor(role_id)
        if att is None:
            return None
        if is_reload:
            fc = 200 + ((self._weap_flash_count.get(role_id, 0) + 1) % 5)
        else:
            fc = (self._weap_flash_count.get(role_id, 0) % 199) + 1
        self._weap_flash_count[role_id] = fc
        att.set_prop("FiringMode", int(firing_mode) & 0xFF)
        att.set_prop("KFXOnlyEffect", False)
        if hit_locations:
            hits = list(hit_locations)[:8]
            att.set_prop("SpawnHitCount", len(hits) & 0xFF)
            for idx, hloc in enumerate(hits):
                att.set_prop("HitLocs", tuple(float(c) for c in hloc[:3]), elem_index=idx)
            att.set_prop("mHitLocation", tuple(float(c) for c in hits[0][:3]))
        att.set_prop("FlashCount", fc & 0xFF, force=True)
        return att

    def trigger_take_hit_effect(
        self,
        victim_role_id: int,
        *,
        instigator_role_id: Optional[int] = None,
        hit_location: Tuple[float, float, float] = (0.0, 0.0, 0.0),
        momentum: Tuple[float, float, float] = (0.0, 0.0, 0.0),
        dmg_shake: int = 1,
        weapon_id: int = 0,
    ) -> Optional[ReplicatedActor]:
        """Trigger KFXClientPlayTakeHit (blood, directional hit indicator, sound, shake)."""
        pawn = self.get_pawn_actor(victim_role_id)
        if pawn is None:
            return None
        fc = (self._dmg_flash_count.get(victim_role_id, 0) + 1) & 0xFF
        if fc == 0:
            fc = 1
        self._dmg_flash_count[victim_role_id] = fc
        inst_pawn = self.get_pawn_actor(instigator_role_id) if instigator_role_id is not None else None
        if weapon_id:
            pawn.set_prop("KFXHitWeaponID", int(weapon_id))
        pawn.set_prop(
            "KFXDmgRepInfo",
            {
                "instigatedBy": ActorRef(inst_pawn.actor_id) if inst_pawn else None,
                "HitLocation": tuple(float(c) for c in hit_location[:3]),
                "Momentum": tuple(float(c) for c in momentum[:3]),
                "DmgShakeView": int(dmg_shake) & 0xFF,
                "FlashCount": fc,
            },
            force=True,
        )
        return pawn

    # ------------------------------------------------------------------
    # 20-30Hz Dirty-Property Delta Replication Loop
    # ------------------------------------------------------------------

    def _replicate_actor_dirty_to_client(
        self,
        view: ClientReplicationView,
        actor: ReplicatedActor,
        *,
        force_reliable: Optional[bool] = None,
    ) -> int:
        # O(1) fast-path skip when nothing on this actor changed since last replicate
        if view.actor_last_version.get(actor.actor_id) == actor._version_seq:
            return 0
        ch = view.get_channel(actor.actor_id)
        if ch is None:
            return 0
        cache = view.channel_classes.get(ch)
        if cache is None:
            cache = self.pkgmap.get_class_cache(actor.class_name)
            view.channel_classes[ch] = cache

        eff = actor.effective_props_for(view.client_id)
        sent = view.sent_versions.setdefault(actor.actor_id, {})
        is_owned_pawn = (actor.kind == "pawn") and actor.is_owned_by(view.client_id)

        rel_props: List[Tuple[str, int, Any]] = []
        unrel_props: List[Tuple[str, int, Any]] = []

        for (prop_name, elem_idx), (val, ver) in eff.items():
            if sent.get((prop_name, elem_idx)) == ver:
                continue
            sent[(prop_name, elem_idx)] = ver
            low_name = prop_name.lower()
            # Never echo movement properties back to the owning client's AutonomousProxy
            # pawn after initial spawn; doing so overwrites local prediction and causes lag!
            if is_owned_pawn and low_name in _OWNER_SKIP_PAWN_MOVEMENT_PROPS:
                continue
            if force_reliable is True:
                rel_props.append((prop_name, elem_idx, val))
            elif force_reliable is False:
                unrel_props.append((prop_name, elem_idx, val))
            elif low_name in _RELIABLE_DELTA_PROPS:
                rel_props.append((prop_name, elem_idx, val))
            else:
                unrel_props.append((prop_name, elem_idx, val))

        view.actor_last_version[actor.actor_id] = actor._version_seq

        sent_bunches = 0
        if rel_props:
            for b in build_actor_delta_bunches(
                ch, self.pkgmap, cache, rel_props,
                reliable=True, actor_to_channel=view.actor_to_channel,
            ):
                view.conn.queue_bunch(b)
                sent_bunches += 1
        if unrel_props:
            for b in build_actor_delta_bunches(
                ch, self.pkgmap, cache, unrel_props,
                reliable=False, actor_to_channel=view.actor_to_channel,
            ):
                view.conn.queue_bunch(b)
                sent_bunches += 1
        return sent_bunches

    def replicate_dirty_all(self, *, force_reliable: Optional[bool] = None) -> int:
        """Replicate all newly spawned actors and dirty property deltas to every joined client.

        Intended to be called at 20-30Hz from `host.py`'s asyncio tick loop.
        Returns total number of actor delta bunches queued.
        """
        total = 0
        for view in self.clients.values():
            if not view.joined:
                continue
            # Ensure any newly created relevant actors have open channels first
            self._sync_new_actors_to_client(view)
            # Replicate dirty deltas for every open actor
            for actor_id in list(view.actor_to_channel.keys()):
                actor = self.actors.get(actor_id)
                if actor is None or actor.destroyed:
                    ch = view.get_channel(actor_id)
                    if ch is not None:
                        view.conn.queue_bunch(build_actor_close_bunch(ch, reliable=True))
                        view.free_channel(ch)
                    continue
                total += self._replicate_actor_dirty_to_client(
                    view, actor, force_reliable=force_reliable
                )
        return total

    # ------------------------------------------------------------------
    # Outgoing S2C RPC Helpers
    # ------------------------------------------------------------------

    def send_rpc(
        self,
        client_id: Any,
        actor_id: int,
        func_name: str,
        *args: Any,
        force_reliable: Optional[bool] = None,
        **kwargs: Any,
    ) -> Optional[OutBunch]:
        """Send an S2C RPC on `actor_id`'s open channel for `client_id` (or `role_id`)."""
        view = self._resolve_view(client_id)
        if view is None:
            return None
        ch = view.get_channel(actor_id)
        if ch is None:
            return None
        cache = view.channel_classes.get(ch)
        if cache is None:
            actor = self.actors.get(actor_id)
            if actor is None:
                return None
            cache = self.pkgmap.get_class_cache(actor.class_name)
            view.channel_classes[ch] = cache
        bunch = build_rpc_bunch(
            ch,
            self.pkgmap,
            cache,
            func_name,
            args=args,
            kwargs=kwargs,
            actor_to_channel=view.actor_to_channel,
            force_reliable=force_reliable,
        )
        view.conn.queue_bunch(bunch)
        return bunch

    def broadcast_rpc(
        self,
        actor_id: int,
        func_name: str,
        *args: Any,
        exclude_client_id: Optional[Any] = None,
        force_reliable: Optional[bool] = None,
        **kwargs: Any,
    ) -> int:
        """Broadcast an S2C RPC on a shared actor channel to every joined client."""
        sent = 0
        for cid, view in self.clients.items():
            if not view.joined or cid == exclude_client_id:
                continue
            if self.send_rpc(cid, actor_id, func_name, *args, force_reliable=force_reliable, **kwargs):
                sent += 1
        return sent

    def send_client_set_hud(
        self,
        client_id: Any,
        hud_class: Optional[str] = None,
        scoreboard_class: Optional[str] = None,
    ) -> Optional[OutBunch]:
        view = self._resolve_view(client_id)
        if view is None or view.pc_actor_id is None:
            return None
        hc = hud_class or self.mode_classes["hud_class"]
        sc = scoreboard_class or self.mode_classes["scoreboard_class"]
        return self.send_rpc(
            view.client_id, view.pc_actor_id, "ClientSetHUD", StaticRef(hc), StaticRef(sc)
        )

    def send_client_goto_state(
        self,
        client_id: Any,
        new_state: str,
        new_label: str = "Begin",
    ) -> Optional[OutBunch]:
        view = self._resolve_view(client_id)
        if view is None or view.pc_actor_id is None:
            return None
        return self.send_rpc(
            view.client_id, view.pc_actor_id, "ClientGotoState", new_state, new_label
        )

    def send_client_restart(
        self,
        client_id: Any,
        pawn_actor_id: Optional[int] = None,
    ) -> Optional[OutBunch]:
        view = self._resolve_view(client_id)
        if view is None or view.pc_actor_id is None:
            return None
        pid = pawn_actor_id if pawn_actor_id is not None else view.pawn_actor_id
        pawn_ref = ActorRef(pid) if pid is not None else None
        return self.send_rpc(view.client_id, view.pc_actor_id, "ClientReStart", pawn_ref)

    def send_client_adjust_position(
        self,
        client_id: Any,
        timestamp: float,
        new_state: str,
        new_physics: int,
        location: Tuple[float, float, float],
        velocity: Tuple[float, float, float],
        new_base: Optional[Any] = None,
    ) -> Optional[OutBunch]:
        view = self._resolve_view(client_id)
        if view is None or view.pc_actor_id is None:
            return None
        return self.send_rpc(
            view.client_id,
            view.pc_actor_id,
            "ClientAdjustPosition",
            float(timestamp),
            str(new_state),
            int(new_physics),
            float(location[0]),
            float(location[1]),
            float(location[2]),
            float(velocity[0]),
            float(velocity[1]),
            float(velocity[2]),
            new_base,
        )

    def send_very_short_client_adjust_position(
        self,
        client_id: Any,
        timestamp: float,
        location: Tuple[float, float, float],
        new_base: Optional[Any] = None,
    ) -> Optional[OutBunch]:
        view = self._resolve_view(client_id)
        if view is None or view.pc_actor_id is None:
            return None
        return self.send_rpc(
            view.client_id,
            view.pc_actor_id,
            "VeryShortClientAdjustPosition",
            float(timestamp),
            float(location[0]),
            float(location[1]),
            float(location[2]),
            new_base,
        )

    def send_short_client_adjust_position(
        self,
        client_id: Any,
        timestamp: float,
        new_state: str,
        new_physics: int,
        location: Tuple[float, float, float],
        new_base: Optional[Any] = None,
    ) -> Optional[OutBunch]:
        view = self._resolve_view(client_id)
        if view is None or view.pc_actor_id is None:
            return None
        return self.send_rpc(
            view.client_id,
            view.pc_actor_id,
            "ShortClientAdjustPosition",
            float(timestamp),
            str(new_state),
            int(new_physics),
            float(location[0]),
            float(location[1]),
            float(location[2]),
            new_base,
        )

    def send_client_set_location(
        self,
        client_id: Any,
        location: Tuple[float, float, float],
        rotation: Tuple[int, int, int],
    ) -> Optional[OutBunch]:
        view = self._resolve_view(client_id)
        if view is None or view.pc_actor_id is None:
            return None
        return self.send_rpc(
            view.client_id, view.pc_actor_id, "ClientSetLocation", location, rotation
        )

    def send_client_set_rotation(
        self,
        client_id: Any,
        rotation: Tuple[int, int, int],
    ) -> Optional[OutBunch]:
        view = self._resolve_view(client_id)
        if view is None or view.pc_actor_id is None:
            return None
        return self.send_rpc(view.client_id, view.pc_actor_id, "ClientSetRotation", rotation)

    def send_kfx_client_init_weapon(
        self,
        client_id: Any,
        weapon_id: int,
        weapon_actor_id: Optional[int] = None,
    ) -> Optional[OutBunch]:
        view = self._resolve_view(client_id)
        if view is None:
            return None
        wid = weapon_actor_id if weapon_actor_id is not None else view.weapon_actor_id
        if wid is None:
            return None
        return self.send_rpc(view.client_id, wid, "KFXClientInit", int(weapon_id))

    def send_client_weapon_set(
        self,
        client_id: Any,
        b_possibly_switch: bool = True,
        weapon_actor_id: Optional[int] = None,
    ) -> Optional[OutBunch]:
        view = self._resolve_view(client_id)
        if view is None:
            return None
        wid = weapon_actor_id if weapon_actor_id is not None else view.weapon_actor_id
        if wid is None:
            return None
        return self.send_rpc(view.client_id, wid, "ClientWeaponSet", bool(b_possibly_switch))

    def send_client_switch_to_best_weapon(self, client_id: Any) -> Optional[OutBunch]:
        view = self._resolve_view(client_id)
        if view is None or view.pc_actor_id is None:
            return None
        return self.send_rpc(view.client_id, view.pc_actor_id, "ClientSwitchToBestWeapon")

    def send_client_dying(
        self,
        client_id: Any,
        damage_type: str = DMG_TYPE_INSTANT,
        hit_location: Tuple[float, float, float] = (0.0, 0.0, 0.0),
    ) -> Optional[OutBunch]:
        view = self._resolve_view(client_id)
        if view is None or view.pc_actor_id is None:
            return None
        return self.send_rpc(
            view.client_id,
            view.pc_actor_id,
            "ClientDying",
            StaticRef(damage_type),
            tuple(float(c) for c in hit_location[:3]),
        )

    def send_client_damage_shake(self, client_id: Any, damage: int) -> Optional[OutBunch]:
        view = self._resolve_view(client_id)
        if view is None or view.pc_actor_id is None:
            return None
        return self.send_rpc(view.client_id, view.pc_actor_id, "ClientDamageShake", int(damage))

    def send_kick_back_muzzle(
        self,
        client_id: Any,
        up_base: float,
        lateral_base: float,
        up_max: float,
        lateral_max: float,
    ) -> Optional[OutBunch]:
        view = self._resolve_view(client_id)
        if view is None or view.pawn_actor_id is None:
            return None
        return self.send_rpc(
            view.client_id,
            view.pawn_actor_id,
            "KickBackMuzzle",
            float(up_base),
            float(lateral_base),
            float(up_max),
            float(lateral_max),
        )

    def send_client_speed_down(self, client_id: Any) -> Optional[OutBunch]:
        view = self._resolve_view(client_id)
        if view is None or view.pawn_actor_id is None:
            return None
        return self.send_rpc(view.client_id, view.pawn_actor_id, "KFXClientSpeedDown")

    def send_client_pre_reload(self, client_id: Any) -> Optional[OutBunch]:
        view = self._resolve_view(client_id)
        if view is None or view.weapon_actor_id is None:
            return None
        return self.send_rpc(view.client_id, view.weapon_actor_id, "ClientPreReload")

    def send_client_post_reload(self, client_id: Any) -> Optional[OutBunch]:
        view = self._resolve_view(client_id)
        if view is None or view.weapon_actor_id is None:
            return None
        return self.send_rpc(view.client_id, view.weapon_actor_id, "ClientPostReload")

    def send_kfx_change_weapon_ack(self, client_id: Any, ack_id: int) -> Optional[OutBunch]:
        view = self._resolve_view(client_id)
        if view is None or view.pc_actor_id is None:
            return None
        return self.send_rpc(view.client_id, view.pc_actor_id, "KFXChangeWeaponACK", int(ack_id))

    def send_client_message(
        self,
        client_id: Any,
        message: str,
        msg_type: str = "Event",
    ) -> Optional[OutBunch]:
        view = self._resolve_view(client_id)
        if view is None or view.pc_actor_id is None:
            return None
        return self.send_rpc(
            view.client_id, view.pc_actor_id, "ClientMessage", str(message), str(msg_type)
        )

    def broadcast_chat_message(
        self,
        sender_role_id: int,
        message: str,
        *,
        team_only: bool = False,
    ) -> int:
        sender_view = self.get_client_by_role(sender_role_id)
        sender_pri = ActorRef(sender_view.pri_actor_id) if (sender_view and sender_view.pri_actor_id) else None
        msg_type = "TeamSay" if team_only else "Say"
        sent = 0
        for cid, view in self.clients.items():
            if not view.joined or view.pc_actor_id is None:
                continue
            if team_only and sender_view is not None and view.team_id != sender_view.team_id:
                continue
            if self.send_rpc(cid, view.pc_actor_id, "TeamMessage", sender_pri, str(message), msg_type):
                sent += 1
        return sent

    def broadcast_kill_notification(
        self,
        killer_role_id: Optional[int],
        victim_role_id: int,
        weapon_id: int,
        *,
        headshot: bool = False,
        suicide: bool = False,
        damage_type: str = DMG_TYPE_INSTANT,
        killer_total_kills: int = 1,
    ) -> int:
        """Broadcast KFX kill feed notification (`KFXReceiveLocalizedMessage`) to every client."""
        if suicide or killer_role_id is None or killer_role_id == victim_role_id:
            msg_class = COMBAT_MSG_SUICIDE
            killer_pri_ref: Optional[ActorRef] = None
        elif headshot:
            msg_class = COMBAT_MSG_HEADSHOT
            kv = self.get_client_by_role(killer_role_id)
            killer_pri_ref = ActorRef(kv.pri_actor_id) if (kv and kv.pri_actor_id) else None
        else:
            msg_class = COMBAT_MSG_NORMAL
            kv = self.get_client_by_role(killer_role_id)
            killer_pri_ref = ActorRef(kv.pri_actor_id) if (kv and kv.pri_actor_id) else None

        vv = self.get_client_by_role(victim_role_id)
        victim_pri_ref = ActorRef(vv.pri_actor_id) if (vv and vv.pri_actor_id) else None

        sent = 0
        for cid, view in self.clients.items():
            if not view.joined or view.pc_actor_id is None:
                continue
            if self.send_rpc(
                cid,
                view.pc_actor_id,
                "KFXReceiveLocalizedMessage",
                StaticRef(msg_class),
                int(weapon_id),
                killer_pri_ref,
                victim_pri_ref,
                StaticRef(damage_type),
                int(killer_total_kills),
            ):
                sent += 1
        return sent

    def broadcast_game_ended(self, winner_team: Optional[int] = None) -> int:
        """Notify all connected clients that the match ended (opens scoreboard)."""
        if winner_team is not None:
            self.update_gri_state(winner_team=winner_team, stop_countdown=True)
        else:
            self.update_gri_state(stop_countdown=True)
        self.replicate_dirty_all(force_reliable=True)
        sent = 0
        for cid, view in self.clients.items():
            if not view.joined or view.pc_actor_id is None:
                continue
            self.send_rpc(cid, view.pc_actor_id, "ClientGameEnded")
            self.send_client_goto_state(cid, "GameEnded", "Begin")
            sent += 1
        return sent

    # ------------------------------------------------------------------
    # Incoming C2S Actor Bunch & RPC Parser + Dispatcher
    # ------------------------------------------------------------------

    def receive_actor_bunch(
        self,
        client_id: Any,
        bunch: InBunch,
    ) -> List[DecodedRPC]:
        """Parse an incoming C2S `CHTYPE_Actor` bunch and dispatch RPCs to `combat.py`."""
        view = self.clients.get(client_id)
        if view is None:
            return []

        ch = bunch.ch_index
        actor_id = view.get_actor_id(ch)
        cache = view.channel_classes.get(ch)
        if actor_id is None or cache is None:
            log.debug("Client %s sent bunch on unknown actor channel %d", client_id, ch)
            return []

        actor = self.actors.get(actor_id)
        actor_kind = actor.kind if actor else ""

        decoded = decode_actor_bunch(
            bunch,
            self.pkgmap,
            cache,
            is_open_initial=False,
            channel_to_actor=view.channel_to_actor,
        )

        rpcs = decoded.rpcs
        for rpc in rpcs:
            rpc.actor_id = actor_id
            rpc.actor_kind = actor_kind
            rpc.role_id = view.role_id
            self._enrich_c2s_rpc(rpc)
            self._dispatch_rpc(client_id, view.role_id, rpc)

        return rpcs

    @staticmethod
    def _enrich_c2s_rpc(rpc: DecodedRPC) -> None:
        """Attach unpacked convenience fields for movement RPCs (ServerMove/Dual/Short)."""
        lname = rpc.name.lower()
        if lname == "servermove":
            pitch, yaw, roll = unpack_server_move_view(
                rpc.args.get("View", 0), rpc.args.get("ClientRoll", 0)
            )
            rpc.extra["rotation"] = (pitch, yaw, roll)
            rpc.extra["location"] = rpc.args.get("ClientLoc", (0.0, 0.0, 0.0))
            rpc.extra["velocity"] = rpc.args.get("Velocity", (0.0, 0.0, 0.0))
            rpc.extra["accel"] = rpc.args.get("InAccel", (0.0, 0.0, 0.0))
            rpc.extra["physics"] = rpc.args.get("Physics", PHYS_WALKING)
            rpc.extra["crouched"] = bool(rpc.args.get("NewbDuck", False))
            rpc.extra["jump"] = bool(rpc.args.get("NewbJumpStatus", False))
            rpc.extra["timestamp"] = float(rpc.args.get("TimeStamp", 0.0))
        elif lname == "shortservermove":
            pitch, yaw, roll = unpack_server_move_view(
                rpc.args.get("View", 0), rpc.args.get("ClientRoll", 0)
            )
            rpc.extra["rotation"] = (pitch, yaw, roll)
            rpc.extra["location"] = rpc.args.get("ClientLoc", (0.0, 0.0, 0.0))
            rpc.extra["velocity"] = rpc.args.get("Velocity", (0.0, 0.0, 0.0))
            rpc.extra["physics"] = rpc.args.get("Physics", PHYS_WALKING)
            rpc.extra["crouched"] = bool(rpc.args.get("NewbDuck", False))
            rpc.extra["jump"] = bool(rpc.args.get("NewbJumpStatus", False))
            rpc.extra["timestamp"] = float(rpc.args.get("TimeStamp", 0.0))
        elif lname == "dualservermove":
            pitch, yaw, roll = unpack_server_move_view(
                rpc.args.get("View", 0), rpc.args.get("ClientRoll", 0)
            )
            flags = unpack_dual_server_move_compress(rpc.args.get("PendingCompress", 0))
            rpc.extra["rotation"] = (pitch, yaw, roll)
            rpc.extra["location"] = rpc.args.get("ClientLoc", (0.0, 0.0, 0.0))
            rpc.extra["velocity"] = rpc.args.get("Velocity", (0.0, 0.0, 0.0))
            rpc.extra["accel"] = rpc.args.get("InAccel", (0.0, 0.0, 0.0))
            rpc.extra["physics"] = rpc.args.get("Physics", PHYS_WALKING)
            rpc.extra["crouched"] = flags["NewbDuck"]
            rpc.extra["jump"] = flags["NewbJumpStatus"]
            rpc.extra["timestamp"] = float(rpc.args.get("TimeStamp", 0.0))
            rpc.extra["dual_flags"] = flags

    def _dispatch_rpc(self, client_id: Any, role_id: int, rpc: DecodedRPC) -> None:
        handler = self.rpc_handler
        if handler is None:
            return
        if callable(handler):
            handler(client_id, role_id, rpc)
            return

        # Structured combat handler interface: prefer `handle_rpc` / `on_rpc` or per-RPC methods
        generic = getattr(handler, "handle_rpc", None) or getattr(handler, "on_rpc", None)
        if callable(generic):
            generic(client_id, role_id, rpc)
            return

        lname = rpc.name.lower()
        route_map = {
            "servermove": "on_server_move",
            "shortservermove": "on_server_move",
            "dualservermove": "on_server_move",
            "serverstartfire": "on_start_fire",
            "serverstopfire": "on_stop_fire",
            "serverprereload": "on_reload",
            "serverchangedweapon": "on_change_weapon",
            "kfxchangeweapon": "on_change_weapon",
            "serversay": "on_chat",
            "serverteamsay": "on_chat",
            "suicide": "on_suicide",
            "serverrestartplayer": "on_restart_player",
            "serveracknowledgepossession": "on_acknowledge_possession",
            "serverupdateping": "on_update_ping",
        }
        method_name = route_map.get(lname)
        if method_name:
            fn = getattr(handler, method_name, None)
            if callable(fn):
                fn(client_id, role_id, rpc)


# ---------------------------------------------------------------------------
# Client-Side Actor Mirror (for unit tests & 2-player simulation clients)
# ---------------------------------------------------------------------------

@dataclass
class MirroredActor:
    """Client-side view of an actor received over CHTYPE_Actor bunches."""
    ch_index: int
    class_name: str
    class_cache: ClassNetCache
    is_static: bool = False
    spawn_location: Tuple[float, float, float] = (0.0, 0.0, 0.0)
    spawn_rotation: Tuple[int, int, int] = (0, 0, 0)
    props: Dict[Tuple[str, int], Any] = field(default_factory=dict)
    rpcs: List[DecodedRPC] = field(default_factory=list)
    closed: bool = False

    def get(self, prop_name: str, elem_index: int = 0, default: Any = None) -> Any:
        key = (prop_name, elem_index)
        if key in self.props:
            return self.props[key]
        low = prop_name.lower()
        for (k, ei), v in self.props.items():
            if ei == elem_index and k.lower() == low:
                return v
        return default


class ClientActorMirror:
    """Client-side UE2.5 Actor channel decoder for testing & multiplayer simulation."""

    def __init__(self, pkgmap: PackageMap) -> None:
        self.pkgmap: PackageMap = pkgmap
        self.actors: Dict[int, MirroredActor] = {}
        self.all_rpcs: List[DecodedRPC] = []

    def process_bunch(self, bunch: InBunch) -> DecodedActorBunch:
        ch = bunch.ch_index
        existing = self.actors.get(ch)
        is_open_init = bunch.b_open and (existing is None or existing.closed)
        cache = existing.class_cache if (existing and not is_open_init) else None

        decoded = decode_actor_bunch(
            bunch, self.pkgmap, cache, is_open_initial=is_open_init
        )

        if is_open_init and decoded.spawn_class:
            cls_cache = self.pkgmap.get_class_cache(decoded.spawn_class)
            actor = MirroredActor(
                ch_index=ch,
                class_name=cls_cache.full_name,
                class_cache=cls_cache,
                is_static=decoded.is_static_actor,
                spawn_location=decoded.spawn_location or (0.0, 0.0, 0.0),
                spawn_rotation=decoded.spawn_rotation or (0, 0, 0),
            )
            self.actors[ch] = actor
            existing = actor

        if existing is not None:
            for prop_name, elem_idx, val in decoded.properties:
                existing.props[(prop_name, elem_idx)] = val
            for rpc in decoded.rpcs:
                existing.rpcs.append(rpc)
                self.all_rpcs.append(rpc)
            if bunch.b_close:
                existing.closed = True

        return decoded

    def find_by_class(
        self,
        class_substr: str,
        *,
        exact: bool = False,
        include_closed: bool = False,
    ) -> List[MirroredActor]:
        low = class_substr.lower()
        out: List[MirroredActor] = []
        for a in self.actors.values():
            if not include_closed and a.closed:
                continue
            cname = a.class_name.lower()
            short = cname.rsplit(".", 1)[-1]
            if exact:
                if cname == low or short == low:
                    out.append(a)
            elif low in cname:
                out.append(a)
        return out

    def get_own_pc(self) -> Optional[MirroredActor]:
        for a in self.actors.values():
            if not a.closed and a.get("bNetOwner") and "player" in a.class_name.lower() and "replicationinfo" not in a.class_name.lower():
                return a
        return None

    def get_own_pawn(self) -> Optional[MirroredActor]:
        for a in self.actors.values():
            if not a.closed and a.get("bNetOwner") and "pawn" in a.class_name.lower():
                return a
        return None

    def get_own_weapon(self) -> Optional[MirroredActor]:
        for a in self.actors.values():
            if not a.closed and a.get("bNetOwner") and "weap" in a.class_name.lower() and "attachment" not in a.class_name.lower():
                return a
        return None

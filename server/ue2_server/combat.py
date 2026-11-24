"""Authoritative multiplayer FPS combat, movement sync, hitscan, kills/deaths,
respawns, and match scoreboard engine for CSO Malaysia (UE2.5 build 3369).

Designed to pair directly with:
- `server.ue2_server.map_loader` (`MapSpawnData`, `SpawnPoint`, `load_map_spawns`)
- `server.ue2_server.replication` (`ReplicationManager`, `DecodedRPC`, `PHYS_*`,
  `DMG_TYPE_*`, `unpack_server_move_view`)
- `server.ue2_server.host` (30Hz tick loop + `on_match_end` callback)
- `server.realm` / `server.database` (`get_match_results()` -> `add_match_stats`)

Works both attached to a live `ReplicationManager` AND standalone for unit tests.
"""

from __future__ import annotations

import csv
import inspect
import io
import json
import logging
import math
import os
import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from .map_loader import MapSpawnData, SpawnPoint, load_map_spawns
from .packagemap import DEFAULT_GAME_DIR
from .replication import (
    DMG_TYPE_C4,
    DMG_TYPE_DELAYED,
    DMG_TYPE_INSTANT,
    PHYS_FALLING,
    PHYS_WALKING,
    DecodedRPC,
    ReplicationManager,
    unpack_server_move_view,
)

log = logging.getLogger("csg.ue2.combat")

# ---------------------------------------------------------------------------
# Constants (UE2.5 / CSO Malaysia KFXPawn & KFXFireBase verified values)
# ---------------------------------------------------------------------------

ROT_TO_RAD: float = (2.0 * math.pi) / 65536.0
RAD_TO_ROT: float = 65536.0 / (2.0 * math.pi)

# Pawn standing / crouched cylinder geometry (UE2 units, aligned with PawnAttribute.csv:
# CollisionHeight=92, CollisionRadius=55, CrouchHeight=70, BaseEyeHeight=61, CrouchEyeHeight=30)
PAWN_COLLISION_RADIUS: float = 40.0
PAWN_STAND_HALF_HEIGHT: float = 92.0
PAWN_STAND_EYE_OFFSET: float = 61.0
PAWN_STAND_HEAD_Z_MIN: float = 28.0
PAWN_STAND_HEAD_Z_MAX: float = 84.0
PAWN_STAND_STOMACH_Z_MAX: float = 8.0
PAWN_STAND_LEGS_Z_MAX: float = -16.0

PAWN_CROUCH_HALF_HEIGHT: float = 70.0
PAWN_CROUCH_EYE_OFFSET: float = 30.0
PAWN_CROUCH_HEAD_Z_MIN: float = 14.0
PAWN_CROUCH_HEAD_Z_MAX: float = 58.0
PAWN_CROUCH_STOMACH_Z_MAX: float = -4.0
PAWN_CROUCH_LEGS_Z_MAX: float = -22.0

PAWN_HEAD_RADIUS: float = 18.0

# Hitbox IDs & multipliers (verified in KFXGame.KFXPawn.KFXHixBoxDmg)
HITBOX_CHEST: int = 0
HITBOX_STOMACH: int = 1
HITBOX_HEAD: int = 2
HITBOX_LEGS: int = 7

HITBOX_MULTIPLIER: Dict[int, float] = {
    HITBOX_HEAD: 4.0,
    HITBOX_STOMACH: 1.25,
    HITBOX_CHEST: 1.0,
    HITBOX_LEGS: 0.75,
}

MELEE_HITBOX_MULTIPLIER: Dict[int, float] = {
    HITBOX_HEAD: 2.0,
    HITBOX_STOMACH: 1.0,
    HITBOX_CHEST: 1.0,
    HITBOX_LEGS: 1.0,
}

# Movement validation bounds (aligned with PawnAttribute.csv GroundSpeed=520, AirSpeed=650,
# JumpZ=763, MaxFallSpeed=1456; generous for multi-client FPS hitches while catching teleports/NaN)
MAX_WORLD_COORD: float = 65536.0
DEFAULT_MAX_MOVE_SPEED: float = 1800.0
DEFAULT_MIN_STEP_ALLOWANCE: float = 900.0
DEFAULT_DESYNC_TOLERANCE: float = 450.0
DEFAULT_RESPAWN_DELAY: float = 3.0

# WeaponClass.csv ID -> UClass
WEAPON_CLASS_ID_MAP: Dict[int, str] = {
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
}


# ---------------------------------------------------------------------------
# 3D Math Helpers (UE2 Left-Handed Z-Up Rotator & Ray-Cylinder Intersection)
# ---------------------------------------------------------------------------

def rotator_to_unit_vector(pitch: int, yaw: int) -> Tuple[float, float, float]:
    """Convert UE2 16-bit rotator `(Pitch, Yaw)` to a unit direction vector."""
    p = (int(pitch) & 0xFFFF) * ROT_TO_RAD
    y = (int(yaw) & 0xFFFF) * ROT_TO_RAD
    cp = math.cos(p)
    return (cp * math.cos(y), cp * math.sin(y), math.sin(p))


def vector_to_rotator(dx: float, dy: float, dz: float) -> Tuple[int, int, int]:
    """Convert a 3D direction vector `(dx, dy, dz)` to UE2 `(Pitch, Yaw, 0)`."""
    horiz = math.hypot(dx, dy)
    yaw_rad = math.atan2(dy, dx)
    pitch_rad = math.atan2(dz, horiz)
    pitch = int(round(pitch_rad * RAD_TO_ROT)) & 0xFFFF
    yaw = int(round(yaw_rad * RAD_TO_ROT)) & 0xFFFF
    return (pitch, yaw, 0)


def _vec_sub(
    a: Tuple[float, float, float], b: Tuple[float, float, float]
) -> Tuple[float, float, float]:
    return (a[0] - b[0], a[1] - b[1], a[2] - b[2])


def _vec_len(v: Tuple[float, float, float]) -> float:
    return math.sqrt(v[0] * v[0] + v[1] * v[1] + v[2] * v[2])


def _vec_dist(
    a: Tuple[float, float, float], b: Tuple[float, float, float]
) -> float:
    dx = a[0] - b[0]
    dy = a[1] - b[1]
    dz = a[2] - b[2]
    return math.sqrt(dx * dx + dy * dy + dz * dz)


def _is_finite_vec3(v: Sequence[float]) -> bool:
    return (
        len(v) >= 3
        and math.isfinite(float(v[0]))
        and math.isfinite(float(v[1]))
        and math.isfinite(float(v[2]))
    )


def ray_intersect_vertical_cylinder(
    origin: Tuple[float, float, float],
    direction: Tuple[float, float, float],
    max_distance: float,
    center_x: float,
    center_y: float,
    z_min: float,
    z_max: float,
    radius: float,
) -> Optional[Tuple[float, Tuple[float, float, float]]]:
    """Intersect ray `P(t) = origin + t * direction` (`0 <= t <= max_distance`)
    with a finite vertical cylinder centered at `(center_x, center_y)` spanning
    `[z_min, z_max]` with `radius`.

    Returns `(t_hit, (hx, hy, hz))` for the closest intersection, or `None`.
    """
    if max_distance <= 0.0 or radius <= 0.0 or z_max <= z_min:
        return None

    ox, oy, oz = origin
    dx, dy, dz = direction
    rel_x = ox - center_x
    rel_y = oy - center_y
    r2 = radius * radius

    # Origin already inside the cylinder
    if (rel_x * rel_x + rel_y * rel_y) <= r2 and z_min <= oz <= z_max:
        return (0.0, (ox, oy, oz))

    best_t: Optional[float] = None

    # 1. Curved side surface: (rel_x + t*dx)^2 + (rel_y + t*dy)^2 = r^2
    a = dx * dx + dy * dy
    if a > 1e-12:
        b = 2.0 * (rel_x * dx + rel_y * dy)
        c = rel_x * rel_x + rel_y * rel_y - r2
        disc = b * b - 4.0 * a * c
        if disc >= 0.0:
            sqrt_disc = math.sqrt(disc)
            inv_2a = 0.5 / a
            t0 = (-b - sqrt_disc) * inv_2a
            t1 = (-b + sqrt_disc) * inv_2a
            for t in (t0, t1):
                if 0.0 <= t <= max_distance:
                    hz = oz + t * dz
                    if z_min <= hz <= z_max:
                        if best_t is None or t < best_t:
                            best_t = t

    # 2. Top & bottom circular caps
    if abs(dz) > 1e-12:
        for z_cap in (z_min, z_max):
            t = (z_cap - oz) / dz
            if 0.0 <= t <= max_distance:
                px = rel_x + t * dx
                py = rel_y + t * dy
                if (px * px + py * py) <= r2:
                    if best_t is None or t < best_t:
                        best_t = t

    if best_t is None:
        return None

    hit_pos = (ox + best_t * dx, oy + best_t * dy, oz + best_t * dz)
    return (best_t, hit_pos)


def _apply_spread(
    direction: Tuple[float, float, float],
    yaw_offset_rad: float,
    pitch_offset_rad: float,
) -> Tuple[float, float, float]:
    """Perturb a unit direction vector by small angular offsets (for shotgun pellets)."""
    if yaw_offset_rad == 0.0 and pitch_offset_rad == 0.0:
        return direction
    dx, dy, dz = direction
    horiz = math.hypot(dx, dy)
    yaw = math.atan2(dy, dx) + yaw_offset_rad
    pitch = max(-1.55, min(1.55, math.atan2(dz, horiz) + pitch_offset_rad))
    cp = math.cos(pitch)
    return (cp * math.cos(yaw), cp * math.sin(yaw), math.sin(pitch))


# ---------------------------------------------------------------------------
# Weapon Attribute Database (WeaponAttribute.csv + built-in fallback table)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class WeaponStats:
    """Combat parameters for a single CSO Malaysia weapon."""

    weapon_id: int
    name: str
    weapon_class: str = "KFXWeapons.KFXWeapRifle"
    inv_group: int = 1  # 1=Major, 2=Minor, 3=Melee, 4=Grenade, 5=C4
    damage1: float = 30.0
    damage2: float = 0.0
    fire_rate1: float = 0.12
    fire_rate2: float = 0.2
    range1: float = 8064.0
    range2: float = 8064.0
    valid_range1: float = 8064.0
    valid_range2: float = 8064.0
    range_dmg_factor1: float = 0.85
    range_dmg_factor2: float = 1.0
    momentum1: float = 8000.0
    momentum2: float = 8000.0
    ammo_per_fire1: int = 1
    ammo_per_fire2: int = 1
    shot_per_fire1: int = 1
    shot_per_fire2: int = 1
    clip_size: int = 30
    reserve_ammo: int = 60
    reload_time: float = 2.5
    armor_pct1: float = 0.25
    armor_pct2: float = 0.0
    speed_factor1: float = 0.9

    @property
    def is_melee(self) -> bool:
        return (
            self.inv_group == 3
            or "melee" in self.weapon_class.lower()
            or (self.weapon_id >> 16) == 3
        )

    @property
    def is_grenade(self) -> bool:
        return (
            self.inv_group == 4
            or "toss" in self.weapon_class.lower()
            or (self.weapon_id >> 16) == 4
        )

    @property
    def is_c4(self) -> bool:
        return self.weapon_id == 1 or "cfour" in self.weapon_class.lower()

    @property
    def damage_type_class(self) -> str:
        if self.is_c4:
            return DMG_TYPE_C4
        if self.is_grenade:
            return DMG_TYPE_DELAYED
        return DMG_TYPE_INSTANT

    def damage_for_mode(self, mode: int) -> float:
        if mode == 1 and self.damage2 > 0.0:
            return self.damage2
        return self.damage1

    def fire_rate_for_mode(self, mode: int) -> float:
        if mode == 1 and self.fire_rate2 > 0.0:
            return self.fire_rate2
        return max(0.05, self.fire_rate1)

    def range_for_mode(self, mode: int) -> Tuple[float, float, float]:
        """Return `(max_range, valid_range, range_dmg_factor)` for fire mode."""
        if mode == 1 and self.range2 > 0.0:
            return (
                self.range2,
                self.valid_range2 if self.valid_range2 > 0.0 else self.range2,
                self.range_dmg_factor2 if self.range_dmg_factor2 > 0.0 else 1.0,
            )
        r = self.range1 if self.range1 > 0.0 else 8064.0
        vr = self.valid_range1 if self.valid_range1 > 0.0 else r
        rf = self.range_dmg_factor1 if self.range_dmg_factor1 > 0.0 else 1.0
        return (r, vr, rf)

    def shots_for_mode(self, mode: int) -> int:
        s = self.shot_per_fire2 if mode == 1 and self.shot_per_fire2 > 0 else self.shot_per_fire1
        return max(1, s)

    def armor_pct_for_mode(self, mode: int) -> float:
        return self.armor_pct2 if mode == 1 and self.armor_pct2 > 0.0 else self.armor_pct1

    def momentum_for_mode(self, mode: int) -> float:
        return self.momentum2 if mode == 1 and self.momentum2 > 0.0 else self.momentum1


# Verified fallback stats from WeaponAttribute.csv
DEFAULT_WEAPON_STATS: Dict[int, WeaponStats] = {
    65537: WeaponStats(
        65537, "Ak47", "KFXWeapons.KFXWeapRifle", 1,
        35.0, 0.0, 0.12, 0.2, 8064.0, 0.0, 8064.0, 0.0, 0.943, 1.0,
        8000.0, 8000.0, 1, 0, 1, 0, 30, 60, 2.4, 0.229, 0.0, 0.9,
    ),
    65538: WeaponStats(
        65538, "M4a1", "KFXWeapons.KFXWeapRifle", 1,
        31.0, 0.0, 0.11, 0.2, 8064.0, 0.0, 8064.0, 0.0, 0.871, 1.0,
        8000.0, 8000.0, 1, 0, 1, 0, 30, 60, 3.0, 0.323, 0.0, 0.9,
    ),
    65539: WeaponStats(
        65539, "Mp5", "KFXWeapons.KFXWeapRifle", 1,
        20.0, 0.0, 0.0995, 0.2, 8064.0, 0.0, 8064.0, 0.0, 0.28, 1.0,
        6000.0, 6000.0, 1, 0, 1, 0, 30, 60, 2.6, 0.52, 0.0, 1.0,
    ),
    65540: WeaponStats(
        65540, "XM1014", "KFXWeapons.KFXWeapRifle", 1,
        17.0, 0.0, 0.4, 0.2, 2400.0, 0.0, 1600.0, 0.0, 0.5, 1.0,
        9000.0, 9000.0, 1, 0, 5, 0, 7, 32, 2.5, 0.35, 0.0, 0.9,
    ),
    65541: WeaponStats(
        65541, "Awp", "KFXWeapons.KFXWeapSniper", 1,
        115.0, 115.0, 1.45, 1.45, 10000.0, 10000.0, 10000.0, 10000.0, 1.0, 1.0,
        12000.0, 12000.0, 1, 1, 1, 1, 5, 15, 2.9, 0.0, 0.0, 0.7,
    ),
    65542: WeaponStats(
        65542, "M249", "KFXWeapons.KFXWeapMachinegun", 1,
        31.0, 0.0, 0.13, 0.2, 8064.0, 0.0, 8064.0, 0.0, 0.85, 1.0,
        8000.0, 8000.0, 1, 0, 1, 0, 100, 200, 4.5, 0.25, 0.0, 0.8,
    ),
    65544: WeaponStats(
        65544, "M3", "KFXWeapons.KFXWeapRifle", 1,
        20.0, 0.0, 1.0, 0.2, 2200.0, 0.0, 1400.0, 0.0, 0.5, 1.0,
        10000.0, 10000.0, 1, 0, 7, 0, 8, 32, 2.6, 0.35, 0.0, 0.9,
    ),
    65545: WeaponStats(
        65545, "Mp7", "KFXWeapons.KFXWeapRifle", 1,
        28.0, 0.0, 0.0995, 0.2, 8064.0, 0.0, 8064.0, 0.0, 0.35, 1.0,
        6000.0, 6000.0, 1, 0, 1, 0, 30, 60, 2.5, 0.45, 0.0, 1.0,
    ),
    65546: WeaponStats(
        65546, "M24", "KFXWeapons.KFXWeapSniper", 1,
        74.0, 74.0, 1.45, 1.45, 10000.0, 10000.0, 10000.0, 10000.0, 1.0, 1.0,
        10000.0, 10000.0, 1, 1, 1, 1, 10, 30, 2.8, 0.0, 0.0, 0.8,
    ),
    65549: WeaponStats(
        65549, "AUG", "KFXWeapons.KFXWeapRifle", 1,
        31.0, 0.0, 0.11, 0.2, 8064.0, 0.0, 8064.0, 0.0, 0.87, 1.0,
        8000.0, 8000.0, 1, 0, 1, 0, 30, 60, 2.8, 0.3, 0.0, 0.9,
    ),
    65550: WeaponStats(
        65550, "G3", "KFXWeapons.KFXWeapSniper", 1,
        60.0, 60.0, 0.3, 0.3, 10000.0, 10000.0, 10000.0, 10000.0, 0.95, 1.0,
        9000.0, 9000.0, 1, 1, 1, 1, 20, 60, 3.0, 0.15, 0.0, 0.85,
    ),
    131078: WeaponStats(
        131078, "Glock", "KFXWeapons.KFXWeapPistal", 2,
        24.0, 24.0, 0.2, 0.5, 6048.0, 6048.0, 6048.0, 6048.0, 0.209, 0.209,
        5000.0, 5000.0, 1, 1, 1, 3, 20, 40, 2.7, 0.5, 0.5, 1.0,
    ),
    131079: WeaponStats(
        131079, "DEagle", "KFXWeapons.KFXWeapPistal", 2,
        53.0, 53.0, 0.3, 0.2, 8064.0, 8064.0, 8064.0, 8064.0, 0.17, 0.17,
        8000.0, 8000.0, 1, 1, 1, 1, 7, 21, 2.1, 0.265, 0.0, 1.0,
    ),
    196616: WeaponStats(
        196616, "Melon Knife", "KFXWeapons.KFXWeapMelee", 3,
        20.0, 65.0, 0.4, 1.0, 150.0, 150.0, 150.0, 150.0, 1.0, 1.0,
        4000.0, 8000.0, 0, 0, 1, 1, 10000, 10000, 0.0, 0.267, 0.124, 1.0,
    ),
    196617: WeaponStats(
        196617, "Hammer", "KFXWeapons.KFXWeapMelee", 3,
        50.0, 120.0, 0.7, 1.2, 175.0, 175.0, 175.0, 175.0, 1.0, 1.0,
        6000.0, 10000.0, 0, 0, 1, 1, 10000, 10000, 0.0, 0.2, 0.1, 1.0,
    ),
    196618: WeaponStats(
        196618, "Dagger", "KFXWeapons.KFXWeapMelee", 3,
        20.0, 65.0, 0.4, 1.0, 128.0, 128.0, 128.0, 128.0, 1.0, 1.0,
        4000.0, 8000.0, 0, 0, 1, 1, 10000, 10000, 0.0, 0.25, 0.12, 1.0,
    ),
    196619: WeaponStats(
        196619, "Axe", "KFXWeapons.KFXWeapMelee", 3,
        30.0, 75.0, 0.5, 1.1, 128.0, 128.0, 128.0, 128.0, 1.0, 1.0,
        5000.0, 9000.0, 0, 0, 1, 1, 10000, 10000, 0.0, 0.2, 0.1, 1.0,
    ),
    262156: WeaponStats(
        262156, "HE Grenade", "KFXWeapons.KFXWeapToss", 4,
        95.0, 0.0, 0.2, 0.0, 800.0, 0.0, 800.0, 0.0, 0.0, 0.0,
        15000.0, 0.0, 1, 0, 1, 0, 1, 0, 0.0, 0.163, 0.0, 1.0,
    ),
    262155: WeaponStats(
        262155, "Flashbang", "KFXWeapons.KFXWeapToss", 4,
        0.0, 0.0, 0.2, 0.0, 800.0, 0.0, 800.0, 0.0, 0.0, 0.0,
        0.0, 0.0, 1, 0, 1, 0, 1, 0, 0.0, 0.0, 0.0, 1.0,
    ),
    262157: WeaponStats(
        262157, "Smoke", "KFXWeapons.KFXWeapToss", 4,
        0.0, 0.0, 0.2, 0.0, 800.0, 0.0, 800.0, 0.0, 0.0, 0.0,
        0.0, 0.0, 1, 0, 1, 0, 1, 0, 0.0, 0.0, 0.0, 1.0,
    ),
    262154: WeaponStats(
        262154, "Pig Bomb", "KFXWeapons.KFXWeapToss", 4,
        0.0, 0.0, 0.2, 0.0, 800.0, 0.0, 800.0, 0.0, 0.0, 0.0,
        0.0, 0.0, 1, 0, 1, 0, 1, 0, 0.0, 0.0, 0.0, 1.0,
    ),
    1: WeaponStats(
        1, "C4", "KFXWeapons.KFXWeapCFour", 5,
        500.0, 0.0, 0.2, 0.2, 4000.0, 0.0, 4000.0, 0.0, 0.0, 0.0,
        20000.0, 0.0, 1, 0, 1, 0, 1, 0, 0.0, 0.0, 0.0, 1.0,
    ),
}


def _safe_float(val: Any, default: float = 0.0) -> float:
    try:
        return float(str(val).strip())
    except (TypeError, ValueError):
        return default


def _safe_int(val: Any, default: int = 0) -> int:
    try:
        return int(float(str(val).strip()))
    except (TypeError, ValueError):
        return default


class WeaponDatabase:
    """Loads CSO Malaysia weapon stats from `WeaponAttribute.csv` (XOR 0x9D)
    and `data/items.json`, with built-in verified fallback stats."""

    def __init__(
        self,
        game_dir: str = DEFAULT_GAME_DIR,
        items_json_path: Optional[str] = None,
    ) -> None:
        self.game_dir: str = game_dir
        self.weapons: Dict[int, WeaponStats] = dict(DEFAULT_WEAPON_STATS)
        self.item_names: Dict[int, str] = {}
        self._load_weapon_csv()
        self._load_items_json(items_json_path)

    def _load_weapon_csv(self) -> None:
        csv_path = Path(self.game_dir) / "System" / "WeaponAttribute.csv"
        if not csv_path.is_file():
            return
        try:
            raw = csv_path.read_bytes()
            dec = bytes(b ^ 0x9D for b in raw[3:]) if raw[:3] == b"KFX" else raw
            text = dec.decode("gbk", errors="replace")
            reader = csv.DictReader(io.StringIO(text))
            for row in reader:
                wid = _safe_int(row.get("ID"), 0)
                if wid <= 0:
                    continue
                cls_id = _safe_int(row.get("Class"), 1)
                wcls = WEAPON_CLASS_ID_MAP.get(cls_id, "KFXWeapons.KFXWeapRifle")
                inv_grp = _safe_int(row.get("InvGroup"), 1)
                clip = _safe_int(row.get("ReloadMax1"), 30)
                reserve = _safe_int(row.get("Ammo1"), 60)
                if inv_grp == 3 and clip <= 0:
                    clip = 10000
                    reserve = 10000
                self.weapons[wid] = WeaponStats(
                    weapon_id=wid,
                    name=str(row.get("Name") or f"Weapon_{wid}").strip(),
                    weapon_class=wcls,
                    inv_group=inv_grp,
                    damage1=_safe_float(row.get("Damage1"), 30.0),
                    damage2=_safe_float(row.get("Damage2"), 0.0),
                    fire_rate1=_safe_float(row.get("FireRate1"), 0.12),
                    fire_rate2=_safe_float(row.get("FireRate2"), 0.2),
                    range1=_safe_float(row.get("Range1"), 8064.0),
                    range2=_safe_float(row.get("Range2"), 0.0),
                    valid_range1=_safe_float(row.get("ValidRange1"), 8064.0),
                    valid_range2=_safe_float(row.get("ValidRange2"), 0.0),
                    range_dmg_factor1=_safe_float(row.get("RangeDmgFactor1"), 0.85),
                    range_dmg_factor2=_safe_float(row.get("RangeDmgFactor2"), 1.0),
                    momentum1=_safe_float(row.get("Momentum1"), 8000.0),
                    momentum2=_safe_float(row.get("Momentum2"), 8000.0),
                    ammo_per_fire1=_safe_int(row.get("AmmoPerFire1"), 1),
                    ammo_per_fire2=_safe_int(row.get("AmmoPerFire2"), 0),
                    shot_per_fire1=max(1, _safe_int(row.get("ShotPerFire1"), 1)),
                    shot_per_fire2=_safe_int(row.get("ShotPerFire2"), 0),
                    clip_size=max(1, clip),
                    reserve_ammo=max(0, reserve),
                    reload_time=max(0.0, _safe_float(row.get("ReloadTime"), 2.4)),
                    armor_pct1=_safe_float(row.get("ArmorPct1"), 0.25),
                    armor_pct2=_safe_float(row.get("ArmorPct2"), 0.0),
                    speed_factor1=_safe_float(row.get("SpeedFactor1"), 0.9),
                )
        except Exception as exc:
            log.warning("Failed to parse WeaponAttribute.csv (%s); using built-in table", exc)

    def _load_items_json(self, items_json_path: Optional[str]) -> None:
        candidates: List[Path] = []
        if items_json_path:
            candidates.append(Path(items_json_path))
        else:
            # Resolve <repo>/data/items.json relative to server/ue2_server/combat.py
            repo_root = Path(__file__).resolve().parents[2]
            candidates.append(repo_root / "data" / "items.json")
        for p in candidates:
            if not p.is_file():
                continue
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                for entry in data:
                    it = _safe_int(entry.get("item_type"), 0)
                    if it > 0:
                        self.item_names[it] = str(entry.get("name", ""))
                break
            except Exception as exc:
                log.debug("Could not load items.json from %s: %s", p, exc)

    def get(self, weapon_id: int) -> WeaponStats:
        wid = int(weapon_id)
        ws = self.weapons.get(wid)
        if ws is not None:
            return ws
        # Infer sensible fallback from weapon_id high 16-bit category (1=Major, 2=Minor, 3=Melee, 4=Grenade)
        cat = wid >> 16
        name = self.item_names.get(wid, f"Weapon_{wid}")
        if cat == 3:
            return WeaponStats(
                wid, name, "KFXWeapons.KFXWeapMelee", 3,
                25.0, 65.0, 0.4, 1.0, 150.0, 150.0, 150.0, 150.0, 1.0, 1.0,
                4000.0, 8000.0, 0, 0, 1, 1, 10000, 10000, 0.0, 0.25, 0.12, 1.0,
            )
        if cat == 2:
            return WeaponStats(
                wid, name, "KFXWeapons.KFXWeapPistal", 2,
                28.0, 28.0, 0.22, 0.22, 6048.0, 6048.0, 6048.0, 6048.0, 0.3, 0.3,
                6000.0, 6000.0, 1, 1, 1, 1, 15, 45, 2.3, 0.35, 0.0, 1.0,
            )
        if cat == 4:
            return WeaponStats(
                wid, name, "KFXWeapons.KFXWeapToss", 4,
                95.0, 0.0, 0.2, 0.0, 800.0, 0.0, 800.0, 0.0, 0.0, 0.0,
                15000.0, 0.0, 1, 0, 1, 0, 1, 0, 0.0, 0.16, 0.0, 1.0,
            )
        return WeaponStats(
            wid, name, "KFXWeapons.KFXWeapRifle", 1,
            32.0, 0.0, 0.12, 0.2, 8064.0, 0.0, 8064.0, 0.0, 0.85, 1.0,
            8000.0, 8000.0, 1, 0, 1, 0, 30, 60, 2.5, 0.25, 0.0, 0.9,
        )


_DEFAULT_WEAPON_DB: Optional[WeaponDatabase] = None


def get_default_weapon_db(game_dir: str = DEFAULT_GAME_DIR) -> WeaponDatabase:
    global _DEFAULT_WEAPON_DB
    if _DEFAULT_WEAPON_DB is None or _DEFAULT_WEAPON_DB.game_dir != game_dir:
        _DEFAULT_WEAPON_DB = WeaponDatabase(game_dir=game_dir)
    return _DEFAULT_WEAPON_DB


# ---------------------------------------------------------------------------
# Combat Data Structures
# ---------------------------------------------------------------------------

@dataclass
class PlayerState:
    """Authoritative server-side combat & movement state for one player."""

    role_id: int
    name: str
    team_id: int = 0  # 0=Blue, 1=Red
    pos: Tuple[float, float, float] = (0.0, 0.0, 0.0)
    rot: Tuple[int, int, int] = (0, 0, 0)  # (Pitch, Yaw, Roll) 0..65535
    vel: Tuple[float, float, float] = (0.0, 0.0, 0.0)
    physics: int = PHYS_WALKING
    hp: int = 100
    max_hp: int = 100
    alive: bool = True
    respawn_at: float = 0.0
    weapon_id: int = 65537
    ammo: int = 30
    kills: int = 0
    deaths: int = 0
    headshots: int = 0
    knife_kills: int = 0
    body_type: int = 1
    head_type: int = 0
    coat_type: int = 0
    trousers_type: int = 0

    # Extended authoritative runtime fields
    client_id: Any = None
    level: int = 1
    armor: int = 0
    reserve_ammo: int = 60
    special_kills: int = 0
    crouched: bool = False
    jumping: bool = False
    firing: bool = False
    firing_mode: int = 0
    reloading: bool = False
    reload_end_at: float = 0.0
    last_fire_time: float = -999.0
    last_move_time: float = 0.0
    last_move_timestamp: float = 0.0
    has_moved: bool = False
    ping: int = 5
    connected: bool = True
    joined_at: float = 0.0
    loadout: Dict[str, Any] = field(default_factory=dict)

    def eye_position(self) -> Tuple[float, float, float]:
        eye_z = PAWN_CROUCH_EYE_OFFSET if self.crouched else PAWN_STAND_EYE_OFFSET
        return (self.pos[0], self.pos[1], self.pos[2] + eye_z)

    def aim_direction(self) -> Tuple[float, float, float]:
        return rotator_to_unit_vector(self.rot[0], self.rot[1])

    def hitbox_bounds(self) -> Tuple[Tuple[float, float, float], Tuple[float, float, float]]:
        """Return `((head_z_min, head_z_max, head_r), (body_z_min, body_z_max, body_r))`."""
        z = self.pos[2]
        if self.crouched:
            return (
                (z + PAWN_CROUCH_HEAD_Z_MIN, z + PAWN_CROUCH_HEAD_Z_MAX, PAWN_HEAD_RADIUS),
                (z - PAWN_CROUCH_HALF_HEIGHT, z + PAWN_CROUCH_HEAD_Z_MIN, PAWN_COLLISION_RADIUS),
            )
        return (
            (z + PAWN_STAND_HEAD_Z_MIN, z + PAWN_STAND_HEAD_Z_MAX, PAWN_HEAD_RADIUS),
            (z - PAWN_STAND_HALF_HEIGHT, z + PAWN_STAND_HEAD_Z_MIN, PAWN_COLLISION_RADIUS),
        )


@dataclass(frozen=True)
class HitResult:
    """Result of a single 3D ray hitscan / melee trace against players."""

    shooter_role_id: int
    victim_role_id: Optional[int]
    weapon_id: int
    hitbox_id: int
    headshot: bool
    distance: float
    hit_location: Tuple[float, float, float]
    damage: int
    killed: bool


@dataclass(frozen=True)
class KillEvent:
    """Recorded kill event in the match history."""

    timestamp: float
    killer_role_id: Optional[int]
    victim_role_id: int
    weapon_id: int
    headshot: bool
    knife_kill: bool
    suicide: bool
    damage: int
    hit_location: Tuple[float, float, float]


@dataclass(frozen=True)
class MoveResult:
    """Result of processing a client `ServerMove` / `ShortServerMove` / `DualServerMove`."""

    accepted: bool
    adjusted: bool
    pos: Tuple[float, float, float]
    rot: Tuple[int, int, int]
    vel: Tuple[float, float, float]
    physics: int
    reason: str = ""


# ---------------------------------------------------------------------------
# Authoritative Match World
# ---------------------------------------------------------------------------

class MatchWorld:
    """Authoritative FPS combat & match state for a single multiplayer room."""

    def __init__(
        self,
        *,
        map_name: str = "DF-DiTieZhan",
        map_id: int = 1,
        game_mode: int = 1,
        shoot_limit: int = 50,
        time_limit: int = 15,
        respawn_delay: float = DEFAULT_RESPAWN_DELAY,
        replication: Optional[ReplicationManager] = None,
        map_spawns: Optional[MapSpawnData] = None,
        weapon_db: Optional[WeaponDatabase] = None,
        game_dir: str = DEFAULT_GAME_DIR,
        friendly_fire: bool = False,
        max_move_speed: float = DEFAULT_MAX_MOVE_SPEED,
        min_step_allowance: float = DEFAULT_MIN_STEP_ALLOWANCE,
        desync_tolerance: float = DEFAULT_DESYNC_TOLERANCE,
        clock: Callable[[], float] = time.monotonic,
        on_match_end: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        self.map_name: str = os.path.splitext(os.path.basename(map_name))[0]
        self.map_id: int = int(map_id)
        self.game_mode: int = int(game_mode)
        self.is_team_game: bool = self.game_mode != 2  # Mode 2 = Death Match (FFA)
        self.shoot_limit: int = max(0, int(shoot_limit))
        self.time_limit_seconds: int = (
            int(time_limit) * 60 if 0 < int(time_limit) <= 60 else max(0, int(time_limit))
        )
        self.respawn_delay: float = max(0.0, float(respawn_delay))
        self.friendly_fire: bool = bool(friendly_fire)
        self.max_move_speed: float = float(max_move_speed)
        self.min_step_allowance: float = float(min_step_allowance)
        self.desync_tolerance: float = float(desync_tolerance)
        self._clock: Callable[[], float] = clock
        self.on_match_end: Optional[Callable[[Dict[str, Any]], None]] = on_match_end

        self.replication: Optional[ReplicationManager] = replication
        self.map_spawns: MapSpawnData = (
            map_spawns if map_spawns is not None else load_map_spawns(self.map_name, game_dir=game_dir)
        )
        self.weapon_db: WeaponDatabase = (
            weapon_db if weapon_db is not None else get_default_weapon_db(game_dir=game_dir)
        )

        # Match state
        self.players: Dict[int, PlayerState] = {}
        self.client_to_role: Dict[Any, int] = {}
        self.team_scores: List[int] = [0, 0]  # [blue_score, red_score]
        self.started_at: float = self._clock()
        self.elapsed_seconds: float = 0.0
        self.remaining_seconds: float = float(self.time_limit_seconds)
        self._last_replicated_sec: int = -1
        self.match_ended: bool = False
        self.winner_team: Optional[int] = None
        self.winner_role_id: Optional[int] = None
        self.end_reason: str = ""
        self.kill_feed: List[KillEvent] = []
        self._spawn_counter: Dict[int, int] = {0: 0, 1: 0, 255: 0}

    def attach_replication(self, replication: ReplicationManager) -> None:
        """Bind a `ReplicationManager` to receive authoritative combat/movement updates."""
        self.replication = replication
        replication.rpc_handler = self

    # ------------------------------------------------------------------
    # Spawn Point Selection & Player Lifecycle
    # ------------------------------------------------------------------

    def pick_spawn_point(
        self,
        team_id: int = 0,
        *,
        exclude_role_id: Optional[int] = None,
    ) -> SpawnPoint:
        """Pick a team `PlayerStart` from `.ut2` map data, avoiding occupied/enemy spawns."""
        effective_team = (1 if int(team_id) == 1 else 0) if self.is_team_game else 255
        pool = self.map_spawns.get_spawns_for_team(effective_team)
        if not pool:
            return self.map_spawns.pick_spawn(team_id=effective_team, index=0)

        idx = self._spawn_counter.get(effective_team, 0)
        self._spawn_counter[effective_team] = idx + 1

        alive_others = [
            p
            for p in self.players.values()
            if p.alive and p.connected and p.role_id != exclude_role_id
        ]
        if not alive_others:
            return pool[idx % len(pool)]

        # Prefer spawn points that are not overlapping any player and maximize distance to enemies
        best_sp = pool[idx % len(pool)]
        best_score = -1e18
        for offset in range(len(pool)):
            sp = pool[(idx + offset) % len(pool)]
            min_any = min(_vec_dist(sp.location, o.pos) for o in alive_others)
            enemies = [
                o
                for o in alive_others
                if (not self.is_team_game) or (o.team_id != (1 if int(team_id) == 1 else 0))
            ]
            min_enemy = (
                min(_vec_dist(sp.location, e.pos) for e in enemies)
                if enemies
                else min_any
            )
            # Heavily penalize overlapping another alive player (< 64u)
            overlap_penalty = -10000.0 if min_any < 64.0 else 0.0
            score = min_enemy + 0.25 * min_any + overlap_penalty
            if score > best_score:
                best_score = score
                best_sp = sp
        return best_sp

    def add_player(
        self,
        role_id: int,
        name: str,
        team_id: int = 0,
        *,
        client_id: Any = None,
        body_type: int = 1,
        head_type: int = 0,
        coat_type: int = 0,
        trousers_type: int = 0,
        weapon_id: int = 65537,
        level: int = 1,
        armor: int = 0,
        max_hp: int = 100,
        loadout: Optional[Dict[str, Any]] = None,
        spawn_pos: Optional[Tuple[float, float, float]] = None,
        spawn_rot: Optional[Tuple[int, int, int]] = None,
    ) -> PlayerState:
        """Register or reconnect a player in the match world at a real team `PlayerStart`."""
        rid = int(role_id)
        tidx = 1 if int(team_id) == 1 else 0
        now = self._clock()
        ws = self.weapon_db.get(weapon_id)

        if spawn_pos is None or spawn_rot is None:
            sp = self.pick_spawn_point(tidx, exclude_role_id=rid)
            pos = spawn_pos if spawn_pos is not None else sp.location
            rot = spawn_rot if spawn_rot is not None else sp.rotation
        else:
            pos = (float(spawn_pos[0]), float(spawn_pos[1]), float(spawn_pos[2]))
            rot = (int(spawn_rot[0]) & 0xFFFF, int(spawn_rot[1]) & 0xFFFF, int(spawn_rot[2]) & 0xFFFF)

        existing = self.players.get(rid)
        if existing is not None:
            existing.name = str(name)
            existing.team_id = tidx
            existing.client_id = client_id
            existing.connected = True
            existing.body_type = int(body_type)
            existing.head_type = int(head_type)
            existing.coat_type = int(coat_type)
            existing.trousers_type = int(trousers_type)
            existing.level = int(level)
            if loadout:
                existing.loadout = dict(loadout)
            if not existing.alive:
                existing.pos = pos
                existing.rot = rot
                existing.vel = (0.0, 0.0, 0.0)
                existing.hp = existing.max_hp
                existing.alive = True
                existing.respawn_at = 0.0
            if client_id is not None:
                self.client_to_role[client_id] = rid
            return existing

        player = PlayerState(
            role_id=rid,
            name=str(name),
            team_id=tidx,
            pos=pos,
            rot=rot,
            vel=(0.0, 0.0, 0.0),
            physics=PHYS_WALKING,
            hp=int(max_hp),
            max_hp=int(max_hp),
            alive=True,
            respawn_at=0.0,
            weapon_id=ws.weapon_id,
            ammo=ws.clip_size,
            kills=0,
            deaths=0,
            headshots=0,
            knife_kills=0,
            body_type=int(body_type),
            head_type=int(head_type),
            coat_type=int(coat_type),
            trousers_type=int(trousers_type),
            client_id=client_id,
            level=int(level),
            armor=int(armor),
            reserve_ammo=ws.reserve_ammo,
            joined_at=now,
            last_move_time=now,
            loadout=dict(loadout) if loadout else {},
        )
        self.players[rid] = player
        if client_id is not None:
            self.client_to_role[client_id] = rid
        return player

    def remove_player(self, role_id: int) -> Optional[PlayerState]:
        """Mark a player disconnected while preserving their match stats for `get_match_results()`."""
        player = self.players.get(int(role_id))
        if player is None:
            return None
        player.connected = False
        player.firing = False
        player.reloading = False
        if player.client_id is not None:
            self.client_to_role.pop(player.client_id, None)
            player.client_id = None
        return player

    def get_player(self, role_id: int) -> Optional[PlayerState]:
        return self.players.get(int(role_id))

    def get_player_by_client(self, client_id: Any) -> Optional[PlayerState]:
        rid = self.client_to_role.get(client_id)
        return self.players.get(rid) if rid is not None else None

    def connected_players(self) -> List[PlayerState]:
        return [p for p in self.players.values() if p.connected]

    # ------------------------------------------------------------------
    # Incoming RPC Entry Point (wired directly to ReplicationManager.rpc_handler)
    # ------------------------------------------------------------------

    def handle_rpc(self, client_id: Any, role_id: int, rpc: DecodedRPC) -> Any:
        """Dispatch any decoded C2S UE2 RPC from `ReplicationManager`."""
        lname = rpc.name.lower()
        if lname in ("servermove", "shortservermove", "dualservermove"):
            return self.on_server_move(client_id, role_id, rpc)
        if lname in ("serverstartfire", "serverfire", "kfxserverfireautoaim"):
            return self.on_start_fire(client_id, role_id, rpc)
        if lname == "serverstopfire":
            return self.on_stop_fire(client_id, role_id, rpc)
        if lname == "serverprereload":
            return self.on_reload(client_id, role_id, rpc)
        if lname in ("serverchangedweapon", "kfxchangeweapon"):
            return self.on_change_weapon(client_id, role_id, rpc)
        if lname in ("serversay", "serverteamsay"):
            return self.on_chat(client_id, role_id, rpc)
        if lname == "suicide":
            return self.on_suicide(client_id, role_id, rpc)
        if lname == "serverrestartplayer":
            return self.on_restart_player(client_id, role_id, rpc)
        if lname == "serveracknowledgepossession":
            return self.on_acknowledge_possession(client_id, role_id, rpc)
        if lname == "serverupdateping":
            return self.on_update_ping(client_id, role_id, rpc)
        return None

    # ------------------------------------------------------------------
    # Movement Handling & Desync Correction (`ServerMove` -> `ClientAdjustPosition`)
    # ------------------------------------------------------------------

    def on_server_move(self, client_id: Any, role_id: int, rpc: DecodedRPC) -> MoveResult:
        """Process decoded `ServerMove`, `ShortServerMove`, or `DualServerMove` RPC."""
        extra = rpc.extra or {}
        args = rpc.args or {}

        loc = extra.get("location") or args.get("ClientLoc")
        if "rotation" in extra:
            rot = extra["rotation"]
        else:
            rot = unpack_server_move_view(args.get("View", 0), args.get("ClientRoll", 0))

        vel = extra.get("velocity") if "velocity" in extra else args.get("Velocity")
        physics = extra.get("physics") if "physics" in extra else args.get("Physics")
        crouched = bool(extra.get("crouched", args.get("NewbDuck", False)))
        jump = bool(extra.get("jump", args.get("NewbJumpStatus", False)))
        timestamp = float(extra.get("timestamp", args.get("TimeStamp", 0.0)))

        return self.handle_server_move(
            role_id,
            location=loc,
            rotation=rot,
            velocity=vel,
            physics=physics,
            crouched=crouched,
            jump=jump,
            timestamp=timestamp,
        )

    def handle_server_move(
        self,
        role_id: int,
        *,
        location: Optional[Tuple[float, float, float]] = None,
        rotation: Optional[Tuple[int, int, int]] = None,
        velocity: Optional[Tuple[float, float, float]] = None,
        physics: Optional[int] = None,
        crouched: Optional[bool] = None,
        jump: Optional[bool] = None,
        timestamp: float = 0.0,
        now: Optional[float] = None,
    ) -> MoveResult:
        """Validate and apply authoritative movement from a client `ServerMove`."""
        player = self.players.get(int(role_id))
        if player is None:
            return MoveResult(False, False, (0.0, 0.0, 0.0), (0, 0, 0), (0.0, 0.0, 0.0), PHYS_WALKING, "unknown_player")

        if not player.alive or self.match_ended:
            return MoveResult(False, False, player.pos, player.rot, player.vel, player.physics, "not_alive")

        t_now = self._clock() if now is None else float(now)

        # Parse rotation first (always valid modulo 65536)
        if rotation is not None:
            new_rot = (
                int(rotation[0]) & 0xFFFF,
                int(rotation[1]) & 0xFFFF,
                int(rotation[2]) & 0xFFFF,
            )
        else:
            new_rot = player.rot

        # Validate location coordinates
        if location is None:
            new_loc = player.pos
        else:
            if not _is_finite_vec3(location):
                self._send_adjust_position(player, timestamp)
                return MoveResult(False, True, player.pos, player.rot, player.vel, player.physics, "non_finite_location")
            new_loc = (float(location[0]), float(location[1]), float(location[2]))
            if (
                abs(new_loc[0]) > MAX_WORLD_COORD
                or abs(new_loc[1]) > MAX_WORLD_COORD
                or abs(new_loc[2]) > MAX_WORLD_COORD
            ):
                self._send_adjust_position(player, timestamp)
                return MoveResult(False, True, player.pos, player.rot, player.vel, player.physics, "out_of_bounds")

        # Determine dt for speed check
        dt_wall = max(0.0, t_now - player.last_move_time)
        dt_ts = (
            max(0.0, timestamp - player.last_move_timestamp)
            if (player.has_moved and timestamp > player.last_move_timestamp and (timestamp - player.last_move_timestamp) < 5.0)
            else 0.0
        )
        dt = max(0.016, min(2.0, max(dt_wall, dt_ts)))

        # Validate step distance against max speed + jitter allowance
        step_dist = _vec_dist(player.pos, new_loc)
        max_step = max(self.min_step_allowance, self.max_move_speed * dt + self.desync_tolerance)
        if step_dist > max_step:
            # Reject impossible teleport/desync and correct client with ClientAdjustPosition
            log.debug(
                "Movement desync for role=%d (%s): dist=%.1f > max_step=%.1f; sending ClientAdjustPosition",
                player.role_id, player.name, step_dist, max_step,
            )
            self._send_adjust_position(player, timestamp)
            return MoveResult(False, True, player.pos, player.rot, player.vel, player.physics, "speed_exceeded")

        # Validate or infer velocity (ensure remote ROLE_SimulatedProxy gets smooth velocity extrapolation)
        inferred_vel = False
        if velocity is not None and _is_finite_vec3(velocity):
            vx, vy, vz = float(velocity[0]), float(velocity[1]), float(velocity[2])
            speed = math.sqrt(vx * vx + vy * vy + vz * vz)
            if speed < 1e-2 and step_dist > 1.0:
                inferred_vel = True
            else:
                if speed > self.max_move_speed * 2.0:
                    scale = (self.max_move_speed * 2.0) / speed
                    vx, vy, vz = vx * scale, vy * scale, vz * scale
                new_vel = (vx, vy, vz)
        else:
            inferred_vel = True

        if inferred_vel:
            if step_dist > 1e-2:
                inv_dt = 1.0 / dt
                vx = (new_loc[0] - player.pos[0]) * inv_dt
                vy = (new_loc[1] - player.pos[1]) * inv_dt
                vz = (new_loc[2] - player.pos[2]) * inv_dt
                speed = math.sqrt(vx * vx + vy * vy + vz * vz)
                if speed > self.max_move_speed * 2.0:
                    scale = (self.max_move_speed * 2.0) / speed
                    vx, vy, vz = vx * scale, vy * scale, vz * scale
                new_vel = (vx, vy, vz)
            else:
                new_vel = (0.0, 0.0, 0.0)

        # Never replicate PHYS_NONE (0) for a living pawn: if ShortServerMove omitted
        # Physics (decoded as 0), infer PHYS_WALKING/PHYS_FALLING so remote SimulatedProxy
        # clients keep smooth 60FPS APawn::physWalking velocity extrapolation active!
        if physics is not None and 1 <= int(physics) <= 16:
            new_phys = int(physics)
        else:
            new_phys = PHYS_FALLING if (jump or abs(new_vel[2]) > 80.0) else PHYS_WALKING

        # Commit authoritative player state
        player.pos = new_loc
        player.rot = new_rot
        player.vel = new_vel
        player.physics = new_phys
        if crouched is not None:
            player.crouched = bool(crouched)
        if jump is not None:
            player.jumping = bool(jump)
        player.last_move_time = t_now
        player.last_move_timestamp = timestamp
        player.has_moved = True

        # Mark Pawn dirty so every other client gets smooth position/rotation/velocity sync!
        if self.replication is not None:
            self.replication.update_pawn_state(
                player.role_id,
                location=player.pos,
                rotation=player.rot,
                velocity=player.vel,
                physics=player.physics,
                crouched=player.crouched,
            )

        return MoveResult(True, False, player.pos, player.rot, player.vel, player.physics)

    def _send_adjust_position(self, player: PlayerState, timestamp: float) -> None:
        if self.replication is None:
            return
        self.replication.send_client_adjust_position(
            player.role_id,
            float(timestamp),
            "PlayerWalking",
            player.physics,
            player.pos,
            player.vel,
            None,
        )

    # ------------------------------------------------------------------
    # Shooting, 3D Hitscan / Melee Hit Registration, Damage & Kills
    # ------------------------------------------------------------------

    def on_start_fire(self, client_id: Any, role_id: int, rpc: DecodedRPC) -> List[HitResult]:
        """Handle `Weapon.ServerStartFire(byte Mode)` / `ServerFire`."""
        mode = int(rpc.args.get("Mode", rpc.args.get("mode", 0))) if rpc.args else 0
        return self.handle_start_fire(role_id, mode=mode)

    def on_stop_fire(self, client_id: Any, role_id: int, rpc: DecodedRPC) -> None:
        """Handle `Weapon.ServerStopFire(byte Mode)`."""
        self.handle_stop_fire(role_id)

    def handle_start_fire(
        self,
        role_id: int,
        *,
        mode: int = 0,
        aim_rot: Optional[Tuple[int, int, int]] = None,
        now: Optional[float] = None,
    ) -> List[HitResult]:
        """Begin firing for `role_id` and immediately evaluate one authoritative shot."""
        player = self.players.get(int(role_id))
        if player is None or not player.alive or self.match_ended:
            return []
        if aim_rot is not None:
            player.rot = (
                int(aim_rot[0]) & 0xFFFF,
                int(aim_rot[1]) & 0xFFFF,
                int(aim_rot[2]) & 0xFFFF,
            )
        player.firing = True
        player.firing_mode = 1 if int(mode) == 1 else 0
        return self.fire_shot(role_id, mode=player.firing_mode, now=now)

    def handle_stop_fire(self, role_id: int) -> None:
        """Stop automatic firing for `role_id`."""
        player = self.players.get(int(role_id))
        if player is not None:
            player.firing = False

    def trace_ray_against_players(
        self,
        shooter: PlayerState,
        origin: Tuple[float, float, float],
        direction: Tuple[float, float, float],
        max_range: float,
    ) -> Optional[Tuple[PlayerState, int, float, Tuple[float, float, float]]]:
        """Trace a 3D ray against all alive enemy players' head & body cylinders.

        Returns `(victim, hitbox_id, distance, hit_location)` for the closest hit, or `None`.
        """
        best: Optional[Tuple[PlayerState, int, float, Tuple[float, float, float]]] = None

        for target in self.players.values():
            if target.role_id == shooter.role_id or not target.alive or not target.connected:
                continue
            if self.is_team_game and not self.friendly_fire and target.team_id == shooter.team_id:
                continue

            (head_z0, head_z1, head_r), (body_z0, body_z1, body_r) = target.hitbox_bounds()
            tx, ty, tz = target.pos

            head_hit = ray_intersect_vertical_cylinder(
                origin, direction, max_range, tx, ty, head_z0, head_z1, head_r
            )
            body_hit = ray_intersect_vertical_cylinder(
                origin, direction, max_range, tx, ty, body_z0, body_z1, body_r
            )

            chosen_t: Optional[float] = None
            chosen_loc: Optional[Tuple[float, float, float]] = None
            chosen_hitbox: int = HITBOX_CHEST

            if head_hit is not None and (body_hit is None or head_hit[0] <= body_hit[0] + 16.0):
                chosen_t, chosen_loc = head_hit
                chosen_hitbox = HITBOX_HEAD
            elif body_hit is not None:
                chosen_t, chosen_loc = body_hit
                hz = chosen_loc[2]
                if target.crouched:
                    stomach_max = tz + PAWN_CROUCH_STOMACH_Z_MAX
                    legs_max = tz + PAWN_CROUCH_LEGS_Z_MAX
                else:
                    stomach_max = tz + PAWN_STAND_STOMACH_Z_MAX
                    legs_max = tz + PAWN_STAND_LEGS_Z_MAX
                if hz <= legs_max:
                    chosen_hitbox = HITBOX_LEGS
                elif hz <= stomach_max:
                    chosen_hitbox = HITBOX_STOMACH
                else:
                    chosen_hitbox = HITBOX_CHEST

            if chosen_t is not None and chosen_loc is not None:
                if best is None or chosen_t < best[2]:
                    best = (target, chosen_hitbox, chosen_t, chosen_loc)

        return best

    def calculate_damage(
        self,
        weapon: WeaponStats,
        mode: int,
        distance: float,
        hitbox_id: int,
        victim_armor: int = 0,
    ) -> Tuple[int, int]:
        """Compute `(final_hp_damage, armor_absorbed)` per CSO Malaysia formulas."""
        base_dmg = weapon.damage_for_mode(mode)
        if base_dmg <= 0.0:
            return (0, 0)

        max_range, valid_range, range_fac = weapon.range_for_mode(mode)
        if distance >= max_range and max_range > 0.0:
            return (0, 0)

        # KFXFireBase.KFXDecayDamage distance falloff
        mid = base_dmg * range_fac
        if valid_range > 0.0 and distance < valid_range:
            dmg = base_dmg - (base_dmg - mid) * (distance / valid_range)
        elif max_range > valid_range:
            dmg = mid * max(0.0, (max_range - distance) / (max_range - valid_range))
        else:
            dmg = mid

        # KFXPawn.KFXHixBoxDmg hitbox multiplier
        mult_table = MELEE_HITBOX_MULTIPLIER if weapon.is_melee else HITBOX_MULTIPLIER
        dmg *= mult_table.get(hitbox_id, 1.0)

        # KFXPawn.KFXArmorAbsorbDmg
        armor_absorbed = 0
        armor_pct = weapon.armor_pct_for_mode(mode)
        if victim_armor > 0 and armor_pct > 0.0:
            absorb = min(victim_armor, int(round(dmg * armor_pct * 0.5)))
            armor_absorbed = max(0, absorb)
            dmg = max(1.0, dmg - armor_absorbed)

        return (max(1, int(round(dmg))), armor_absorbed)

    def fire_shot(
        self,
        role_id: int,
        *,
        mode: int = 0,
        now: Optional[float] = None,
        ignore_cooldown: bool = False,
    ) -> List[HitResult]:
        """Execute one authoritative weapon shot (hitscan/melee/shotgun/HE) for `role_id`."""
        shooter = self.players.get(int(role_id))
        if shooter is None or not shooter.alive or not shooter.connected or self.match_ended:
            return []

        t_now = self._clock() if now is None else float(now)
        weapon = self.weapon_db.get(shooter.weapon_id)

        # Reject while reloading
        if shooter.reloading:
            if t_now >= shooter.reload_end_at:
                self._finish_reload(shooter)
            else:
                return []

        # Respect weapon fire-rate cooldown
        fire_rate = weapon.fire_rate_for_mode(mode)
        if not ignore_cooldown and (t_now - shooter.last_fire_time) < (fire_rate * 0.85):
            return []

        # Consume ammo (melee weapons have unlimited ammo / ammo_per_fire=0)
        ammo_cost = 0 if weapon.is_melee else max(0, weapon.ammo_per_fire1)
        if ammo_cost > 0:
            if shooter.ammo < ammo_cost:
                # Auto-trigger reload if reserve remains
                if shooter.reserve_ammo > 0:
                    self.start_reload(shooter.role_id, now=t_now)
                return []
            shooter.ammo -= ammo_cost

        shooter.last_fire_time = t_now

        # Update weapon clip replication
        if self.replication is not None:
            self.replication.update_weapon_state(
                shooter.role_id,
                clip_ammo=shooter.ammo,
                reserve_ammo=shooter.reserve_ammo,
                is_reload=False,
            )

        # Grenade / area splash path
        if weapon.is_grenade:
            return self._resolve_grenade_shot(shooter, weapon, mode, t_now)

        # Hitscan / melee ray trace (supports multi-pellet shotguns)
        origin = shooter.eye_position()
        base_dir = shooter.aim_direction()
        max_range, _, _ = weapon.range_for_mode(mode)
        num_shots = weapon.shots_for_mode(mode)

        # Pellet angular offsets (pellet 0 is always dead center)
        pellet_offsets: List[Tuple[float, float]] = [(0.0, 0.0)]
        if num_shots > 1:
            spread_rad = 0.035  # ~2 degrees
            for i in range(1, num_shots):
                angle = (2.0 * math.pi * (i - 1)) / max(1, num_shots - 1)
                pellet_offsets.append((spread_rad * math.cos(angle), spread_rad * math.sin(angle)))

        hit_locations: List[Tuple[float, float, float]] = []
        results: List[HitResult] = []
        momentum_mag = weapon.momentum_for_mode(mode)

        for yaw_off, pitch_off in pellet_offsets:
            ray_dir = _apply_spread(base_dir, yaw_off, pitch_off)
            hit = self.trace_ray_against_players(shooter, origin, ray_dir, max_range)
            if hit is None:
                miss_end = (
                    origin[0] + ray_dir[0] * min(max_range, 4000.0),
                    origin[1] + ray_dir[1] * min(max_range, 4000.0),
                    origin[2] + ray_dir[2] * min(max_range, 4000.0),
                )
                hit_locations.append(miss_end)
                continue

            victim, hitbox_id, dist, hit_loc = hit
            hit_locations.append(hit_loc)
            dmg, armor_abs = self.calculate_damage(weapon, mode, dist, hitbox_id, victim.armor)
            if dmg <= 0:
                continue

            momentum = (ray_dir[0] * momentum_mag, ray_dir[1] * momentum_mag, ray_dir[2] * momentum_mag)
            killed = self.apply_damage(
                victim.role_id,
                dmg,
                killer_role_id=shooter.role_id,
                weapon_id=weapon.weapon_id,
                hitbox_id=hitbox_id,
                hit_location=hit_loc,
                momentum=momentum,
                armor_absorbed=armor_abs,
                damage_type=weapon.damage_type_class,
                now=t_now,
            )
            results.append(
                HitResult(
                    shooter_role_id=shooter.role_id,
                    victim_role_id=victim.role_id,
                    weapon_id=weapon.weapon_id,
                    hitbox_id=hitbox_id,
                    headshot=(hitbox_id == HITBOX_HEAD),
                    distance=dist,
                    hit_location=hit_loc,
                    damage=dmg,
                    killed=killed,
                )
            )

        # Trigger 3rd-person muzzle flash & impact decals on KFXWeapAttachment
        if self.replication is not None:
            self.replication.trigger_weapon_fire_effect(
                shooter.role_id,
                firing_mode=mode,
                hit_locations=hit_locations[:8],
                is_reload=False,
            )

        # Auto-reload when magazine hits 0 and reserve remains
        if not weapon.is_melee and shooter.ammo == 0 and shooter.reserve_ammo > 0:
            self.start_reload(shooter.role_id, now=t_now)

        return results

    def _resolve_grenade_shot(
        self,
        shooter: PlayerState,
        weapon: WeaponStats,
        mode: int,
        t_now: float,
    ) -> List[HitResult]:
        """Resolve an explosive grenade splash along shooter's aim direction."""
        origin = shooter.eye_position()
        direction = shooter.aim_direction()
        throw_dist = 600.0
        blast_center = (
            origin[0] + direction[0] * throw_dist,
            origin[1] + direction[1] * throw_dist,
            origin[2] + direction[2] * throw_dist,
        )
        blast_radius = max(100.0, weapon.range1)
        base_dmg = weapon.damage_for_mode(mode)
        results: List[HitResult] = []

        if self.replication is not None:
            self.replication.trigger_weapon_fire_effect(
                shooter.role_id,
                firing_mode=mode,
                hit_locations=[blast_center],
                is_reload=False,
            )

        if base_dmg <= 0.0:
            return results

        for target in list(self.players.values()):
            if not target.alive or not target.connected:
                continue
            if (
                target.role_id != shooter.role_id
                and self.is_team_game
                and not self.friendly_fire
                and target.team_id == shooter.team_id
            ):
                continue
            dist = _vec_dist(blast_center, target.pos)
            if dist >= blast_radius:
                continue
            falloff = 1.0 - (dist / blast_radius)
            dmg = max(1, int(round(base_dmg * falloff)))
            diff = _vec_sub(target.pos, blast_center)
            dlen = max(1.0, _vec_len(diff))
            mom_mag = weapon.momentum1 * falloff
            momentum = (diff[0] / dlen * mom_mag, diff[1] / dlen * mom_mag, diff[2] / dlen * mom_mag)
            killed = self.apply_damage(
                target.role_id,
                dmg,
                killer_role_id=shooter.role_id,
                weapon_id=weapon.weapon_id,
                hitbox_id=HITBOX_CHEST,
                hit_location=target.pos,
                momentum=momentum,
                damage_type=DMG_TYPE_DELAYED,
                now=t_now,
            )
            results.append(
                HitResult(
                    shooter_role_id=shooter.role_id,
                    victim_role_id=target.role_id,
                    weapon_id=weapon.weapon_id,
                    hitbox_id=HITBOX_CHEST,
                    headshot=False,
                    distance=dist,
                    hit_location=target.pos,
                    damage=dmg,
                    killed=killed,
                )
            )
        return results

    def apply_damage(
        self,
        victim_role_id: int,
        damage: int,
        *,
        killer_role_id: Optional[int] = None,
        weapon_id: int = 65537,
        hitbox_id: int = HITBOX_CHEST,
        hit_location: Optional[Tuple[float, float, float]] = None,
        momentum: Tuple[float, float, float] = (0.0, 0.0, 0.0),
        armor_absorbed: int = 0,
        damage_type: str = DMG_TYPE_INSTANT,
        now: Optional[float] = None,
    ) -> bool:
        """Apply authoritative damage to `victim_role_id`, handling hit feedback, death,
        scoreboard updates, kill feed broadcast, and match-win detection.

        Returns `True` if this damage killed the victim.
        """
        victim = self.players.get(int(victim_role_id))
        if victim is None or not victim.alive or self.match_ended:
            return False

        dmg = max(0, int(damage))
        if dmg <= 0:
            return False

        t_now = self._clock() if now is None else float(now)
        hloc = hit_location if hit_location is not None else victim.pos
        headshot = hitbox_id == HITBOX_HEAD

        if armor_absorbed > 0:
            victim.armor = max(0, victim.armor - int(armor_absorbed))
        victim.hp = max(0, victim.hp - dmg)

        # Replicate victim hit feedback (Health, Armor, KFXDmgRepInfo, KickBackMuzzle)
        if self.replication is not None:
            self.replication.update_pawn_state(
                victim.role_id,
                health=victim.hp,
                armor=victim.armor,
                hit_weapon_id=weapon_id,
            )
            self.replication.trigger_take_hit_effect(
                victim.role_id,
                instigator_role_id=killer_role_id,
                hit_location=hloc,
                momentum=momentum,
                dmg_shake=2 if headshot else 1,
                weapon_id=weapon_id,
            )
            if victim.hp > 0:
                if headshot:
                    self.replication.send_kick_back_muzzle(victim.role_id, dmg * 0.5, 2.0, 12.0, 9.0)
                else:
                    self.replication.send_kick_back_muzzle(victim.role_id, dmg * 0.1, 0.0, 4.0, 1.0)
                self.replication.send_client_speed_down(victim.role_id)

        if victim.hp <= 0:
            self._handle_kill(
                killer_role_id=killer_role_id,
                victim=victim,
                weapon_id=weapon_id,
                headshot=headshot,
                damage=dmg,
                hit_location=hloc,
                momentum=momentum,
                damage_type=damage_type,
                now=t_now,
            )
            return True

        return False

    def _handle_kill(
        self,
        *,
        killer_role_id: Optional[int],
        victim: PlayerState,
        weapon_id: int,
        headshot: bool,
        damage: int,
        hit_location: Tuple[float, float, float],
        momentum: Tuple[float, float, float],
        damage_type: str,
        now: float,
    ) -> None:
        victim.alive = False
        victim.hp = 0
        victim.deaths += 1
        victim.firing = False
        victim.reloading = False
        victim.respawn_at = now + self.respawn_delay

        suicide = killer_role_id is None or killer_role_id == victim.role_id
        killer = None if suicide else self.players.get(int(killer_role_id))
        ws = self.weapon_db.get(weapon_id)
        is_knife = (not suicide) and ws.is_melee
        is_special = (not suicide) and (ws.is_grenade or ws.is_c4)

        if killer is not None:
            killer.kills += 1
            if headshot:
                killer.headshots += 1
            if is_knife:
                killer.knife_kills += 1
            if is_special:
                killer.special_kills += 1
            if self.is_team_game and killer.team_id in (0, 1):
                self.team_scores[killer.team_id] += 1

        event = KillEvent(
            timestamp=now,
            killer_role_id=killer.role_id if killer else None,
            victim_role_id=victim.role_id,
            weapon_id=weapon_id,
            headshot=headshot and (not suicide),
            knife_kill=is_knife,
            suicide=suicide,
            damage=damage,
            hit_location=hit_location,
        )
        self.kill_feed.append(event)

        # Replicate death state, PRI scoreboard, GRI team scores, and kill feed broadcast
        if self.replication is not None:
            self.replication.update_pawn_state(
                victim.role_id,
                health=0,
                tear_off=True,
                tear_off_momentum=momentum,
                hit_damage_type=damage_type,
                take_hit_location=hit_location,
            )
            self.replication.send_client_dying(victim.role_id, damage_type, hit_location)
            self.replication.send_client_goto_state(victim.role_id, "Dead", "Begin")
            self.replication.update_pri_state(
                victim.role_id,
                deaths=victim.deaths,
                dead_status=True,
            )
            if killer is not None:
                self.replication.update_pri_state(
                    killer.role_id,
                    kills=killer.kills,
                    score=float(killer.kills),
                    head_kill=headshot,
                )
            self.replication.update_gri_state(
                blue_score=float(self.team_scores[0]),
                red_score=float(self.team_scores[1]),
            )
            self.replication.broadcast_kill_notification(
                killer.role_id if killer else None,
                victim.role_id,
                weapon_id,
                headshot=headshot and (not suicide),
                suicide=suicide,
                damage_type=damage_type,
                killer_total_kills=killer.kills if killer else 0,
            )

        # Win detection (shoot_limit / GoalScore)
        if self.shoot_limit > 0 and killer is not None:
            if self.is_team_game:
                if self.team_scores[killer.team_id] >= self.shoot_limit:
                    self.end_match(reason="kill_limit", winner_team=killer.team_id)
            else:
                if killer.kills >= self.shoot_limit:
                    self.end_match(reason="kill_limit", winner_role_id=killer.role_id)

    # ------------------------------------------------------------------
    # Reload, Weapon Switch, Suicide, Chat & Respawn
    # ------------------------------------------------------------------

    def on_reload(self, client_id: Any, role_id: int, rpc: DecodedRPC) -> bool:
        return self.start_reload(role_id)

    def start_reload(self, role_id: int, *, now: Optional[float] = None) -> bool:
        """Begin weapon reload for `role_id`."""
        player = self.players.get(int(role_id))
        if player is None or not player.alive or player.reloading or self.match_ended:
            return False
        ws = self.weapon_db.get(player.weapon_id)
        if ws.is_melee or player.ammo >= ws.clip_size or player.reserve_ammo <= 0:
            return False
        t_now = self._clock() if now is None else float(now)
        player.firing = False
        player.reloading = True
        player.reload_end_at = t_now + max(0.2, ws.reload_time)
        if self.replication is not None:
            self.replication.update_weapon_state(player.role_id, is_reload=True)
            self.replication.send_client_pre_reload(player.role_id)
            self.replication.trigger_weapon_fire_effect(player.role_id, is_reload=True)
        return True

    def _finish_reload(self, player: PlayerState) -> None:
        ws = self.weapon_db.get(player.weapon_id)
        needed = max(0, ws.clip_size - player.ammo)
        taken = min(needed, player.reserve_ammo)
        player.ammo += taken
        player.reserve_ammo -= taken
        player.reloading = False
        player.reload_end_at = 0.0
        if self.replication is not None:
            self.replication.update_weapon_state(
                player.role_id,
                clip_ammo=player.ammo,
                reserve_ammo=player.reserve_ammo,
                is_reload=False,
            )
            self.replication.send_client_post_reload(player.role_id)

    def on_change_weapon(self, client_id: Any, role_id: int, rpc: DecodedRPC) -> bool:
        """Handle `KFXPlayer.KFXChangeWeapon(int Id)` or `Pawn.ServerChangedWeapon`."""
        args = rpc.args or {}
        if rpc.name.lower() == "kfxchangeweapon":
            new_wid = int(args.get("Id", 0))
            if new_wid > 0:
                return self.change_weapon(role_id, new_wid, ack_id=new_wid)
        return False

    def change_weapon(
        self,
        role_id: int,
        new_weapon_id: int,
        *,
        ack_id: Optional[int] = None,
    ) -> bool:
        """Switch a player's active weapon and replicate to all clients."""
        player = self.players.get(int(role_id))
        if player is None or not player.alive or self.match_ended:
            return False
        ws = self.weapon_db.get(int(new_weapon_id))
        player.weapon_id = ws.weapon_id
        player.ammo = ws.clip_size
        player.reserve_ammo = ws.reserve_ammo
        player.reloading = False
        player.reload_end_at = 0.0
        player.firing = False
        if self.replication is not None:
            self.replication.switch_player_weapon(
                player.role_id,
                ws.weapon_id,
                clip_ammo=player.ammo,
                reserve_ammo=player.reserve_ammo,
                ack_id=ack_id,
            )
        return True

    def on_suicide(self, client_id: Any, role_id: int, rpc: DecodedRPC) -> bool:
        player = self.players.get(int(role_id))
        if player is None or not player.alive or self.match_ended:
            return False
        return self.apply_damage(
            player.role_id,
            max(player.hp, player.max_hp),
            killer_role_id=None,
            weapon_id=player.weapon_id,
            hit_location=player.pos,
        )

    def on_chat(self, client_id: Any, role_id: int, rpc: DecodedRPC) -> int:
        msg = str((rpc.args or {}).get("Msg", "")).strip()
        if not msg or self.replication is None:
            return 0
        team_only = rpc.name.lower() == "serverteamsay"
        return self.replication.broadcast_chat_message(role_id, msg, team_only=team_only)

    def on_restart_player(self, client_id: Any, role_id: int, rpc: DecodedRPC) -> bool:
        player = self.players.get(int(role_id))
        if player is None or player.alive or self.match_ended:
            return False
        now = self._clock()
        if now >= player.respawn_at:
            return self.respawn_player(role_id, now=now)
        return False

    def on_acknowledge_possession(self, client_id: Any, role_id: int, rpc: DecodedRPC) -> None:
        player = self.players.get(int(role_id))
        if player is not None and self.replication is not None:
            self.replication.send_client_set_rotation(player.role_id, player.rot)

    def on_update_ping(self, client_id: Any, role_id: int, rpc: DecodedRPC) -> None:
        player = self.players.get(int(role_id))
        if player is None:
            return
        # Store reasonable ping value on PRI
        player.ping = max(1, min(255, int(player.ping)))
        if self.replication is not None:
            self.replication.update_pri_state(player.role_id, ping=player.ping)

    def respawn_player(
        self,
        role_id: int,
        *,
        now: Optional[float] = None,
        spawn_point: Optional[SpawnPoint] = None,
    ) -> bool:
        """Respawn a dead player at a team `PlayerStart` with full HP & fresh ammo."""
        player = self.players.get(int(role_id))
        if player is None or not player.connected or self.match_ended:
            return False

        t_now = self._clock() if now is None else float(now)
        sp = spawn_point if spawn_point is not None else self.pick_spawn_point(
            player.team_id, exclude_role_id=player.role_id
        )
        ws = self.weapon_db.get(player.weapon_id)

        player.pos = sp.location
        player.rot = sp.rotation
        player.vel = (0.0, 0.0, 0.0)
        player.physics = PHYS_WALKING
        player.hp = player.max_hp
        player.alive = True
        player.respawn_at = 0.0
        player.crouched = False
        player.jumping = False
        player.firing = False
        player.reloading = False
        player.reload_end_at = 0.0
        player.ammo = ws.clip_size
        player.reserve_ammo = ws.reserve_ammo
        player.last_move_time = t_now
        player.has_moved = False

        if self.replication is not None:
            respawn_kwargs: Dict[str, Any] = {
                "health": player.hp,
                "health_max": float(player.max_hp),
                "armor": player.armor,
                "body_type": player.body_type,
                "head_type": player.head_type,
                "trousers_type": player.trousers_type,
                "weapon_id": player.weapon_id,
                "clip_ammo": player.ammo,
                "reserve_ammo": player.reserve_ammo,
            }
            if "coat_type" in inspect.signature(self.replication.respawn_player_pawn).parameters:
                respawn_kwargs["coat_type"] = player.coat_type
            self.replication.respawn_player_pawn(
                player.role_id,
                sp.location,
                sp.rotation,
                **respawn_kwargs,
            )
        return True

    # ------------------------------------------------------------------
    # 30Hz Simulation Tick (Respawns, Reloads, Auto-Fire, Match Timer)
    # ------------------------------------------------------------------

    def tick(self, now: Optional[float] = None) -> Dict[str, Any]:
        """Advance match timers, pending reloads, auto-respawns, and sustained fire.

        Intended to be called at 20-30Hz by `UE2MatchServer._tick_loop`.
        Returns a summary dict of actions taken this tick.
        """
        t_now = self._clock() if now is None else float(now)
        respawned: List[int] = []
        reloaded: List[int] = []
        auto_hits: List[HitResult] = []

        if self.match_ended:
            return {"respawned": respawned, "reloaded": reloaded, "hits": auto_hits, "match_ended": True}

        # 1. Update match clock & GRI timer
        self.elapsed_seconds = max(0.0, t_now - self.started_at)
        if self.time_limit_seconds > 0:
            self.remaining_seconds = max(0.0, float(self.time_limit_seconds) - self.elapsed_seconds)
        else:
            self.remaining_seconds = 0.0

        elapsed_int = int(self.elapsed_seconds)
        if elapsed_int != self._last_replicated_sec:
            self._last_replicated_sec = elapsed_int
            if self.replication is not None:
                self.replication.update_gri_state(
                    elapsed_time=elapsed_int,
                    remaining_time=int(math.ceil(self.remaining_seconds)),
                )

        # 2. Check time-limit expiry
        if self.time_limit_seconds > 0 and self.remaining_seconds <= 0.0:
            self.end_match(reason="time_limit")
            return {"respawned": respawned, "reloaded": reloaded, "hits": auto_hits, "match_ended": True}

        # 3. Process per-player timers (respawn, reload, held auto-fire)
        for player in list(self.players.values()):
            if not player.connected:
                continue

            if not player.alive:
                if player.respawn_at > 0.0 and t_now >= player.respawn_at:
                    if self.respawn_player(player.role_id, now=t_now):
                        respawned.append(player.role_id)
                continue

            if player.reloading:
                if t_now >= player.reload_end_at:
                    self._finish_reload(player)
                    reloaded.append(player.role_id)
                continue

            if player.firing and not self.match_ended:
                ws = self.weapon_db.get(player.weapon_id)
                rate = ws.fire_rate_for_mode(player.firing_mode)
                if (t_now - player.last_fire_time) >= rate:
                    hits = self.fire_shot(player.role_id, mode=player.firing_mode, now=t_now)
                    auto_hits.extend(hits)

        return {
            "respawned": respawned,
            "reloaded": reloaded,
            "hits": auto_hits,
            "match_ended": self.match_ended,
        }

    # ------------------------------------------------------------------
    # Match End & Realm Persistence Summary (`get_match_results`)
    # ------------------------------------------------------------------

    def _determine_winner(self) -> Tuple[Optional[int], Optional[int]]:
        """Compute `(winner_team, winner_role_id)` from current scores."""
        if self.is_team_game:
            if self.team_scores[0] > self.team_scores[1]:
                return (0, None)
            if self.team_scores[1] > self.team_scores[0]:
                return (1, None)
            return (None, None)

        if not self.players:
            return (None, None)
        ranked = sorted(self.players.values(), key=lambda p: (p.kills, -p.deaths), reverse=True)
        if len(ranked) == 1:
            return (None, ranked[0].role_id if ranked[0].kills > 0 else None)
        if ranked[0].kills > ranked[1].kills:
            return (None, ranked[0].role_id)
        return (None, None)

    def end_match(
        self,
        reason: str = "completed",
        *,
        winner_team: Optional[int] = None,
        winner_role_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Finalize the match, broadcast UE2 `ClientGameEnded`, and invoke `on_match_end`."""
        if not self.match_ended:
            self.match_ended = True
            self.end_reason = reason
            det_team, det_role = self._determine_winner()
            self.winner_team = winner_team if winner_team is not None else det_team
            self.winner_role_id = winner_role_id if winner_role_id is not None else det_role

            for p in self.players.values():
                p.firing = False

            if self.replication is not None:
                self.replication.broadcast_game_ended(winner_team=self.winner_team)

            results = self.get_match_results()
            if self.on_match_end is not None:
                try:
                    self.on_match_end(results)
                except Exception:
                    log.exception("Error in MatchWorld.on_match_end callback")
            return results

        return self.get_match_results()

    def get_match_results(self) -> Dict[str, Any]:
        """Export per-player combat stats & rewards for `realm.py` -> `database.add_match_stats()`.

        Every player entry includes:
        `role_id`, `name`, `team_id`, `kills`, `deaths`, `headshots`, `head_kills`,
        `knife_kills`, `special_kills`, `victory`, `defeated`, `deuce`,
        `honor_gain`, `gp_gain`.
        """
        win_team, win_role = (
            (self.winner_team, self.winner_role_id)
            if self.match_ended
            else self._determine_winner()
        )

        per_player: Dict[int, Dict[str, Any]] = {}
        for rid, p in self.players.items():
            if self.is_team_game:
                if win_team is None:
                    victory, defeated, deuce = 0, 0, 1
                elif p.team_id == win_team:
                    victory, defeated, deuce = 1, 0, 0
                else:
                    victory, defeated, deuce = 0, 1, 0
            else:
                if win_role is None:
                    victory, defeated, deuce = 0, 0, 1
                elif p.role_id == win_role:
                    victory, defeated, deuce = 1, 0, 0
                else:
                    victory, defeated, deuce = 0, 1, 0

            # CSO-style Honor (XP) and GP reward calculation
            honor_gain = (
                50
                + p.kills * 15
                + p.headshots * 5
                + p.knife_kills * 10
                + victory * 50
                + deuce * 20
            )
            gp_gain = (
                200
                + p.kills * 30
                + p.headshots * 15
                + p.knife_kills * 20
                + victory * 100
                + deuce * 50
            )

            per_player[rid] = {
                "role_id": p.role_id,
                "name": p.name,
                "team_id": p.team_id,
                "kills": p.kills,
                "deaths": p.deaths,
                "headshots": p.headshots,
                "head_kills": p.headshots,
                "knife_kills": p.knife_kills,
                "special_kills": p.special_kills,
                "victory": victory,
                "defeated": defeated,
                "deuce": deuce,
                "honor_gain": honor_gain,
                "gp_gain": gp_gain,
            }

        return {
            "map_id": self.map_id,
            "map_name": self.map_name,
            "game_mode": self.game_mode,
            "team_scores": [self.team_scores[0], self.team_scores[1]],
            "blue_score": self.team_scores[0],
            "red_score": self.team_scores[1],
            "winner_team": win_team,
            "winner_role_id": win_role,
            "elapsed_seconds": int(self.elapsed_seconds),
            "end_reason": self.end_reason or ("completed" if self.match_ended else "in_progress"),
            "players": per_player,
        }


__all__ = [
    "HITBOX_CHEST",
    "HITBOX_STOMACH",
    "HITBOX_HEAD",
    "HITBOX_LEGS",
    "HITBOX_MULTIPLIER",
    "MELEE_HITBOX_MULTIPLIER",
    "DEFAULT_WEAPON_STATS",
    "WeaponStats",
    "WeaponDatabase",
    "get_default_weapon_db",
    "PlayerState",
    "HitResult",
    "KillEvent",
    "MoveResult",
    "MatchWorld",
    "rotator_to_unit_vector",
    "vector_to_rotator",
    "ray_intersect_vertical_cylinder",
]

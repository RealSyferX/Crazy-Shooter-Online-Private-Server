"""UE2.5 `.ut2` Map Spawn Loader for CSO Malaysia.

Parses real shipped `C:\\Program Files (x86)\\CSO Malaysia\\Maps\\<MapName>.ut2`
files (KFXArchive 50-byte header + XOR 0x9D, or plain UE2 0x9E2A83C1) to extract
actual `PlayerStart` actor spawn points:
- `Location`: `(x, y, z)` floats
- `Rotation`: `(pitch, yaw, roll)` ints (UE2 16-bit rotator units, 0..65535)
- `TeamNumber`: `0` (Blue), `1` (Red), `255` (DM/FFA/Any)
- `bEnabled`: bool (defaults to True)

Every `PlayerStart` export in CSO Malaysia maps has `RF_HasStack (0x02000000)`
set, so `FStateFrame` is skipped before reading UE2 tagged properties (handling
`BoolProperty` with `size_code == 5` as found in `DF-ShuangShiZhenJieDao.ut2`).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .packagemap import (
    DEFAULT_GAME_DIR,
    RF_HAS_STACK,
    UE2Package,
    load_ue2_package,
    read_tagged_properties,
)

# Sensible non-overlapping fallback spawns if a map file is missing or lacks valid spawns
DEFAULT_FALLBACK_BLUE_SPAWNS: Tuple[Tuple[Tuple[float, float, float], Tuple[int, int, int]], ...] = (
    ((-512.0, -256.0, 64.0), (0, 0, 0)),
    ((-512.0, 0.0, 64.0), (0, 0, 0)),
    ((-512.0, 256.0, 64.0), (0, 0, 0)),
    ((-640.0, -128.0, 64.0), (0, 0, 0)),
    ((-640.0, 128.0, 64.0), (0, 0, 0)),
    ((-768.0, -256.0, 64.0), (0, 0, 0)),
    ((-768.0, 0.0, 64.0), (0, 0, 0)),
    ((-768.0, 256.0, 64.0), (0, 0, 0)),
)

DEFAULT_FALLBACK_RED_SPAWNS: Tuple[Tuple[Tuple[float, float, float], Tuple[int, int, int]], ...] = (
    ((512.0, -256.0, 64.0), (0, 32768, 0)),
    ((512.0, 0.0, 64.0), (0, 32768, 0)),
    ((512.0, 256.0, 64.0), (0, 32768, 0)),
    ((640.0, -128.0, 64.0), (0, 32768, 0)),
    ((640.0, 128.0, 64.0), (0, 32768, 0)),
    ((768.0, -256.0, 64.0), (0, 32768, 0)),
    ((768.0, 0.0, 64.0), (0, 32768, 0)),
    ((768.0, 256.0, 64.0), (0, 32768, 0)),
)


@dataclass(frozen=True)
class SpawnPoint:
    """Single parsed PlayerStart actor from a `.ut2` map."""

    name: str
    location: Tuple[float, float, float]
    rotation: Tuple[int, int, int] = (0, 0, 0)  # (Pitch, Yaw, Roll) in UE2 units
    team_number: int = 0  # 0=Blue, 1=Red, 255=DM/Any
    enabled: bool = True
    class_name: str = "PlayerStart"

    @property
    def x(self) -> float:
        return self.location[0]

    @property
    def y(self) -> float:
        return self.location[1]

    @property
    def z(self) -> float:
        return self.location[2]

    @property
    def pitch(self) -> int:
        return self.rotation[0]

    @property
    def yaw(self) -> int:
        return self.rotation[1]

    @property
    def roll(self) -> int:
        return self.rotation[2]


@dataclass
class MapSpawnData:
    """All spawn points extracted from a `.ut2` map."""

    map_name: str
    map_path: str
    spawns: List[SpawnPoint] = field(default_factory=list)
    blue_spawns: List[SpawnPoint] = field(default_factory=list)
    red_spawns: List[SpawnPoint] = field(default_factory=list)
    dm_spawns: List[SpawnPoint] = field(default_factory=list)
    used_fallback: bool = False

    def get_spawns_for_team(self, team_id: int) -> List[SpawnPoint]:
        """Return enabled spawn list for team_id (0=Blue, 1=Red, other=DM/Any)."""
        if team_id == 0:
            if self.blue_spawns:
                return self.blue_spawns
            if self.dm_spawns:
                return self.dm_spawns
            return self.spawns
        if team_id == 1:
            if self.red_spawns:
                return self.red_spawns
            if self.dm_spawns:
                return self.dm_spawns
            return self.spawns
        # Deathmatch / Free-for-all / spectator
        if self.dm_spawns:
            return self.dm_spawns
        return self.spawns

    def pick_spawn(self, team_id: int = 0, index: int = 0) -> SpawnPoint:
        """Deterministically pick a spawn point for team_id using round-robin index."""
        pool = self.get_spawns_for_team(team_id)
        if not pool:
            return SpawnPoint(
                name="FallbackSpawn",
                location=(0.0, 0.0, 64.0),
                rotation=(0, 0, 0),
                team_number=team_id,
            )
        return pool[index % len(pool)]


def _build_fallback_spawns(map_name: str, map_path: str) -> MapSpawnData:
    blue = [
        SpawnPoint(name=f"FallbackBlue{i}", location=loc, rotation=rot, team_number=0)
        for i, (loc, rot) in enumerate(DEFAULT_FALLBACK_BLUE_SPAWNS)
    ]
    red = [
        SpawnPoint(name=f"FallbackRed{i}", location=loc, rotation=rot, team_number=1)
        for i, (loc, rot) in enumerate(DEFAULT_FALLBACK_RED_SPAWNS)
    ]
    all_spawns = blue + red
    return MapSpawnData(
        map_name=map_name,
        map_path=map_path,
        spawns=all_spawns,
        blue_spawns=blue,
        red_spawns=red,
        dm_spawns=list(all_spawns),
        used_fallback=True,
    )


def resolve_map_path(map_name: str, game_dir: str = DEFAULT_GAME_DIR) -> str:
    """Resolve a map name or filename to its absolute `.ut2` path."""
    if os.path.isfile(map_name):
        return os.path.abspath(map_name)

    stem = os.path.splitext(os.path.basename(map_name))[0]
    maps_dir = os.path.join(game_dir, "Maps")
    direct = os.path.join(maps_dir, f"{stem}.ut2")
    if os.path.isfile(direct):
        return os.path.abspath(direct)

    # Case-insensitive fallback scan
    if os.path.isdir(maps_dir):
        target = f"{stem}.ut2".lower()
        for fn in os.listdir(maps_dir):
            if fn.lower() == target:
                return os.path.abspath(os.path.join(maps_dir, fn))

    return os.path.abspath(direct)


def parse_map_spawns_from_package(pkg: UE2Package) -> MapSpawnData:
    """Extract all `PlayerStart` actors from an already-loaded `.ut2` UE2Package."""
    spawns: List[SpawnPoint] = []
    for exp in pkg.exports:
        cls_name = pkg.get_object_name(exp.class_index)
        if "playerstart" not in cls_name.lower():
            continue
        if exp.serial_size <= 0:
            continue

        has_stack = bool(exp.object_flags & RF_HAS_STACK)
        props, _ = read_tagged_properties(
            pkg.data,
            pkg.names,
            exp.serial_offset,
            exp.serial_offset + exp.serial_size,
            has_stack=has_stack,
        )

        loc = props.get("Location")
        if not (isinstance(loc, tuple) and len(loc) == 3):
            continue

        rot_raw = props.get("Rotation")
        if isinstance(rot_raw, tuple) and len(rot_raw) == 3:
            rot = (
                int(rot_raw[0]) & 0xFFFF,
                int(rot_raw[1]) & 0xFFFF,
                int(rot_raw[2]) & 0xFFFF,
            )
        else:
            rot = (0, 0, 0)

        team_raw = props.get("TeamNumber", 0)
        team_num = int(team_raw) if isinstance(team_raw, (int, float)) else 0
        enabled = bool(props.get("bEnabled", True))

        spawns.append(
            SpawnPoint(
                name=exp.object_name,
                location=(float(loc[0]), float(loc[1]), float(loc[2])),
                rotation=rot,
                team_number=team_num,
                enabled=enabled,
                class_name=cls_name,
            )
        )

    enabled_spawns = [s for s in spawns if s.enabled] or spawns
    if not enabled_spawns:
        return _build_fallback_spawns(pkg.name, pkg.path)

    blue = [s for s in enabled_spawns if s.team_number == 0]
    red = [s for s in enabled_spawns if s.team_number == 1]
    dm = [s for s in enabled_spawns if s.team_number not in (0, 1)]

    # For DM-only maps (e.g. DM-FeiQiGongChang where all spawns have TeamNumber=255),
    # split DM spawns cleanly into Blue/Red halves so team modes still get separated spawns.
    if not blue and not red and dm:
        half = max(1, len(dm) // 2)
        blue = list(dm[:half])
        red = list(dm[half:]) or list(dm)
    elif not blue:
        blue = list(dm) if dm else list(enabled_spawns)
    elif not red:
        red = list(dm) if dm else list(enabled_spawns)

    if not dm:
        dm = list(enabled_spawns)

    return MapSpawnData(
        map_name=pkg.name,
        map_path=pkg.path,
        spawns=enabled_spawns,
        blue_spawns=blue,
        red_spawns=red,
        dm_spawns=dm,
        used_fallback=False,
    )


class MapLoader:
    """Cached loader for `.ut2` map spawn points."""

    def __init__(self, game_dir: str = DEFAULT_GAME_DIR) -> None:
        self.game_dir = os.path.abspath(game_dir)
        self._cache: Dict[str, MapSpawnData] = {}

    def load(self, map_name: str) -> MapSpawnData:
        key = os.path.splitext(os.path.basename(map_name))[0].lower()
        cached = self._cache.get(key)
        if cached is not None:
            return cached

        map_path = resolve_map_path(map_name, self.game_dir)
        if not os.path.isfile(map_path):
            data = _build_fallback_spawns(
                os.path.splitext(os.path.basename(map_name))[0], map_path
            )
            self._cache[key] = data
            return data

        try:
            pkg = load_ue2_package(map_path)
            data = parse_map_spawns_from_package(pkg)
        except Exception:
            data = _build_fallback_spawns(
                os.path.splitext(os.path.basename(map_name))[0], map_path
            )

        self._cache[key] = data
        return data

    def get_spawn_point(
        self, map_name: str, team_id: int = 0, index: int = 0
    ) -> SpawnPoint:
        return self.load(map_name).pick_spawn(team_id=team_id, index=index)

    def get_team_spawns(self, map_name: str, team_id: int = 0) -> List[SpawnPoint]:
        return self.load(map_name).get_spawns_for_team(team_id)


_DEFAULT_LOADER: Optional[MapLoader] = None


def get_default_map_loader(game_dir: str = DEFAULT_GAME_DIR) -> MapLoader:
    global _DEFAULT_LOADER
    if _DEFAULT_LOADER is None or _DEFAULT_LOADER.game_dir != os.path.abspath(game_dir):
        _DEFAULT_LOADER = MapLoader(game_dir=game_dir)
    return _DEFAULT_LOADER


def load_map_spawns(
    map_name: str, game_dir: str = DEFAULT_GAME_DIR
) -> MapSpawnData:
    """Load and cache `PlayerStart` spawn points from `<MapName>.ut2`."""
    return get_default_map_loader(game_dir).load(map_name)


def get_spawn_point(
    map_name: str,
    team_id: int = 0,
    index: int = 0,
    game_dir: str = DEFAULT_GAME_DIR,
) -> SpawnPoint:
    """Return a real `PlayerStart` spawn point for `(map_name, team_id, index)`."""
    return get_default_map_loader(game_dir).get_spawn_point(
        map_name, team_id=team_id, index=index
    )

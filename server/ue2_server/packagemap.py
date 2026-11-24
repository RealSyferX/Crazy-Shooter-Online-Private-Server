"""UE2.5 PackageMap (FPackageMapLevel) and FClassNetCache for CSO Malaysia.

Binary-verified against retail Core.dll, Engine.dll, CS.ini, and shipped
KFXArchive .u/.ut2/.utx/.uax/.usx/.ukx packages (PackageVersion=129,
LicenseeMode=29, EngineVersion=3369):
- KFXArchive files start with a 50-byte header (`KFXArchive...`) followed by
  the UE2 package payload XOR'd with 0x9D.
- UPackageMap::AddLinker skips packages with PKG_ClientOptional (0x00000004)
  such as IpDrv.u (flags=0x5), and recurses over ImportMap entries with
  ClassName=='Package' and PackageIndex==0.
- UPackageMap::Compute assigns sequential ObjectBase/NameBase across List[].
  First package owning a name wins its NameIndex; MaxNameIndex encodes NAME_None.
- UPackageMapLevel::SerializeObject writes 1-bit bIsDynamic:
    1 -> WriteInt(ChIndex, 1023)  (0 = None, 1..1022 = open Actor channel)
    0 -> WriteInt(ObjectIndex, MaxObjectIndex)  (static package export)
- FClassNetCache collects each class's own Children->Next CPF_Net (0x20)
  properties and FUNC_Net (0x40) root functions (SuperField == 0), sorted
  ascending by 0-based linker ExportIndex, stacked on SuperCache.MaxIndex.
"""

from __future__ import annotations

import math
import os
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

# ---------------------------------------------------------------------------
# Constants (binary-verified from Core.dll & Engine.dll)
# ---------------------------------------------------------------------------

KFX_ARCHIVE_MAGIC = b"KFXArchive"
KFX_HEADER_SIZE = 50
KFX_XOR_KEY = 0x9D
_KFX_XOR_TABLE = bytes(i ^ KFX_XOR_KEY for i in range(256))

UE2_PACKAGE_SIGNATURE = 0x9E2A83C1

PKG_ALLOW_DOWNLOAD = 0x00000001
PKG_CLIENT_OPTIONAL = 0x00000004

RF_HAS_STACK = 0x02000000

CPF_OPTIONAL_PARM = 0x00000010
CPF_NET = 0x00000020
CPF_PARM = 0x00000080
CPF_OUT_PARM = 0x00000100
CPF_RETURN_PARM = 0x00000400

FUNC_NET = 0x00000040
FUNC_NET_RELIABLE = 0x00000080
FUNC_SIMULATED = 0x00000100
FUNC_EXEC = 0x00000200
FUNC_NATIVE = 0x00000400
FUNC_EVENT = 0x00000800
FUNC_ACCESS_MASK = 0x000E0000  # Public | Private | Protected

MAX_CHANNELS = 1023

DEFAULT_GAME_DIR = r"C:\Program Files (x86)\CSO Malaysia"

# Exact order from System\CS.ini [Engine.GameEngine] ServerPackages=
DEFAULT_SERVER_PACKAGES: Tuple[str, ...] = (
    "Core",
    "Engine",
    "Fire",
    "Editor",
    "IpDrv",  # Skipped by PKG_ClientOptional (0x4), kept for CS.ini parity
    "GamePlay",
    "KFXEffects",
    "KFXNAEffects",
    "KFXGame",
    "KFXWeapons",
)

PACKAGE_SEARCH_SUBDIRS: Tuple[Tuple[str, str], ...] = (
    ("System", ".u"),
    ("Maps", ".ut2"),
    ("Textures", ".utx"),
    ("Sounds", ".uax"),
    ("Music", ".umx"),
    ("StaticMeshes", ".usx"),
    ("Animations", ".ukx"),
    ("Saves", ".uvx"),
)

# Friendly aliases for callers using generic names
CLASS_ALIASES: Dict[str, str] = {
    "kfxplayercontroller": "KFXPlayer",
    "kfxgame.kfxplayercontroller": "KFXGame.KFXPlayer",
    "kfxweapon": "KFXWeapBase",
    "kfxweapons.kfxweapon": "KFXGame.KFXWeapBase",
    "kfxgame.kfxweapon": "KFXGame.KFXWeapBase",
}

# Standard classes pre-built on request
STANDARD_NET_CLASSES: Tuple[str, ...] = (
    "Engine.Actor",
    "Engine.Info",
    "Engine.ReplicationInfo",
    "Engine.GameReplicationInfo",
    "KFXGame.KFXGameReplicationInfo",
    "KFXGame.KFXMeleeGameReplicationInfo",
    "KFXGame.KFXSingleGameReplicationInfo",
    "KFXGame.KFXRoundGameReplicationInfo",
    "KFXGame.KFXBombGameReplicationInfo",
    "KFXGame.KFXOccupyGameReplicationInfo",
    "Engine.TeamInfo",
    "KFXGame.KFXTeamInfo",
    "Engine.PlayerReplicationInfo",
    "KFXGame.KFXPlayerReplicationInfo",
    "KFXGame.KFXMeleePlayerReplicationInfo",
    "KFXGame.KFXSinglePlayerReplicationInfo",
    "KFXGame.KFXRoundPlayerReplicationInfo",
    "KFXGame.KFXBombPlayerReplicationInfo",
    "KFXGame.KFXOccupyPlayerReplicationInfo",
    "Engine.Controller",
    "Engine.PlayerController",
    "KFXGame.KFXPlayerBase",
    "KFXGame.KFXPlayer",
    "KFXGame.KFXMeleePlayer",
    "KFXGame.KFXSinglePlayer",
    "KFXGame.KFXRoundPlayer",
    "KFXGame.KFXBombPlayer",
    "KFXGame.KFXOccupyPlayer",
    "Engine.Pawn",
    "KFXGame.KFXPawnBase",
    "KFXGame.KFXPawn",
    "Engine.Inventory",
    "Engine.Ammunition",
    "Engine.Weapon",
    "KFXGame.KFXWeapBase",
    "KFXWeapons.KFXWeapRifle",
    "KFXWeapons.KFXWeapSniper",
    "KFXWeapons.KFXWeapPistal",
    "KFXWeapons.KFXWeapMelee",
    "KFXWeapons.KFXWeapToss",
    "KFXWeapons.KFXWeapCFour",
    "KFXWeapons.KFXWeapMachinegun",
    "KFXWeapons.KFXWeapGreenMG",
    "KFXWeapons.KFXWeapRocket",
    "Engine.WeaponAttachment",
    "KFXGame.KFXWeapAttachment",
)

# Property class names in UE2 packages
PROPERTY_CLASS_NAMES = frozenset({
    "ByteProperty",
    "IntProperty",
    "BoolProperty",
    "FloatProperty",
    "ObjectProperty",
    "NameProperty",
    "DelegateProperty",
    "ClassProperty",
    "ArrayProperty",
    "StructProperty",
    "VectorProperty",
    "RotatorProperty",
    "StrProperty",
    "MapProperty",
    "FixedArrayProperty",
})


# ---------------------------------------------------------------------------
# Low-level UE2 / KFXArchive binary helpers
# ---------------------------------------------------------------------------

def decode_kfx_archive(raw: bytes) -> Tuple[bytes, bool]:
    """Decode a KFXArchive (50B header + XOR 0x9D) or return plain UE2 bytes."""
    if len(raw) >= KFX_HEADER_SIZE and raw[:10] == KFX_ARCHIVE_MAGIC:
        return raw[KFX_HEADER_SIZE:].translate(_KFX_XOR_TABLE), True
    return raw, False


def read_compact_index(data: bytes, pos: int) -> Tuple[int, int]:
    """Decode a UE2 FCompactIndex (AR_INDEX) signed varint."""
    b0 = data[pos]
    pos += 1
    neg = b0 & 0x80
    val = b0 & 0x3F
    if b0 & 0x40:
        b1 = data[pos]
        pos += 1
        val |= (b1 & 0x7F) << 6
        if b1 & 0x80:
            b2 = data[pos]
            pos += 1
            val |= (b2 & 0x7F) << 13
            if b2 & 0x80:
                b3 = data[pos]
                pos += 1
                val |= (b3 & 0x7F) << 20
                if b3 & 0x80:
                    b4 = data[pos]
                    pos += 1
                    val |= b4 << 27
    return (-val if neg else val), pos


def encode_compact_index(val: int) -> bytes:
    """Encode a signed integer as a UE2 FCompactIndex (for searching/testing)."""
    neg = val < 0
    v = -val if neg else val
    out = bytearray()
    b0 = (v & 0x3F) | (0x80 if neg else 0) | (0x40 if v >= 0x40 else 0)
    out.append(b0)
    v >>= 6
    while v > 0:
        b = (v & 0x7F) | (0x80 if v >= 0x80 else 0)
        out.append(b)
        v >>= 7
    return bytes(out)


def read_fstring(data: bytes, pos: int) -> Tuple[str, int]:
    """Decode a UE2 FString (FCompactIndex length + Latin-1 or UTF-16LE + NUL)."""
    length, pos = read_compact_index(data, pos)
    if length == 0:
        return "", pos
    if length > 0:
        raw = data[pos : pos + length]
        pos += length
        return raw.rstrip(b"\x00").decode("latin-1", errors="replace"), pos
    n = -length
    raw = data[pos : pos + n * 2]
    pos += n * 2
    return raw.decode("utf-16-le", errors="replace").rstrip("\x00"), pos


def enum_bit_width(num_values: int) -> int:
    """Exact UByteProperty::NetSerializeItem bit count: ceil(log2(Num))."""
    if num_values <= 1:
        return 1
    return int(math.ceil(math.log2(num_values)))


def read_tagged_properties(
    data: bytes,
    names: Sequence[str],
    start_pos: int,
    end_pos: int,
    has_stack: bool = False,
) -> Tuple[Dict[str, Any], int]:
    """Parse UE2 FPropertyTag stream (optionally skipping RF_HasStack FStateFrame).

    Returns (properties_dict, end_offset_after_None_terminator).
    Note: Size MUST be read before handling BoolProperty, because UnrealEd can
    emit BoolProperty with size_code == 5 followed by a 0x00 size byte!
    """
    pos = start_pos
    if has_stack and pos < end_pos:
        node, pos = read_compact_index(data, pos)
        _state_node, pos = read_compact_index(data, pos)
        pos += 8  # ProbeMask (uint64)
        pos += 4  # LatentAction (int32)
        if node != 0:
            _offset, pos = read_compact_index(data, pos)

    props: Dict[str, Any] = {}
    size_table = (1, 2, 4, 12, 16)

    while pos < end_pos:
        name_idx, pos = read_compact_index(data, pos)
        if name_idx < 0 or name_idx >= len(names):
            break
        prop_name = names[name_idx]
        if prop_name == "None":
            break
        if pos >= end_pos:
            break

        info = data[pos]
        pos += 1
        ptype = info & 0x0F
        size_code = (info >> 4) & 0x07
        array_flag = (info >> 7) & 1

        struct_name: Optional[str] = None
        if ptype == 10:  # StructProperty
            sn_idx, pos = read_compact_index(data, pos)
            if 0 <= sn_idx < len(names):
                struct_name = names[sn_idx]

        # Read property byte size (ALWAYS present before BoolProperty check!)
        if size_code < 5:
            size = size_table[size_code]
        elif size_code == 5:
            size = data[pos]
            pos += 1
        elif size_code == 6:
            size = struct.unpack_from("<H", data, pos)[0]
            pos += 2
        else:
            size = struct.unpack_from("<I", data, pos)[0]
            pos += 4

        arr_idx = 0
        if array_flag and ptype != 3:
            b = data[pos]
            pos += 1
            if b < 0x80:
                arr_idx = b
            elif b < 0xC0:
                b2 = data[pos]
                pos += 1
                arr_idx = ((b & 0x3F) << 8) | b2
            else:
                b2, b3, b4 = data[pos], data[pos + 1], data[pos + 2]
                pos += 3
                arr_idx = ((b & 0x3F) << 24) | (b2 << 16) | (b3 << 8) | b4

        key = prop_name if arr_idx == 0 else f"{prop_name}[{arr_idx}]"

        if ptype == 3:  # BoolProperty: value lives in array_flag, 0 payload bytes
            props[key] = bool(array_flag)
            continue

        val_bytes = data[pos : pos + size]
        pos += size

        if ptype == 1:  # ByteProperty
            val: Any = val_bytes[0] if len(val_bytes) >= 1 else 0
        elif ptype == 2 and len(val_bytes) == 4:  # IntProperty
            val = struct.unpack("<i", val_bytes)[0]
        elif ptype == 4 and len(val_bytes) == 4:  # FloatProperty
            val = struct.unpack("<f", val_bytes)[0]
        elif ptype == 5:  # ObjectProperty
            val, _ = read_compact_index(val_bytes, 0) if val_bytes else (0, 0)
        elif ptype == 6:  # NameProperty
            ni, _ = read_compact_index(val_bytes, 0) if val_bytes else (0, 0)
            val = names[ni] if 0 <= ni < len(names) else ""
        elif ptype == 10 and struct_name == "Vector" and len(val_bytes) == 12:
            val = struct.unpack("<3f", val_bytes)
        elif ptype == 10 and struct_name == "Rotator" and len(val_bytes) == 12:
            val = struct.unpack("<3i", val_bytes)
        elif ptype == 13 and val_bytes:  # StrProperty
            val, _ = read_fstring(val_bytes, 0)
        else:
            val = val_bytes

        props[key] = val

    return props, pos


# ---------------------------------------------------------------------------
# Package & NetCache data structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PackageGeneration:
    export_count: int
    name_count: int


@dataclass(frozen=True)
class PackageImport:
    class_package: str
    class_name: str
    package_index: int
    object_name: str


@dataclass(frozen=True)
class PackageExport:
    index: int          # 0-based linker ExportIndex
    class_index: int    # 0=UClass, >0=Export(i-1), <0=Import(-i-1)
    super_index: int
    package_index: int  # Outer (0=root package, >0=Export(i-1))
    object_name: str
    object_flags: int
    serial_size: int
    serial_offset: int


class UE2Package:
    """Parsed UE2.5 package (.u, .ut2, .utx, .uax, .usx, .ukx)."""

    def __init__(self, path: str) -> None:
        self.path = os.path.abspath(path)
        self.filename = os.path.basename(self.path)
        self.name = os.path.splitext(self.filename)[0]

        with open(self.path, "rb") as f:
            raw = f.read()

        data, self.is_kfx = decode_kfx_archive(raw)
        self.data = data
        self.total_size = len(data)

        if len(data) < 56:
            raise ValueError(f"Package too small ({len(data)} bytes): {self.path}")

        (
            sig,
            self.version,
            self.licensee,
            self.package_flags,
            name_count,
            name_offset,
            export_count,
            export_offset,
            import_count,
            import_offset,
        ) = struct.unpack_from("<IHHIIIIIII", data, 0)

        if sig != UE2_PACKAGE_SIGNATURE:
            raise ValueError(
                f"Invalid UE2 package signature {sig:#x} in {self.path}"
            )

        guid_parts = struct.unpack_from("<4I", data, 36)
        self.guid_tuple: Tuple[int, int, int, int] = guid_parts
        self.guid: str = "".join(f"{g:08X}" for g in guid_parts)

        gen_count = struct.unpack_from("<I", data, 52)[0]
        self.generations: List[PackageGeneration] = [
            PackageGeneration(*struct.unpack_from("<II", data, 56 + i * 8))
            for i in range(gen_count)
        ]

        # Parse NameTable
        self.names: List[str] = []
        self.name_to_local_index: Dict[str, int] = {}
        pos = name_offset
        for idx in range(name_count):
            s, pos = read_fstring(data, pos)
            pos += 4  # NameFlags
            self.names.append(s)
            low = s.lower()
            if low not in self.name_to_local_index:
                self.name_to_local_index[low] = idx

        # Parse ImportTable
        self.imports: List[PackageImport] = []
        pos = import_offset
        for _ in range(import_count):
            cp_idx, pos = read_compact_index(data, pos)
            cn_idx, pos = read_compact_index(data, pos)
            pkg_idx = struct.unpack_from("<i", data, pos)[0]
            pos += 4
            on_idx, pos = read_compact_index(data, pos)
            self.imports.append(
                PackageImport(
                    class_package=self.names[cp_idx],
                    class_name=self.names[cn_idx],
                    package_index=pkg_idx,
                    object_name=self.names[on_idx],
                )
            )

        # Parse ExportTable
        self.exports: List[PackageExport] = []
        pos = export_offset
        for ei in range(export_count):
            cls_idx, pos = read_compact_index(data, pos)
            sup_idx, pos = read_compact_index(data, pos)
            pkg_idx = struct.unpack_from("<i", data, pos)[0]
            pos += 4
            on_idx, pos = read_compact_index(data, pos)
            obj_flags = struct.unpack_from("<I", data, pos)[0]
            pos += 4
            ser_size, pos = read_compact_index(data, pos)
            ser_off = 0
            if ser_size > 0:
                ser_off, pos = read_compact_index(data, pos)
            self.exports.append(
                PackageExport(
                    index=ei,
                    class_index=cls_idx,
                    super_index=sup_idx,
                    package_index=pkg_idx,
                    object_name=self.names[on_idx],
                    object_flags=obj_flags,
                    serial_size=ser_size,
                    serial_offset=ser_off,
                )
            )

        # Lazy lookup indexes
        self._full_names: Optional[List[str]] = None
        self._by_full_name: Optional[Dict[str, int]] = None
        self._top_level_by_name: Optional[Dict[str, int]] = None
        self._classes_by_name: Optional[Dict[str, int]] = None

    @property
    def export_count(self) -> int:
        return len(self.exports)

    @property
    def name_count(self) -> int:
        return len(self.names)

    @property
    def is_client_optional(self) -> bool:
        return bool(self.package_flags & PKG_CLIENT_OPTIONAL)

    def uses_line(self, remote_gen: Optional[int] = None) -> str:
        """Exact Engine.dll UNetConnection::SendPackageMap USES line."""
        gen = remote_gen if remote_gen is not None else len(self.generations)
        return (
            f"USES GUID={self.guid} PKG={self.name} FLAGS={self.package_flags} "
            f"SIZE={self.total_size} GEN={gen} FNAME={self.filename}"
        )

    def dependency_packages(self) -> List[str]:
        """Direct imported packages (ImportMap ClassName=='Package' & PackageIndex==0)."""
        deps: List[str] = []
        seen: set[str] = set()
        for imp in self.imports:
            if imp.class_name == "Package" and imp.package_index == 0:
                low = imp.object_name.lower()
                if low not in seen:
                    seen.add(low)
                    deps.append(imp.object_name)
        return deps

    def get_object_name(self, index: int) -> str:
        """Resolve an export (>0) or import (<0) object name (0 => 'Class')."""
        if index == 0:
            return "Class"
        if index > 0:
            return self.exports[index - 1].object_name
        return self.imports[-index - 1].object_name

    def get_export_class_name(self, export_index: int) -> str:
        return self.get_object_name(self.exports[export_index].class_index)

    def _ensure_indexes(self) -> None:
        if self._full_names is not None:
            return
        full_names: List[str] = []
        by_full: Dict[str, int] = {}
        top_by_name: Dict[str, int] = {}
        cls_by_name: Dict[str, int] = {}

        for ei, exp in enumerate(self.exports):
            parts = [exp.object_name]
            outer = exp.package_index
            while outer > 0:
                oexp = self.exports[outer - 1]
                parts.append(oexp.object_name)
                outer = oexp.package_index
            parts.append(self.name)
            parts.reverse()
            full = ".".join(parts)
            full_names.append(full)

            low_full = full.lower()
            if low_full not in by_full:
                by_full[low_full] = ei
            if exp.package_index == 0:
                low_name = exp.object_name.lower()
                if low_name not in top_by_name:
                    top_by_name[low_name] = ei
            if exp.class_index == 0:
                cls_by_name[exp.object_name.lower()] = ei

        self._full_names = full_names
        self._by_full_name = by_full
        self._top_level_by_name = top_by_name
        self._classes_by_name = cls_by_name

    def get_full_name(self, export_index: int) -> str:
        self._ensure_indexes()
        assert self._full_names is not None
        return self._full_names[export_index]

    def find_export_by_full_name(self, full_name: str) -> Optional[int]:
        self._ensure_indexes()
        assert self._by_full_name is not None
        return self._by_full_name.get(full_name.lower())

    def find_class_export(self, class_name: str) -> Optional[int]:
        self._ensure_indexes()
        assert self._classes_by_name is not None
        return self._classes_by_name.get(class_name.lower())

    def find_top_export(self, object_name: str) -> Optional[int]:
        self._ensure_indexes()
        assert self._top_level_by_name is not None
        return self._top_level_by_name.get(object_name.lower())

    def find_export_chain(self, chain: Sequence[str]) -> Optional[int]:
        """Find export matching outer-to-inner path within this package."""
        self._ensure_indexes()
        assert self._by_full_name is not None
        key = ".".join([self.name.lower(), *(c.lower() for c in chain)])
        ei = self._by_full_name.get(key)
        if ei is None and len(chain) == 1:
            assert self._top_level_by_name is not None
            ei = self._top_level_by_name.get(chain[0].lower())
        return ei

    def find_export(
        self,
        name: str,
        class_name: Optional[str] = None,
        outer_name: Optional[str] = None,
    ) -> Optional[int]:
        """Flexible export lookup by name + optional class_name / outer_name."""
        target = name.lower()
        cls_target = class_name.lower() if class_name else None
        out_target = outer_name.lower() if outer_name else None
        for ei, exp in enumerate(self.exports):
            if exp.object_name.lower() != target:
                continue
            if cls_target is not None:
                if self.get_object_name(exp.class_index).lower() != cls_target:
                    continue
            if out_target is not None:
                o = (
                    self.exports[exp.package_index - 1].object_name.lower()
                    if exp.package_index > 0
                    else self.name.lower()
                )
                if o != out_target:
                    continue
            return ei
        return None


@dataclass
class PackageInfo:
    """Matches Core.dll FPackageInfo entry inside UPackageMap::List."""

    package: UE2Package
    object_base: int = 0
    object_count: int = 0
    name_base: int = 0
    name_count: int = 0
    remote_generation: int = 1

    @property
    def name(self) -> str:
        return self.package.name

    @property
    def guid(self) -> str:
        return self.package.guid

    def uses_line(self) -> str:
        return self.package.uses_line(self.remote_generation)


@dataclass(frozen=True)
class StructFieldInfo:
    """Single field inside a non-native replicated UStruct."""

    name: str
    prop_type: str
    array_dim: int = 1
    enum_name: Optional[str] = None
    enum_bits: int = 8
    struct_name: Optional[str] = None
    object_class: Optional[str] = None
    meta_class: Optional[str] = None


@dataclass(frozen=True)
class RpcParamInfo:
    """Single parameter of a FUNC_Net RPC function."""

    name: str
    prop_type: str
    optional: bool = False
    out_parm: bool = False
    array_dim: int = 1
    enum_name: Optional[str] = None
    enum_bits: int = 8
    struct_name: Optional[str] = None
    object_class: Optional[str] = None
    meta_class: Optional[str] = None


@dataclass
class NetFieldEntry:
    """Matches FFieldNetCache entry inside FClassNetCache."""

    rep_index: int
    name: str
    kind: str  # "property" or "function"
    owner_class: str
    package_name: str
    export_index: int
    object_index: int
    rep_offset: int = 0

    # Property metadata
    prop_type: str = ""
    array_dim: int = 1
    enum_name: Optional[str] = None
    enum_bits: int = 8
    struct_name: Optional[str] = None
    struct_fields: List[StructFieldInfo] = field(default_factory=list)
    object_class: Optional[str] = None
    meta_class: Optional[str] = None

    # Function metadata
    function_flags: int = 0
    params: List[RpcParamInfo] = field(default_factory=list)

    @property
    def is_property(self) -> bool:
        return self.kind == "property"

    @property
    def is_function(self) -> bool:
        return self.kind == "function"

    @property
    def is_reliable(self) -> bool:
        return bool(self.function_flags & FUNC_NET_RELIABLE)

    @property
    def is_simulated(self) -> bool:
        return bool(self.function_flags & FUNC_SIMULATED)

    @property
    def is_event(self) -> bool:
        return bool(self.function_flags & FUNC_EVENT)


@dataclass
class ClassNetCache:
    """Matches Core.dll FClassNetCache for a UClass."""

    class_name: str
    package_name: str
    full_name: str
    class_object_index: int
    super_name: Optional[str]
    super_cache: Optional["ClassNetCache"]
    fields_base: int
    max_index: int
    b_net_initial_rotation: bool
    own_fields: List[NetFieldEntry] = field(default_factory=list)
    all_fields: List[NetFieldEntry] = field(default_factory=list)
    by_index: Dict[int, NetFieldEntry] = field(default_factory=dict)
    by_name: Dict[str, NetFieldEntry] = field(default_factory=dict)

    def get_max_index(self) -> int:
        return self.max_index

    def get_field(self, key: Union[int, str]) -> Optional[NetFieldEntry]:
        if isinstance(key, int):
            return self.by_index.get(key)
        return self.by_name.get(key.lower())

    def get_rep_index(self, field_name: str) -> int:
        entry = self.by_name.get(field_name.lower())
        if entry is None:
            raise KeyError(
                f"Field {field_name!r} not in ClassNetCache for {self.full_name}"
            )
        return entry.rep_index

    def has_field(self, field_name: str) -> bool:
        return field_name.lower() in self.by_name


# ---------------------------------------------------------------------------
# Global package file cache (avoids re-reading / re-XORing .u files per match)
# ---------------------------------------------------------------------------

_PACKAGE_INDEX_CACHE: Dict[str, Dict[str, str]] = {}
_PARSED_PACKAGE_CACHE: Dict[str, UE2Package] = {}


def discover_package_files(game_dir: str = DEFAULT_GAME_DIR) -> Dict[str, str]:
    """Scan CSO Malaysia asset directories for all UE2 packages (case-insensitive stem -> path)."""
    norm_dir = os.path.abspath(game_dir)
    cached = _PACKAGE_INDEX_CACHE.get(norm_dir)
    if cached is not None:
        return cached

    found: Dict[str, str] = {}
    for subdir, ext in PACKAGE_SEARCH_SUBDIRS:
        folder = os.path.join(norm_dir, subdir)
        if not os.path.isdir(folder):
            continue
        for fname in sorted(os.listdir(folder)):
            if fname.lower().endswith(ext):
                stem = os.path.splitext(fname)[0].lower()
                if stem not in found:
                    found[stem] = os.path.join(folder, fname)

    _PACKAGE_INDEX_CACHE[norm_dir] = found
    return found


def load_ue2_package(path: str, use_cache: bool = True) -> UE2Package:
    """Load and cache a UE2Package from disk."""
    abs_path = os.path.abspath(path)
    if use_cache and abs_path in _PARSED_PACKAGE_CACHE:
        return _PARSED_PACKAGE_CACHE[abs_path]
    pkg = UE2Package(abs_path)
    if use_cache:
        _PARSED_PACKAGE_CACHE[abs_path] = pkg
    return pkg


def read_server_packages_from_ini(game_dir: str = DEFAULT_GAME_DIR) -> List[str]:
    """Read ServerPackages= entries from System\\CS.ini (or fallback to defaults)."""
    ini_path = os.path.join(game_dir, "System", "CS.ini")
    if not os.path.isfile(ini_path):
        return list(DEFAULT_SERVER_PACKAGES)
    try:
        with open(ini_path, "rb") as f:
            decoded, _ = decode_kfx_archive(f.read())
        text = decoded.decode("latin-1", errors="replace")
        pkgs: List[str] = []
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if line.startswith("ServerPackages="):
                val = line.split("=", 1)[1].strip()
                if val:
                    pkgs.append(val)
        return pkgs if pkgs else list(DEFAULT_SERVER_PACKAGES)
    except OSError:
        return list(DEFAULT_SERVER_PACKAGES)


# ---------------------------------------------------------------------------
# PackageMap (FPackageMapLevel)
# ---------------------------------------------------------------------------

class PackageMap:
    """Exact UE2.5 UPackageMap / UPackageMapLevel + FClassNetCache implementation."""

    def __init__(
        self,
        map_name: str = "DF-DiTieZhan",
        game_dir: str = DEFAULT_GAME_DIR,
        server_packages: Optional[Sequence[str]] = None,
        include_map: bool = True,
    ) -> None:
        self.game_dir = os.path.abspath(game_dir)
        self.map_name = os.path.splitext(os.path.basename(map_name))[0] if map_name else ""
        self._file_index = discover_package_files(self.game_dir)

        self.entries: List[PackageInfo] = []
        self._pkg_to_info: Dict[str, PackageInfo] = {}
        self._seen_packages: set[str] = set()

        self.max_object_index: int = 0
        self.max_name_index: int = 0
        self._name_indices: Dict[str, int] = {}  # lower(name) -> global NameIndex

        self._class_caches: Dict[str, ClassNetCache] = {}
        self._enum_bits_cache: Dict[str, int] = {}
        self._struct_fields_cache: Dict[str, List[StructFieldInfo]] = {}
        self._bnet_init_rot_cache: Dict[str, bool] = {}

        # UE2 ULevel::Listen adds the Map linker first, then ServerPackages.
        if include_map and self.map_name:
            self.add_linker(self.map_name)

        srv_pkgs = (
            list(server_packages)
            if server_packages is not None
            else read_server_packages_from_ini(self.game_dir)
        )
        for pkg_name in srv_pkgs:
            self.add_linker(pkg_name)

        self.compute()

    # ------------------------------------------------------------------
    # UPackageMap::AddLinker & UPackageMap::Compute
    # ------------------------------------------------------------------

    def add_linker(self, package_name_or_path: str) -> Optional[PackageInfo]:
        """Exact UPackageMap::AddLinker (Core.dll 0x101231c0).

        - Skips packages with PKG_ClientOptional (0x4) (e.g. IpDrv.u).
        - Appends PackageInfo to self.entries.
        - Recurses over ImportMap entries with ClassName=='Package' & PackageIndex==0.
        """
        if os.path.isfile(package_name_or_path):
            path = os.path.abspath(package_name_or_path)
            key = os.path.splitext(os.path.basename(path))[0].lower()
        else:
            key = os.path.splitext(os.path.basename(package_name_or_path))[0].lower()
            path = self._file_index.get(key)
            if path is None:
                return None

        if key in self._seen_packages:
            return self._pkg_to_info.get(key)
        self._seen_packages.add(key)

        pkg = load_ue2_package(path)
        if pkg.is_client_optional:
            return None

        info = PackageInfo(
            package=pkg,
            remote_generation=max(1, len(pkg.generations)),
        )
        self.entries.append(info)
        self._pkg_to_info[key] = info

        # Recurse over top-level imported Package entries in ImportMap order
        for dep_name in pkg.dependency_packages():
            self.add_linker(dep_name)

        return info

    def compute(self) -> None:
        """Exact UPackageMap::Compute (Core.dll 0x10123330)."""
        max_obj = 0
        max_name = 0
        name_indices: Dict[str, int] = {}

        for info in self.entries:
            pkg = info.package
            info.object_base = max_obj
            info.name_base = max_name

            local_gen = len(pkg.generations)
            rem_gen = info.remote_generation
            if 0 < rem_gen <= local_gen:
                gen = pkg.generations[rem_gen - 1]
                info.object_count = min(pkg.export_count, gen.export_count)
                info.name_count = min(pkg.name_count, gen.name_count)
            else:
                info.object_count = pkg.export_count
                info.name_count = pkg.name_count

            # First package containing a name owns its global NameIndex
            base = info.name_base
            for j in range(info.name_count):
                low = pkg.names[j].lower()
                if low not in name_indices:
                    name_indices[low] = base + j

            max_obj += info.object_count
            max_name += info.name_count

        self.max_object_index = max_obj
        self.max_name_index = max_name
        self._name_indices = name_indices
        # Clear cached class caches if Compute is re-run
        self._class_caches.clear()

    # ------------------------------------------------------------------
    # Control channel USES lines
    # ------------------------------------------------------------------

    def uses_lines(self) -> List[str]:
        """Return exact S2C `USES GUID=... PKG=... FLAGS=... SIZE=... GEN=... FNAME=...` lines."""
        return [info.uses_line() for info in self.entries]

    def get_package_info(self, package_name: str) -> Optional[PackageInfo]:
        return self._pkg_to_info.get(package_name.lower())

    def get_package(self, package_name: str) -> Optional[UE2Package]:
        info = self._pkg_to_info.get(package_name.lower())
        return info.package if info else None

    # ------------------------------------------------------------------
    # Object <-> Index & Name <-> Index mappings
    # ------------------------------------------------------------------

    def object_to_index(self, obj_ref: Union[str, Tuple[str, int]]) -> int:
        """Map a static object reference to its global PackageMap ObjectIndex (-1 if unmapped).

        Accepts:
        - `(pkg_name, export_idx_0based)` tuple
        - `"Package.Object"` or `"Package.Outer.Object"` (e.g. `"KFXGame.KFXPawn"`, `"DF-DiTieZhan.LevelInfo0"`)
        - Unqualified class/object name (e.g. `"Actor"`, `"KFXPawn"`, `"KFXPlayerController"` alias)
        """
        if isinstance(obj_ref, tuple):
            pkg_name, export_idx = obj_ref
            info = self._pkg_to_info.get(pkg_name.lower())
            if info is None or export_idx < 0 or export_idx >= info.object_count:
                return -1
            return info.object_base + export_idx

        ref = CLASS_ALIASES.get(obj_ref.lower(), obj_ref)
        if "." in ref:
            pkg_part, rest = ref.split(".", 1)
            info = self._pkg_to_info.get(pkg_part.lower())
            if info is None:
                return -1
            pkg = info.package
            ei = pkg.find_export_by_full_name(ref)
            if ei is None:
                ei = pkg.find_export_chain(rest.split("."))
            if ei is None or ei >= info.object_count:
                return -1
            return info.object_base + ei

        # Unqualified name: prefer UClass exports, then top-level exports
        for info in self.entries:
            ei = info.package.find_class_export(ref)
            if ei is not None and ei < info.object_count:
                return info.object_base + ei
        for info in self.entries:
            ei = info.package.find_top_export(ref)
            if ei is not None and ei < info.object_count:
                return info.object_base + ei
        return -1

    def index_to_object(self, index: int) -> Optional[Tuple[str, str, int]]:
        """Reverse-map a global static ObjectIndex to `(package_name, full_name, export_index)`."""
        if index < 0 or index >= self.max_object_index:
            return None
        for info in self.entries:
            if info.object_base <= index < info.object_base + info.object_count:
                ei = index - info.object_base
                return (info.name, info.package.get_full_name(ei), ei)
        return None

    def name_to_index(self, name: Optional[str]) -> int:
        """Map an FName string to its global NameIndex.

        Note: `"None"` / `""` / `None` maps to `self.max_name_index` (matching
        Core.dll `UPackageMap::SerializeName`: `Index == MaxNameIndex` => NAME_None,
        or the actual `None` name entry if serialized as `None`). Wait: Core.dll
        `SerializeName` sends `MaxNameIndex` for `NAME_None` (FName index 0), and
        for any other name sends its `NameIndices` slot in `0..MaxNameIndex-1`.
        Returns -1 if name is not present in any mapped package.
        """
        if not name or name.lower() == "none":
            return self.max_name_index
        return self._name_indices.get(name.lower(), -1)

    def index_to_name(self, index: int) -> Optional[str]:
        """Reverse-map a global NameIndex to its FName string."""
        if index == self.max_name_index:
            return "None"
        if index < 0 or index > self.max_name_index:
            return None
        for info in self.entries:
            if info.name_base <= index < info.name_base + info.name_count:
                return info.package.names[index - info.name_base]
        return None

    def get_class_index(self, class_name: str) -> int:
        """Return static PackageMap ObjectIndex for a UClass (raises KeyError if missing)."""
        idx = self.object_to_index(class_name)
        if idx < 0:
            raise KeyError(f"Class {class_name!r} not found in PackageMap")
        return idx

    def get_level_info_index(self) -> int:
        """Return static PackageMap ObjectIndex for the map's LevelInfo0 actor (-1 if absent)."""
        if not self.map_name:
            return -1
        info = self._pkg_to_info.get(self.map_name.lower())
        if info is None:
            return -1
        ei = info.package.find_export("LevelInfo0", class_name="LevelInfo")
        if ei is None:
            # Fallback: first export of class LevelInfo
            for exp in info.package.exports:
                if info.package.get_object_name(exp.class_index) == "LevelInfo":
                    ei = exp.index
                    break
        if ei is None or ei >= info.object_count:
            return -1
        return info.object_base + ei

    # ------------------------------------------------------------------
    # Wire serialization helpers (matching Core.dll & Engine.dll)
    # ------------------------------------------------------------------

    def serialize_name(self, writer: Any, name: Optional[str]) -> None:
        """UPackageMap::SerializeName (Core.dll 0x10122d50): WriteInt(Index, MaxNameIndex + 1)."""
        idx = self.name_to_index(name)
        if idx < 0:
            idx = self.max_name_index  # fallback to NAME_None
        writer.write_int(idx, self.max_name_index + 1)

    def deserialize_name(self, reader: Any) -> str:
        """Decode an FName via ReadInt(MaxNameIndex + 1)."""
        idx = reader.read_int(self.max_name_index + 1)
        return self.index_to_name(idx) or "None"

    def serialize_object(
        self,
        writer: Any,
        *,
        static_index: Optional[int] = None,
        static_ref: Optional[Union[str, Tuple[str, int]]] = None,
        channel_index: Optional[int] = None,
    ) -> None:
        """UPackageMapLevel::SerializeObject (Engine.dll 0x10543840).

        - If `channel_index` is provided (or all args None): writes bIsDynamic=1 + WriteInt(ch, 1023)
          where ch=0 encodes NULL/None and 1..1022 encodes an open Actor channel.
        - If `static_index` or `static_ref` is provided: resolves static index; if >= 0,
          writes bIsDynamic=0 + WriteInt(obj_idx, MaxObjectIndex), else writes NULL (1 + 0).
        """
        if static_ref is not None and static_index is None:
            static_index = self.object_to_index(static_ref)

        if static_index is not None and 0 <= static_index < self.max_object_index:
            writer.write_bit(0)  # bIsDynamic = 0 (static package object)
            writer.write_int(static_index, self.max_object_index)
        else:
            ch = 0 if channel_index is None else channel_index
            if ch < 0 or ch >= MAX_CHANNELS:
                ch = 0
            writer.write_bit(1)  # bIsDynamic = 1 (dynamic Actor channel or NULL)
            writer.write_int(ch, MAX_CHANNELS)

    def deserialize_object(self, reader: Any) -> Tuple[bool, int]:
        """Decode UPackageMapLevel::SerializeObject -> `(is_dynamic, channel_or_object_index)`."""
        is_dynamic = bool(reader.read_bit())
        if is_dynamic:
            return True, reader.read_int(MAX_CHANNELS)
        return False, reader.read_int(self.max_object_index)

    # ------------------------------------------------------------------
    # Internal UE2 reflection helpers (UField / UStruct / UClass / UEnum)
    # ------------------------------------------------------------------

    def _resolve_ref(
        self, pkg: UE2Package, idx: int
    ) -> Optional[Tuple[UE2Package, int]]:
        """Resolve an export (>0) or import (<0) reference across mapped packages."""
        if idx == 0:
            return None
        if idx > 0:
            return (pkg, idx - 1)

        imp = pkg.imports[-idx - 1]
        chain = [imp.object_name]
        p = imp.package_index
        while p < 0:
            pi = pkg.imports[-p - 1]
            chain.append(pi.object_name)
            p = pi.package_index

        root_pkg_name = chain[-1]
        target_pkg = self.get_package(root_pkg_name)
        if target_pkg is None:
            return None

        target_chain = list(reversed(chain[:-1]))
        if not target_chain:
            return None
        ei = target_pkg.find_export_chain(target_chain)
        if ei is None:
            return None
        return (target_pkg, ei)

    def _resolve_class_ref(self, class_name: str) -> Optional[Tuple[UE2Package, int]]:
        """Find `(UE2Package, export_index)` for a UClass by qualified or short name."""
        ref = CLASS_ALIASES.get(class_name.lower(), class_name)
        if "." in ref:
            pkg_part, cls_part = ref.split(".", 1)
            pkg = self.get_package(pkg_part)
            if pkg is None:
                return None
            ei = pkg.find_class_export(cls_part)
            return (pkg, ei) if ei is not None else None

        for info in self.entries:
            ei = info.package.find_class_export(ref)
            if ei is not None:
                return (info.package, ei)
        return None

    @staticmethod
    def _parse_ufield_header(
        pkg: UE2Package, ei: int, is_class: bool = False
    ) -> Tuple[int, int, int, int]:
        """Parse UObject prefix + UField (SuperField, Next) -> (super_field, next_field, pos, end)."""
        exp = pkg.exports[ei]
        data = pkg.data
        pos = exp.serial_offset
        end = exp.serial_offset + exp.serial_size

        if exp.object_flags & RF_HAS_STACK:
            node, pos = read_compact_index(data, pos)
            _, pos = read_compact_index(data, pos)
            pos += 12
            if node != 0:
                _, pos = read_compact_index(data, pos)

        if not is_class:
            _, pos = read_tagged_properties(data, pkg.names, pos, end, has_stack=False)

        super_field, pos = read_compact_index(data, pos)
        next_field, pos = read_compact_index(data, pos)
        return super_field, next_field, pos, end

    def _parse_enum_bits(self, pkg: UE2Package, ei: int) -> Tuple[str, int]:
        """Read UEnum::Names.Num() and return `(enum_name, ceil_log2(num))`."""
        ename = pkg.exports[ei].object_name
        cache_key = f"{pkg.name}.{ename}".lower()
        if cache_key in self._enum_bits_cache:
            return ename, self._enum_bits_cache[cache_key]

        _, _, pos, _ = self._parse_ufield_header(pkg, ei, is_class=False)
        count, _ = read_compact_index(pkg.data, pos)
        bits = enum_bit_width(count)
        self._enum_bits_cache[cache_key] = bits
        self._enum_bits_cache[ename.lower()] = bits
        return ename, bits

    def get_enum_bits(self, enum_name: str) -> int:
        """Look up bit width of a UE2 enum (e.g. 'ENetRole' -> 3, 'EPhysics' -> 5)."""
        low = enum_name.lower()
        if low in self._enum_bits_cache:
            return self._enum_bits_cache[low]
        for info in self.entries:
            ei = info.package.find_export(enum_name, class_name="Enum")
            if ei is not None:
                _, bits = self._parse_enum_bits(info.package, ei)
                return bits
        return 8

    def _parse_uproperty(self, pkg: UE2Package, ei: int) -> Dict[str, Any]:
        """Parse a UProperty export (flags, ArrayDim, RepOffset, Enum/Struct/Class refs)."""
        exp = pkg.exports[ei]
        cls_name = pkg.get_object_name(exp.class_index)
        super_field, next_field, pos, _ = self._parse_ufield_header(pkg, ei, is_class=False)
        data = pkg.data

        array_dim, _elem_size = struct.unpack_from("<HH", data, pos)
        pos += 4
        prop_flags = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        _category, pos = read_compact_index(data, pos)

        rep_offset = 0
        if prop_flags & CPF_NET:
            rep_offset = struct.unpack_from("<H", data, pos)[0]
            pos += 2

        enum_name: Optional[str] = None
        enum_bits = 8
        struct_name: Optional[str] = None
        struct_ref: Optional[Tuple[UE2Package, int]] = None
        object_class: Optional[str] = None
        meta_class: Optional[str] = None

        if cls_name == "ByteProperty":
            enum_idx, pos = read_compact_index(data, pos)
            if enum_idx != 0:
                resolved = self._resolve_ref(pkg, enum_idx)
                if resolved is not None:
                    enum_name, enum_bits = self._parse_enum_bits(*resolved)
                else:
                    enum_name = pkg.get_object_name(enum_idx)
        elif cls_name == "ObjectProperty":
            prop_cls_idx, pos = read_compact_index(data, pos)
            object_class = pkg.get_object_name(prop_cls_idx)
        elif cls_name == "ClassProperty":
            prop_cls_idx, pos = read_compact_index(data, pos)
            meta_cls_idx, pos = read_compact_index(data, pos)
            object_class = pkg.get_object_name(prop_cls_idx)
            meta_class = pkg.get_object_name(meta_cls_idx)
        elif cls_name == "StructProperty":
            st_idx, pos = read_compact_index(data, pos)
            struct_name = pkg.get_object_name(st_idx)
            struct_ref = self._resolve_ref(pkg, st_idx)

        return {
            "name": exp.object_name,
            "prop_type": cls_name,
            "super_field": super_field,
            "next_field": next_field,
            "array_dim": max(1, array_dim),
            "prop_flags": prop_flags,
            "rep_offset": rep_offset,
            "enum_name": enum_name,
            "enum_bits": enum_bits,
            "struct_name": struct_name,
            "struct_ref": struct_ref,
            "object_class": object_class,
            "meta_class": meta_class,
        }

    def _parse_struct_fields(
        self, pkg: UE2Package, ei: int
    ) -> List[StructFieldInfo]:
        """Parse non-native UStruct children in Children->Next serialization order."""
        st_name = pkg.exports[ei].object_name
        cache_key = f"{pkg.name}.{st_name}".lower()
        if cache_key in self._struct_fields_cache:
            return self._struct_fields_cache[cache_key]

        # Native special-cased structs do not need recursive expansion
        if st_name in ("Vector", "Rotator", "Plane", "CompressedPosition", "Quat", "Coords"):
            self._struct_fields_cache[cache_key] = []
            return []

        super_field, _, pos, _ = self._parse_ufield_header(pkg, ei, is_class=False)
        _script_text, pos = read_compact_index(pkg.data, pos)
        children, pos = read_compact_index(pkg.data, pos)

        fields: List[StructFieldInfo] = []
        if super_field != 0:
            sup_res = self._resolve_ref(pkg, super_field)
            if sup_res is not None:
                fields.extend(self._parse_struct_fields(*sup_res))

        child_idx = children
        visited: set[int] = set()
        while child_idx > 0 and child_idx not in visited:
            visited.add(child_idx)
            cei = child_idx - 1
            cname = pkg.get_export_class_name(cei)
            if cname in PROPERTY_CLASS_NAMES:
                pinfo = self._parse_uproperty(pkg, cei)
                fields.append(
                    StructFieldInfo(
                        name=pinfo["name"],
                        prop_type=pinfo["prop_type"],
                        array_dim=pinfo["array_dim"],
                        enum_name=pinfo["enum_name"],
                        enum_bits=pinfo["enum_bits"],
                        struct_name=pinfo["struct_name"],
                        object_class=pinfo["object_class"],
                        meta_class=pinfo["meta_class"],
                    )
                )
                child_idx = pinfo["next_field"]
            else:
                _, child_idx, _, _ = self._parse_ufield_header(pkg, cei, is_class=False)

        self._struct_fields_cache[cache_key] = fields
        self._struct_fields_cache[st_name.lower()] = fields
        return fields

    def get_struct_fields(self, struct_name: str) -> List[StructFieldInfo]:
        """Look up field list of a UStruct (e.g. 'Color', 'AnimRep', 'KFXPlayerInfo', 'KFXAvatarData')."""
        low = struct_name.lower()
        if low in self._struct_fields_cache:
            return self._struct_fields_cache[low]
        for info in self.entries:
            ei = info.package.find_export(struct_name, class_name="Struct")
            if ei is not None:
                return self._parse_struct_fields(info.package, ei)
        return []

    def _parse_ufunction(self, pkg: UE2Package, ei: int) -> Dict[str, Any]:
        """Parse a UFunction export: SuperField, Next, FunctionFlags, RepOffset, and RPC params."""
        exp = pkg.exports[ei]
        sf, nf, pos, end = self._parse_ufield_header(pkg, ei, is_class=False)
        data = pkg.data
        _script_text, pos = read_compact_index(data, pos)
        children, pos = read_compact_index(data, pos)
        _friendly, pos = read_compact_index(data, pos)

        # In UE2.5 v129, UFunction ends with:
        #   iNative (u16) + OperPrecedence (u8) + FunctionFlags (u32) + [RepOffset (u16) if FUNC_Net]
        # Total tail = 9 bytes if FUNC_Net, 7 bytes otherwise.
        # Every script function has at least one access bit (0x000E0000) and upper byte 0x00.
        fn_flags = 0
        rep_offset = 0
        rem = end - pos
        if rem >= 9:
            f_net = struct.unpack_from("<I", data, end - 6)[0]
            f_nonet = struct.unpack_from("<I", data, end - 4)[0]
            # Validate 9-byte FUNC_Net tail vs 7-byte non-net tail
            net_valid = (
                bool(f_net & FUNC_NET)
                and (f_net & 0xFF000000) == 0
                and bool(f_net & FUNC_ACCESS_MASK)
            )
            nonet_valid = (
                not bool(f_nonet & FUNC_NET)
                and (f_nonet & 0xFF000000) == 0
                and bool(f_nonet & FUNC_ACCESS_MASK)
            )
            if net_valid and not nonet_valid:
                fn_flags = f_net
                rep_offset = struct.unpack_from("<H", data, end - 2)[0]
            elif nonet_valid and not net_valid:
                fn_flags = f_nonet
            elif net_valid and nonet_valid:
                # Tie-breaker: check EX_EndOfScript (0x46) right before iNative
                if end - 10 >= pos and data[end - 10] == 0x46:
                    fn_flags = f_net
                    rep_offset = struct.unpack_from("<H", data, end - 2)[0]
                else:
                    fn_flags = f_nonet
            else:
                fn_flags = f_nonet
        elif rem >= 7:
            fn_flags = struct.unpack_from("<I", data, end - 4)[0]

        # Only parse parameter properties for FUNC_Net functions (saves time)
        params: List[RpcParamInfo] = []
        if fn_flags & FUNC_NET:
            child_idx = children
            visited: set[int] = set()
            while child_idx > 0 and child_idx not in visited:
                visited.add(child_idx)
                cei = child_idx - 1
                cname = pkg.get_export_class_name(cei)
                if cname in PROPERTY_CLASS_NAMES:
                    pinfo = self._parse_uproperty(pkg, cei)
                    pflags = pinfo["prop_flags"]
                    if (pflags & (CPF_PARM | CPF_RETURN_PARM)) == CPF_PARM:
                        params.append(
                            RpcParamInfo(
                                name=pinfo["name"],
                                prop_type=pinfo["prop_type"],
                                optional=bool(pflags & CPF_OPTIONAL_PARM),
                                out_parm=bool(pflags & CPF_OUT_PARM),
                                array_dim=pinfo["array_dim"],
                                enum_name=pinfo["enum_name"],
                                enum_bits=pinfo["enum_bits"],
                                struct_name=pinfo["struct_name"],
                                object_class=pinfo["object_class"],
                                meta_class=pinfo["meta_class"],
                            )
                        )
                    child_idx = pinfo["next_field"]
                else:
                    _, child_idx, _, _ = self._parse_ufield_header(pkg, cei, is_class=False)

        return {
            "name": exp.object_name,
            "super_field": sf,
            "next_field": nf,
            "function_flags": fn_flags,
            "rep_offset": rep_offset,
            "params": params,
        }

    def _class_own_bnet_initial_rotation(
        self, pkg: UE2Package, ei: int
    ) -> Optional[bool]:
        """Inspect UClass default properties for explicit `bNetInitialRotation` override."""
        ni = pkg.name_to_local_index.get("bnetinitialrotation")
        if ni is None:
            return None
        exp = pkg.exports[ei]
        raw = pkg.data[exp.serial_offset : exp.serial_offset + exp.serial_size]
        ci = encode_compact_index(ni)
        # Search in the trailing half/default-properties region of UClass
        idx = raw.find(ci)
        result: Optional[bool] = None
        while idx != -1:
            if idx + len(ci) < len(raw):
                ib = raw[idx + len(ci)]
                if (ib & 0x0F) == 3:  # BoolProperty tag
                    result = bool(ib & 0x80)
            idx = raw.find(ci, idx + 1)
        return result

    # ------------------------------------------------------------------
    # FClassNetCache (Core.dll 0x10121250 + 0x101220a0 + 0x10123700)
    # ------------------------------------------------------------------

    def get_class_cache(self, class_name: str) -> ClassNetCache:
        """Build/return exact FClassNetCache for a UClass matching Core.dll/Engine.dll.

        Supports short names (`"Actor"`, `"KFXPawn"`, `"KFXPlayer"`, `"KFXWeapon"`),
        qualified names (`"KFXGame.KFXMeleePlayer"`), and alias `"KFXPlayerController"`.
        """
        resolved_name = CLASS_ALIASES.get(class_name.lower(), class_name)
        cache_key = resolved_name.lower()
        if cache_key in self._class_caches:
            return self._class_caches[cache_key]

        ref = self._resolve_class_ref(resolved_name)
        if ref is None:
            raise KeyError(
                f"Class {class_name!r} not found in PackageMap packages"
            )
        pkg, ei = ref
        exp = pkg.exports[ei]
        full_name = f"{pkg.name}.{exp.object_name}"
        full_key = full_name.lower()
        if full_key in self._class_caches:
            self._class_caches[cache_key] = self._class_caches[full_key]
            return self._class_caches[full_key]

        # Parse UClass -> UStruct header (SuperField, Next, ScriptText, Children)
        sf, _nf, pos, _end = self._parse_ufield_header(pkg, ei, is_class=True)
        _script_text, pos = read_compact_index(pkg.data, pos)
        children, pos = read_compact_index(pkg.data, pos)

        # Build SuperClass cache recursively
        super_cache: Optional[ClassNetCache] = None
        super_name: Optional[str] = None
        if sf != 0:
            sup_res = self._resolve_ref(pkg, sf)
            if sup_res is not None:
                spkg, sei = sup_res
                super_name = f"{spkg.name}.{spkg.exports[sei].object_name}"
                super_cache = self.get_class_cache(super_name)

        # Inherit bNetInitialRotation from superclass unless overridden in defaults
        own_rot = self._class_own_bnet_initial_rotation(pkg, ei)
        if own_rot is not None:
            b_net_init_rot = own_rot
        elif super_cache is not None:
            b_net_init_rot = super_cache.b_net_initial_rotation
        else:
            b_net_init_rot = False

        # Collect own Children->Next CPF_Net properties and FUNC_Net root functions
        raw_net_fields: List[Tuple[int, str, Dict[str, Any]]] = []
        child_idx = children
        visited: set[int] = set()
        while child_idx > 0 and child_idx not in visited:
            visited.add(child_idx)
            cei = child_idx - 1
            cname = pkg.get_export_class_name(cei)
            if cname in PROPERTY_CLASS_NAMES:
                pinfo = self._parse_uproperty(pkg, cei)
                if pinfo["prop_flags"] & CPF_NET:
                    raw_net_fields.append((cei, "property", pinfo))
                child_idx = pinfo["next_field"]
            elif cname == "Function":
                finfo = self._parse_ufunction(pkg, cei)
                if (finfo["function_flags"] & FUNC_NET) and finfo["super_field"] == 0:
                    raw_net_fields.append((cei, "function", finfo))
                child_idx = finfo["next_field"]
            else:
                _, child_idx, _, _ = self._parse_ufield_header(pkg, cei, is_class=False)

        # CRITICAL Core.dll 0x101220a0 / 0x10122129 rule:
        # UClass::Link sorts NetFields ascending by 0-based ExportIndex!
        raw_net_fields.sort(key=lambda item: item[0])

        fields_base = super_cache.max_index if super_cache is not None else 0
        own_fields: List[NetFieldEntry] = []
        next_rep_idx = fields_base

        for cei, kind, meta in raw_net_fields:
            obj_idx = self.object_to_index((pkg.name, cei))
            if obj_idx < 0:
                # UPackageMap::GetClassNetCache skips fields unmapped by PackageMap
                continue

            if kind == "property":
                st_fields: List[StructFieldInfo] = []
                if meta["struct_ref"] is not None:
                    st_fields = self._parse_struct_fields(*meta["struct_ref"])
                entry = NetFieldEntry(
                    rep_index=next_rep_idx,
                    name=meta["name"],
                    kind="property",
                    owner_class=exp.object_name,
                    package_name=pkg.name,
                    export_index=cei,
                    object_index=obj_idx,
                    rep_offset=meta["rep_offset"],
                    prop_type=meta["prop_type"],
                    array_dim=meta["array_dim"],
                    enum_name=meta["enum_name"],
                    enum_bits=meta["enum_bits"],
                    struct_name=meta["struct_name"],
                    struct_fields=st_fields,
                    object_class=meta["object_class"],
                    meta_class=meta["meta_class"],
                )
            else:
                entry = NetFieldEntry(
                    rep_index=next_rep_idx,
                    name=meta["name"],
                    kind="function",
                    owner_class=exp.object_name,
                    package_name=pkg.name,
                    export_index=cei,
                    object_index=obj_idx,
                    rep_offset=meta["rep_offset"],
                    function_flags=meta["function_flags"],
                    params=meta["params"],
                )

            own_fields.append(entry)
            next_rep_idx += 1

        all_fields = list(super_cache.all_fields) if super_cache is not None else []
        all_fields.extend(own_fields)

        by_index = {f.rep_index: f for f in all_fields}
        by_name: Dict[str, NetFieldEntry] = {}
        for f in all_fields:
            by_name[f.name.lower()] = f

        cls_obj_idx = self.object_to_index((pkg.name, ei))
        cache = ClassNetCache(
            class_name=exp.object_name,
            package_name=pkg.name,
            full_name=full_name,
            class_object_index=cls_obj_idx,
            super_name=super_name,
            super_cache=super_cache,
            fields_base=fields_base,
            max_index=next_rep_idx,
            b_net_initial_rotation=b_net_init_rot,
            own_fields=own_fields,
            all_fields=all_fields,
            by_index=by_index,
            by_name=by_name,
        )

        self._class_caches[full_key] = cache
        self._class_caches[exp.object_name.lower()] = cache
        self._class_caches[cache_key] = cache
        return cache

    def has_net_initial_rotation(self, class_name: str) -> bool:
        """Return whether UActorChannel open bunch includes initial Rotation after Location."""
        return self.get_class_cache(class_name).b_net_initial_rotation

    def build_standard_caches(self) -> Dict[str, ClassNetCache]:
        """Build ClassNetCache for all standard CSO Malaysia replicated actor classes."""
        result: Dict[str, ClassNetCache] = {}
        for cname in STANDARD_NET_CLASSES:
            try:
                c = self.get_class_cache(cname)
                result[c.class_name] = c
            except KeyError:
                continue
        return result


# Backwards-compatible alias matching UE2 naming
PackageMapLevel = PackageMap

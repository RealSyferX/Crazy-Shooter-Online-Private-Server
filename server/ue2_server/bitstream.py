"""
UE2.5 (UT2004 build 3369 / CSO Malaysia) UDP Bitstream, Packet Framing,
Reliable Bunch Ordering, and ACK Layer.

Binary-verified against CSO Malaysia System\\Core.dll, Engine.dll, IpDrv.dll,
and live raw UDP captures from CS.exe:
  - Zero custom encryption/XOR on UDP transport (pure stock UE2.5 build 3369).
  - LSB-first bit order within each byte.
  - Trailing sentinel '1' bit + '0' padding to byte boundary on every UDP packet.
  - Variable-width ReadInt(Max) / WriteInt(Val, Max) matching Core.dll FBitReader/FBitWriter.
  - MAX_PACKET = 512 (4096 bits), MAX_PACKETID = 16384 (14 bits),
    MAX_CHANNELS = 1023, MAX_CHSEQUENCE = 1024 (10 bits), CHTYPE_MAX = 8 (3 bits).
  - No partial-bunch bits on wire in UE2.5 build 3369.
"""

from __future__ import annotations

import math
import struct
import time
from typing import Callable, Dict, List, Optional, Set, Tuple, Union

# ---------------------------------------------------------------------------
# Engine / Network Protocol Constants (binary-verified build 3369 / CSO MY)
# ---------------------------------------------------------------------------

ENGINE_VERSION: int = 3369               # 0x0D29
ENGINE_MIN_NET_VERSION: int = 3180       # 0x0C6C
ENGINE_NEGOTIATION_CODE: int = 0x93FE92CE  # -1812032818 signed int32

MAX_PACKET: int = 512                    # 0x200 bytes MTU payload
MAX_PACKET_BITS: int = MAX_PACKET * 8    # 4096 bits
PACKET_OVERHEAD: int = 32                # 0x20 bytes
RECV_BUFFER_SIZE: int = 576              # 0x240 bytes

MAX_PACKETID: int = 16384                # 0x4000 (14 bits)
MAX_CHANNELS: int = 1023                 # 0x3FF (9..10 bits via ReadInt/WriteInt)
MAX_CHSEQUENCE: int = 1024               # 0x400 (10 bits)

CHTYPE_NONE: int = 0
CHTYPE_CONTROL: int = 1
CHTYPE_ACTOR: int = 2
CHTYPE_FILE: int = 3
CHTYPE_VOICE: int = 4
CHTYPE_MAX: int = 8                      # 3 bits via ReadInt/WriteInt

# Maximum usable payload bits inside a single UDP datagram (reserve 1 bit for trailing sentinel '1')
MAX_DATAGRAM_PAYLOAD_BITS: int = MAX_PACKET_BITS - 1  # 4095 bits

# Default reliable bunch resend & keepalive intervals (seconds) — tuned for snappy LAN/online sync
DEFAULT_RESEND_INTERVAL: float = 0.20
DEFAULT_KEEPALIVE_INTERVAL: float = 0.15


# ---------------------------------------------------------------------------
# Core Math / Protocol Helpers
# ---------------------------------------------------------------------------

def make_relative(value: int, reference: int, max_val: int) -> int:
    """
    UE2 MakeRelative(Value, Reference, Max) for power-of-2 modular wraparound
    (PacketId mod 16384, ChSequence mod 1024).
    """
    half = max_val >> 1
    mask = max_val - 1
    return reference + (((value - reference + half) & mask) - half)


def challenge_response(challenge: int) -> int:
    """
    Exact UGameEngine::ChallengeResponse(INT Challenge) from Engine.dll (0x104116a0).
    Returns signed 32-bit int:
      ((c * 237) ^ (c >> 16) ^ (c << 16) ^ 0x93FE92CE) with arithmetic right shift.
    """
    c_u32 = challenge & 0xFFFFFFFF
    c_s32 = c_u32 - 0x100000000 if c_u32 >= 0x80000000 else c_u32
    mul = (c_s32 * 237) & 0xFFFFFFFF
    sar16 = (c_s32 >> 16) & 0xFFFFFFFF
    shl16 = (c_u32 << 16) & 0xFFFFFFFF
    res = (mul ^ sar16 ^ shl16 ^ ENGINE_NEGOTIATION_CODE) & 0xFFFFFFFF
    return res - 0x100000000 if res >= 0x80000000 else res


def ceil_log2(value: int) -> int:
    """UE2 appCeilLogTwo(DWORD Arg)."""
    if value <= 1:
        return 0
    return (value - 1).bit_length()


def int_bit_length(val: int, max_val: int) -> int:
    """Return exact number of bits written by WriteInt(val, max_val)."""
    if max_val <= 1:
        return 0
    if val < 0:
        val = 0
    elif val >= max_val:
        val = max_val - 1
    new_val = 0
    mask = 1
    bits = 0
    while new_val + mask < max_val:
        bits += 1
        if val & mask:
            new_val += mask
        mask <<= 1
    return bits


def _round_ue2(x: float) -> int:
    """Match Core.dll UStructProperty::NetSerializeItem floor(x + 0.5)."""
    return math.floor(float(x) + 0.5)


# ---------------------------------------------------------------------------
# BitReader (UE2 Core.dll FBitReader)
# ---------------------------------------------------------------------------

class BitReader:
    """
    LSB-first bit-level reader matching UE2.5 Core.dll FBitReader.
    """

    __slots__ = ("data", "num_bits", "pos", "error")

    def __init__(
        self,
        data: Union[bytes, bytearray, memoryview] = b"",
        num_bits: Optional[int] = None,
        pos: int = 0,
    ) -> None:
        self.data: bytes = bytes(data)
        total_avail = len(self.data) * 8
        if num_bits is None:
            self.num_bits: int = total_avail
        else:
            self.num_bits = min(max(0, int(num_bits)), total_avail)
        self.pos: int = pos
        self.error: bool = False

    @property
    def bits_left(self) -> int:
        rem = self.num_bits - self.pos
        return rem if rem > 0 else 0

    @property
    def bytes_left(self) -> int:
        return self.bits_left // 8

    def at_end(self) -> bool:
        return self.error or self.pos >= self.num_bits

    def is_error(self) -> bool:
        return self.error

    def tell(self) -> int:
        return self.pos

    def seek(self, bit_pos: int) -> None:
        if bit_pos < 0 or bit_pos > self.num_bits:
            self.error = True
        else:
            self.pos = bit_pos

    def clone(self) -> "BitReader":
        r = BitReader(self.data, self.num_bits, self.pos)
        r.error = self.error
        return r

    # -- Primitive bit/int/byte reads ---------------------------------------

    def read_bit(self) -> int:
        pos = self.pos
        if pos >= self.num_bits:
            self.error = True
            return 0
        self.pos = pos + 1
        return (self.data[pos >> 3] >> (pos & 7)) & 1

    def read_bool(self) -> bool:
        return self.read_bit() != 0

    def read_bits(self, count: int) -> int:
        """Read `count` bits LSB-first into an unsigned Python int."""
        if count <= 0:
            return 0
        pos = self.pos
        if pos + count > self.num_bits:
            self.error = True
            self.pos = self.num_bits
            return 0
        data = self.data
        # Fast path for byte-aligned reads
        if (pos & 7) == 0:
            full_bytes = count >> 3
            rem_bits = count & 7
            byte_off = pos >> 3
            val = int.from_bytes(data[byte_off:byte_off + full_bytes], "little") if full_bytes else 0
            if rem_bits:
                val |= (data[byte_off + full_bytes] & ((1 << rem_bits) - 1)) << (full_bytes * 8)
            self.pos = pos + count
            return val
        # General unaligned LSB-first path
        val = 0
        shift = 0
        remaining = count
        while remaining > 0:
            byte_idx = pos >> 3
            bit_off = pos & 7
            take = min(remaining, 8 - bit_off)
            chunk = (data[byte_idx] >> bit_off) & ((1 << take) - 1)
            val |= chunk << shift
            pos += take
            shift += take
            remaining -= take
        self.pos = pos
        return val

    def read_bits_bytes(self, count: int) -> bytes:
        """Read `count` raw bits LSB-first into a bytes object of len ceil(count/8)."""
        if count <= 0:
            return b""
        pos = self.pos
        if pos + count > self.num_bits:
            self.error = True
            self.pos = self.num_bits
            return b""
        nbytes = (count + 7) >> 3
        rem_bits = count & 7
        data = self.data
        if (pos & 7) == 0:
            byte_off = pos >> 3
            out = bytearray(data[byte_off:byte_off + nbytes])
            if rem_bits:
                out[-1] &= (1 << rem_bits) - 1
            self.pos = pos + count
            return bytes(out)
        # Unaligned bit-copy into packed LSB-first bytearray
        out = bytearray(nbytes)
        bit_off = pos & 7
        inv_off = 8 - bit_off
        byte_idx = pos >> 3
        full_bytes = count >> 3
        for i in range(full_bytes):
            lo = data[byte_idx + i] >> bit_off
            hi = (data[byte_idx + i + 1] << inv_off) & 0xFF
            out[i] = lo | hi
        if rem_bits:
            # Read remaining 1..7 bits at the end
            tail_pos = pos + (full_bytes << 3)
            tail_val = 0
            for b in range(rem_bits):
                p = tail_pos + b
                if (data[p >> 3] >> (p & 7)) & 1:
                    tail_val |= 1 << b
            out[full_bytes] = tail_val
        self.pos = pos + count
        return bytes(out)

    def read_int(self, max_val: int) -> int:
        """
        Exact UE2 Core.dll FBitReader::ReadInt(DWORD Max).
        Variable bit width: reads bits while (val + mask < max_val).
        """
        if max_val <= 1:
            return 0
        val = 0
        mask = 1
        while val + mask < max_val:
            if self.read_bit():
                val |= mask
            mask <<= 1
        return val

    def read_byte(self) -> int:
        return self.read_bits(8)

    def read_bytes(self, count: int) -> bytes:
        if count <= 0:
            return b""
        return self.read_bits_bytes(count * 8)

    def read_uint16(self) -> int:
        raw = self.read_bytes(2)
        if self.error or len(raw) < 2:
            return 0
        return struct.unpack("<H", raw)[0]

    def read_int16(self) -> int:
        raw = self.read_bytes(2)
        if self.error or len(raw) < 2:
            return 0
        return struct.unpack("<h", raw)[0]

    def read_uint32(self) -> int:
        raw = self.read_bytes(4)
        if self.error or len(raw) < 4:
            return 0
        return struct.unpack("<I", raw)[0]

    def read_int32(self) -> int:
        raw = self.read_bytes(4)
        if self.error or len(raw) < 4:
            return 0
        return struct.unpack("<i", raw)[0]

    def read_float(self) -> float:
        raw = self.read_bytes(4)
        if self.error or len(raw) < 4:
            return 0.0
        return struct.unpack("<f", raw)[0]

    # -- UE2 Packed Int (FCompactIndex / AR_INDEX) & FString ----------------

    def read_int_packed(self) -> int:
        """
        Read UE2 FCompactIndex (AR_INDEX) signed 1..5 byte varint.
        Verified against Core.dll (0x10145660).
        """
        b0 = self.read_byte()
        if self.error:
            return 0
        neg = (b0 & 0x80) != 0
        val = b0 & 0x3F
        if b0 & 0x40:
            b1 = self.read_byte()
            if self.error:
                return 0
            val |= (b1 & 0x7F) << 6
            if b1 & 0x80:
                b2 = self.read_byte()
                if self.error:
                    return 0
                val |= (b2 & 0x7F) << 13
                if b2 & 0x80:
                    b3 = self.read_byte()
                    if self.error:
                        return 0
                    val |= (b3 & 0x7F) << 20
                    if b3 & 0x80:
                        b4 = self.read_byte()
                        if self.error:
                            return 0
                        val |= b4 << 27
        return -val if neg else val

    read_compact_index = read_int_packed

    def read_fstring(self) -> str:
        """
        Read UE2 FString: FCompactIndex length + ANSI (len > 0) or UTF-16LE (len < 0)
        including trailing NUL terminator. Verified against Core.dll (0x1013c8c0).
        """
        length = self.read_int_packed()
        if self.error or length == 0:
            return ""
        if length > 0:
            if length * 8 > self.bits_left:
                self.error = True
                self.pos = self.num_bits
                return ""
            raw = self.read_bytes(length)
            if raw.endswith(b"\x00"):
                raw = raw[:-1]
            return raw.decode("latin-1")
        else:
            char_count = -length
            if char_count * 16 > self.bits_left:
                self.error = True
                self.pos = self.num_bits
                return ""
            raw = self.read_bytes(char_count * 2)
            text = raw.decode("utf-16-le", errors="replace")
            if text.endswith("\x00"):
                text = text[:-1]
            return text

    # -- Vectors & Rotators -------------------------------------------------

    def read_vector(self) -> Tuple[float, float, float]:
        """Read uncompressed 3x float32 FVector."""
        raw = self.read_bytes(12)
        if self.error or len(raw) < 12:
            return (0.0, 0.0, 0.0)
        return struct.unpack("<3f", raw)

    def read_rotator(self) -> Tuple[int, int, int]:
        """Read uncompressed 3x int32 FRotator (Pitch, Yaw, Roll)."""
        raw = self.read_bytes(12)
        if self.error or len(raw) < 12:
            return (0, 0, 0)
        return struct.unpack("<3i", raw)

    def read_compressed_vector(self) -> Tuple[float, float, float]:
        """
        Read UE2.5 compressed FVector (Core.dll UStructProperty::NetSerializeItem 0x57
        and Engine.dll UActorChannel initial Location 0x10538830):
          bits_minus_1 = ReadInt(20)   # 0..19 -> bits = 1..20
          bias = 1 << bits
          limit = 1 << (bits + 1)
          X = ReadInt(limit) - bias
          Y = ReadInt(limit) - bias
          Z = ReadInt(limit) - bias
        """
        bits_minus_1 = self.read_int(20)
        if self.error:
            return (0.0, 0.0, 0.0)
        bits = bits_minus_1 + 1
        bias = 1 << bits
        limit = 1 << (bits + 1)
        dx = self.read_int(limit)
        dy = self.read_int(limit)
        dz = self.read_int(limit)
        if self.error:
            return (0.0, 0.0, 0.0)
        return (float(dx - bias), float(dy - bias), float(dz - bias))

    def read_compressed_rotator(self) -> Tuple[int, int, int]:
        """
        Read UE2.5 compressed FRotator (Core.dll UStructProperty::NetSerializeItem 0x58
        and Engine.dll UActorChannel initial Rotation 0x105378a0):
          For each of (Pitch, Yaw, Roll):
            1-bit flag `has_component`; if 1 -> 8-bit byte << 8, else 0.
        """
        pitch = (self.read_byte() << 8) if self.read_bit() else 0
        yaw = (self.read_byte() << 8) if self.read_bit() else 0
        roll = (self.read_byte() << 8) if self.read_bit() else 0
        return (pitch, yaw, roll)

    def read_compressed_position(
        self,
    ) -> Tuple[Tuple[float, float, float], Tuple[int, int, int], Tuple[float, float, float]]:
        """
        Read UE2.5 CompressedPosition (Core.dll 0x5d):
          1. Location: compressed Vector
          2. Rotation: unconditional 2 raw bytes (Pitch>>8, Yaw>>8), Roll=0
          3. Velocity: compressed Vector
        """
        loc = self.read_compressed_vector()
        pitch_b = self.read_byte()
        yaw_b = self.read_byte()
        vel = self.read_compressed_vector()
        return (loc, (pitch_b << 8, yaw_b << 8, 0), vel)

    def read_compressed_quat(self) -> Tuple[float, float, float, float]:
        """Read UE2.5 compressed FQuat (Core.dll 0x5f): 3 floats X,Y,Z; W=sqrt(max(0,1-x^2-y^2-z^2))."""
        x = self.read_float()
        y = self.read_float()
        z = self.read_float()
        w_sq = max(0.0, 1.0 - (x * x + y * y + z * z))
        return (x, y, z, math.sqrt(w_sq))

    def read_compressed_plane(self) -> Tuple[float, float, float, float]:
        """Read UE2.5 compressed FPlane (Core.dll 0x5b): 4x signed int16."""
        x = float(self.read_int16())
        y = float(self.read_int16())
        z = float(self.read_int16())
        w = float(self.read_int16())
        return (x, y, z, w)


# ---------------------------------------------------------------------------
# BitWriter (UE2 Core.dll FBitWriter)
# ---------------------------------------------------------------------------

class BitWriter:
    """
    LSB-first bit-level writer matching UE2.5 Core.dll FBitWriter.
    """

    __slots__ = ("buf", "num_bits", "max_bits", "error")

    def __init__(self, max_bits: int = MAX_PACKET_BITS) -> None:
        self.buf: bytearray = bytearray()
        self.num_bits: int = 0
        self.max_bits: int = max_bits
        self.error: bool = False

    @property
    def num_bytes(self) -> int:
        return (self.num_bits + 7) >> 3

    def is_error(self) -> bool:
        return self.error

    def reset(self) -> None:
        self.buf.clear()
        self.num_bits = 0
        self.error = False

    def clone(self) -> "BitWriter":
        w = BitWriter(self.max_bits)
        w.buf = bytearray(self.buf)
        w.num_bits = self.num_bits
        w.error = self.error
        return w

    def _ensure_bits(self, extra_bits: int) -> bool:
        new_total = self.num_bits + extra_bits
        if self.max_bits > 0 and new_total > self.max_bits:
            self.error = True
            return False
        need_bytes = (new_total + 7) >> 3
        if need_bytes > len(self.buf):
            self.buf.extend(b"\x00" * (need_bytes - len(self.buf)))
        return True

    # -- Primitive bit/int/byte writes --------------------------------------

    def write_bit(self, bit: int) -> None:
        if not self._ensure_bits(1):
            return
        if bit:
            self.buf[self.num_bits >> 3] |= 1 << (self.num_bits & 7)
        self.num_bits += 1

    def write_bool(self, val: bool) -> None:
        self.write_bit(1 if val else 0)

    def write_bits(self, value: int, count: int) -> None:
        """Write `count` bits LSB-first from `value`."""
        if count <= 0:
            return
        if not self._ensure_bits(count):
            return
        pos = self.num_bits
        val = value & ((1 << count) - 1)
        if (pos & 7) == 0:
            byte_off = pos >> 3
            full_bytes = count >> 3
            rem_bits = count & 7
            if full_bytes:
                raw = (val & ((1 << (full_bytes * 8)) - 1)).to_bytes(full_bytes, "little")
                self.buf[byte_off:byte_off + full_bytes] = raw
                val >>= full_bytes * 8
            if rem_bits:
                self.buf[byte_off + full_bytes] |= val & ((1 << rem_bits) - 1)
            self.num_bits = pos + count
            return
        remaining = count
        while remaining > 0:
            byte_idx = pos >> 3
            bit_off = pos & 7
            take = min(remaining, 8 - bit_off)
            chunk = val & ((1 << take) - 1)
            self.buf[byte_idx] |= chunk << bit_off
            val >>= take
            pos += take
            remaining -= take
        self.num_bits = pos

    def write_bits_bytes(self, data: Union[bytes, bytearray], count: int) -> None:
        """Write `count` raw LSB-first bits from `data`."""
        if count <= 0:
            return
        if not self._ensure_bits(count):
            return
        pos = self.num_bits
        full_bytes = count >> 3
        rem_bits = count & 7
        if (pos & 7) == 0:
            byte_off = pos >> 3
            if full_bytes:
                self.buf[byte_off:byte_off + full_bytes] = data[:full_bytes]
            if rem_bits:
                self.buf[byte_off + full_bytes] |= data[full_bytes] & ((1 << rem_bits) - 1)
            self.num_bits = pos + count
            return
        # Unaligned copy: byte-by-byte shifted into buf
        bit_off = pos & 7
        inv_off = 8 - bit_off
        byte_idx = pos >> 3
        buf = self.buf
        for i in range(full_bytes):
            b = data[i]
            buf[byte_idx + i] |= (b << bit_off) & 0xFF
            buf[byte_idx + i + 1] |= b >> inv_off
        self.num_bits = pos + (full_bytes << 3)
        if rem_bits:
            self.write_bits(data[full_bytes], rem_bits)

    def write_int(self, val: int, max_val: int) -> None:
        """
        Exact UE2 Core.dll FBitWriter::WriteInt(DWORD Value, DWORD Max).
        Variable bit width: emits bits while (new_val + mask < max_val).
        """
        if max_val <= 1:
            return
        if val < 0:
            val = 0
        elif val >= max_val:
            val = max_val - 1
        new_val = 0
        mask = 1
        while new_val + mask < max_val:
            bit = 1 if (val & mask) else 0
            self.write_bit(bit)
            if bit:
                new_val += mask
            mask <<= 1

    def write_byte(self, val: int) -> None:
        self.write_bits(val & 0xFF, 8)

    def write_bytes(self, data: Union[bytes, bytearray]) -> None:
        if not data:
            return
        self.write_bits_bytes(data, len(data) * 8)

    def write_uint16(self, val: int) -> None:
        self.write_bytes(struct.pack("<H", val & 0xFFFF))

    def write_int16(self, val: int) -> None:
        self.write_bytes(struct.pack("<h", val))

    def write_uint32(self, val: int) -> None:
        self.write_bytes(struct.pack("<I", val & 0xFFFFFFFF))

    def write_int32(self, val: int) -> None:
        self.write_bytes(struct.pack("<i", val))

    def write_float(self, val: float) -> None:
        self.write_bytes(struct.pack("<f", float(val)))

    # -- UE2 Packed Int (FCompactIndex / AR_INDEX) & FString ----------------

    def write_int_packed(self, val: int) -> None:
        """
        Write UE2 FCompactIndex (AR_INDEX) signed 1..5 byte varint.
        Verified against Core.dll (0x10145660).
        """
        neg = val < 0
        v = -val if neg else val
        b0 = (0x80 if neg else 0) | (0x40 if v >= 0x40 else 0) | (v & 0x3F)
        self.write_byte(b0)
        if b0 & 0x40:
            v >>= 6
            b1 = (0x80 if v >= 0x80 else 0) | (v & 0x7F)
            self.write_byte(b1)
            if b1 & 0x80:
                v >>= 7
                b2 = (0x80 if v >= 0x80 else 0) | (v & 0x7F)
                self.write_byte(b2)
                if b2 & 0x80:
                    v >>= 7
                    b3 = (0x80 if v >= 0x80 else 0) | (v & 0x7F)
                    self.write_byte(b3)
                    if b3 & 0x80:
                        v >>= 7
                        self.write_byte(v & 0xFF)

    write_compact_index = write_int_packed

    def write_fstring(self, text: str) -> None:
        """
        Write UE2 FString: FCompactIndex length + ANSI (all ord <= 0xFF) or
        UTF-16LE (any ord > 0xFF), including trailing NUL.
        """
        if not text:
            self.write_int_packed(0)
            return
        if all(ord(ch) <= 0xFF for ch in text):
            raw = text.encode("latin-1") + b"\x00"
            self.write_int_packed(len(raw))
            self.write_bytes(raw)
        else:
            raw = (text + "\x00").encode("utf-16-le")
            self.write_int_packed(-(len(text) + 1))
            self.write_bytes(raw)

    # -- Vectors & Rotators -------------------------------------------------

    def write_vector(self, vec: Tuple[float, float, float]) -> None:
        """Write uncompressed 3x float32 FVector."""
        self.write_bytes(struct.pack("<3f", float(vec[0]), float(vec[1]), float(vec[2])))

    def write_rotator(self, rot: Tuple[int, int, int]) -> None:
        """Write uncompressed 3x int32 FRotator (Pitch, Yaw, Roll)."""
        self.write_bytes(struct.pack("<3i", int(rot[0]), int(rot[1]), int(rot[2])))

    def write_compressed_vector(self, vec: Tuple[float, float, float]) -> None:
        """
        Write UE2.5 compressed FVector (Core.dll UStructProperty::NetSerializeItem 0x57
        and Engine.dll UActorChannel initial Location 0x10538830):
          ix, iy, iz = floor(X+0.5), floor(Y+0.5), floor(Z+0.5)
          bits = clamp(ceil_log2(max(|ix|,|iy|,|iz|) + 1), 1, 20)
          WriteInt(bits - 1, 20)
          bias = 1 << bits; limit = 1 << (bits + 1)
          WriteInt(ix + bias, limit); WriteInt(iy + bias, limit); WriteInt(iz + bias, limit)
        """
        ix = _round_ue2(vec[0])
        iy = _round_ue2(vec[1])
        iz = _round_ue2(vec[2])
        peak = max(abs(ix), abs(iy), abs(iz))
        bits = ceil_log2(peak + 1)
        if bits < 1:
            bits = 1
        elif bits > 20:
            bits = 20
        bias = 1 << bits
        limit = 1 << (bits + 1)
        dx = max(0, min(limit - 1, ix + bias))
        dy = max(0, min(limit - 1, iy + bias))
        dz = max(0, min(limit - 1, iz + bias))
        self.write_int(bits - 1, 20)
        self.write_int(dx, limit)
        self.write_int(dy, limit)
        self.write_int(dz, limit)

    def write_compressed_rotator(self, rot: Tuple[int, int, int]) -> None:
        """
        Write UE2.5 compressed FRotator (Core.dll UStructProperty::NetSerializeItem 0x58):
          For each of (Pitch, Yaw, Roll):
            b = (angle >> 8) & 0xFF
            write_bit(1 if b != 0 else 0)
            if b != 0: write_byte(b)
        """
        for comp in (rot[0], rot[1], rot[2]):
            b = (int(comp) >> 8) & 0xFF
            if b:
                self.write_bit(1)
                self.write_byte(b)
            else:
                self.write_bit(0)

    def write_compressed_position(
        self,
        loc: Tuple[float, float, float],
        rot: Tuple[int, int, int],
        vel: Tuple[float, float, float],
    ) -> None:
        """
        Write UE2.5 CompressedPosition (Core.dll 0x5d):
          Location (compressed Vector) + Pitch>>8 (u8) + Yaw>>8 (u8) + Velocity (compressed Vector).
        """
        self.write_compressed_vector(loc)
        self.write_byte((int(rot[0]) >> 8) & 0xFF)
        self.write_byte((int(rot[1]) >> 8) & 0xFF)
        self.write_compressed_vector(vel)

    def write_compressed_quat(self, quat: Tuple[float, float, float, float]) -> None:
        """Write UE2.5 compressed FQuat (Core.dll 0x5f)."""
        x, y, z, w = float(quat[0]), float(quat[1]), float(quat[2]), float(quat[3])
        if w < 0.0:
            x, y, z = -x, -y, -z
        self.write_float(x)
        self.write_float(y)
        self.write_float(z)

    def write_compressed_plane(self, plane: Tuple[float, float, float, float]) -> None:
        """Write UE2.5 compressed FPlane (Core.dll 0x5b): 4x int16(floor(v + 0.5))."""
        for v in plane:
            iv = max(-32768, min(32767, _round_ue2(v)))
            self.write_int16(iv)

    # -- Extraction & Packet Sentinel ---------------------------------------

    def get_bytes(self) -> bytes:
        return bytes(self.buf[:self.num_bytes])

    def finalize_packet(self) -> bytes:
        """
        Return a byte-aligned UDP datagram with UE2's trailing sentinel '1' bit
        followed by zero-pad bits (matches UNetConnection::FlushNet).
        Does NOT mutate this writer's buffer.
        """
        return append_packet_sentinel(self)


# ---------------------------------------------------------------------------
# Packet Trailing Sentinel Helpers (FlushNet / ReceivedRawPacket)
# ---------------------------------------------------------------------------

def strip_packet_sentinel(raw: Union[bytes, bytearray, memoryview]) -> Optional[BitReader]:
    """
    Validate and strip UE2's trailing sentinel '1' bit from a raw UDP packet
    (Engine.dll!UNetConnection::ReceivedRawPacket 0x1053f360).
    Returns a BitReader sized to the exact payload bit count, or None if invalid.
    """
    data = bytes(raw)
    n = len(data)
    if n <= 0:
        return None
    last_byte = data[-1]
    if last_byte == 0:
        return None
    # Scan down from bit 7 (0x80) to find the highest '1' bit
    highest_bit = last_byte.bit_length() - 1
    payload_bits = (n - 1) * 8 + highest_bit
    return BitReader(data, payload_bits)


def append_packet_sentinel(writer: BitWriter) -> bytes:
    """
    Append trailing sentinel '1' bit and zero-pad to byte boundary
    (Engine.dll!UNetConnection::FlushNet 0x1053f4b0).
    """
    pos = writer.num_bits
    total_bits = pos + 1
    need_bytes = (total_bits + 7) >> 3
    out = bytearray(writer.buf[:writer.num_bytes])
    if len(out) < need_bytes:
        out.extend(b"\x00" * (need_bytes - len(out)))
    # Clear any stray bits above `pos` in the final byte before setting sentinel
    bit_off = pos & 7
    out[pos >> 3] &= (1 << bit_off) - 1
    out[pos >> 3] |= 1 << bit_off
    return bytes(out)


# ---------------------------------------------------------------------------
# Bunches (InBunch / OutBunch)
# ---------------------------------------------------------------------------

class InBunch(BitReader):
    """
    Incoming UE2.5 channel bunch. Subclasses BitReader (mirroring FInBunch : FBitReader)
    and also exposes `.reader()` for creating a fresh reader positioned at bit 0.
    """

    def __init__(
        self,
        data: bytes,
        num_bits: int,
        *,
        packet_id: int = 0,
        ch_index: int = 0,
        ch_type: int = CHTYPE_NONE,
        ch_sequence: int = 0,
        b_control: bool = False,
        b_open: bool = False,
        b_close: bool = False,
        b_reliable: bool = False,
        b_partial: bool = False,
        b_partial_initial: bool = False,
        b_partial_final: bool = False,
    ) -> None:
        super().__init__(data, num_bits, pos=0)
        self.packet_id: int = packet_id
        self.ch_index: int = ch_index
        self.ch_type: int = ch_type
        self.ch_sequence: int = ch_sequence
        self.b_control: bool = b_control
        self.b_open: bool = b_open
        self.b_close: bool = b_close
        self.b_reliable: bool = b_reliable
        self.b_partial: bool = b_partial
        self.b_partial_initial: bool = b_partial_initial
        self.b_partial_final: bool = b_partial_final

    def reader(self) -> BitReader:
        """Return a fresh BitReader starting at bit 0 of this bunch."""
        return BitReader(self.data, self.num_bits, pos=0)

    def __repr__(self) -> str:
        return (
            f"InBunch(pkt={self.packet_id}, ch={self.ch_index}, type={self.ch_type}, "
            f"seq={self.ch_sequence}, open={int(self.b_open)}, close={int(self.b_close)}, "
            f"rel={int(self.b_reliable)}, bits={self.num_bits})"
        )


class OutBunch(BitWriter):
    """
    Outgoing UE2.5 channel bunch. Subclasses BitWriter (mirroring FOutBunch : FBitWriter).
    """

    def __init__(
        self,
        ch_index: int = 0,
        ch_type: int = CHTYPE_CONTROL,
        *,
        b_open: bool = False,
        b_close: bool = False,
        b_reliable: bool = False,
        ch_sequence: int = 0,
        max_bits: int = MAX_PACKET_BITS,
    ) -> None:
        super().__init__(max_bits=max_bits)
        self.ch_index: int = ch_index
        self.ch_type: int = ch_type
        self.b_open: bool = b_open
        self.b_close: bool = b_close
        self.b_reliable: bool = b_reliable
        self.ch_sequence: int = ch_sequence
        self.b_partial: bool = False
        self.b_partial_initial: bool = False
        self.b_partial_final: bool = False
        # Transport tracking
        self.packet_id: int = -1
        self.sent_packet_ids: Set[int] = set()
        self.time_sent: float = 0.0
        self.acked: bool = False

    @property
    def b_control(self) -> bool:
        return bool(self.b_open or self.b_close)

    def header_bits(self) -> int:
        """Exact wire bit size of this bunch header (including IsAck=0 bit)."""
        bits = 1  # IsAck = 0
        bits += 1  # bControl
        if self.b_control:
            bits += 2  # bOpen, bClose
        bits += 1  # bReliable
        bits += int_bit_length(self.ch_index, MAX_CHANNELS)
        if self.b_reliable:
            bits += int_bit_length(self.ch_sequence & (MAX_CHSEQUENCE - 1), MAX_CHSEQUENCE)
        if self.b_reliable or self.b_open:
            bits += int_bit_length(self.ch_type, CHTYPE_MAX)
        bits += int_bit_length(self.num_bits, MAX_PACKET_BITS)
        return bits

    def wire_bits(self) -> int:
        return self.header_bits() + self.num_bits

    def write_to_packet(self, writer: BitWriter) -> None:
        """Serialize this bunch (IsAck=0 + header + payload bits) into a packet BitWriter."""
        writer.write_bit(0)  # IsAck = 0
        b_ctrl = self.b_control
        writer.write_bit(1 if b_ctrl else 0)
        if b_ctrl:
            writer.write_bit(1 if self.b_open else 0)
            writer.write_bit(1 if self.b_close else 0)
        writer.write_bit(1 if self.b_reliable else 0)
        writer.write_int(self.ch_index, MAX_CHANNELS)
        if self.b_reliable:
            writer.write_int(self.ch_sequence & (MAX_CHSEQUENCE - 1), MAX_CHSEQUENCE)
        if self.b_reliable or self.b_open:
            writer.write_int(self.ch_type, CHTYPE_MAX)
        writer.write_int(self.num_bits, MAX_PACKET_BITS)
        if self.num_bits > 0:
            writer.write_bits_bytes(self.buf, self.num_bits)

    def __repr__(self) -> str:
        return (
            f"OutBunch(ch={self.ch_index}, type={self.ch_type}, seq={self.ch_sequence}, "
            f"open={int(self.b_open)}, close={int(self.b_close)}, "
            f"rel={int(self.b_reliable)}, bits={self.num_bits})"
        )


# ---------------------------------------------------------------------------
# Stateless Single-Packet Decode Helper
# ---------------------------------------------------------------------------

def decode_raw_packet(
    raw: bytes,
    in_packet_id_ref: int = -1,
    out_ack_id_ref: int = -1,
    in_reliable_refs: Optional[Dict[int, int]] = None,
    channel_types: Optional[Dict[int, int]] = None,
) -> Optional[Tuple[int, List[int], List[InBunch]]]:
    """
    Decode a single raw UE2.5 UDP packet without mutating any connection state.
    Returns `(packet_id, ack_ids, bunches)` or `None` if sentinel/header is invalid.
    """
    reader = strip_packet_sentinel(raw)
    if reader is None:
        return None
    raw_pkt_id = reader.read_int(MAX_PACKETID)
    if reader.error:
        return None
    pkt_id = make_relative(raw_pkt_id, in_packet_id_ref, MAX_PACKETID)

    acks: List[int] = []
    bunches: List[InBunch] = []
    ch_types = dict(channel_types) if channel_types else {}
    rel_refs = in_reliable_refs or {}

    while not reader.at_end():
        is_ack = reader.read_bit()
        if reader.error:
            break
        if is_ack:
            raw_ack = reader.read_int(MAX_PACKETID)
            if reader.error:
                break
            ack_id = make_relative(raw_ack, out_ack_id_ref, MAX_PACKETID)
            acks.append(ack_id)
        else:
            b_control = bool(reader.read_bit())
            if b_control:
                b_open = bool(reader.read_bit())
                b_close = bool(reader.read_bit())
            else:
                b_open = False
                b_close = False
            b_reliable = bool(reader.read_bit())
            ch_index = reader.read_int(MAX_CHANNELS)
            if b_reliable:
                raw_seq = reader.read_int(MAX_CHSEQUENCE)
                ch_seq = make_relative(raw_seq, rel_refs.get(ch_index, 0), MAX_CHSEQUENCE)
            else:
                ch_seq = 0
            if b_reliable or b_open:
                ch_type = reader.read_int(CHTYPE_MAX)
                if ch_type != CHTYPE_NONE:
                    ch_types[ch_index] = ch_type
            else:
                ch_type = ch_types.get(ch_index, CHTYPE_NONE)
            bunch_bits = reader.read_int(MAX_PACKET_BITS)
            if reader.error or bunch_bits > reader.bits_left:
                break
            bunch_data = reader.read_bits_bytes(bunch_bits)
            bunches.append(
                InBunch(
                    data=bunch_data,
                    num_bits=bunch_bits,
                    packet_id=pkt_id,
                    ch_index=ch_index,
                    ch_type=ch_type,
                    ch_sequence=ch_seq,
                    b_control=b_control,
                    b_open=b_open,
                    b_close=b_close,
                    b_reliable=b_reliable,
                )
            )
    return (pkt_id, acks, bunches)


# ---------------------------------------------------------------------------
# Per-Client Connection State (PacketId, ACKs, Reliable Sequencing, Flushing)
# ---------------------------------------------------------------------------

class UE2ConnectionState:
    """
    Full UE2.5 build 3369 UDP reliability, framing, ACK, and channel sequence
    state machine for one client connection (matches UNetConnection).
    """

    def __init__(
        self,
        *,
        resend_interval: float = DEFAULT_RESEND_INTERVAL,
        keepalive_interval: float = DEFAULT_KEEPALIVE_INTERVAL,
        on_ack: Optional[Callable[[int], None]] = None,
    ) -> None:
        # Packet numbering (Engine.dll: OutPacketId=0, InPacketId=-1, OutAckPacketId=-1)
        self.out_packet_id: int = 0
        self.in_packet_id: int = -1
        self.out_ack_packet_id: int = -1

        # Pending ACKs (incoming packet IDs we need to acknowledge to peer)
        self.pending_acks: List[int] = []
        self.last_received_acks: List[int] = []

        # Per-channel reliable sequence counters (first reliable bunch is seq=1)
        self.in_reliable: Dict[int, int] = {}
        self.out_reliable: Dict[int, int] = {}

        # Out-of-order incoming reliable buffer: ch_index -> {ch_seq: InBunch}
        self.in_reliable_queue: Dict[int, Dict[int, InBunch]] = {}

        # Optional partial bunch reassembly buffer (kept for forward API completeness;
        # UE2.5 build 3369 has no wire bPartial bits)
        self.in_partial_buffer: Dict[int, List[InBunch]] = {}

        # Channel metadata
        self.channel_types: Dict[int, int] = {0: CHTYPE_CONTROL}

        # Outgoing queues
        self.out_queue: List[OutBunch] = []
        self.out_reliable_unacked: Dict[int, List[OutBunch]] = {}

        # Timing & stats
        self.resend_interval: float = resend_interval
        self.keepalive_interval: float = keepalive_interval
        self.last_recv_time: float = time.monotonic()
        self.last_send_time: float = time.monotonic()
        self.packets_in: int = 0
        self.packets_out: int = 0
        self.bad_packets: int = 0
        self.acks_in: int = 0
        self.acks_out: int = 0
        self.on_ack: Optional[Callable[[int], None]] = on_ack

    # -- Channel Helpers ----------------------------------------------------

    def reset_channel(self, ch_index: int) -> None:
        """Clear per-channel reliable state after a channel is closed."""
        self.in_reliable.pop(ch_index, None)
        self.out_reliable.pop(ch_index, None)
        self.in_reliable_queue.pop(ch_index, None)
        self.in_partial_buffer.pop(ch_index, None)
        self.out_reliable_unacked.pop(ch_index, None)
        if ch_index != 0:
            self.channel_types.pop(ch_index, None)

    def has_unacked_reliable(self, ch_index: Optional[int] = None) -> bool:
        if ch_index is not None:
            return bool(self.out_reliable_unacked.get(ch_index))
        return any(bool(v) for v in self.out_reliable_unacked.values())

    def has_pending_output(self) -> bool:
        return bool(self.pending_acks or self.out_queue)

    # -- Receive Path -------------------------------------------------------

    def receive_raw_packet(
        self,
        raw: bytes,
        now: Optional[float] = None,
    ) -> List[InBunch]:
        """
        Parse an incoming raw UDP datagram, update PacketId & ACK state,
        order reliable bunches per channel, and return ready-to-process InBunches.
        """
        ts = time.monotonic() if now is None else now
        reader = strip_packet_sentinel(raw)
        if reader is None:
            self.bad_packets += 1
            return []

        raw_pkt_id = reader.read_int(MAX_PACKETID)
        if reader.error:
            self.bad_packets += 1
            return []

        pkt_id = make_relative(raw_pkt_id, self.in_packet_id, MAX_PACKETID)
        if pkt_id <= self.in_packet_id:
            # Duplicate or stale out-of-order UDP packet (matches UNetConnection::ReceivedPacket)
            return []

        self.in_packet_id = pkt_id
        self.last_recv_time = ts
        self.packets_in += 1
        self.pending_acks.append(pkt_id)
        self.last_received_acks.clear()

        delivered: List[InBunch] = []

        while not reader.at_end():
            is_ack = reader.read_bit()
            if reader.error:
                self.bad_packets += 1
                break

            if is_ack:
                raw_ack_id = reader.read_int(MAX_PACKETID)
                if reader.error:
                    self.bad_packets += 1
                    break
                ack_id = make_relative(raw_ack_id, self.out_ack_packet_id, MAX_PACKETID)
                self._handle_ack(ack_id)
            else:
                b_control = bool(reader.read_bit())
                if b_control:
                    b_open = bool(reader.read_bit())
                    b_close = bool(reader.read_bit())
                else:
                    b_open = False
                    b_close = False
                b_reliable = bool(reader.read_bit())
                ch_index = reader.read_int(MAX_CHANNELS)
                if b_reliable:
                    raw_seq = reader.read_int(MAX_CHSEQUENCE)
                    ref_seq = self.in_reliable.get(ch_index, 0)
                    ch_seq = make_relative(raw_seq, ref_seq, MAX_CHSEQUENCE)
                else:
                    ch_seq = 0
                if b_reliable or b_open:
                    ch_type = reader.read_int(CHTYPE_MAX)
                    if ch_type != CHTYPE_NONE:
                        self.channel_types[ch_index] = ch_type
                else:
                    ch_type = self.channel_types.get(ch_index, CHTYPE_NONE)

                bunch_bits = reader.read_int(MAX_PACKET_BITS)
                if reader.error or bunch_bits > reader.bits_left:
                    self.bad_packets += 1
                    break

                bunch_data = reader.read_bits_bytes(bunch_bits)
                bunch = InBunch(
                    data=bunch_data,
                    num_bits=bunch_bits,
                    packet_id=pkt_id,
                    ch_index=ch_index,
                    ch_type=ch_type,
                    ch_sequence=ch_seq,
                    b_control=b_control,
                    b_open=b_open,
                    b_close=b_close,
                    b_reliable=b_reliable,
                )

                if b_reliable:
                    expected = self.in_reliable.get(ch_index, 0) + 1
                    if ch_seq < expected:
                        # Duplicate reliable bunch already processed
                        continue
                    elif ch_seq == expected:
                        self.in_reliable[ch_index] = ch_seq
                        self._deliver_with_reassembly(bunch, delivered)
                        # Drain any buffered consecutive bunches for this channel
                        q = self.in_reliable_queue.get(ch_index)
                        if q:
                            nxt = ch_seq + 1
                            while nxt in q:
                                queued_bunch = q.pop(nxt)
                                self.in_reliable[ch_index] = nxt
                                self._deliver_with_reassembly(queued_bunch, delivered)
                                nxt += 1
                            if not q:
                                self.in_reliable_queue.pop(ch_index, None)
                    else:
                        # Future reliable bunch; buffer until missing sequence(s) arrive
                        self.in_reliable_queue.setdefault(ch_index, {})[ch_seq] = bunch
                else:
                    self._deliver_with_reassembly(bunch, delivered)

        return delivered

    def _deliver_with_reassembly(self, bunch: InBunch, delivered: List[InBunch]) -> None:
        """
        Deliver a bunch (with optional partial reassembly if b_partial is ever set
        programmatically; UE2.5 wire packets always have b_partial=False).
        """
        if not bunch.b_partial:
            delivered.append(bunch)
            return
        ch = bunch.ch_index
        if bunch.b_partial_initial:
            self.in_partial_buffer[ch] = [bunch]
        else:
            parts = self.in_partial_buffer.get(ch)
            if parts is None:
                return
            parts.append(bunch)
        if bunch.b_partial_final:
            parts = self.in_partial_buffer.pop(ch, [])
            if not parts:
                return
            merged = BitWriter(max_bits=0)
            for part in parts:
                merged.write_bits_bytes(part.data, part.num_bits)
            first = parts[0]
            last = parts[-1]
            delivered.append(
                InBunch(
                    data=merged.get_bytes(),
                    num_bits=merged.num_bits,
                    packet_id=last.packet_id,
                    ch_index=first.ch_index,
                    ch_type=first.ch_type,
                    ch_sequence=last.ch_sequence,
                    b_control=first.b_control or last.b_control,
                    b_open=first.b_open,
                    b_close=last.b_close,
                    b_reliable=first.b_reliable,
                )
            )

    def _handle_ack(self, ack_id: int) -> None:
        self.acks_in += 1
        self.last_received_acks.append(ack_id)
        if ack_id > self.out_ack_packet_id:
            self.out_ack_packet_id = ack_id
        # Mark any unacked reliable bunches that were carried in `ack_id` as ACKed
        empty_channels: List[int] = []
        for ch_index, bunches in self.out_reliable_unacked.items():
            remaining: List[OutBunch] = []
            for b in bunches:
                if ack_id in b.sent_packet_ids:
                    b.acked = True
                else:
                    remaining.append(b)
            if remaining:
                self.out_reliable_unacked[ch_index] = remaining
            else:
                empty_channels.append(ch_index)
        for ch_index in empty_channels:
            self.out_reliable_unacked.pop(ch_index, None)
        if self.on_ack is not None:
            self.on_ack(ack_id)

    # -- Send Path ----------------------------------------------------------

    def queue_bunch(self, bunch: OutBunch) -> int:
        """
        Queue an OutBunch for transmission on the next flush().
        Assigns ChSequence automatically if `bunch.b_reliable` is True.
        Returns the assigned ChSequence (0 for unreliable).
        """
        if bunch.b_reliable:
            seq = self.out_reliable.get(bunch.ch_index, 0) + 1
            self.out_reliable[bunch.ch_index] = seq
            bunch.ch_sequence = seq
        else:
            bunch.ch_sequence = 0
        if bunch.ch_type != CHTYPE_NONE:
            self.channel_types[bunch.ch_index] = bunch.ch_type
        if bunch.wire_bits() + 14 > MAX_DATAGRAM_PAYLOAD_BITS:
            raise ValueError(
                f"UE2.5 bunch too large for single 512B UDP packet: "
                f"{bunch.wire_bits()} bits (max {MAX_DATAGRAM_PAYLOAD_BITS - 14})"
            )
        self.out_queue.append(bunch)
        return bunch.ch_sequence

    # Alias for convenience
    send_bunch = queue_bunch

    def queue_control_message(
        self,
        text: str,
        *,
        b_open: bool = False,
        b_close: bool = False,
    ) -> OutBunch:
        """
        Create and queue a reliable Channel 0 (CHTYPE_CONTROL) FString bunch.
        """
        bunch = OutBunch(
            ch_index=0,
            ch_type=CHTYPE_CONTROL,
            b_open=b_open,
            b_close=b_close,
            b_reliable=True,
        )
        bunch.write_fstring(text)
        self.queue_bunch(bunch)
        return bunch

    send_control_message = queue_control_message

    def _collect_retransmits(self, now: float) -> List[OutBunch]:
        retransmits: List[OutBunch] = []
        for ch_index in sorted(self.out_reliable_unacked.keys()):
            for b in self.out_reliable_unacked[ch_index]:
                if not b.acked and (now - b.time_sent) >= self.resend_interval:
                    retransmits.append(b)
        return retransmits

    def flush(
        self,
        now: Optional[float] = None,
        *,
        force_keepalive: bool = False,
    ) -> List[bytes]:
        """
        Pack pending ACKs, timed-out reliable retransmits, and queued OutBunches
        into 1 or more raw UE2.5 UDP packets (each <= 512 bytes with sentinel '1').
        Returns list of raw UDP datagram bytes to send via `sendto()`.
        """
        ts = time.monotonic() if now is None else now
        retransmits = self._collect_retransmits(ts)

        # Nothing to send?
        if not self.pending_acks and not retransmits and not self.out_queue:
            if not force_keepalive and (ts - self.last_send_time) < self.keepalive_interval:
                return []
            if not force_keepalive:
                # Only emit keepalive automatically if we have already heard from peer
                if self.in_packet_id < 0:
                    return []
            pkt = self._build_keepalive_packet()
            self.last_send_time = ts
            return [pkt]

        packets: List[bytes] = []
        writer, cur_pkt_id = self._begin_packet()

        def finish_current_packet() -> None:
            nonlocal writer, cur_pkt_id
            packets.append(append_packet_sentinel(writer))
            self.packets_out += 1
            self.last_send_time = ts

        def ensure_space(bits_needed: int) -> None:
            nonlocal writer, cur_pkt_id
            if writer.num_bits + bits_needed > MAX_DATAGRAM_PAYLOAD_BITS:
                finish_current_packet()
                writer, cur_pkt_id = self._begin_packet()

        # 1. Pack pending ACKs (15 bits each: 1 bit IsAck=1 + 14 bits AckPacketId)
        if self.pending_acks:
            acks_to_send = self.pending_acks
            self.pending_acks = []
            for ack_id in acks_to_send:
                ensure_space(15)
                writer.write_bit(1)
                writer.write_int(ack_id & (MAX_PACKETID - 1), MAX_PACKETID)
                self.acks_out += 1

        # 2. Pack timed-out reliable retransmits (do not re-add to unacked list)
        for b in retransmits:
            needed = b.wire_bits()
            ensure_space(needed)
            b.write_to_packet(writer)
            b.packet_id = cur_pkt_id
            b.sent_packet_ids.add(cur_pkt_id)
            b.time_sent = ts

        # 3. Pack newly queued bunches
        if self.out_queue:
            queued = self.out_queue
            self.out_queue = []
            for b in queued:
                needed = b.wire_bits()
                ensure_space(needed)
                b.write_to_packet(writer)
                b.packet_id = cur_pkt_id
                b.time_sent = ts
                if b.b_reliable:
                    b.sent_packet_ids.add(cur_pkt_id)
                    self.out_reliable_unacked.setdefault(b.ch_index, []).append(b)

        finish_current_packet()
        return packets

    def _begin_packet(self) -> Tuple[BitWriter, int]:
        pkt_id = self.out_packet_id
        self.out_packet_id += 1
        writer = BitWriter(max_bits=MAX_DATAGRAM_PAYLOAD_BITS)
        writer.write_int(pkt_id & (MAX_PACKETID - 1), MAX_PACKETID)
        return writer, pkt_id

    def _build_keepalive_packet(self) -> bytes:
        writer, _ = self._begin_packet()
        self.packets_out += 1
        return append_packet_sentinel(writer)

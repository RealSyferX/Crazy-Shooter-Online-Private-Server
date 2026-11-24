"""
KFXClientNetwork.dll wire framing, 42-byte key handshake, and KSG_EncodeDecode_Simple cipher.

Verified directly against KFXClientNetwork.dll (MD5 / Ghidra 12.2):
  - Framing: 2-byte LE uint16 wire_len = len(payload) + 2, followed by payload (max < 0xFFDC)
  - Handshake (S2C unencrypted, 42 bytes payload):
      [0] = 0x20, [1] = 0x00
      [0x08:0x0C] = uint32_le(scramble_u32(client_send_key))
      [0x11:0x15] = uint32_le(scramble_u32(client_recv_key))
  - Cipher (KFXClientNetwork.dll!0x10003610 -> KSG_EncodeDecode_Simple @ 0x10003580, mode=0):
      Uses 5,679 uint32_le lookup table from KFXClientNetwork.dll @ 0x10006080.
      In mode=0 (always used by CreateSocketStreamPool::Connect @ 0x10001090), the wrapper
      0x10003610 copies *puKey BY VALUE into a temporary stack slot before calling 0x10003580,
      so the inner LCG seed update is discarded and both keys remain STATIC for the entire
      connection (both Bishop 7451 and Realm 7452).
      Client encodes C2S with static client_send_key and decodes S2C with static client_recv_key.
      Server decodes C2S with static client_send_key and encodes S2C with static client_recv_key.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import secrets
import struct
from pathlib import Path
from typing import Tuple

MAX_PAYLOAD_SIZE = 0xFFDB
KSG_TABLE_LEN = 5679


def md5_upper(password: str) -> str:
    """Matches KFXClient.dll!FUN_10729590 uppercase 32-char MD5 hex."""
    return hashlib.md5(password.encode("utf-8")).hexdigest().upper()


def scramble_u32(key: int) -> int:
    """Inverse of KFXClientNetwork.dll!0x10002f57 handshake key unscramble."""
    key &= 0xFFFFFFFF
    v0 = ((((~(key >> 24)) & 0xFF) - 0x67) & 0xFF) ^ 0xCF
    borrow0 = 1 if (v0 ^ 0xCF) < 0x99 else 0
    mid = ((~key) >> 8) & 0xFFFF
    v_mid = ((mid + 0x6D23 + borrow0) & 0xFFFF) ^ 0x6D23
    low24_xor = ((v_mid << 8) | v0) ^ 0x6D23CF
    borrow3 = 1 if low24_xor < 0x6D2399 else 0
    b3_out = (~key) & 0xFF
    v3 = ((b3_out + 0x2E + borrow3) & 0xFF) ^ 0x2E
    return ((v3 << 24) | (v_mid << 8) | v0) & 0xFFFFFFFF


def unscramble_u32(wire_val: int) -> int:
    """Exact replica of KFXClientNetwork.dll!0x10002f57 (used by test client)."""
    v = wire_val & 0xFFFFFFFF
    ecx = (~(((v ^ 0x006D23CF) - 0x006D2399) & 0xFFFFFFFF)) & 0x00FFFF00
    ebx = ((~(((v ^ 0x2E6D23CF) - 0x2E6D2399) & 0xFFFFFFFF)) & 0xFFFFFFFF) >> 24
    edx = ((~(((v ^ 0xFFFFFFCF) + 0x67) & 0xFFFFFFFF)) & 0xFFFFFFFF) << 24
    return (ecx | ebx | edx) & 0xFFFFFFFF


class KSGCipherTable:
    """Holds the 5,679-dword lookup table extracted from KFXClientNetwork.dll."""

    def __init__(self, dwords: Tuple[int, ...]):
        if len(dwords) != KSG_TABLE_LEN:
            raise ValueError(f"Expected {KSG_TABLE_LEN} dwords, got {len(dwords)}")
        self.table = dwords

    @classmethod
    def from_file(cls, path: Path | str) -> "KSGCipherTable":
        raw = Path(path).read_bytes()
        if len(raw) != KSG_TABLE_LEN * 4:
            raise ValueError(f"Invalid KSG table file size: {len(raw)} (expected {KSG_TABLE_LEN * 4})")
        return cls(struct.unpack(f"<{KSG_TABLE_LEN}I", raw))

    def crypt(self, data: bytes | bytearray, seed: int) -> bytes:
        """
        Apply symmetric KFXClientNetwork.dll mode-0 XOR transform (0x10003610 -> 0x10003580).
        Because 0x10003610 passes a by-value copy of *puKey to 0x10003580, the caller's
        key is never mutated and remains static across all packets on the stream.
        """
        buf = bytearray(data)
        n = len(buf)
        u = seed & 0xFFFFFFFF
        dwords = n >> 2
        rem = n & 3
        off = 0
        tbl = self.table
        while dwords != 0:
            dwords -= 1
            # Matches x86: lea eax, [ecx + esi]; xor edx, edx; div dword ptr [0x1000b93c]
            u = (tbl[((u + dwords) & 0xFFFFFFFF) % KSG_TABLE_LEN] + 0x2E6D23C1) & 0xFFFFFFFF
            val = struct.unpack_from("<I", buf, off)[0] ^ u
            struct.pack_into("<I", buf, off, val)
            off += 4
        u = (u ^ tbl[rem % KSG_TABLE_LEN]) & 0xFFFFFFFF
        for _ in range(rem):
            buf[off] ^= (u & 0xFF)
            off += 1
            u >>= 8
        return bytes(buf)


def build_handshake_payload(client_send_key: int, client_recv_key: int) -> bytes:
    """Build the 42-byte unencrypted S2C handshake packet."""
    payload = bytearray(42)
    payload[0] = 0x20
    payload[1] = 0x00
    struct.pack_into("<I", payload, 0x08, scramble_u32(client_send_key))
    struct.pack_into("<I", payload, 0x11, scramble_u32(client_recv_key))
    return bytes(payload)


def parse_handshake_payload(payload: bytes) -> Tuple[int, int]:
    """Parse a 42-byte S2C handshake packet -> (client_send_key, client_recv_key)."""
    if len(payload) < 0x15 or payload[0] != 0x20:
        raise ValueError(f"Invalid KFX handshake payload (len={len(payload)})")
    raw_send = struct.unpack_from("<I", payload, 0x08)[0]
    raw_recv = struct.unpack_from("<I", payload, 0x11)[0]
    return unscramble_u32(raw_send), unscramble_u32(raw_recv)


class KFXStream:
    """Async framed + encrypted KFX TCP stream (supports both server and client roles)."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        cipher: KSGCipherTable,
        *,
        is_server: bool = True,
    ):
        self.reader = reader
        self.writer = writer
        self.cipher = cipher
        self.is_server = is_server
        self.recv_key: int = 0
        self.send_key: int = 0
        self.handshaked: bool = False
        self._write_lock = asyncio.Lock()

    @property
    def peer_addr(self) -> str:
        info = self.writer.get_extra_info("peername")
        if info:
            return f"{info[0]}:{info[1]}"
        return "unknown"

    async def server_handshake(self, c2s_key: int | None = None, s2c_key: int | None = None) -> Tuple[int, int]:
        """Server-side: generate keys, send unencrypted 42-byte handshake, arm cipher."""
        client_send_key = secrets.randbits(32) if c2s_key is None else (c2s_key & 0xFFFFFFFF)
        client_recv_key = secrets.randbits(32) if s2c_key is None else (s2c_key & 0xFFFFFFFF)
        # Server decrypts C2S using client_send_key, encrypts S2C using client_recv_key
        self.recv_key = client_send_key
        self.send_key = client_recv_key
        hs = build_handshake_payload(client_send_key, client_recv_key)
        await self._write_raw_frame(hs)
        self.handshaked = True
        return client_send_key, client_recv_key

    async def client_handshake(self) -> Tuple[int, int]:
        """Client-side: receive unencrypted 42-byte handshake, arm cipher."""
        hs = await self._read_raw_frame()
        client_send_key, client_recv_key = parse_handshake_payload(hs)
        # Client encodes C2S with client_send_key, decodes S2C with client_recv_key
        self.send_key = client_send_key
        self.recv_key = client_recv_key
        self.handshaked = True
        return client_send_key, client_recv_key

    async def _read_raw_frame(self) -> bytes:
        hdr = await self.reader.readexactly(2)
        wire_len = struct.unpack("<H", hdr)[0]
        if wire_len < 2 or wire_len - 2 > MAX_PAYLOAD_SIZE:
            raise ValueError(f"Invalid KFX frame length: {wire_len}")
        payload_len = wire_len - 2
        if payload_len == 0:
            return b""
        return await self.reader.readexactly(payload_len)

    async def _write_raw_frame(self, payload: bytes) -> None:
        if len(payload) > MAX_PAYLOAD_SIZE:
            raise ValueError(f"Payload too large: {len(payload)} > {MAX_PAYLOAD_SIZE}")
        frame = struct.pack("<H", len(payload) + 2) + payload
        self.writer.write(frame)
        await self.writer.drain()

    async def read_packet(self) -> bytes:
        raw = await self._read_raw_frame()
        if not self.handshaked:
            return raw
        return self.cipher.crypt(raw, self.recv_key)

    async def send_packet(self, payload: bytes) -> None:
        async with self._write_lock:
            if self.handshaked:
                enc = self.cipher.crypt(payload, self.send_key)
            else:
                enc = payload
            await self._write_raw_frame(enc)

    async def close(self) -> None:
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass

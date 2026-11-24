#!/usr/bin/env python3
"""
Two-Player Live Multiplayer Simulation Test for CSG Private Server.

Simulates TWO full CSO Malaysia clients (`brrbrrpatapim` on Blue Team and
`random_player` on Red Team) end-to-end across:
  1. Bishop TCP authentication (static mode-0 KSG cipher) -> RealmList (0xFA)
  2. Realm TCP login -> CreateRole -> Channel 1 -> Room #1 (CreateRoom,
     JoinRoom, ChangeTeam, Ready, StartGame)
  3. S2C 0x15 GameStartCommond(result=1, ip=127.0.0.1, port=7777) with ZERO
     standalone CS.exe subprocess spawns (mode = "ue2_multiplayer")
  4. Real OS UDP sockets talking UE2.5 build 3369 bitstream directly to the
     in-process UE2MatchServer on 127.0.0.1:7777:
       - HELLO -> CHALLENGE -> NETSPEED -> LOGIN -> USES -> WELCOME -> JOIN
       - Actor channel spawns: KFXPlayerController, GRI, TeamInfo[0/1], both
         PRIs (`brrbrrpatapim` & `random_player`), both KFXPawns at real `.ut2`
         PlayerStart coordinates, KFXWeap* & KFXWeapAttachment, HUD/Start RPCs
       - Bidirectional Movement Sync (`ServerMove` -> replicated peer `KFXPawn`
         Location + Rotation updates)
       - Shooting, Hit, Kill, Death, Scoreboard PRI/TeamInfo Sync & Respawn
         (`ServerStartFire` -> damage -> kill/death `Health <= 0` -> PRI
         `kills=1`/`deaths=1`/Blue score=1 -> full-HP respawn at real Red
         `.ut2` PlayerStart)
       - Match End -> Realm Persistence (both clients disconnect -> SQLite
         `csg.db` persists real kills/deaths/head_kills/victory/defeated/honor/GP
         + S2C 0x1E delivered + room state restored + UDP port released)
"""
from __future__ import annotations

import asyncio
import math
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from server.crypto import KFXStream, KSGCipherTable, md5_upper
from server.main import CSGServerApp, load_config
from server.packets import pack_cstr, unpack_cstr
from server.ue2_server.bitstream import (
    CHTYPE_ACTOR,
    CHTYPE_CONTROL,
    UE2ConnectionState,
    challenge_response,
)
from server.ue2_server.combat import PAWN_STAND_EYE_OFFSET, vector_to_rotator
from server.ue2_server.control import decode_control_bunch, parse_control_command, parse_kv_params
from server.ue2_server.host import get_cached_package_map, is_udp_port_available
from server.ue2_server.packagemap import PackageMap
from server.ue2_server.replication import (
    PHYS_WALKING,
    ClientActorMirror,
    MirroredActor,
    build_rpc_bunch,
    get_weapon_accessories,
    get_weapon_class,
    pack_server_move_view,
)


# ---------------------------------------------------------------------------
# Helpers: Ephemeral TCP Ports, Bishop/Realm KFX TCP Client
# ---------------------------------------------------------------------------

def allocate_free_tcp_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def build_bishop_login_req(username: str, password: str) -> bytes:
    buf = bytearray(0x89)
    buf[0] = 0x00
    buf[1:33] = pack_cstr(username, 32)
    buf[0x21:0x61] = pack_cstr(md5_upper(password), 64)
    buf[0x61:0x81] = pack_cstr("", 32)
    struct.pack_into("<II", buf, 0x81, 0, 2)
    return bytes(buf)


async def connect_kfx(host: str, port: int, cipher: KSGCipherTable) -> KFXStream:
    reader, writer = await asyncio.open_connection(host, port)
    stream = KFXStream(reader, writer, cipher, is_server=False)
    await stream.client_handshake()
    return stream


async def recv_until_opcode(stream: KFXStream, target_op: int, timeout: float = 5.0) -> bytes:
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        rem = deadline - asyncio.get_running_loop().time()
        if rem <= 0:
            raise TimeoutError(f"Timed out waiting for S2C opcode 0x{target_op:02X}")
        pkt = await asyncio.wait_for(stream.read_packet(), timeout=rem)
        if pkt and pkt[0] == target_op:
            return pkt


async def bishop_and_realm_login(
    *,
    bishop_port: int,
    cipher: KSGCipherTable,
    username: str,
    password: str,
    role_name: str,
    body_type: int,
    head_type: int,
    coat_type: int,
    trousers_type: int,
) -> Dict[str, Any]:
    """Authenticate via Bishop TCP -> connect to Realm TCP -> CreateRole -> Join Channel 1."""
    b_stream = await connect_kfx("127.0.0.1", bishop_port, cipher)
    try:
        await b_stream.send_packet(build_bishop_login_req(username, password))
        resp = await recv_until_opcode(b_stream, 0x01)
        assert len(resp) == 0x2D
        res = struct.unpack_from("<i", resp, 1)[0]
        cookie = struct.unpack_from("<i", resp, 0x21)[0]
        acc_role_id = struct.unpack_from("<i", resp, 0x25)[0]
        assert res == 1 and cookie != 0, f"Bishop login failed for {username}: res={res}"

        rl = await recv_until_opcode(b_stream, 0xFA)
        assert struct.unpack_from("<H", rl, 5)[0] >= 1
        realm_port = struct.unpack_from("!H", rl, 7 + 2)[0]
        realm_ip = socket.inet_ntoa(rl[7 + 4 : 7 + 8])
    finally:
        await b_stream.close()

    r_stream = await connect_kfx(realm_ip, realm_port, cipher)
    await r_stream.send_packet(struct.pack("<BII", 0x00, acc_role_id, cookie))
    assert struct.unpack_from("<i", await recv_until_opcode(r_stream, 0x00), 1)[0] == 1

    create_role_pkt = (
        bytes([0x02])
        + pack_cstr(role_name, 32)
        + struct.pack("<IIII", body_type, head_type, coat_type, trousers_type)
    )
    await r_stream.send_packet(create_role_pkt)
    assert struct.unpack_from("<i", await recv_until_opcode(r_stream, 0x02), 1)[0] == 1

    login_realm_pkt = struct.pack("<BIIBB", 0x03, acc_role_id, cookie, 0, 0) + pack_cstr("my", 32)
    await r_stream.send_packet(login_realm_pkt)
    assert struct.unpack_from("<ii", await recv_until_opcode(r_stream, 0x03), 1) == (1, 0)
    ch_list = await recv_until_opcode(r_stream, 0x04)
    assert struct.unpack_from("<i", ch_list, 1)[0] >= 1

    # Join Channel 1
    await r_stream.send_packet(struct.pack("<BB", 0x05, 1))
    jc = await recv_until_opcode(r_stream, 0x05)
    assert len(jc) == 0x11D and struct.unpack_from("<i", jc, 1)[0] == 1
    role_id = struct.unpack_from("<i", jc, 5)[0]
    got_name = unpack_cstr(jc, 9, 32)
    assert got_name == role_name, f"Expected role_name={role_name!r}, got {got_name!r}"
    initial_csp, initial_gp = struct.unpack_from("<ii", jc, 0x115)

    # Drain auto-pushed ChannelPlayerList (0x08)
    await recv_until_opcode(r_stream, 0x08)

    return {
        "stream": r_stream,
        "role_id": role_id,
        "role_name": role_name,
        "cookie": cookie,
        "initial_csp": initial_csp,
        "initial_gp": initial_gp,
    }


# ---------------------------------------------------------------------------
# Real OS UDP UE2.5 Build 3369 Client Simulator
# ---------------------------------------------------------------------------

def vec_dist(a: Tuple[float, float, float], b: Tuple[float, float, float]) -> float:
    return math.sqrt((a[0] - b[0]) ** 2 + (a[1] - b[1]) ** 2 + (a[2] - b[2]) ** 2)


def rotator_diff(a: int, b: int) -> int:
    d = ((int(a) - int(b) + 32768) & 0xFFFF) - 32768
    return abs(d)


class SimulatedUE2UDPClient(asyncio.DatagramProtocol):
    """Real asyncio UDP socket speaking UE2.5 build 3369 bitstream to UE2MatchServer."""

    def __init__(self, name: str, server_addr: Tuple[str, int], pkgmap: PackageMap) -> None:
        self.name = name
        self.server_addr = server_addr
        self.pkgmap = pkgmap
        self.conn = UE2ConnectionState(resend_interval=0.25, keepalive_interval=0.15)
        self.mirror = ClientActorMirror(pkgmap)

        self.transport: Optional[asyncio.DatagramTransport] = None
        self._flush_task: Optional[asyncio.Task[None]] = None
        self._rx_event = asyncio.Event()

        self.control_messages: List[str] = []
        self.uses_entries: List[Dict[str, str]] = []
        self.challenge_params: Optional[Dict[str, str]] = None
        self.welcome_params: Optional[Dict[str, str]] = None
        self.datagrams_in: int = 0
        self.datagrams_out: int = 0
        self._move_ts: float = 1.0
        self._closed: bool = False

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: self,
            local_addr=("127.0.0.1", 0),
        )
        self.transport = transport
        self._flush_task = loop.create_task(self._flush_loop(), name=f"ue2-sim-{self.name}")

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        self.datagrams_in += 1
        bunches = self.conn.receive_raw_packet(data, now=time.monotonic())
        for bunch in bunches:
            if bunch.ch_index == 0 or bunch.ch_type == CHTYPE_CONTROL:
                for line in decode_control_bunch(bunch):
                    self.control_messages.append(line)
                    cmd, rest = parse_control_command(line)
                    if cmd == "CHALLENGE":
                        self.challenge_params = parse_kv_params(rest)
                    elif cmd == "USES":
                        self.uses_entries.append(parse_kv_params(rest))
                    elif cmd == "WELCOME":
                        self.welcome_params = parse_kv_params(rest)
            elif bunch.ch_type == CHTYPE_ACTOR:
                self.mirror.process_bunch(bunch)
                if bunch.b_close:
                    self.conn.reset_channel(bunch.ch_index)
        self._rx_event.set()
        self.flush_now()

    def error_received(self, exc: Exception) -> None:
        pass

    def flush_now(self) -> None:
        if self._closed or self.transport is None or self.transport.is_closing():
            return
        pkts = self.conn.flush(now=time.monotonic())
        for pkt in pkts:
            self.transport.sendto(pkt, self.server_addr)
            self.datagrams_out += 1

    async def _flush_loop(self) -> None:
        try:
            while not self._closed:
                self.flush_now()
                await asyncio.sleep(1.0 / 60.0)
        except asyncio.CancelledError:
            pass

    async def wait_for(
        self,
        predicate: Callable[[], Any],
        *,
        timeout: float = 5.0,
        desc: str = "condition",
    ) -> Any:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while True:
            val = predicate()
            if val:
                return val
            rem = deadline - loop.time()
            if rem <= 0:
                raise TimeoutError(f"[{self.name}] Timed out waiting for: {desc}")
            self._rx_event.clear()
            try:
                await asyncio.wait_for(self._rx_event.wait(), timeout=min(0.05, rem))
            except asyncio.TimeoutError:
                pass

    async def connect_and_join(self, *, url: str, expected_map: str) -> None:
        """Complete full UE2.5 build 3369 handshake: HELLO -> CHALLENGE -> NETSPEED -> LOGIN -> USES -> WELCOME -> JOIN."""
        # 1. HELLO (exact wire text captured from real CS.exe)
        self.conn.queue_control_message(
            "HELLO REVISION=0 MINVER=3180 VER=3369",
            b_open=True,
        )
        self.flush_now()

        # 2. CHALLENGE
        chal = await self.wait_for(
            lambda: self.challenge_params,
            timeout=5.0,
            desc="S2C CHALLENGE",
        )
        assert int(chal.get("VER", "0")) == 3369, f"Unexpected CHALLENGE VER: {chal}"
        challenge_val = int(chal["CHALLENGE"])
        resp_val = challenge_response(challenge_val)

        # 3. NETSPEED + LOGIN
        self.conn.queue_control_message("NETSPEED 9636")
        self.conn.queue_control_message(f"LOGIN RESPONSE={resp_val} URL={url}")
        self.flush_now()

        # 4. USES + WELCOME
        welcome = await self.wait_for(
            lambda: self.welcome_params,
            timeout=5.0,
            desc="S2C WELCOME",
        )
        assert welcome.get("LEVEL", "").lower() == expected_map.lower(), (
            f"Expected WELCOME LEVEL={expected_map}, got {welcome}"
        )
        assert len(self.uses_entries) == len(self.pkgmap.entries), (
            f"Expected {len(self.pkgmap.entries)} USES entries, got {len(self.uses_entries)}"
        )
        # Verify every USES package name & GUID matches our PackageMap order
        for idx, (u_kv, p_entry) in enumerate(zip(self.uses_entries, self.pkgmap.entries)):
            assert u_kv.get("PKG", "").lower() == p_entry.name.lower(), (
                f"USES[{idx}] package mismatch: {u_kv} vs {p_entry.name}"
            )
            assert u_kv.get("GUID", "").upper() == p_entry.guid.upper(), (
                f"USES[{idx}] GUID mismatch for {p_entry.name}"
            )

        # 5. JOIN
        self.conn.queue_control_message("JOIN")
        self.flush_now()

        # 6. Wait for initial Actor replication (PC, GRI, 2 TeamInfos, own PRI, own Pawn, own Weapon + initial RPCs)
        await self.wait_for(
            lambda: (
                self.mirror.get_own_pc() is not None
                and self.mirror.get_own_pawn() is not None
                and self.mirror.get_own_weapon() is not None
                and len(self.mirror.find_by_class("GameReplicationInfo")) >= 1
                and len(self.mirror.find_by_class("TeamInfo")) >= 2
                and len(self.mirror.find_by_class("PlayerReplicationInfo")) >= 1
                and any(r.name.lower() == "clientrestart" for r in self.mirror.all_rpcs)
            ),
            timeout=5.0,
            desc="initial PC/GRI/TeamInfo/PRI/Pawn/Weapon & ClientReStart",
        )

    def get_pri_by_name(self, player_name: str) -> Optional[MirroredActor]:
        low = player_name.lower()
        for pri in self.mirror.find_by_class("PlayerReplicationInfo"):
            pname = str(pri.get("PlayerName", 0, "") or "")
            if pname.lower() == low:
                return pri
        return None

    def get_pawn_for_player(self, player_name: str) -> Optional[MirroredActor]:
        """Resolve a player's active KFXPawn by matching Pawn.PlayerReplicationInfo -> PRI channel."""
        pri = self.get_pri_by_name(player_name)
        if pri is None:
            return None
        for pawn in self.mirror.find_by_class("Pawn"):
            pri_ref = pawn.get("PlayerReplicationInfo")
            if pri_ref is not None and getattr(pri_ref, "is_dynamic", False) and pri_ref.channel_index == pri.ch_index:
                return pawn
        return None

    def get_team_info(self, team_index: int) -> Optional[MirroredActor]:
        for ti in self.mirror.find_by_class("TeamInfo"):
            if int(ti.get("TeamIndex", 0, -1)) == team_index:
                return ti
        return None

    def send_server_move(
        self,
        location: Tuple[float, float, float],
        rotation: Tuple[int, int, int],
        *,
        velocity: Tuple[float, float, float] = (0.0, 0.0, 0.0),
        physics: int = PHYS_WALKING,
        crouch: bool = False,
        jump: bool = False,
    ) -> None:
        pc = self.mirror.get_own_pc()
        assert pc is not None, f"[{self.name}] Missing own PlayerController channel"
        self._move_ts += 0.05
        view_int = pack_server_move_view(rotation[0], rotation[1])
        bunch = build_rpc_bunch(
            pc.ch_index,
            self.pkgmap,
            pc.class_cache,
            "ServerMove",
            kwargs={
                "TimeStamp": self._move_ts,
                "InAccel": (0.0, 0.0, 0.0),
                "ClientLoc": location,
                "NewbRun": True,
                "NewbDuck": crouch,
                "NewbJumpStatus": jump,
                "NewbDoubleJump": False,
                "DoubleClickMove": 0,
                "ClientRoll": (int(rotation[2]) >> 8) & 0xFF,
                "View": view_int,
                "OldTimeDelta": 0,
                "OldAccel": 0,
                "Velocity": velocity,
                "Physics": physics,
            },
            force_reliable=True,
        )
        self.conn.queue_bunch(bunch)
        self.flush_now()

    def send_start_fire(self, mode: int = 0) -> None:
        weap = self.mirror.get_own_weapon()
        assert weap is not None, f"[{self.name}] Missing own Weapon channel"
        bunch = build_rpc_bunch(
            weap.ch_index,
            self.pkgmap,
            weap.class_cache,
            "ServerStartFire",
            kwargs={"Mode": int(mode)},
            force_reliable=True,
        )
        self.conn.queue_bunch(bunch)
        self.flush_now()

    def send_stop_fire(self, mode: int = 0) -> None:
        weap = self.mirror.get_own_weapon()
        assert weap is not None, f"[{self.name}] Missing own Weapon channel"
        bunch = build_rpc_bunch(
            weap.ch_index,
            self.pkgmap,
            weap.class_cache,
            "ServerStopFire",
            kwargs={"Mode": int(mode)},
            force_reliable=True,
        )
        self.conn.queue_bunch(bunch)
        self.flush_now()

    async def disconnect_and_close(self) -> None:
        if self._closed:
            return
        try:
            self.conn.queue_control_message("DISCONNECT", b_close=True)
            self.flush_now()
            await asyncio.sleep(0.08)
        finally:
            self._closed = True
            if self._flush_task is not None:
                self._flush_task.cancel()
                try:
                    await self._flush_task
                except asyncio.CancelledError:
                    pass
                self._flush_task = None
            if self.transport is not None and not self.transport.is_closing():
                self.transport.close()


# ---------------------------------------------------------------------------
# Main Two-Player Live Multiplayer Simulation Test Suite
# ---------------------------------------------------------------------------

async def run_multiplayer_match_test() -> None:
    # Verify UDP 7777 is free before starting so we verify exact port=7777 allocation
    assert is_udp_port_available(7777), (
        "UDP port 7777 is already bound by another process; stop any running server before running this test"
    )

    cfg = load_config(BASE_DIR / "config.json")
    cfg["bind_host"] = "127.0.0.1"
    cfg["public_ip"] = "127.0.0.1"
    cfg["bishop_port"] = allocate_free_tcp_port()
    cfg["realm_port"] = allocate_free_tcp_port()
    cfg["http_port"] = allocate_free_tcp_port()
    cfg["match_server"]["enabled"] = True
    cfg["match_server"]["mode"] = "ue2_multiplayer"
    cfg["match_server"]["spawn_dedicated_cs_exe"] = False
    cfg["match_server"]["port_range_start"] = 7777
    cfg["match_server"]["port_range_end"] = 7795
    cfg["match_server"]["tick_hz"] = 30.0
    cfg["match_server"]["respawn_delay"] = 0.6
    cfg["match_server"]["client_timeout"] = 30.0

    # Strict guard proving NO standalone CS.exe or external subprocess is ever spawned
    popen_calls: List[Any] = []
    orig_popen = subprocess.Popen

    def _forbid_popen(*args: Any, **kwargs: Any) -> Any:
        popen_calls.append((args, kwargs))
        raise AssertionError(f"Unexpected subprocess.Popen call during ue2_multiplayer match: {args!r}")

    subprocess.Popen = _forbid_popen  # type: ignore[assignment]

    udp_p1: Optional[SimulatedUE2UDPClient] = None
    udp_p2: Optional[SimulatedUE2UDPClient] = None
    r1: Optional[KFXStream] = None
    r2: Optional[KFXStream] = None

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "csg.db"
            cfg["database_path"] = str(db_path)

            app = CSGServerApp(cfg, BASE_DIR)
            await app.start()
            try:
                cipher = app.cipher
                print(
                    f"[PASS] 1. CSGServerApp started in ue2_multiplayer mode "
                    f"(Bishop={cfg['bishop_port']}, Realm={cfg['realm_port']}, HTTP={cfg['http_port']})"
                )

                # -----------------------------------------------------------
                # 2. Bishop -> Realm -> Channel 1 -> Room #1 (2 Players)
                # -----------------------------------------------------------
                p1 = await bishop_and_realm_login(
                    bishop_port=cfg["bishop_port"],
                    cipher=cipher,
                    username="brrbrrpatapim",
                    password="password123",
                    role_name="brrbrrpatapim",
                    body_type=1,
                    head_type=6554721,
                    coat_type=6620247,
                    trousers_type=6685803,
                )
                r1 = p1["stream"]

                p2 = await bishop_and_realm_login(
                    bishop_port=cfg["bishop_port"],
                    cipher=cipher,
                    username="random_player",
                    password="password456",
                    role_name="random_player",
                    body_type=2,
                    head_type=6559724,
                    coat_type=6625247,
                    trousers_type=6690803,
                )
                r2 = p2["stream"]

                # brrbrrpatapim creates Room #1: map_id=1 (DF-DiTieZhan), game_mode=1 (Team Deathmatch / KFXMeleeGame)
                create_room_pkt = (
                    bytes([0x09])
                    + pack_cstr("Live UE2 Arena", 32)
                    + pack_cstr("", 32)
                    + struct.pack("<IIIIBBI", 1, 1, 0, 8, 1, 0, 0xFFFFFFFF)
                )
                await r1.send_packet(create_room_pkt)
                crm = await recv_until_opcode(r1, 0x09)
                assert struct.unpack_from("<i", crm, 1)[0] == 1
                room_id = struct.unpack_from("<i", crm, 5)[0]
                assert room_id == 1, f"Expected Room #1, got Room #{room_id}"
                await recv_until_opcode(r1, 0x0B)
                await recv_until_opcode(r1, 0x0E)

                # random_player joins Room #1 -> switches to Red Team (team_id=1) -> Ready (1)
                await r2.send_packet(struct.pack("<BI", 0x0B, room_id) + pack_cstr("", 32))
                jr2 = await recv_until_opcode(r2, 0x0C)
                assert struct.unpack_from("<i", jr2, 1)[0] == 1
                await recv_until_opcode(r2, 0x0E)
                await recv_until_opcode(r1, 0x0F)

                await r2.send_packet(struct.pack("<Bi", 0x0E, 1))  # Red Team
                ch_t2 = await recv_until_opcode(r2, 0x12)
                assert struct.unpack_from("<i", ch_t2, 1)[0] == 1
                await recv_until_opcode(r1, 0x13)

                await r2.send_packet(struct.pack("<Bi", 0x0F, 1))  # Ready=1
                rdy1 = await recv_until_opcode(r1, 0x14)
                assert struct.unpack_from("<Ii", rdy1, 1) == (p2["role_id"], 1)
                await recv_until_opcode(r2, 0x14)

                # brrbrrpatapim (Blue host) starts the match!
                await r1.send_packet(bytes([0x10]))
                gs1 = await recv_until_opcode(r1, 0x15)
                gs2 = await recv_until_opcode(r2, 0x15)

                res1 = struct.unpack_from("<i", gs1, 1)[0]
                ip1 = socket.inet_ntoa(gs1[5:9])
                port1 = struct.unpack_from("!H", gs1, 9)[0]
                res2 = struct.unpack_from("<i", gs2, 1)[0]
                ip2 = socket.inet_ntoa(gs2[5:9])
                port2 = struct.unpack_from("!H", gs2, 9)[0]

                assert (res1, ip1, port1) == (1, "127.0.0.1", 7777), (
                    f"Player 1 GameStartCommond mismatch: {(res1, ip1, port1)}"
                )
                assert (res2, ip2, port2) == (1, "127.0.0.1", 7777), (
                    f"Player 2 GameStartCommond mismatch: {(res2, ip2, port2)}"
                )

                # Drain room state=4 (playing) updates
                cri1 = await recv_until_opcode(r1, 0x0B)
                cri2 = await recv_until_opcode(r2, 0x0B)
                assert cri1[0x48] == 4 and cri2[0x48] == 4

                # Assert in-process UE2MatchServer is active and ZERO CS.exe processes were spawned
                inst = app.match_manager.get_match(1, room_id)
                assert inst is not None and inst.mode == "ue2_multiplayer"
                assert inst.proc is None, "Standalone CS.exe process must NOT be spawned!"
                assert inst.ue2_server is not None and inst.ue2_server.running
                assert len(popen_calls) == 0, f"Unexpected subprocess spawns: {popen_calls}"
                ue2_srv = inst.ue2_server
                print(
                    f"[PASS] 2. Bishop -> Realm -> Room #{room_id} StartGame: both players received "
                    f"S2C 0x15(result=1, 127.0.0.1:{port1}), zero CS.exe spawned"
                )

                # -----------------------------------------------------------
                # 3. Real UDP UE2.5 Handshake & Actor Spawning (Both Players)
                # -----------------------------------------------------------
                pkgmap = get_cached_package_map(ue2_srv.map_name, game_dir=ue2_srv.game_dir)
                udp_p1 = SimulatedUE2UDPClient("brrbrrpatapim", (ip1, port1), pkgmap)
                udp_p2 = SimulatedUE2UDPClient("random_player", (ip2, port2), pkgmap)
                await udp_p1.start()
                await udp_p2.start()

                url1 = (
                    f"{ip1}:{port1}/Index.ut2?Session={p1['cookie']}?mapid=1"
                    f"?Name={p1['role_name']}?RoleID={p1['role_id']}?Team=0"
                )
                url2 = (
                    f"{ip2}:{port2}/Index.ut2?Session={p2['cookie']}?mapid=1"
                    f"?Name={p2['role_name']}?RoleID={p2['role_id']}?Team=1"
                )

                await udp_p1.connect_and_join(url=url1, expected_map="DF-DiTieZhan")
                await udp_p2.connect_and_join(url=url2, expected_map="DF-DiTieZhan")

                # Wait until BOTH clients see ALL shared actors: GRI, 2 PRIs, 2 KFXPawns
                for sim in (udp_p1, udp_p2):
                    await sim.wait_for(
                        lambda s=sim: (
                            s.get_pri_by_name("brrbrrpatapim") is not None
                            and s.get_pri_by_name("random_player") is not None
                            and s.get_pawn_for_player("brrbrrpatapim") is not None
                            and s.get_pawn_for_player("random_player") is not None
                        ),
                        timeout=5.0,
                        desc="both PRIs & both KFXPawns replicated",
                    )

                # Verify PC, GRI, PRIs, and KFXPawns on both clients
                for sim, own_name, own_team in (
                    (udp_p1, "brrbrrpatapim", 0),
                    (udp_p2, "random_player", 1),
                ):
                    pc = sim.mirror.get_own_pc()
                    assert pc is not None and "player" in pc.class_name.lower()
                    assert pc.get("bNetOwner") is True
                    gris = sim.mirror.find_by_class("GameReplicationInfo")
                    assert len(gris) == 1
                    pri_blue = sim.get_pri_by_name("brrbrrpatapim")
                    pri_red = sim.get_pri_by_name("random_player")
                    assert pri_blue is not None and int(pri_blue.get("TeamID", 0, -1)) == 0
                    assert pri_red is not None and int(pri_red.get("TeamID", 0, -1)) == 1

                    # Verify owner-only isolation: each client sees ONLY its own PC & Weapon
                    pcs = [
                        a for a in sim.mirror.actors.values()
                        if not a.closed
                        and "player" in a.class_name.lower()
                        and "replicationinfo" not in a.class_name.lower()
                    ]
                    assert len(pcs) == 1, f"[{own_name}] Expected 1 own PC, got {len(pcs)}"

                    own_pawn = sim.get_pawn_for_player(own_name)
                    assert own_pawn is not None and own_pawn.get("bNetOwner") is True
                    assert int(own_pawn.get("Health", 0, 0)) == 100
                    # Verify PawnAttribute.csv physical dimensions (fixes sunken feet & matches retail physics)
                    assert abs(float(own_pawn.get("DrawScale", 0, 0.0)) - 0.85) < 0.01
                    assert abs(float(own_pawn.get("CollisionHeight", 0, 0.0)) - 92.0) < 0.1
                    assert abs(float(own_pawn.get("CollisionRadius", 0, 0.0)) - 55.0) < 0.1
                    assert abs(float(own_pawn.get("GroundSpeed", 0, 0.0)) - 520.0) < 0.1
                    assert abs(float(own_pawn.get("JumpZ", 0, 0.0)) - 763.0) < 0.1

                # Verify BOTH pawns spawned at real DF-DiTieZhan.ut2 PlayerStart coordinates
                blue_spawns = ue2_srv.map_spawns.blue_spawns
                red_spawns = ue2_srv.map_spawns.red_spawns
                assert len(blue_spawns) > 0 and len(red_spawns) > 0

                p1_pawn_on_p1 = udp_p1.get_pawn_for_player("brrbrrpatapim")
                p2_pawn_on_p2 = udp_p2.get_pawn_for_player("random_player")
                assert p1_pawn_on_p1 is not None and p2_pawn_on_p2 is not None

                p1_spawn = tuple(p1_pawn_on_p1.get("Location", 0, p1_pawn_on_p1.spawn_location))
                p2_spawn = tuple(p2_pawn_on_p2.get("Location", 0, p2_pawn_on_p2.spawn_location))

                min_blue_d = min(vec_dist(p1_spawn, sp.location) for sp in blue_spawns)
                min_red_d = min(vec_dist(p2_spawn, sp.location) for sp in red_spawns)
                assert min_blue_d < 2.0, f"brrbrrpatapim spawn {p1_spawn} not at a real Blue PlayerStart (d={min_blue_d})"
                assert min_red_d < 2.0, f"random_player spawn {p2_spawn} not at a real Red PlayerStart (d={min_red_d})"
                print(
                    f"[PASS] 3. Real UDP UE2.5 Handshake ({len(pkgmap.entries)} USES pkgs) & Actor Spawns: "
                    f"PC/GRI/2xPRI/2xKFXPawn at real DF-DiTieZhan PlayerStarts "
                    f"(Blue={tuple(round(c, 1) for c in p1_spawn)}, Red={tuple(round(c, 1) for c in p2_spawn)})"
                )

                # Verify 3P weapon accessory mapping from WeaponAttribute.csv (e.g. M249=13 NOT 10 Hammer!)
                assert get_weapon_class(65542, game_dir=ue2_srv.game_dir) == ("KFXWeapons.KFXWeapMachinegun", 13)
                assert get_weapon_class(196617, game_dir=ue2_srv.game_dir) == ("KFXWeapons.KFXWeapMelee", 10)
                assert get_weapon_class(65537, game_dir=ue2_srv.game_dir) == ("KFXWeapons.KFXWeapRifle", 1)
                assert get_weapon_accessories(65542, game_dir=ue2_srv.game_dir)[0] == 13

                # -----------------------------------------------------------
                # 4. Bidirectional Fast-Sync Movement Test (Zero-Wait Event Relay + No Owner Echo + Upright Body)
                # -----------------------------------------------------------
                target_p1_loc = (p1_spawn[0] + 120.0, p1_spawn[1] + 80.0, p1_spawn[2])
                target_p1_yaw = 16384  # 90 deg
                target_p1_pitch = 14000  # looking sharply upward (must go to ViewPitch, NEVER Pawn.Rotation.Pitch!)
                t_send_p1 = time.perf_counter()
                udp_p1.send_server_move(
                    target_p1_loc,
                    (target_p1_pitch, target_p1_yaw, 0),
                    velocity=(180.0, 120.0, 0.0),
                    physics=0,  # simulate ShortServerMove omitting Physics -> must replicate PHYS_WALKING (1), NEVER 0!
                )

                def _p2_sees_p1_move() -> bool:
                    pawn = udp_p2.get_pawn_for_player("brrbrrpatapim")
                    if pawn is None:
                        return False
                    loc = pawn.get("Location")
                    rot = pawn.get("Rotation")
                    vel = pawn.get("Velocity")
                    if loc is None or rot is None or vel is None:
                        return False
                    return (
                        vec_dist(loc, target_p1_loc) <= 2.0
                        and rotator_diff(rot[1], target_p1_yaw) <= 300
                        and vec_dist(vel, (180.0, 120.0, 0.0)) <= 3.0
                    )

                await udp_p2.wait_for(
                    _p2_sees_p1_move,
                    timeout=4.0,
                    desc="random_player sees brrbrrpatapim ServerMove position/rotation/velocity sync",
                )
                relay_p1_ms = (time.perf_counter() - t_send_p1) * 1000.0
                assert relay_p1_ms < 50.0, f"Event-driven P1->P2 relay too slow: {relay_p1_ms:.1f}ms"

                # Verify remote pawn stays upright (Rotation.Pitch == 0, Roll == 0), ViewPitch tracks upward aim,
                # and Physics == PHYS_WALKING (never PHYS_NONE=0) with Base=LevelInfo0 for smooth 60FPS extrapolation!
                p1_on_p2 = udp_p2.get_pawn_for_player("brrbrrpatapim")
                assert p1_on_p2 is not None
                p1_rot_on_p2 = p1_on_p2.get("Rotation")
                assert p1_rot_on_p2[0] == 0 and p1_rot_on_p2[2] == 0, (
                    f"Pawn body tilted vertically! Expected (0, yaw, 0), got {p1_rot_on_p2}"
                )
                assert int(p1_on_p2.get("ViewPitch", 0, -1)) == ((target_p1_pitch & 0xFFFF) >> 8), (
                    f"ViewPitch mismatch: got {p1_on_p2.get('ViewPitch')} expected {(target_p1_pitch & 0xFFFF) >> 8}"
                )
                assert int(p1_on_p2.get("Physics", 0, 0)) == PHYS_WALKING, (
                    f"Remote pawn Physics must be PHYS_WALKING (1), got {p1_on_p2.get('Physics')}"
                )
                assert p1_on_p2.get("Base") is not None, "Walking remote pawn must have Base=LevelInfo0"

                # Verify server did NOT echo stale Location back to owning AutonomousProxy client
                # (prevents UE2 local movement rubber-banding!)
                own_p1_loc_after = tuple(p1_pawn_on_p1.get("Location", 0, p1_spawn))
                assert vec_dist(own_p1_loc_after, p1_spawn) < 2.0, (
                    f"Server echoed Location back to owning AutonomousProxy pawn: {own_p1_loc_after} vs spawn {p1_spawn}"
                )

                # Now random_player moves -> assert brrbrrpatapim receives synced position/rotation/velocity immediately
                target_p2_loc = (p2_spawn[0] - 110.0, p2_spawn[1] + 95.0, p2_spawn[2])
                target_p2_yaw = 32768  # 180 deg
                target_p2_pitch = 512
                t_send_p2 = time.perf_counter()
                udp_p2.send_server_move(
                    target_p2_loc,
                    (target_p2_pitch, target_p2_yaw, 0),
                    velocity=(-165.0, 140.0, 0.0),
                )

                def _p1_sees_p2_move() -> bool:
                    pawn = udp_p1.get_pawn_for_player("random_player")
                    if pawn is None:
                        return False
                    loc = pawn.get("Location")
                    rot = pawn.get("Rotation")
                    vel = pawn.get("Velocity")
                    if loc is None or rot is None or vel is None:
                        return False
                    return (
                        vec_dist(loc, target_p2_loc) <= 2.0
                        and rotator_diff(rot[1], target_p2_yaw) <= 300
                        and vec_dist(vel, (-165.0, 140.0, 0.0)) <= 3.0
                    )

                await udp_p1.wait_for(
                    _p1_sees_p2_move,
                    timeout=4.0,
                    desc="brrbrrpatapim sees random_player ServerMove position/rotation/velocity sync",
                )
                relay_p2_ms = (time.perf_counter() - t_send_p2) * 1000.0
                assert relay_p2_ms < 50.0, f"Event-driven P2->P1 relay too slow: {relay_p2_ms:.1f}ms"
                print(
                    f"[PASS] 4. Bidirectional Fast-Sync Movement over real UDP "
                    f"(P1->P2={relay_p1_ms:.2f}ms, P2->P1={relay_p2_ms:.2f}ms, zero owner rubber-band echo): "
                    f"brrbrrpatapim->{tuple(round(c, 1) for c in target_p1_loc)} yaw={target_p1_yaw} & "
                    f"random_player->{tuple(round(c, 1) for c in target_p2_loc)} yaw={target_p2_yaw}"
                )

                # -----------------------------------------------------------
                # 5. Shooting, Hit, Kill, Death, Scoreboard Sync & Respawn Test
                # -----------------------------------------------------------
                # Verify distance is within AK47 effective range (< 8064u)
                combat_dist = vec_dist(target_p1_loc, target_p2_loc)
                assert combat_dist < 8000.0, f"Spawn distance {combat_dist:.1f} exceeds AK47 range"

                # 5a. Chest shot: brrbrrpatapim aims at random_player's chest and fires 1 shot
                eye_p1 = (target_p1_loc[0], target_p1_loc[1], target_p1_loc[2] + PAWN_STAND_EYE_OFFSET)
                chest_p2 = (target_p2_loc[0], target_p2_loc[1], target_p2_loc[2] + 12.0)
                chest_rot = vector_to_rotator(
                    chest_p2[0] - eye_p1[0],
                    chest_p2[1] - eye_p1[1],
                    chest_p2[2] - eye_p1[2],
                )
                udp_p1.send_server_move(target_p1_loc, chest_rot)
                await asyncio.sleep(0.08)
                udp_p1.send_start_fire(mode=0)
                await asyncio.sleep(0.04)
                udp_p1.send_stop_fire(mode=0)

                def _p2_damaged() -> Optional[int]:
                    pawn = udp_p2.get_pawn_for_player("random_player")
                    if pawn is None:
                        return None
                    hp = int(pawn.get("Health", 0, 100))
                    return hp if 0 < hp < 100 else None

                hp_after_hit = await udp_p2.wait_for(
                    _p2_damaged,
                    timeout=4.0,
                    desc="random_player takes non-lethal chest damage (0 < Health < 100)",
                )
                assert 0 < hp_after_hit < 100

                # 5b. Headshot kill: aim directly at random_player's head (z + 35.0) and fire until dead
                head_p2 = (target_p2_loc[0], target_p2_loc[1], target_p2_loc[2] + 35.0)
                head_rot = vector_to_rotator(
                    head_p2[0] - eye_p1[0],
                    head_p2[1] - eye_p1[1],
                    head_p2[2] - eye_p1[2],
                )
                udp_p1.send_server_move(target_p1_loc, head_rot)
                await asyncio.sleep(0.18)  # Exceed AK47 fire-rate cooldown

                old_p2_pawn_on_p2 = udp_p2.get_pawn_for_player("random_player")
                assert old_p2_pawn_on_p2 is not None
                old_p2_pawn_ch = old_p2_pawn_on_p2.ch_index
                restarts_before = sum(
                    1 for r in udp_p2.mirror.all_rpcs if r.name.lower() == "clientrestart"
                )

                for _ in range(5):
                    udp_p1.send_start_fire(mode=0)
                    await asyncio.sleep(0.04)
                    udp_p1.send_stop_fire(mode=0)
                    cur_p = udp_p2.get_pawn_for_player("random_player")
                    if cur_p is not None and int(cur_p.get("Health", 0, 100)) <= 0:
                        break
                    await asyncio.sleep(0.16)

                # Assert death, ClientDying, kill feed RPC, PRI kills/deaths, and Blue TeamInfo Score == 1
                await udp_p2.wait_for(
                    lambda: (
                        (p := udp_p2.get_pawn_for_player("random_player")) is not None
                        and int(p.get("Health", 0, 100)) <= 0
                        and any(r.name.lower() == "clientdying" for r in udp_p2.mirror.all_rpcs)
                    ),
                    timeout=4.0,
                    desc="random_player death (Health <= 0 + ClientDying)",
                )

                for sim in (udp_p1, udp_p2):
                    await sim.wait_for(
                        lambda s=sim: (
                            (pb := s.get_pri_by_name("brrbrrpatapim")) is not None
                            and int(pb.get("fxKills", 0, 0)) == 1
                            and float(pb.get("Score", 0, 0.0)) == 1.0
                            and (pr := s.get_pri_by_name("random_player")) is not None
                            and int(pr.get("fxDeaths", 0, 0)) == 1
                            and float(pr.get("Deaths", 0, 0.0)) == 1.0
                            and bool(pr.get("bDeadStatus", 0, False)) is True
                            and (tb := s.get_team_info(0)) is not None
                            and float(tb.get("Score", 0, 0.0)) == 1.0
                            and any(
                                r.name.lower() == "kfxreceivelocalizedmessage"
                                for r in s.mirror.all_rpcs
                            )
                        ),
                        timeout=4.0,
                        desc="PRI kills=1/deaths=1, Blue TeamInfo score=1, and kill feed RPC",
                    )

                print(
                    f"[PASS] 5a. Combat Hit & Kill Sync: chest hit HP={hp_after_hit} -> headshot kill "
                    f"(Health=0, ClientDying, PRI brrbrrpatapim kills=1 / random_player deaths=1, Blue score=1)"
                )

                # 5c. Respawn Test: wait for respawn_delay (0.6s) -> full HP at real Red PlayerStart
                await udp_p2.wait_for(
                    lambda: (
                        sum(1 for r in udp_p2.mirror.all_rpcs if r.name.lower() == "clientrestart") > restarts_before
                        and (np := udp_p2.get_pawn_for_player("random_player")) is not None
                        and not np.closed
                        and int(np.get("Health", 0, 0)) == 100
                        and (pr := udp_p2.get_pri_by_name("random_player")) is not None
                        and bool(pr.get("bDeadStatus", 0, True)) is False
                    ),
                    timeout=4.0,
                    desc="random_player respawns with Health=100 + ClientReStart + bDeadStatus=False",
                )

                respawned_p2_own = udp_p2.get_pawn_for_player("random_player")
                assert respawned_p2_own is not None
                respawn_loc = tuple(respawned_p2_own.get("Location", 0, respawned_p2_own.spawn_location))
                min_red_respawn_d = min(vec_dist(respawn_loc, sp.location) for sp in red_spawns)
                assert min_red_respawn_d < 2.0, (
                    f"Respawned random_player location {respawn_loc} not at a real Red PlayerStart "
                    f"(min_d={min_red_respawn_d:.2f})"
                )

                # Also verify brrbrrpatapim sees random_player's respawned alive pawn at full HP!
                await udp_p1.wait_for(
                    lambda: (
                        (np := udp_p1.get_pawn_for_player("random_player")) is not None
                        and not np.closed
                        and int(np.get("Health", 0, 0)) == 100
                        and vec_dist(
                            tuple(np.get("Location", 0, np.spawn_location)),
                            respawn_loc,
                        ) <= 2.0
                    ),
                    timeout=4.0,
                    desc="brrbrrpatapim sees random_player respawned pawn at Red PlayerStart with Health=100",
                )
                print(
                    f"[PASS] 5b. Auto-Respawn Sync: random_player respawned with HP=100 "
                    f"(ch {old_p2_pawn_ch}->{respawned_p2_own.ch_index}) at real Red PlayerStart "
                    f"{tuple(round(c, 1) for c in respawn_loc)}"
                )

                # -----------------------------------------------------------
                # 6. Match End -> Realm Persistence (csg.db + S2C 0x1E)
                # -----------------------------------------------------------
                await udp_p1.disconnect_and_close()
                await udp_p2.disconnect_and_close()

                # Both clients receive S2C 0x1E GameEndAndUpdataRoleInfoRespond over Realm TCP
                ge1 = await recv_until_opcode(r1, 0x1E, timeout=5.0)
                ge2 = await recv_until_opcode(r2, 0x1E, timeout=5.0)
                assert len(ge1) == 0xA9 and len(ge2) == 0xA9

                (
                    k1, d1, hk1, _kk1, _sk1, v1, _du1, def1, gp1, lvl1, _place1, hon1
                ) = struct.unpack_from("<12I", ge1, 1)
                (
                    k2, d2, hk2, _kk2, _sk2, v2, _du2, def2, gp2, lvl2, _place2, hon2
                ) = struct.unpack_from("<12I", ge2, 1)

                assert (k1, d1, v1, def1) == (1, 0, 1, 0), (
                    f"Unexpected S2C 0x1E for brrbrrpatapim: kills={k1} deaths={d1} win={v1} loss={def1}"
                )
                assert hk1 >= 1, f"Expected headshot kill persisted for brrbrrpatapim, got head_kills={hk1}"
                assert gp1 > p1["initial_gp"] and hon1 > 0 and lvl1 >= 1

                assert (k2, d2, v2, def2) == (0, 1, 0, 1), (
                    f"Unexpected S2C 0x1E for random_player: kills={k2} deaths={d2} win={v2} loss={def2}"
                )
                assert gp2 > p2["initial_gp"] and hon2 > 0 and lvl2 >= 1

                # Verify Room state restored to waiting (0x0B room_state == 2)
                cri_after = await recv_until_opcode(r1, 0x0B, timeout=5.0)
                assert cri_after[0x48] in (2, 3), f"Expected waiting room_state after match end, got {cri_after[0x48]}"

                # Directly query SQLite csg.db to prove real persistence!
                con = sqlite3.connect(str(db_path))
                con.row_factory = sqlite3.Row
                try:
                    row1 = con.execute(
                        "SELECT * FROM roles WHERE role_name = ?", ("brrbrrpatapim",)
                    ).fetchone()
                    row2 = con.execute(
                        "SELECT * FROM roles WHERE role_name = ?", ("random_player",)
                    ).fetchone()
                    assert row1 is not None and row2 is not None
                    assert (
                        row1["kill_count"],
                        row1["death_count"],
                        row1["head_kill_count"],
                        row1["victory_count"],
                        row1["defeated_count"],
                        row1["honor_point"],
                        row1["game_cash"],
                    ) == (1, 0, hk1, 1, 0, hon1, gp1), f"SQLite mismatch for brrbrrpatapim: {dict(row1)}"
                    assert (
                        row2["kill_count"],
                        row2["death_count"],
                        row2["victory_count"],
                        row2["defeated_count"],
                        row2["honor_point"],
                        row2["game_cash"],
                    ) == (0, 1, 0, 1, hon2, gp2), f"SQLite mismatch for random_player: {dict(row2)}"
                finally:
                    con.close()

                # Verify UDP port 7777 was cleanly released (zero orphan sockets)
                deadline = asyncio.get_running_loop().time() + 3.0
                while not is_udp_port_available(7777):
                    if asyncio.get_running_loop().time() >= deadline:
                        raise AssertionError("UDP port 7777 was NOT released after match end!")
                    await asyncio.sleep(0.05)

                print(
                    f"[PASS] 6. Match End -> Realm Persistence & Cleanup: "
                    f"brrbrrpatapim(kills={k1}, head={hk1}, win={v1}, honor={hon1}, GP=+{gp1 - p1['initial_gp']}), "
                    f"random_player(deaths={d2}, loss={def2}, honor={hon2}, GP=+{gp2 - p2['initial_gp']}), "
                    f"S2C 0x1E + SQLite csg.db verified & UDP 7777 cleanly released!"
                )
                print("\n=== ALL 6 TWO-PLAYER LIVE UE2.5 MULTIPLAYER MATCH SUITES PASSED! ===")
            finally:
                if udp_p1 is not None:
                    await udp_p1.disconnect_and_close()
                if udp_p2 is not None:
                    await udp_p2.disconnect_and_close()
                if r1 is not None:
                    await r1.close()
                if r2 is not None:
                    await r2.close()
                await app.stop()
    finally:
        subprocess.Popen = orig_popen  # type: ignore[assignment]


if __name__ == "__main__":
    asyncio.run(run_multiplayer_match_test())

#!/usr/bin/env python3
"""
End-to-end automated protocol & HTTP API test suite for CSG Private Server.

Simulates TWO full CSO Malaysia clients using the exact KFXClientNetwork.dll
framing/handshake/static mode-0 cipher and KFXClient.dll binary packet formats against an
isolated live server instance (ephemeral ports + temporary SQLite DB).
"""
from __future__ import annotations

import asyncio
import json
import socket
import struct
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from server.crypto import (
    KSG_TABLE_LEN,
    KSGCipherTable,
    KFXStream,
    md5_upper,
    parse_handshake_payload,
    scramble_u32,
    unscramble_u32,
)
from server.main import CSGServerApp, load_config
from server.match_manager import MatchManager, is_client_only_engine_dll, is_udp_port_bound
from server.packets import (
    clamp_time32,
    encode_email_list_respond,
    pack_cstr,
    unpack_cstr,
)


def kfx_dll_mode0_reference(table: tuple[int, ...], data: bytes, static_key: int) -> bytes:
    """
    Independent exact replica of KFXClientNetwork.dll!0x10003610 -> 0x10003580 (mode=0).
    Uses a STATIC 32-bit key (never rolled across packets) and 32-bit wrapping (u + dwords).
    """
    buf = bytearray(data)
    u = static_key & 0xFFFFFFFF
    dwords = len(buf) >> 2
    rem = len(buf) & 3
    off = 0
    while dwords:
        dwords -= 1
        idx = ((u + dwords) & 0xFFFFFFFF) % KSG_TABLE_LEN
        u = (table[idx] + 0x2E6D23C1) & 0xFFFFFFFF
        v = struct.unpack_from("<I", buf, off)[0] ^ u
        struct.pack_into("<I", buf, off, v)
        off += 4
    u = (u ^ table[rem % KSG_TABLE_LEN]) & 0xFFFFFFFF
    for _ in range(rem):
        buf[off] ^= (u & 0xFF)
        off += 1
        u >>= 8
    return bytes(buf)


async def raw_read_frame(reader: asyncio.StreamReader) -> bytes:
    wire_len = struct.unpack("<H", await reader.readexactly(2))[0]
    assert wire_len >= 2
    return await reader.readexactly(wire_len - 2)


async def raw_write_frame(writer: asyncio.StreamWriter, payload: bytes) -> None:
    writer.write(struct.pack("<H", len(payload) + 2) + payload)
    await writer.drain()


def http_json(url: str, method: str = "GET", payload: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Content-Type": "application/json"} if payload is not None else {}
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as err:
        return err.code, json.loads(err.read().decode("utf-8"))


async def connect_kfx(host: str, port: int, cipher: KSGCipherTable) -> KFXStream:
    reader, writer = await asyncio.open_connection(host, port)
    stream = KFXStream(reader, writer, cipher, is_server=False)
    await stream.client_handshake()
    return stream


def build_bishop_login_req(username: str, password: str) -> bytes:
    buf = bytearray(0x89)
    buf[0] = 0x00
    buf[1:33] = pack_cstr(username, 32)
    buf[0x21:0x61] = pack_cstr(md5_upper(password), 64)
    buf[0x61:0x81] = pack_cstr("", 32)
    struct.pack_into("<II", buf, 0x81, 0, 2)
    return bytes(buf)


async def recv_until_opcode(stream: KFXStream, target_op: int, timeout: float = 3.0) -> bytes:
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        rem = deadline - asyncio.get_running_loop().time()
        if rem <= 0:
            raise TimeoutError(f"Timed out waiting for S2C opcode 0x{target_op:02X}")
        pkt = await asyncio.wait_for(stream.read_packet(), timeout=rem)
        if pkt and pkt[0] == target_op:
            return pkt


async def run_all_tests() -> None:
    # 1. Verify handshake scramble/unscramble round-trip & timestamp clamping
    for k in (0, 1, 0x12345678, 0xDEADBEEF, 0xFFFFFFFF, 0xA5A55A5A):
        assert unscramble_u32(scramble_u32(k)) == k, f"Scramble round-trip failed for {hex(k)}"
    assert clamp_time32(-10) == 0 and clamp_time32(2**32) == 0x7FFFFFFF
    # Post-2038 email timestamp must not overflow localtime() / struct packing
    em_future = encode_email_list_respond(1, [{
        "email_id": 1, "send_role_id": 0, "send_role_name": "Sys",
        "title": "Future", "created_at": 2**32 + 12345,
    }])
    assert struct.unpack_from("<I", em_future, 9 + 0x6C)[0] == 0x7FFFFFFF
    assert struct.unpack_from("<I", em_future, 9 + 0x74)[0] == 0x7FFFFFFF
    print("[PASS] 1. Handshake scramble_u32 / unscramble_u32 & 32-bit timestamp clamping")

    # 2. Boot isolated server stack on test ports (spawn_dedicated_cs_exe=False for CI safety)
    cfg = load_config(BASE_DIR / "config.json")
    cfg["bind_host"] = "127.0.0.1"
    cfg["public_ip"] = "127.0.0.1"
    cfg["bishop_port"] = 17451
    cfg["realm_port"] = 17452
    cfg["http_port"] = 18080
    cfg["match_server"]["mode"] = "virtual"
    cfg["match_server"]["spawn_dedicated_cs_exe"] = False

    # 1c. Verify MatchManager binary guards, UDP bind detector, and mode-filtered Random map selection
    engine_path = Path(cfg.get("client_dir", r"C:\Program Files (x86)\CSO Malaysia")) / "System" / "Engine.dll"
    if engine_path.exists():
        assert is_client_only_engine_dll(engine_path) is True, "Retail CSO Malaysia Engine.dll stub not detected"
    udp_probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_probe.bind(("0.0.0.0", 0))
    bound_port = udp_probe.getsockname()[1]
    assert is_udp_port_bound(bound_port) is True
    udp_probe.close()
    assert is_udp_port_bound(bound_port) is False

    with tempfile.TemporaryDirectory() as tmpdir:
        cfg["database_path"] = str(Path(tmpdir) / "test_csg.db")
        app = CSGServerApp(cfg, BASE_DIR)
        await app.start()
        try:
            cipher = app.cipher

            # Verify KFXMapMode.csv Random map filtering by game_mode
            for _ in range(10):
                assert app.gamedata.pick_map_for_mode(2, 0, reroll=True) in (7, 10)  # Death Match
                assert app.gamedata.pick_map_for_mode(4, 0, reroll=True) in (4, 10)  # Bomb Match
                assert app.gamedata.pick_map_for_mode(5, 0, reroll=True) in (9, 12)  # Occupation
            # Verify standalone CLI never includes ?Listen, -server, or -NULLRENDER
            sa_cmd = app.match_manager.build_standalone_command("BD-BianJingTuCheng", "KFXGame.KFXMeleeGame", 4, "Hero", 0)
            sa_joined = " ".join(sa_cmd)
            assert "?Listen" not in sa_joined and "-server" not in sa_joined and "-NULLRENDER" not in sa_joined
            assert "-updated" in sa_cmd and "LOG=NUL" in sa_cmd
            # Verify external_dedicated refuses retail client Engine.dll with ?Listen
            if engine_path.exists():
                ext_cfg = json.loads(json.dumps(cfg))
                ext_cfg["match_server"]["mode"] = "external_dedicated"
                ext_cfg["match_server"]["dedicated_server_exe"] = str(engine_path.parent / "CS.exe")
                ext_mm = MatchManager(ext_cfg, app.gamedata)
                _inst, ext_ready, ext_msg = await ext_mm.start_match_async(1, 99, 4, 1, 16)
                assert ext_ready is False and "ULevel::Listen" in ext_msg
            print("[PASS] 1c. MatchManager Engine.dll stub guard, UDP probe & KFXMapMode Random map filtering")

            # 1b. Verify 32-bit wrapping add in (u + dwords) % 5679 when u + dwords >= 2^32
            wrap_plain = b"\x00" * 8
            wrap_ct = cipher.crypt(wrap_plain, 0xFFFFFFFF)
            expected_u0 = (cipher.table[0] + 0x2E6D23C1) & 0xFFFFFFFF
            expected_u1 = (cipher.table[(expected_u0 + 0) % KSG_TABLE_LEN] + 0x2E6D23C1) & 0xFFFFFFFF
            assert struct.unpack("<II", wrap_ct) == (expected_u0, expected_u1), "32-bit wrap bug in (u + dwords)"
            assert wrap_ct == kfx_dll_mode0_reference(cipher.table, wrap_plain, 0xFFFFFFFF)
            assert cipher.crypt(wrap_ct, 0xFFFFFFFF) == wrap_plain
            print("[PASS] 1b. KSG cipher 32-bit (u + dwords) wrap & static-key symmetry")

            # 3. Verify HTTP Launcher API endpoints
            code, status_data = http_json("http://127.0.0.1:18080/api/auth/registration-status?launcher=1")
            assert code == 200 and status_data["available"] is True
            assert status_data["launcher"]["defaultGp"] == cfg["default_gp"]

            code, reg_data = http_json(
                "http://127.0.0.1:18080/api/auth/register",
                method="POST",
                payload={"username": "player1", "password": "secret123", "email": "p1@local.test"},
            )
            assert code == 201 and reg_data["username"] == "player1"

            code, news_data = http_json("http://127.0.0.1:18080/api/news")
            assert code == 200 and len(news_data["news"]) >= 1
            print("[PASS] 2. HTTP Launcher API (/registration-status, /register, /news)")

            # 4. Client 1 connects to Bishop using RAW KFXClientNetwork.dll static-key wire codec
            raw_r, raw_w = await asyncio.open_connection("127.0.0.1", 17451)
            hs_raw = await raw_read_frame(raw_r)
            assert len(hs_raw) == 42 and hs_raw[0] == 0x20 and hs_raw[1] == 0x00
            c2s_static_key, s2c_static_key = parse_handshake_payload(hs_raw)

            await raw_write_frame(
                raw_w,
                kfx_dll_mode0_reference(cipher.table, build_bishop_login_req("player1", "secret123"), c2s_static_key),
            )
            resp1 = kfx_dll_mode0_reference(cipher.table, await raw_read_frame(raw_r), s2c_static_key)
            assert resp1[0] == 0x01 and len(resp1) == 0x2D
            res, cookie1, role_id1, has_role1 = (
                struct.unpack_from("<i", resp1, 1)[0],
                struct.unpack_from("<i", resp1, 0x21)[0],
                struct.unpack_from("<i", resp1, 0x25)[0],
                struct.unpack_from("<i", resp1, 0x29)[0],
            )
            assert res == 1 and cookie1 != 0 and has_role1 == 0

            # Frame #2 S2C (0xFA RealmListRespond) MUST decrypt with the EXACT SAME s2c_static_key
            rl_pkt = kfx_dll_mode0_reference(cipher.table, await raw_read_frame(raw_r), s2c_static_key)
            assert rl_pkt[0] == 0xFA, f"Expected 0xFA with static S2C key, got 0x{rl_pkt[0]:02X}"
            rl_cnt = struct.unpack_from("<H", rl_pkt, 5)[0]
            assert rl_cnt >= 1
            realm_port = struct.unpack_from("!H", rl_pkt, 7 + 2)[0]
            realm_ip = socket.inet_ntoa(rl_pkt[7 + 4 : 7 + 8])
            realm_name = unpack_cstr(rl_pkt, 7 + 8, 32)
            assert realm_ip == "127.0.0.1" and realm_port == 17452
            assert len(realm_name) <= 12, f"Realm name too long for SrvChlLabel: {realm_name!r}"
            raw_w.close()
            await raw_w.wait_closed()
            print(f"[PASS] 3. Bishop auth + RealmList ({realm_name} @ {realm_ip}:{realm_port}, static mode-0 keys)")

            # 5. Client 1 connects to Realm -> HideLogin (0x00) -> CreateNewRole (body=1 Male) -> LoginRealm (0x03)
            r1 = await connect_kfx(realm_ip, realm_port, cipher)
            r1_init_send_key, r1_init_recv_key = r1.send_key, r1.recv_key
            await r1.send_packet(struct.pack("<BII", 0x00, role_id1, cookie1))
            hl_resp = await recv_until_opcode(r1, 0x00)
            assert struct.unpack_from("<i", hl_resp, 1)[0] == 1
            assert r1.send_key == r1_init_send_key and r1.recv_key == r1_init_recv_key

            # Real CS.exe sends body=1 (Male PawnList.csv ID)
            create_role_pkt = bytes([0x02]) + pack_cstr("SyferHero", 32) + struct.pack("<IIII", 1, 6554721, 6620247, 6685803)
            await r1.send_packet(create_role_pkt)
            cr_resp = await recv_until_opcode(r1, 0x02)
            assert struct.unpack_from("<i", cr_resp, 1)[0] == 1

            # LoginRealmRequest (0x03) -> S2C 0x03 MUST have has_channel=0 so m_sCurChannelName isn't clobbered
            login_realm_pkt = struct.pack("<BIIBB", 0x03, role_id1, cookie1, 0, 0) + pack_cstr("aa", 32)
            await r1.send_packet(login_realm_pkt)
            lr_resp = await recv_until_opcode(r1, 0x03)
            assert struct.unpack_from("<ii", lr_resp, 1) == (1, 0)
            assert unpack_cstr(lr_resp, 9, 32) == ""

            ch_resp = await recv_until_opcode(r1, 0x04)
            ch_count = struct.unpack_from("<i", ch_resp, 1)[0]
            ch1_name = unpack_cstr(ch_resp, 5 + 9, 32)
            assert ch_count >= 1 and len(f"{realm_name}/{ch1_name}") <= 22
            assert r1.send_key == r1_init_send_key and r1.recv_key == r1_init_recv_key
            print(f"[PASS] 4. Realm HideLogin -> CreateRole (body=1) -> LoginRealm (has_channel=0) -> {ch_count} channels")

            # 6. Join Channel 1 -> verify 285B JoinChannelRespond (body=1) + auto-pushed 0x08 (0 other players)
            await r1.send_packet(struct.pack("<BB", 0x05, 1))
            jc_resp = await recv_until_opcode(r1, 0x05)
            assert len(jc_resp) == 0x11D
            assert struct.unpack_from("<i", jc_resp, 1)[0] == 1
            real_role_id1 = struct.unpack_from("<i", jc_resp, 5)[0]
            assert unpack_cstr(jc_resp, 9, 32) == "SyferHero"
            assert struct.unpack_from("<I", jc_resp, 0x89)[0] == 1  # PawnList.csv Male body_type=1
            csp1, gp1 = struct.unpack_from("<ii", jc_resp, 0x115)
            assert csp1 == cfg["default_csp"] and gp1 == cfg["default_gp"]

            # Server immediately pushes 0x08 excluding self -> count=0 (prevents duplicate/blank 'free' row!)
            cpl1 = await recv_until_opcode(r1, 0x08)
            assert struct.unpack_from("<i", cpl1, 1)[0] == 0

            # Real-client Lobby entry burst: GetRoomList(0x07), GetPlayerItem(0x16), GetRelationList(0x26)
            await r1.send_packet(bytes([0x07]))
            assert struct.unpack_from("<i", await recv_until_opcode(r1, 0x07), 1)[0] == 0

            await r1.send_packet(bytes([0x16]))
            inv_resp = await recv_until_opcode(r1, 0x18)
            # Body slot @ +0x001 must be (0, 1, -1, 0) (PawnList RoleID=1, permanent, Default)
            assert struct.unpack_from("<iiii", inv_resp, 1) == (0, 1, -1, 0)
            owned_before = struct.unpack_from("<i", inv_resp, 0x2E1)[0]
            assert owned_before == 14  # body is NOT inserted into owned inventory
            # Starter items must be permanent Default (left_days=-1, get_type=0)
            first_iid, first_itype, first_left, first_get = struct.unpack_from("<iiii", inv_resp, 0x2E5)
            assert first_iid > 0 and first_itype == 6554721 and first_left == -1 and first_get == 0

            await r1.send_packet(bytes([0x26]))
            assert struct.unpack_from("<i", await recv_until_opcode(r1, 0x2B), 1)[0] == 0
            print(f"[PASS] 5. JoinChannel (body=1, 0x08 self-excluded) + Lobby burst (14 permanent Default items)")

            # 7. Shop Buy: buy_type=1 -> GP (7 days = 604800s), buy_type=0 -> CSP (-1 = permanent), Equip (0x17)
            await r1.send_packet(struct.pack("<Biii", 0x1B, 65541, 7, 1))  # AWP 7d with GP (buy_type=1)
            buy_gp = await recv_until_opcode(r1, 0x1D)
            b_res, b_iid, b_itype, b_left, b_get, b_csp, b_gp = struct.unpack_from("<7i", buy_gp, 1)
            assert b_res == 1 and b_itype == 65541 and b_iid > 0 and b_left == 7 * 86400
            assert b_csp == csp1 and b_gp < gp1

            await r1.send_packet(struct.pack("<Biii", 0x1B, 65541, -1, 0))  # AWP permanent with CSP (buy_type=0)
            buy_csp = await recv_until_opcode(r1, 0x1D)
            c_res, c_iid, c_itype, c_left, c_get, c_csp, c_gp = struct.unpack_from("<7i", buy_csp, 1)
            assert c_res == 1 and c_itype == 65541 and c_iid > 0 and c_left == -1
            assert c_csp < csp1 and c_gp == b_gp

            # Invalid item -> KFXGUI.int code 218
            await r1.send_packet(struct.pack("<Biii", 0x1B, 99999999, 7, 1))
            assert struct.unpack_from("<i", await recv_until_opcode(r1, 0x1D), 1)[0] == 218

            # Equip loadout (45 indices into 0-based owned inventory: 0=head, 1=coat, 2=trousers, 3..5=major, ...)
            indices = [0, 1, 2] + [3, 4, 5, -1, -1] + [6, 7, -1, -1, -1] + [9, 10, 11, -1, -1] + [8, -1, -1, -1, -1] + [-1, -1] + [-1] * 20
            await r1.send_packet(struct.pack("<B45i", 0x17, *indices))
            eq_resp = await recv_until_opcode(r1, 0x19)
            assert struct.unpack_from("<i", eq_resp, 1)[0] == 1
            print(f"[PASS] 6. Shop Buy (GP=1 -> {b_left}s, CSP=0 -> permanent -1, err=218) + Equip Loadout")

            # 8. Client 2 auto-registers -> creates FEMALE role (body=2) -> joins Channel 1
            b2 = await connect_kfx("127.0.0.1", 17451, cipher)
            await b2.send_packet(build_bishop_login_req("player2", "pass456"))
            resp2 = await recv_until_opcode(b2, 0x01)
            assert struct.unpack_from("<i", resp2, 1)[0] == 1
            cookie2 = struct.unpack_from("<i", resp2, 0x21)[0]
            role_id2 = struct.unpack_from("<i", resp2, 0x25)[0]
            await b2.close()

            r2 = await connect_kfx(realm_ip, realm_port, cipher)
            await r2.send_packet(struct.pack("<BII", 0x00, role_id2, cookie2))
            await recv_until_opcode(r2, 0x00)
            await r2.send_packet(bytes([0x02]) + pack_cstr("SarahPro", 32) + struct.pack("<IIII", 2, 6559724, 6625247, 6690803))
            assert struct.unpack_from("<i", await recv_until_opcode(r2, 0x02), 1)[0] == 1
            await r2.send_packet(struct.pack("<BIIBB", 0x03, role_id2, cookie2, 0, 0) + pack_cstr("aa", 32))
            assert struct.unpack_from("<ii", await recv_until_opcode(r2, 0x03), 1) == (1, 0)
            await r2.send_packet(struct.pack("<BB", 0x05, 1))
            jc2 = await recv_until_opcode(r2, 0x05)
            assert struct.unpack_from("<i", jc2, 1)[0] == 1
            real_role_id2 = struct.unpack_from("<i", jc2, 5)[0]
            assert jc2[0x86] == 2 and struct.unpack_from("<I", jc2, 0x89)[0] == 2  # Female sex=2, body_type=2
            # Auto-pushed 0x08 for Client 2 must show ONLY Client 1 (count=1, excluding self!)
            cpl2 = await recv_until_opcode(r2, 0x08)
            assert struct.unpack_from("<i", cpl2, 1)[0] == 1
            assert struct.unpack_from("<I", cpl2, 5)[0] == real_role_id1
            print(f"[PASS] 7. Client 2 Female CreateRole (body=2, sex=2) + JoinChannel (0x08 shows only Client 1)")

            # 9. Room Create (with 0xFFFFFFFF weapon_limit & random_flag overflow regression!),
            #    RoomList (room_state=2), JoinRoom (+ Ready sync), StartGame (nResult=1, room_state=4),
            #    LeaveGame (0x1E offsets), Invite (0xFFFFFFFF overflow + 0x24), FindPlayer/FindRoom, Kick/Nominate
            create_room_pkt = (
                bytes([0x09])
                + pack_cstr("Penang Arena", 32)
                + pack_cstr("", 32)
                + struct.pack("<IIIIBBI", 1, 3, 0xFFFFFFFF, 2, 1, 0, 0xFFFFFFFF)
            )
            await r1.send_packet(create_room_pkt)
            crm_resp = await recv_until_opcode(r1, 0x09)
            assert struct.unpack_from("<i", crm_resp, 1)[0] == 1
            room_id = struct.unpack_from("<i", crm_resp, 5)[0]
            # CreateRoom sends 0x0B CurrentRoomInfoRespond (NOT 0x0C) + 0x0E RoomPlayerListRespond
            cri1 = await recv_until_opcode(r1, 0x0B)
            assert len(cri1) == 0x6D and cri1[0x48] == 2  # room_state = 2 (waiting)
            assert struct.unpack_from("<I", cri1, 0x31)[0] == 0xFFFFFFFF
            assert struct.unpack_from("<I", cri1, 0x49)[0] == 0xFFFFFFFF
            rpl1 = await recv_until_opcode(r1, 0x0E)
            assert struct.unpack_from("<I", rpl1, 5 + 0x84)[0] == 1  # body_type=1

            # SetRoomInfo with map_id=0 (Random) + mode=4 (Bomb Match) MUST pick from {4, 10}
            set_rm = bytearray(0x6D)
            set_rm[0] = 0x0A
            struct.pack_into("<III", set_rm, 0x29, 0, 4, 2)  # map_id=0, mode=4, random_flag=2
            set_rm[0x35] = 2  # max_players=2
            set_rm[0x36] = 20
            set_rm[0x37] = 5
            struct.pack_into("<II", set_rm, 0x3D, 100, 0)
            set_rm[0x45] = 1
            set_rm[0x46] = 1
            struct.pack_into("<I", set_rm, 0x49, 0xFFFFFFFF)
            await r1.send_packet(bytes(set_rm))
            assert struct.unpack_from("<i", await recv_until_opcode(r1, 0x0A), 1)[0] == 1
            cri_rand = await recv_until_opcode(r1, 0x0B)
            assert struct.unpack_from("<I", cri_rand, 0x29)[0] in (4, 10)
            assert struct.unpack_from("<I", cri_rand, 0x2D)[0] == 4
            # Switch back to mode=1 map=3 for rest of test
            struct.pack_into("<III", set_rm, 0x29, 3, 1, 0)
            await r1.send_packet(bytes(set_rm))
            await recv_until_opcode(r1, 0x0A)
            await recv_until_opcode(r1, 0x0B)

            # Client 1 tests InvitePlayer overflow guard (0xFFFFFFFF) & valid invite (0x24 to Client 2)
            await r1.send_packet(struct.pack("<BI", 0x1F, 0xFFFFFFFF))
            inv_miss = await recv_until_opcode(r1, 0x23)
            assert struct.unpack_from("<II", inv_miss, 1) == (0, 0xFFFFFFFF)

            await r1.send_packet(struct.pack("<BI", 0x1F, real_role_id2))
            assert struct.unpack_from("<II", await recv_until_opcode(r1, 0x23), 1) == (1, real_role_id2)
            inv_me = await recv_until_opcode(r2, 0x24)
            assert len(inv_me) == 0x2F and struct.unpack_from("<I", inv_me, 1)[0] == real_role_id1
            assert inv_me[0x25] == room_id and inv_me[0x26] == 1 and inv_me[0x27] == 1

            # Client 2 lists rooms (room_state=2), tests bad room error code (230), joins room (now full -> room_state=3)
            await r2.send_packet(bytes([0x07]))
            rm_list = await recv_until_opcode(r2, 0x07)
            assert struct.unpack_from("<i", rm_list, 1)[0] == 1
            assert rm_list[5 + 0x2E] == 2  # waiting

            await r2.send_packet(struct.pack("<BI", 0x0B, 99) + pack_cstr("", 32))
            assert struct.unpack_from("<i", await recv_until_opcode(r2, 0x0C), 1)[0] == 230

            await r2.send_packet(struct.pack("<BI", 0x0B, room_id) + pack_cstr("", 32))
            jr2 = await recv_until_opcode(r2, 0x0C)
            assert struct.unpack_from("<i", jr2, 1)[0] == 1 and jr2[0x4C] == 3  # full (2/2)
            rpl2 = await recv_until_opcode(r2, 0x0E)
            assert struct.unpack_from("<i", rpl2, 1)[0] == 2
            sjr1 = await recv_until_opcode(r1, 0x0F)
            assert len(sjr1) == 153 and unpack_cstr(sjr1, 5, 32) == "SarahPro"

            # FindPlayer & FindRoom exact offset verification
            await r1.send_packet(bytes([0x1D]) + pack_cstr("SarahPro", 32))
            fp = await recv_until_opcode(r1, 0x21)
            assert fp[0x9D] == room_id and fp[0x9E] == 1 and fp[0x9F] == 1 and fp[0xA0] == 0

            await r1.send_packet(struct.pack("<BI", 0x1E, room_id))
            fr = await recv_until_opcode(r1, 0x22)
            assert fr[5] == room_id and fr[6] == 1 and fr[7] == 1 and fr[8] == 0
            assert struct.unpack_from("<I", fr, 0x42)[0] == 3  # room_state=3 (full)

            # Client 2 switches team + readies up; re-requesting RoomPlayerList syncs 0x14 ready!
            await r2.send_packet(struct.pack("<Bi", 0x0E, 1))
            await recv_until_opcode(r2, 0x12)
            await recv_until_opcode(r1, 0x13)

            await r2.send_packet(struct.pack("<Bi", 0x0F, 1))
            rdy1 = await recv_until_opcode(r1, 0x14)
            assert struct.unpack_from("<Ii", rdy1, 1) == (real_role_id2, 1)
            await recv_until_opcode(r2, 0x14)

            await r1.send_packet(bytes([0x0D]))
            await recv_until_opcode(r1, 0x0E)
            rdy_sync = await recv_until_opcode(r1, 0x14)
            assert struct.unpack_from("<Ii", rdy_sync, 1) == (real_role_id2, 1)

            # Client 1 starts game -> BOTH receive 0x15 with nResult == 1 (NOT session_id!) & room_state == 4
            await r1.send_packet(bytes([0x10]))
            gs1 = await recv_until_opcode(r1, 0x15)
            gs2 = await recv_until_opcode(r2, 0x15)
            res_gs = struct.unpack_from("<i", gs1, 1)[0]
            ip1 = socket.inet_ntoa(gs1[5:9])
            port1 = struct.unpack_from("!H", gs1, 9)[0]
            assert res_gs == 1 and ip1 == "127.0.0.1" and port1 >= 7777 and gs1 == gs2
            cri_play = await recv_until_opcode(r1, 0x0B)
            assert cri_play[0x48] == 4  # room_state=4 (playing)
            await recv_until_opcode(r2, 0x0B)
            print(f"[PASS] 8. Room lifecycle (0xFFFFFFFF guard, states 2/3/4, Invite 0x24) + GameStart (nResult=1, udp={ip1}:{port1})")

            # Both leave match -> 0x2F + 0x1E (verify game_cash @ +0x21, level @ +0x25, honor_point @ +0x2D)
            await r1.send_packet(bytes([0x29]))
            assert struct.unpack_from("<i", await recv_until_opcode(r1, 0x2F), 1)[0] == 1
            ge1 = await recv_until_opcode(r1, 0x1E)
            assert len(ge1) == 0xA9
            ge_gp, ge_lvl, _ge_place, ge_honor = struct.unpack_from("<4I", ge1, 0x21)
            assert ge_gp == b_gp + 200 and ge_lvl >= 1 and ge_honor == 50

            await r2.send_packet(bytes([0x29]))
            assert struct.unpack_from("<i", await recv_until_opcode(r2, 0x2F), 1)[0] == 1
            await recv_until_opcode(r2, 0x1E)
            # Drain room state restore (0x0B -> state 3) + updated room player list (0x0E)
            cri_back = await recv_until_opcode(r1, 0x0B)
            if cri_back[0x48] == 4:
                cri_back = await recv_until_opcode(r1, 0x0B)
            assert cri_back[0x48] == 3

            # 10. Room Chat (chat_type @ +0x01, role_id @ +0x05), PresentItem (0x2B), Email (0x27 nExpend, 0x29 iid/itype),
            #     Friends (nRelation=0 + 0x2D deleted_role_id), Rankings (honor @ +0x35, level @ +0x39), QuestBonus (33B),
            #     Kick (0x36 only) & Live HTTP /api/status
            msg_b = b"jom main wei!\x00"
            await r1.send_packet(struct.pack("<BI", 0x13, len(msg_b)) + msg_b)
            chat2 = await recv_until_opcode(r2, 0x16)
            assert struct.unpack_from("<II", chat2, 1) == (1, real_role_id1)  # chat_type=1 (room), role_id
            assert unpack_cstr(chat2, 9, 32) == "SyferHero"
            assert unpack_cstr(chat2, 0x2D, 64) == "jom main wei!"

            # PresentItem (0x2B) with exact KFXClient.dll layout (+0x09 recv_name, +0x29 buy_type=1 GP, +0x2D len, +0x31 msg)
            gift_msg = b"For you!\x00"
            present_pkt = (
                struct.pack("<Bii", 0x2B, 65541, 7)
                + pack_cstr("SarahPro", 32)
                + struct.pack("<iI", 1, len(gift_msg))
                + gift_msg
            )
            await r1.send_packet(present_pkt)
            pr_resp = await recv_until_opcode(r1, 0x32)
            assert struct.unpack_from("<i", pr_resp, 1)[0] == 1
            await recv_until_opcode(r2, 0x25)  # NewEmailInform

            await r2.send_packet(bytes([0x21]))
            mlist = await recv_until_opcode(r2, 0x26)
            assert struct.unpack_from("<i", mlist, 5)[0] >= 2  # Welcome + Gift
            gift_email_id = struct.unpack_from("<I", mlist, 9)[0]
            # Read email content -> +0x15 nItemLeftDays MUST be 7*86400s and +0x2D nExpend MUST be 0
            await r2.send_packet(struct.pack("<Bi", 0x22, gift_email_id))
            mc = await recv_until_opcode(r2, 0x27)
            assert struct.unpack_from("<i", mc, 0x15)[0] == 7 * 86400
            assert struct.unpack_from("<i", mc, 0x2D)[0] == 0
            assert unpack_cstr(mc, 0x31, 64) == "For you!"
            # TakeOutItem -> +0x09 nItemID, +0x0D nItemType, +0x11 nItemLeftDays == 7*86400s (no double multiply!)
            await r2.send_packet(struct.pack("<Biii", 0x24, gift_email_id, 1, 65541))
            to_resp = await recv_until_opcode(r2, 0x29)
            to_res, to_eid, to_iid, to_itype, to_left, to_get = struct.unpack_from("<6i", to_resp, 1)
            assert to_res == 1 and to_eid == gift_email_id and to_iid > 0 and to_itype == 65541 and to_left == 7 * 86400

            # Relations: nRelation=0 (Friend) -> 0x2C, 0x2B, 0x2D (deleted_role_id)
            await r1.send_packet(struct.pack("<Bi", 0x27, 0) + pack_cstr("SarahPro", 32))
            ar = await recv_until_opcode(r1, 0x2C)
            assert len(ar) == 0x39
            assert struct.unpack_from("<III", ar, 1) == (1, 0, real_role_id2)  # res=1, nRelation=0, nRoleID
            assert unpack_cstr(ar, 5 + 0x0C, 32) == "SarahPro"
            assert struct.unpack_from("<HH", ar, 5 + 0x30)[1] == 1  # online=1

            await r1.send_packet(bytes([0x26]))
            rl_rel = await recv_until_opcode(r1, 0x2B)
            assert struct.unpack_from("<III", rl_rel, 1) == (1, 0, real_role_id2)

            await r1.send_packet(struct.pack("<BI", 0x28, real_role_id2))
            dr = await recv_until_opcode(r1, 0x2D)
            assert struct.unpack_from("<II", dr, 1) == (1, real_role_id2)

            # World Role Rankings -> +0x35 honor_point, +0x39 level
            await r1.send_packet(bytes([0x1A]))
            rank_resp = await recv_until_opcode(r1, 0x1C)
            assert struct.unpack_from("<i", rank_resp, 5)[0] == 2
            top_honor, top_lvl = struct.unpack_from("<II", rank_resp, 0x15 + 0x20)
            assert top_honor == 50 and top_lvl >= 1

            # Quest Bonus -> 33B <B8I with total_honor, new_level, result=1
            first_qid = next(iter(app.gamedata.quests.keys()))
            await r1.send_packet(struct.pack("<Biii", 0x32, first_qid, 1, 0))
            qb = await recv_until_opcode(r1, 0x3D)
            assert len(qb) == 33
            qb_fields = struct.unpack_from("<8I", qb, 1)
            assert qb_fields[0] == first_qid and qb_fields[7] == 1 and qb_fields[2] >= 50 and qb_fields[3] >= 1

            # Kick Client 2 -> ONLY 0x36 (no spurious 0x10/0x0D)
            await r1.send_packet(struct.pack("<BI", 0x2E, real_role_id2))
            k2 = await recv_until_opcode(r2, 0x36)
            assert struct.unpack_from("<I", k2, 1)[0] == real_role_id2
            k1 = await recv_until_opcode(r1, 0x36)
            assert struct.unpack_from("<I", k1, 1)[0] == real_role_id2

            # Live HTTP /api/status
            code, st = http_json("http://127.0.0.1:18080/api/status")
            assert code == 200 and st["realm"]["online_players"] == 2 and len(st["realm"]["rooms"]) == 1
            print("[PASS] 9. Chat, PresentItem/Mail, Friends, Rankings, QuestBonus (33B), Kick & HTTP /api/status")

            await r1.close()
            await r2.close()
            print("\n=== ALL 9 END-TO-END PROTOCOL & API TEST SUITES PASSED! ===")
        finally:
            await app.stop()


if __name__ == "__main__":
    asyncio.run(run_all_tests())

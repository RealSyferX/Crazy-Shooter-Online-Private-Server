"""
Exact binary packet codecs for CSO Malaysia Bishop (7451) and Realm (7452) protocols.

Every opcode and byte offset in this file was verified against Ghidra 12.2 / x86 disassembly
of KFXClient.dll (KFXBishopClient::*, KFXRealmClient::*, UKFXNetGUIController::*) and KFXGUI.u.
All strings use UTF-8 (Windows CP_UTF8 = 0xFDE9, matching MultiByteToWideChar/WideCharToMultiByte).
IPv4 addresses and ports in RealmList, FindPlayer, FindRoom, Invite, and GameStartCommond use
NETWORK BYTE ORDER (big-endian).
All 32-bit wire fields are masked via u32() (& 0xFFFFFFFF) and packed as <I so two's complement
sentinels (such as -1 = 0xFFFFFFFF) and unsigned uint32 values never trigger struct.error.
"""
from __future__ import annotations

import socket
import struct
import time
from typing import Any


def u32(v: int) -> int:
    return int(v) & 0xFFFFFFFF


def u16(v: int) -> int:
    return int(v) & 0xFFFF


def u8(v: int) -> int:
    return int(v) & 0xFF


def clamp_time32(v: int) -> int:
    """Clamp Unix timestamps to signed 32-bit range [0, 0x7FFFFFFF] for MSVCR71!localtime()."""
    iv = int(v)
    if iv < 0:
        return 0
    if iv > 0x7FFFFFFF:
        return 0x7FFFFFFF
    return iv


def pack_cstr(text: str, size: int) -> bytes:
    raw = text.encode("utf-8", errors="replace")[: max(0, size - 1)]
    return raw + b"\x00" * (size - len(raw))


def unpack_cstr(buf: bytes, offset: int, size: int) -> str:
    chunk = buf[offset : offset + size]
    nul = chunk.find(b"\x00")
    if nul != -1:
        chunk = chunk[:nul]
    return chunk.decode("utf-8", errors="replace")


def ip_to_u32_net(ip: str) -> bytes:
    try:
        return socket.inet_aton(ip)
    except OSError:
        return socket.inet_aton("127.0.0.1")


# ======================================================================
# BISHOP GATEWAY PROTOCOL (TCP 7451)
# ======================================================================

def decode_bishop_login_request(data: bytes) -> dict[str, Any]:
    """C2S 0x00 LoginGatewayRequest (137 bytes)."""
    if len(data) < 0x89:
        raise ValueError(f"LoginGatewayRequest too short: {len(data)}")
    return {
        "opcode": data[0],
        "username": unpack_cstr(data, 0x01, 32),
        "password_md5": unpack_cstr(data, 0x21, 64),
        "activate_code": unpack_cstr(data, 0x61, 32),
        "param4": struct.unpack_from("<I", data, 0x81)[0],
        "param5": struct.unpack_from("<I", data, 0x85)[0],
    }


def encode_bishop_login_respond(result: int, cookie: int, role_id: int, has_role: int) -> bytes:
    """
    S2C 0x01 LoginGatewayRespond (45 bytes).
      +0x01 i32 result (1 = success)
      +0x21 i32 cookie  (stored at ctrl+0x3f4)
      +0x25 i32 role_id (stored at ctrl+0x3f8)
      +0x29 i32 has_role (0 => bCreateRole=True; 1 => bCreateRole=False)
    """
    buf = bytearray(0x2D)
    buf[0] = 0x01
    struct.pack_into("<I", buf, 0x01, u32(result))
    struct.pack_into("<I", buf, 0x21, u32(cookie))
    struct.pack_into("<I", buf, 0x25, u32(role_id))
    struct.pack_into("<I", buf, 0x29, u32(has_role))
    return bytes(buf)


def encode_bishop_realm_list(realms: list[dict[str, Any]]) -> bytes:
    """
    S2C 0xFA KFXBishopClient::RealmListRespond.
      +0x00 u8  0xFA
      +0x01 u32 reserved (0)
      +0x05 u16 count
      +0x07 count * 40 bytes:
          +0 u8  realm_id
          +1 u8  work_state
          +2 u16 port (NETWORK byte order -> ntohs)
          +4 4B  ip   (NETWORK byte order -> inet_ntoa)
          +8 32B realm_name
    """
    out = bytearray(7 + len(realms) * 40)
    out[0] = 0xFA
    struct.pack_into("<IH", out, 1, 0, u16(len(realms)))
    for i, r in enumerate(realms):
        off = 7 + i * 40
        out[off] = u8(r["id"])
        out[off + 1] = u8(r.get("work_state", 1))
        struct.pack_into("!H", out, off + 2, u16(r["port"]))
        out[off + 4 : off + 8] = ip_to_u32_net(str(r["ip"]))
        out[off + 8 : off + 40] = pack_cstr(str(r["name"]), 32)
    return bytes(out)


# ======================================================================
# REALM SERVER PROTOCOL (TCP 7452) - S2C ENCODERS
# ======================================================================

def encode_simple_result(opcode: int, result: int) -> bytes:
    return struct.pack("<BI", u8(opcode), u32(result))


def encode_login_realm_respond(result: int, has_channel: int = 0, channel_name: str = "") -> bytes:
    """
    S2C 0x03 LoginRealmRespond (41 bytes).
      +0x00 u8  0x03
      +0x01 i32 result (1 = success)
      +0x05 i32 has_channel (if == 1, KFXClient.dll!LoginRealmEvent writes channel_name into m_sCurChannelName)
      +0x09 32B channel_name
    """
    buf = bytearray(41)
    buf[0] = 0x03
    struct.pack_into("<II", buf, 1, u32(result), u32(has_channel))
    buf[9:41] = pack_cstr(channel_name, 32)
    return bytes(buf)


def encode_channel_list_respond(channels: list[dict[str, Any]]) -> bytes:
    """
    S2C 0x04 ChannelListRespond.
      +0x00 u8  0x04
      +0x01 i32 count
      +0x05 count * 0x29 (41 bytes):
          +0x00 u8  channel_id
          +0x01 i32 max_role_count
          +0x05 i32 state
          +0x09 32B channel_name
    """
    out = bytearray(5 + len(channels) * 0x29)
    out[0] = 0x04
    struct.pack_into("<I", out, 1, u32(len(channels)))
    for i, ch in enumerate(channels):
        off = 5 + i * 0x29
        out[off] = u8(ch["id"])
        struct.pack_into("<II", out, off + 1, u32(ch.get("max_players", 200)), u32(ch.get("state", 1)))
        out[off + 9 : off + 41] = pack_cstr(str(ch["name"]), 32)
    return bytes(out)


def encode_join_channel_respond(result: int, role: dict[str, Any] | None = None) -> bytes:
    """
    S2C 0x05 JoinChannelRespond (0x11D = 285 bytes).
    Maps 1:1 to KFXRealmClient::JoinChannelRespond -> UKFXNetGUIController::PutPlayerInfo.
    """
    buf = bytearray(0x11D)
    buf[0] = 0x05
    struct.pack_into("<I", buf, 0x01, u32(result))
    if result != 1 or role is None:
        return bytes(buf)

    struct.pack_into("<I", buf, 0x05, u32(role["role_id"]))
    buf[0x09:0x29] = pack_cstr(str(role["role_name"]), 32)
    struct.pack_into(
        "<14I",
        buf,
        0x29,
        u32(role["kill_count"]),
        u32(role["death_count"]),
        u32(role["victory_count"]),
        u32(role["deuce_count"]),
        u32(role["defeated_count"]),
        u32(role["head_kill_count"]),
        u32(role["knife_kill_count"]),
        u32(role["special_kill_count"]),
        u32(role["level"]),
        u32(role["honor_point"]),
        u32(role["honor_place"]),
        u32(role["honor_place_last"]),
        u32(role["faction_id"]),
        u32(role["faction_icon_id"]),
    )
    buf[0x61:0x81] = pack_cstr(str(role.get("faction_name", "")), 32)
    buf[0x81] = u8(role.get("faction_role_id", 0))
    buf[0x86] = u8(role.get("sex", 1))
    struct.pack_into(
        "<5I",
        buf,
        0x89,
        u32(role["body_type"]),
        u32(role["head_type"]),
        u32(role["coat_type"]),
        u32(role["trousers_type"]),
        u32(role["major_weapon_id"]),
    )
    # 15 weapon skill levels at +0x9d and 15 skill values at +0xd9 (zeroed by default)
    struct.pack_into("<II", buf, 0x115, u32(role["money_point"]), u32(role["game_cash"]))
    return bytes(buf)


def encode_room_list_respond(rooms: list[dict[str, Any]]) -> bytes:
    """
    S2C 0x07 RoomListRespond (5 + count * 0x35 bytes).
    Entry layout (0x35 = 53 bytes, relative to entry start):
      +0x00 i32 nRoomID
      +0x04 i32 nGameMode
      +0x08 i32 nMapID
      +0x0C 32B szRoomName
      +0x2C u8  nRoleMaxCount
      +0x2D u8  nCurrentRoleCount
      +0x2E u8  nRoomState (2=waiting, 3=full, 4=playing)
      +0x2F u8  nPasswordFlag
      +0x30 u8  nEnableEnterWhenGaming
      +0x31 i32 nWeaponLimit
    """
    out = bytearray(5 + len(rooms) * 0x35)
    out[0] = 0x07
    struct.pack_into("<I", out, 1, u32(len(rooms)))
    for i, rm in enumerate(rooms):
        off = 5 + i * 0x35
        struct.pack_into("<III", out, off, u32(rm["room_id"]), u32(rm["game_mode"]), u32(rm["map_id"]))
        out[off + 0x0C : off + 0x2C] = pack_cstr(str(rm["room_name"]), 32)
        out[off + 0x2C] = u8(rm["max_players"])
        out[off + 0x2D] = u8(rm["cur_players"])
        out[off + 0x2E] = u8(rm.get("room_state", 2))
        out[off + 0x2F] = 1 if rm.get("password") else 0
        out[off + 0x30] = u8(rm.get("enable_join_in_game", 1))
        struct.pack_into("<I", out, off + 0x31, u32(rm.get("weapon_limit", 0)))
    return bytes(out)


def encode_channel_player_list_respond(players: list[dict[str, Any]]) -> bytes:
    """
    S2C 0x08 ChannelPlayerListRespond (5 + count * 0x2E bytes).
    Entry layout (0x2E = 46 bytes):
      +0x00 u32 nRoleID
      +0x04 32B szRoleName
      +0x24 i32 nFactionID
      +0x28 i32 nFactionIconID
      +0x2C u8  nLevel
      +0x2D u8  nSex
    """
    out = bytearray(5 + len(players) * 0x2E)
    out[0] = 0x08
    struct.pack_into("<I", out, 1, u32(len(players)))
    for i, p in enumerate(players):
        off = 5 + i * 0x2E
        struct.pack_into("<I", out, off, u32(p["role_id"]))
        out[off + 0x04 : off + 0x24] = pack_cstr(str(p["role_name"]), 32)
        struct.pack_into("<II", out, off + 0x24, u32(p.get("faction_id", 0)), u32(p.get("faction_icon_id", 0)))
        out[off + 0x2C] = u8(p.get("level", 1))
        out[off + 0x2D] = u8(p.get("sex", 1))
    return bytes(out)


def encode_create_room_respond(result: int, room_id: int) -> bytes:
    """S2C 0x09 CreateRoomRespond (9 bytes)."""
    return struct.pack("<BII", 0x09, u32(result), u32(room_id))


def _fill_room_info_block(buf: bytearray, base: int, rm: dict[str, Any]) -> None:
    """
    Populate the 108-byte room info structure shared by CurrentRoomInfoRespond (base=1)
    and JoinRoomRespond (base=5).
      base + 0x00 (32B): szRoomName
      base + 0x20 (4B) : nRoomID
      base + 0x24 (4B) : nRoomOwnerID      (0x25 in 0x0B, 0x29 in 0x0C)
      base + 0x28 (4B) : nMapID            (0x29 in 0x0B, 0x2D in 0x0C)
      base + 0x2C (4B) : nGameMode         (0x2D in 0x0B, 0x31 in 0x0C)
      base + 0x30 (4B) : nRandomFlag       (0x31 in 0x0B, 0x35 in 0x0C)
      base + 0x34 (1B) : nRoleMaxCount     (0x35 in 0x0B, 0x39 in 0x0C)
      base + 0x35 (1B) : nTime             (0x36 in 0x0B, 0x3A in 0x0C)
      base + 0x36 (1B) : nGameLimit        (0x37 in 0x0B, 0x3B in 0x0C)
      base + 0x37 (1B) : nIsFactionGame    (0x38 in 0x0B, 0x3C in 0x0C)
      base + 0x38 (1B) : nIsSuperRoomOwner (0x39 in 0x0B, 0x3D in 0x0C)
      base + 0x3C (4B) : nShootLimit       (0x3D in 0x0B, 0x41 in 0x0C)
      base + 0x40 (4B) : nPointLimit       (0x41 in 0x0B, 0x45 in 0x0C)
      base + 0x44 (1B) : nBalanceFlag      (0x45 in 0x0B, 0x49 in 0x0C)
      base + 0x45 (1B) : nEnableEnterWhenGaming (0x46 in 0x0B, 0x4A in 0x0C)
      base + 0x46 (1B) : nAutoAimFlag      (0x47 in 0x0B, 0x4B in 0x0C)
      base + 0x47 (1B) : nRoomState        (0x48 in 0x0B, 0x4C in 0x0C) (2=waiting, 3=full, 4=playing)
      base + 0x48 (4B) : nWeaponLimit      (0x49 in 0x0B, 0x4D in 0x0C)
      base + 0x4C (32B): szPassword        (0x4D in 0x0B, 0x51 in 0x0C)
    """
    buf[base : base + 32] = pack_cstr(str(rm["room_name"]), 32)
    struct.pack_into("<I", buf, base + 0x20, u32(rm["room_id"]))
    struct.pack_into("<I", buf, base + 0x24, u32(rm["owner_id"]))
    struct.pack_into("<I", buf, base + 0x28, u32(rm["map_id"]))
    struct.pack_into("<I", buf, base + 0x2C, u32(rm["game_mode"]))
    struct.pack_into("<I", buf, base + 0x30, u32(rm.get("random_flag", 0)))
    buf[base + 0x34] = u8(rm["max_players"])
    buf[base + 0x35] = u8(rm.get("time_limit", 20))
    buf[base + 0x36] = u8(rm.get("game_limit", 5))
    buf[base + 0x37] = u8(rm.get("is_faction_game", 0))
    buf[base + 0x38] = u8(rm.get("is_super_owner", 0))
    struct.pack_into("<I", buf, base + 0x3C, u32(rm.get("shoot_limit", 100)))
    struct.pack_into("<I", buf, base + 0x40, u32(rm.get("point_limit", 0)))
    buf[base + 0x44] = u8(rm.get("balance_flag", 1))
    buf[base + 0x45] = u8(rm.get("enable_join_in_game", 1))
    buf[base + 0x46] = u8(rm.get("auto_aim_flag", 0))
    buf[base + 0x47] = u8(rm.get("room_state", 2))
    struct.pack_into("<I", buf, base + 0x48, u32(rm.get("weapon_limit", 0)))
    buf[base + 0x4C : base + 0x6C] = pack_cstr(str(rm.get("password", "")), 32)


def encode_current_room_info_respond(rm: dict[str, Any]) -> bytes:
    """S2C 0x0B CurrentRoomInfoRespond (0x6D = 109 bytes)."""
    buf = bytearray(0x6D)
    buf[0] = 0x0B
    _fill_room_info_block(buf, 1, rm)
    return bytes(buf)


def encode_join_room_respond(result: int, rm: dict[str, Any] | None = None) -> bytes:
    """S2C 0x0C JoinRoomRespond (0x71 = 113 bytes)."""
    buf = bytearray(0x71)
    buf[0] = 0x0C
    struct.pack_into("<I", buf, 1, u32(result))
    if result == 1 and rm is not None:
        _fill_room_info_block(buf, 5, rm)
    return bytes(buf)


def _pack_room_player_entry(p: dict[str, Any]) -> bytes:
    """
    0x98 (152) byte room player entry used by both RoomPlayerListRespond (0x0E)
    and SomeOneJionRoomRespond (0x0F).
    Offsets relative to entry start:
      +0x00 u32 nRoleID
      +0x04 32B szRoleName
      +0x24 u32 nKillCount
      +0x28 u32 nDeathCount
      +0x2C u32 nVictoryCount
      +0x30 u32 nDeuceCount
      +0x34 u32 nDefeatedCount
      +0x38 u32 nHeadKillCount
      +0x3C u32 nKnifeKillCount
      +0x40 u32 nSpeicalKillCount
      +0x44 u32 nLevel
      +0x48 u32 nHonorPoint
      +0x4C u32 nHonorPointPlace
      +0x81 i8  nSex
      +0x82 u8  nInGameFlag
      +0x83 u8  nTeamID
      +0x84 u32 nCurBodyType (PawnList.csv RoleID: 1=Male, 2=Female)
      +0x88 u32 nRoleHeadType
      +0x8C u32 nRoleCoatType
      +0x90 u32 nRoleTrousersType
      +0x94 u32 nCurMajorWeaponID
    """
    ent = bytearray(0x98)
    struct.pack_into("<I", ent, 0x00, u32(p["role_id"]))
    ent[0x04:0x24] = pack_cstr(str(p["role_name"]), 32)
    struct.pack_into(
        "<11I",
        ent,
        0x24,
        u32(p.get("kill_count", 0)),
        u32(p.get("death_count", 0)),
        u32(p.get("victory_count", 0)),
        u32(p.get("deuce_count", 0)),
        u32(p.get("defeated_count", 0)),
        u32(p.get("head_kill_count", 0)),
        u32(p.get("knife_kill_count", 0)),
        u32(p.get("special_kill_count", 0)),
        u32(p.get("level", 1)),
        u32(p.get("honor_point", 0)),
        u32(p.get("honor_place", 1)),
    )
    ent[0x81] = u8(p.get("sex", 1))
    ent[0x82] = u8(p.get("in_game", 0))
    ent[0x83] = u8(p.get("team_id", 0))
    struct.pack_into(
        "<5I",
        ent,
        0x84,
        u32(p.get("body_type", 1)),
        u32(p.get("head_type", 6554721)),
        u32(p.get("coat_type", 6620247)),
        u32(p.get("trousers_type", 6685803)),
        u32(p.get("major_weapon_id", 65537)),
    )
    return bytes(ent)


def encode_room_player_list_respond(players: list[dict[str, Any]]) -> bytes:
    """S2C 0x0E RoomPlayerListRespond (5 + count * 0x98 bytes)."""
    out = bytearray(5)
    out[0] = 0x0E
    struct.pack_into("<I", out, 1, u32(len(players)))
    for p in players:
        out.extend(_pack_room_player_entry(p))
    return bytes(out)


def encode_someone_join_room_respond(p: dict[str, Any]) -> bytes:
    """S2C 0x0F SomeOneJionRoomRespond (153 bytes)."""
    return bytes([0x0F]) + _pack_room_player_entry(p)


def encode_someone_leave_room_respond(role_id: int) -> bytes:
    """S2C 0x10 SomeOneLeaveRoomRespond (5 bytes)."""
    return struct.pack("<BI", 0x10, u32(role_id))


def encode_room_owner_change_respond(new_owner_id: int, is_super: int = 0) -> bytes:
    """S2C 0x11 RoomOwnerChangeRespond (6 bytes)."""
    return struct.pack("<BIB", 0x11, u32(new_owner_id), u8(is_super))


def encode_someone_change_team_respond(role_id: int, team_id: int) -> bytes:
    """S2C 0x13 SomeOneChangeTeamRespond (9 bytes)."""
    return struct.pack("<BII", 0x13, u32(role_id), u32(team_id))


def encode_ready_game_info_respond(role_id: int, ready_flag: int) -> bytes:
    """S2C 0x14 ReadyGameInfoRespond (9 bytes)."""
    return struct.pack("<BII", 0x14, u32(role_id), u32(ready_flag))


def encode_game_start_command(result: int, ip: str, port: int) -> bytes:
    """
    S2C 0x15 GameStartCommond (11 bytes).
      +0x00 u8  0x15
      +0x01 i32 nResult (MUST be 1 for InRoomState.GameStartCommond to launch match!)
      +0x05 4B  ip (NETWORK byte order -> inet_ntoa)
      +0x09 u16 port (NETWORK byte order -> ntohs)
    """
    out = bytearray(11)
    out[0] = 0x15
    struct.pack_into("<I", out, 1, u32(result))
    out[5:9] = ip_to_u32_net(ip)
    struct.pack_into("!H", out, 9, u16(port))
    return bytes(out)


def encode_chat_content_respond(role_id: int, chat_type: int, sender_name: str, message: str) -> bytes:
    """
    S2C 0x16 ChatContentRespond (KFXClient.dll!0x107252e0 -> PutChatContent 0x10718820).
      +0x00 u8  0x16
      +0x01 i32 chat_type (0=channel, 1=room, 2=personal, 3=group/clan, 4=public)
      +0x05 i32 role_id
      +0x09 32B sender_name
      +0x29 i32 msg_len (including NUL)
      +0x2D msg UTF-8 bytes + NUL
    """
    msg_bytes = message.encode("utf-8", errors="replace") + b"\x00"
    out = bytearray(0x2D + len(msg_bytes))
    out[0] = 0x16
    struct.pack_into("<II", out, 1, u32(chat_type), u32(role_id))
    out[9:41] = pack_cstr(sender_name, 32)
    struct.pack_into("<I", out, 0x29, u32(len(msg_bytes)))
    out[0x2D:] = msg_bytes
    return bytes(out)


def encode_personal_chat_result_respond(result: int, dst_name: str) -> bytes:
    """S2C 0x17 PersonalChatResultRespond (37 bytes)."""
    return struct.pack("<BI", 0x17, u32(result)) + pack_cstr(dst_name, 32)


def _pack_item_info(tup: tuple[int, int, int, int]) -> bytes:
    """Pack 16-byte KFXItemInfo (nItemID, nItemType, nItemLeftDays, nItemGetType), supporting -1."""
    return struct.pack("<4I", u32(tup[0]), u32(tup[1]), u32(tup[2]), u32(tup[3]))


def encode_get_item_list_respond(resolved_loadout: dict[str, Any], inventory: list[dict[str, Any]]) -> bytes:
    """
    S2C 0x18 GetItemListRespond (0x2E5 + len(inventory) * 16 bytes).
    Exact offsets verified from FUN_107259a0 -> PutPlayerUseItem:
      +0x001 (16B):  BodyType (nItemType = PawnList.csv RoleID 1/2)
      +0x011 (16B):  RoleHeadType
      +0x021 (16B):  RoleCoatType
      +0x031 (16B):  RoleTrousers
      +0x041 (80B):  MajorWeapon[5]
      +0x091 (80B):  MininWeapon[5]
      +0x0E1 (80B):  Grenade[5]
      +0x131 (80B):  KnifeID[5]
      +0x181 (16B):  ArmorID
      +0x191 (16B):  ShoesID
      +0x1A1 (320B): BaggageCards[20]
      +0x2E1 (4B):   i32 owned_count
      +0x2E5 (N*16B): owned items (ItemID, ItemType, LeftDays [sec/uses/-1], ItemGetType [0=Default])
    """
    out = bytearray(0x2E5 + len(inventory) * 16)
    out[0] = 0x18
    out[0x001:0x011] = _pack_item_info(resolved_loadout["body"])
    out[0x011:0x021] = _pack_item_info(resolved_loadout["head"])
    out[0x021:0x031] = _pack_item_info(resolved_loadout["coat"])
    out[0x031:0x041] = _pack_item_info(resolved_loadout["trousers"])
    for i in range(5):
        out[0x041 + i * 16 : 0x051 + i * 16] = _pack_item_info(resolved_loadout["major"][i])
        out[0x091 + i * 16 : 0x0A1 + i * 16] = _pack_item_info(resolved_loadout["minor"][i])
        out[0x0E1 + i * 16 : 0x0F1 + i * 16] = _pack_item_info(resolved_loadout["grenade"][i])
        out[0x131 + i * 16 : 0x141 + i * 16] = _pack_item_info(resolved_loadout["knife"][i])
    out[0x181:0x191] = _pack_item_info(resolved_loadout["armor"])
    out[0x191:0x1A1] = _pack_item_info(resolved_loadout["shoes"])
    for i in range(20):
        out[0x1A1 + i * 16 : 0x1B1 + i * 16] = _pack_item_info(resolved_loadout["baggage_cards"][i])

    struct.pack_into("<I", out, 0x2E1, u32(len(inventory)))
    for i, it in enumerate(inventory):
        off = 0x2E5 + i * 16
        out[off : off + 16] = struct.pack(
            "<4I",
            u32(it["item_id"]),
            u32(it["item_type"]),
            u32(it["left_days"]),
            u32(it["item_get_type"]),
        )
    return bytes(out)


def encode_request_role_info_respond(result: int, role: dict[str, Any] | None) -> bytes:
    """S2C 0x1B RequestRoleInfoRespond (0x87 = 135 bytes)."""
    buf = bytearray(0x87)
    buf[0] = 0x1B
    struct.pack_into("<I", buf, 1, u32(result))
    if result == 1 and role is not None:
        struct.pack_into("<I", buf, 5, u32(role["role_id"]))
        buf[9:41] = pack_cstr(str(role["role_name"]), 32)
        struct.pack_into(
            "<11I",
            buf,
            0x29,
            u32(role["kill_count"]),
            u32(role["death_count"]),
            u32(role["victory_count"]),
            u32(role["deuce_count"]),
            u32(role["defeated_count"]),
            u32(role["head_kill_count"]),
            u32(role["knife_kill_count"]),
            u32(role["special_kill_count"]),
            u32(role["level"]),
            u32(role["honor_point"]),
            u32(role["honor_place"]),
        )
        buf[0x86] = u8(role.get("sex", 1))
    return bytes(buf)


def encode_world_role_order_respond(roles: list[dict[str, Any]]) -> bytes:
    """
    S2C 0x1C GetWorldRoleOrderRespond (KFXClient.dll!0x10725e30 -> PutWorldRoleOrder 0x107128e0).
      +0x00 u8  0x1C
      +0x01 i32 timestamp (clamped 32-bit Unix time_t for localtime())
      +0x05 i32 count
      Entries stride 0x4C (76 bytes), starting at +0x15:
        entry + 0x00 (pkt + 0x15): 32B role_name
        entry + 0x20 (pkt + 0x35): i32 nHonorPoint
        entry + 0x24 (pkt + 0x39): i32 nLevel
        entry + 0x28 (pkt + 0x3D): 32B faction_name
    """
    now = clamp_time32(int(time.time()))
    out = bytearray(0x15 + len(roles) * 0x4C)
    out[0] = 0x1C
    struct.pack_into("<II", out, 1, u32(now), u32(len(roles)))
    for i, r in enumerate(roles):
        off = 0x15 + i * 0x4C
        out[off : off + 32] = pack_cstr(str(r["role_name"]), 32)
        struct.pack_into("<II", out, off + 0x20, u32(r["honor_point"]), u32(r["level"]))
        out[off + 0x28 : off + 0x48] = pack_cstr(str(r.get("faction_name", "")), 32)
    return bytes(out)


def encode_world_faction_order_respond(factions: list[dict[str, Any]], my_rank: int = 0) -> bytes:
    """S2C 0x44 GetWorldFactionOrderRespond."""
    now = clamp_time32(int(time.time()))
    out = bytearray(0x0D + len(factions) * 0x50)
    out[0] = 0x44
    struct.pack_into("<III", out, 1, u32(now), u32(len(factions)), u32(my_rank))
    for i, f in enumerate(factions):
        off = 0x0D + i * 0x50
        struct.pack_into("<I", out, off, u32(f.get("faction_id", 0)))
        out[off + 4 : off + 36] = pack_cstr(str(f.get("faction_name", "")), 32)
        struct.pack_into(
            "<III",
            out,
            off + 36,
            u32(f.get("honor_point", 0)),
            u32(clamp_time32(int(f.get("create_time", now)))),
            u32(f.get("leader_id", 0)),
        )
        out[off + 48 : off + 80] = pack_cstr(str(f.get("leader_name", "")), 32)
    return bytes(out)


def encode_player_buy_item_respond(
    result: int,
    item_id: int,
    item_type: int,
    left_days: int,
    get_type: int,
    money_point: int,
    game_cash: int,
) -> bytes:
    """S2C 0x1D PlayerBuyItemRespond (29 bytes)."""
    return struct.pack(
        "<B7I",
        0x1D,
        u32(result),
        u32(item_id),
        u32(item_type),
        u32(left_days),
        u32(get_type),
        u32(money_point),
        u32(game_cash),
    )


def encode_game_end_update_role_respond(role: dict[str, Any]) -> bytes:
    """
    S2C 0x1E GameEndAndUpdataRoleInfoRespond (0xA9 = 169 bytes).
    Verified in KFXClient.dll!0x10725f20 -> PutRoleGrowInfo (0x10712ca0):
      +0x01..+0x1D: kills, deaths, head_kills, knife_kills, special_kills, victory, deuce, defeated
      +0x21 u32: game_cash (GP -> role+0x80)
      +0x25 u32: level (role+0x30)
      +0x29 u32: honor_place
      +0x2D u32: honor_point (role+0x34)
      +0x31 60B: 15*u32 nWeaponSkill
      +0x6D 60B: 15*u32 nWeaponLevel
    """
    buf = bytearray(0xA9)
    buf[0] = 0x1E
    struct.pack_into(
        "<12I",
        buf,
        1,
        u32(role["kill_count"]),
        u32(role["death_count"]),
        u32(role["head_kill_count"]),
        u32(role["knife_kill_count"]),
        u32(role["special_kill_count"]),
        u32(role["victory_count"]),
        u32(role["deuce_count"]),
        u32(role["defeated_count"]),
        u32(role["game_cash"]),
        u32(role["level"]),
        u32(role["honor_place"]),
        u32(role["honor_point"]),
    )
    return bytes(buf)


def encode_email_list_respond(result: int, emails: list[dict[str, Any]]) -> bytes:
    """
    S2C 0x26 EmailInfoListRespond (9 + count * 0x78 bytes).
    Entry stride 0x78 (120 bytes) starting at +9:
      +0x00 i32 email_id
      +0x04 i32 send_role_id
      +0x08 32B send_role_name
      +0x28 i8  email_type
      +0x29 i8  is_locked
      +0x2A i8  is_read
      +0x2B i8  item_count (0=none, 1=attached, 2=taken)
      +0x2C 64B title
      +0x6C i32 created_at (Unix time_t passed to MSVCR71!localtime())
      +0x70 i32 read_time
      +0x74 i32 die_time
    """
    out = bytearray(9 + len(emails) * 0x78)
    out[0] = 0x26
    struct.pack_into("<II", out, 1, u32(result), u32(len(emails)))
    for i, em in enumerate(emails):
        off = 9 + i * 0x78
        struct.pack_into("<II", out, off, u32(em["email_id"]), u32(em["send_role_id"]))
        out[off + 8 : off + 40] = pack_cstr(str(em["send_role_name"]), 32)
        out[off + 0x28] = u8(em.get("email_type", 1))
        out[off + 0x29] = u8(em.get("is_locked", 0))
        out[off + 0x2A] = u8(em.get("is_read", 0))
        out[off + 0x2B] = 1 if int(em.get("item_type", 0)) > 0 else 0
        out[off + 0x2C : off + 0x6C] = pack_cstr(str(em.get("title", "")), 64)
        created = clamp_time32(int(em.get("created_at", int(time.time()))))
        die_time = clamp_time32(created + 30 * 86400)
        struct.pack_into("<III", out, off + 0x6C, u32(created), u32(created), u32(die_time))
    return bytes(out)


def encode_email_content_respond(result: int, email: dict[str, Any] | None) -> bytes:
    """
    S2C 0x27 EmailContentRespond (KFXClient.dll!0x107267f0 -> PutEmailContentToList 0x10714000).
      +0x2D i32 sEmailItem.nExpend (0=attachment available, 1=taken/none)
      +0x31 NUL-terminated UTF-8 email content
    """
    content_bytes = ((email["content"] if email else "").encode("utf-8", errors="replace")) + b"\x00"
    out = bytearray(0x31 + len(content_bytes))
    out[0] = 0x27
    struct.pack_into("<I", out, 1, u32(result))
    if email:
        has_item = int(email.get("item_type", 0)) > 0
        struct.pack_into("<I", out, 5, u32(email["email_id"]))
        struct.pack_into("<I", out, 0x0D, u32(email.get("item_id", 0)))
        struct.pack_into("<I", out, 0x11, u32(email.get("item_type", 0)))
        struct.pack_into("<I", out, 0x15, u32(email.get("item_days", 0)))
        struct.pack_into("<I", out, 0x2D, 0 if has_item else 1)
    out[0x31:] = content_bytes
    return bytes(out)


def encode_send_email_result_respond(result: int, recv_name: str) -> bytes:
    """S2C 0x28 SendEmailResultRespond (37 bytes)."""
    return struct.pack("<BI", 0x28, u32(result)) + pack_cstr(recv_name, 32)


def encode_takeout_item_result_respond(result: int, email_id: int, item: dict[str, Any] | None) -> bytes:
    """
    S2C 0x29 TakeOutItemResultRespond (25 bytes, KFXClient.dll!0x10726950).
      +0x01 result, +0x05 email_id, +0x09 nItemID, +0x0D nItemType, +0x11 nItemLeftDays, +0x15 nItemGetType
    """
    iid = int(item["item_id"]) if item else 0
    itype = int(item["item_type"]) if item else 0
    idays = int(item["left_days"]) if item else 0
    iget = int(item["item_get_type"]) if item else 0
    return struct.pack("<B6I", 0x29, u32(result), u32(email_id), u32(iid), u32(itype), u32(idays), u32(iget))


def encode_delete_email_result_respond(result: int, email_id: int) -> bytes:
    """S2C 0x2A DeleteEmailResultRespond (9 bytes)."""
    return struct.pack("<BII", 0x2A, u32(result), u32(email_id))


def _pack_relation_entry(role: dict[str, Any], relation_type: int, online: bool) -> bytes:
    """
    52-byte (0x34) relation block verified in KFXClient.dll!PutRelationToList (0x1071dea0)
    and AddRelationResultEvent (0x1071e9b0):
      +0x00 i32 nRelation (0=Friend, 1=Blacklist)
      +0x04 i32 nRoleID
      +0x08 i32 nFactionID
      +0x0C 32B szRoleName
      +0x2C i32 nFactionIconID
      +0x30 u16 nLevel
      +0x32 u16 nState (1=online, 0=offline)
    """
    ent = bytearray(0x34)
    struct.pack_into(
        "<III",
        ent,
        0x00,
        u32(relation_type),
        u32(role["role_id"]),
        u32(role.get("faction_id", 0)),
    )
    ent[0x0C:0x2C] = pack_cstr(str(role["role_name"]), 32)
    struct.pack_into(
        "<IHH",
        ent,
        0x2C,
        u32(role.get("faction_icon_id", 0)),
        u16(role.get("level", 1)),
        1 if online else 0,
    )
    return bytes(ent)


def encode_relation_list_respond(relations: list[dict[str, Any]], online_role_ids: set[int]) -> bytes:
    """S2C 0x2B RelationListRespond (5 + count * 0x34 bytes)."""
    out = bytearray(5)
    out[0] = 0x2B
    struct.pack_into("<I", out, 1, u32(len(relations)))
    for r in relations:
        online = int(r["role_id"]) in online_role_ids
        out.extend(_pack_relation_entry(r, int(r["relation_type"]), online))
    return bytes(out)


def encode_add_relation_result_respond(result: int, role: dict[str, Any] | None, relation_type: int, online: bool) -> bytes:
    """S2C 0x2C AddRelationResultRespond (57 bytes = 0x39). Always populates +0x05 nRelation."""
    out = bytearray(0x39)
    out[0] = 0x2C
    struct.pack_into("<I", out, 1, u32(result))
    if role is not None:
        out[5:0x39] = _pack_relation_entry(role, relation_type, online)
    else:
        struct.pack_into("<I", out, 5, u32(relation_type))
    return bytes(out)


def encode_delete_relation_result_respond(result: int, deleted_role_id: int) -> bytes:
    """S2C 0x2D DeleteRelationResultRespond (9 bytes: op, result, deleted_role_id)."""
    return struct.pack("<BII", 0x2D, u32(result), u32(deleted_role_id))


def encode_faction_member_list_respond(members: list[dict[str, Any]]) -> bytes:
    """S2C 0x45 FactionMemberListRespond (5 + count * 0x2C bytes)."""
    out = bytearray(5 + len(members) * 0x2C)
    out[0] = 0x45
    struct.pack_into("<I", out, 1, u32(len(members)))
    for i, m in enumerate(members):
        off = 5 + i * 0x2C
        struct.pack_into("<III", out, off, u32(m["role_id"]), u32(m.get("level", 1)), u32(m.get("state", 1)))
        out[off + 12 : off + 44] = pack_cstr(str(m["role_name"]), 32)
    return bytes(out)


def encode_change_item_in_room_respond(role: dict[str, Any]) -> bytes:
    """S2C 0x30 ChangeItemInRoomRespond (25 bytes)."""
    return struct.pack(
        "<B6I",
        0x30,
        u32(role["role_id"]),
        u32(role["body_type"]),
        u32(role["head_type"]),
        u32(role["coat_type"]),
        u32(role["trousers_type"]),
        u32(role["major_weapon_id"]),
    )


def encode_present_item_respond(result: int, money_point: int, game_cash: int) -> bytes:
    """S2C 0x32 PresentItemRespond (13 bytes)."""
    return struct.pack("<B3I", 0x32, u32(result), u32(money_point), u32(game_cash))


def encode_system_announce_respond(display_times: int, interval: int, text: str) -> bytes:
    """S2C 0x33 SystemAnnounceRespond."""
    tb = text.encode("utf-8", errors="replace") + b"\x00"
    return struct.pack("<B3I", 0x33, u32(display_times), u32(interval), u32(len(tb))) + tb


def encode_someone_kicked_respond(kicked_role_id: int) -> bytes:
    """S2C 0x36 SomeOneKickedRespond (5 bytes)."""
    return struct.pack("<BI", 0x36, u32(kicked_role_id))


def encode_someone_nominated_owner_respond(role_id: int, is_super: int = 0) -> bytes:
    """S2C 0x37 SomeOneNominatedRoomOwnerRespond (6 bytes)."""
    return struct.pack("<BIB", 0x37, u32(role_id), u8(is_super))


def encode_player_quest_task_respond(result: int, task_id: int) -> bytes:
    """S2C 0x3C PlayerQuestTaskRespond (9 bytes)."""
    return struct.pack("<BII", 0x3C, u32(result), u32(task_id))


def encode_player_quest_bonus_respond(
    task_id: int,
    step: int,
    total_honor: int,
    new_level: int,
    is_random: int,
    item_type_id: int,
    item_bonus: int,
    result: int,
) -> bytes:
    """
    S2C 0x3D PlayerQuestBonusRespond (33 bytes, KFXClient.dll!0x10727890 -> 0x10719b80).
      +0x01 TaskID, +0x05 nStep, +0x09 total_honor_point, +0x0D new_level,
      +0x11 nRandom, +0x15 nItemTypeID, +0x19 ItemBonus, +0x1D nResult (1=success)
    """
    return struct.pack(
        "<B8I",
        0x3D,
        u32(task_id),
        u32(step),
        u32(total_honor),
        u32(new_level),
        u32(is_random),
        u32(item_type_id),
        u32(item_bonus),
        u32(result),
    )


def encode_find_player_respond(
    result: int,
    role: dict[str, Any] | None = None,
    realm_ip: str = "127.0.0.1",
    realm_port: int = 7452,
    channel_id: int = 0,
    room_id: int = 0,
    password_flag: int = 0,
    online: bool = True,
) -> bytes:
    """
    S2C 0x21 FindPlayerRespond (0xAF = 175 bytes, KFXClient.dll!0x107262c0 -> FindPlayerEvent 0x10707950).
      +0x29..+0x60 (14*u32): body, head, coat, trousers, major_weapon, level, honor_point,
                             honor_place, honor_place_last, kills, deaths, head_kills, knife_kills, special_kills
      +0x61..+0x74 (5*u32) : suicide_count(0), victory, deuce, defeated, faction_id
      +0x75..+0x94 (32B)   : faction_name
      +0x99 (u32)          : online state
      +0x9D..+0xA0 (4*u8)  : room_id, channel_id, realm_id, password_flag
      +0xA1..+0xA6         : ip_net(4B), port_net(u16_be)
    """
    buf = bytearray(0xAF)
    buf[0] = 0x21
    struct.pack_into("<I", buf, 1, u32(result))
    if result == 1 and role is not None:
        struct.pack_into("<I", buf, 5, u32(role["role_id"]))
        buf[9:41] = pack_cstr(str(role["role_name"]), 32)
        struct.pack_into(
            "<19I",
            buf,
            0x29,
            u32(role["body_type"]),
            u32(role["head_type"]),
            u32(role["coat_type"]),
            u32(role["trousers_type"]),
            u32(role["major_weapon_id"]),
            u32(role["level"]),
            u32(role["honor_point"]),
            u32(role["honor_place"]),
            u32(role["honor_place_last"]),
            u32(role["kill_count"]),
            u32(role["death_count"]),
            u32(role["head_kill_count"]),
            u32(role["knife_kill_count"]),
            u32(role["special_kill_count"]),
            0,  # nSuicideCount
            u32(role["victory_count"]),
            u32(role["deuce_count"]),
            u32(role["defeated_count"]),
            u32(role.get("faction_id", 0)),
        )
        buf[0x75:0x95] = pack_cstr(str(role.get("faction_name", "")), 32)
        struct.pack_into("<I", buf, 0x99, 1 if online else 0)  # online state
        buf[0x9D] = u8(room_id)
        buf[0x9E] = u8(channel_id)
        buf[0x9F] = 1 if online else 0  # realm_id
        buf[0xA0] = u8(password_flag)
        buf[0xA1:0xA5] = ip_to_u32_net(realm_ip)
        struct.pack_into("!H", buf, 0xA5, u16(realm_port))
    return bytes(buf)


def encode_find_room_respond(
    result: int,
    rm: dict[str, Any] | None = None,
    channel_id: int = 1,
    realm_ip: str = "127.0.0.1",
    realm_port: int = 7452,
) -> bytes:
    """
    S2C 0x22 FindRoomRespond (0x4C = 76 bytes, KFXClient.dll!0x10726400 -> FindRoomEvent 0x10707c80).
      +0x05..+0x08 (4*u8): room_id, channel_id, realm_id, password_flag
      +0x09..+0x28 (32B) : room_name
      +0x29..+0x3C (5*u32): map_id, game_mode, max_players, cur_players, time_limit
      +0x3D (u8)         : game_limit
      +0x3E (u32)        : shoot_limit
      +0x42 (u32)        : room_state (2=waiting, 3=full, 4=playing)
      +0x46..+0x4B       : ip_net(4B), port_net(u16_be)
    """
    buf = bytearray(0x4C)
    buf[0] = 0x22
    struct.pack_into("<I", buf, 1, u32(result))
    if result == 1 and rm is not None:
        buf[5] = u8(rm["room_id"])
        buf[6] = u8(channel_id)
        buf[7] = 1  # realm_id
        buf[8] = 1 if rm.get("password") else 0
        buf[9:41] = pack_cstr(str(rm["room_name"]), 32)
        struct.pack_into(
            "<5I",
            buf,
            0x29,
            u32(rm["map_id"]),
            u32(rm["game_mode"]),
            u32(rm["max_players"]),
            u32(rm["cur_players"]),
            u32(rm.get("time_limit", 20)),
        )
        buf[0x3D] = u8(rm.get("game_limit", 5))
        struct.pack_into("<II", buf, 0x3E, u32(rm.get("shoot_limit", 100)), u32(rm.get("room_state", 2)))
        buf[0x46:0x4A] = ip_to_u32_net(realm_ip)
        struct.pack_into("!H", buf, 0x4A, u16(realm_port))
    return bytes(buf)


def encode_someone_invite_me_respond(
    master_role_id: int,
    master_role_name: str,
    room_id: int,
    channel_id: int,
    realm_id: int,
    password_flag: int,
    realm_ip: str,
    realm_port: int,
) -> bytes:
    """
    S2C 0x24 SomeoneInviteMeRespond (0x2F = 47 bytes, KFXClient.dll!0x107265a0 -> 0x107135c0).
      +0x00 u8  0x24
      +0x01 u32 master_role_id
      +0x05 32B master_role_name
      +0x25 u8  room_id
      +0x26 u8  channel_id
      +0x27 u8  realm_id
      +0x28 u8  password_flag
      +0x29 4B  ip_net
      +0x2D u16 port_net
    """
    buf = bytearray(0x2F)
    buf[0] = 0x24
    struct.pack_into("<I", buf, 1, u32(master_role_id))
    buf[5:37] = pack_cstr(master_role_name, 32)
    buf[0x25] = u8(room_id)
    buf[0x26] = u8(channel_id)
    buf[0x27] = u8(realm_id)
    buf[0x28] = u8(password_flag)
    buf[0x29:0x2D] = ip_to_u32_net(realm_ip)
    struct.pack_into("!H", buf, 0x2D, u16(realm_port))
    return bytes(buf)


def encode_realm_list_from_realm(realms: list[dict[str, Any]]) -> bytes:
    """S2C 0xFA KFXRealmClient::RealmListRespond (count u16 is at +1, entries at +3)."""
    out = bytearray(3 + len(realms) * 40)
    out[0] = 0xFA
    struct.pack_into("<H", out, 1, u16(len(realms)))
    for i, r in enumerate(realms):
        off = 3 + i * 40
        out[off] = u8(r["id"])
        out[off + 1] = u8(r.get("work_state", 1))
        struct.pack_into("!H", out, off + 2, u16(r["port"]))
        out[off + 4 : off + 8] = ip_to_u32_net(str(r["ip"]))
        out[off + 8 : off + 40] = pack_cstr(str(r["name"]), 32)
    return bytes(out)

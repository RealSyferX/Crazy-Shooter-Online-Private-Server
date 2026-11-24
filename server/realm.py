"""
Realm / Lobby / Channel / Room / Inventory / Shop / Chat / Mail / Relation / Quest Server (TCP 7452).

Implements the complete KFXRealmClient C2S opcode table (0x00..0x35) verified from KFXClient.dll.
"""
from __future__ import annotations

import asyncio
import logging
import struct
import time
from dataclasses import dataclass, field
from typing import Any

from .bishop import SessionRegistry
from .crypto import KSGCipherTable, KFXStream
from .database import Database
from .gamedata import GameData
from .match_manager import MatchManager
from .packets import (
    encode_add_relation_result_respond,
    encode_change_item_in_room_respond,
    encode_channel_list_respond,
    encode_channel_player_list_respond,
    encode_chat_content_respond,
    encode_create_room_respond,
    encode_current_room_info_respond,
    encode_delete_email_result_respond,
    encode_delete_relation_result_respond,
    encode_email_content_respond,
    encode_email_list_respond,
    encode_faction_member_list_respond,
    encode_find_player_respond,
    encode_find_room_respond,
    encode_game_end_update_role_respond,
    encode_game_start_command,
    encode_get_item_list_respond,
    encode_join_channel_respond,
    encode_join_room_respond,
    encode_login_realm_respond,
    encode_personal_chat_result_respond,
    encode_player_buy_item_respond,
    encode_player_quest_bonus_respond,
    encode_player_quest_task_respond,
    encode_present_item_respond,
    encode_ready_game_info_respond,
    encode_relation_list_respond,
    encode_request_role_info_respond,
    encode_room_list_respond,
    encode_room_owner_change_respond,
    encode_room_player_list_respond,
    encode_send_email_result_respond,
    encode_simple_result,
    encode_someone_change_team_respond,
    encode_someone_invite_me_respond,
    encode_someone_join_room_respond,
    encode_someone_kicked_respond,
    encode_someone_leave_room_respond,
    encode_someone_nominated_owner_respond,
    encode_system_announce_respond,
    encode_takeout_item_result_respond,
    encode_world_faction_order_respond,
    encode_world_role_order_respond,
    pack_cstr,
    u32,
    unpack_cstr,
)

log = logging.getLogger("csg.realm")


@dataclass(eq=False)
class ClientSession:
    stream: KFXStream
    account_id: int = 0
    username: str = ""
    cookie: int = 0
    role_id: int = 0
    role_name: str = ""
    channel_id: int = 0
    room_id: int = 0
    team_id: int = 0  # 0 = Red / Team A, 1 = Blue / Team B
    ready: int = 0
    in_game: int = 0
    connected_at: float = field(default_factory=time.time)


@dataclass
class Room:
    room_id: int
    channel_id: int
    room_name: str
    password: str
    owner_id: int
    map_id: int
    game_mode: int
    max_players: int = 16
    time_limit: int = 20
    shoot_limit: int = 100
    game_limit: int = 5
    point_limit: int = 0
    balance_flag: int = 1
    enable_join_in_game: int = 1
    auto_aim_flag: int = 0
    is_faction_game: int = 0
    random_flag: int = 0
    is_super_owner: int = 0
    weapon_limit: int = 0
    room_state: int = 2  # KFXGUI.u enum: 2 = waiting (sCanEnter), 3 = full (sPersonEnough), 4 = playing (sInGame)
    active_match_session: int = 0
    players: dict[int, ClientSession] = field(default_factory=dict)

    def refresh_waiting_state(self) -> None:
        if self.room_state != 4:
            self.room_state = 3 if len(self.players) >= self.max_players else 2

    def to_dict(self) -> dict[str, Any]:
        return {
            "room_id": self.room_id,
            "channel_id": self.channel_id,
            "room_name": self.room_name,
            "password": self.password,
            "owner_id": self.owner_id,
            "map_id": self.map_id,
            "game_mode": self.game_mode,
            "max_players": self.max_players,
            "cur_players": len(self.players),
            "time_limit": self.time_limit,
            "shoot_limit": self.shoot_limit,
            "game_limit": self.game_limit,
            "point_limit": self.point_limit,
            "balance_flag": self.balance_flag,
            "enable_join_in_game": self.enable_join_in_game,
            "auto_aim_flag": self.auto_aim_flag,
            "is_faction_game": self.is_faction_game,
            "random_flag": self.random_flag,
            "is_super_owner": self.is_super_owner,
            "weapon_limit": self.weapon_limit,
            "room_state": self.room_state,
        }


class Channel:
    def __init__(self, channel_id: int, name: str, max_players: int = 200, state: int = 1):
        self.id = channel_id
        self.name = name
        self.max_players = max_players
        self.state = state
        self.players: dict[int, ClientSession] = {}
        self.rooms: dict[int, Room] = {}
        self._next_room_id = 1

    def allocate_room_id(self) -> int:
        for rid in range(1, 255):
            if rid not in self.rooms:
                return rid
        self._next_room_id += 1
        return self._next_room_id


class RealmServer:
    def __init__(
        self,
        config: dict[str, Any],
        cipher: KSGCipherTable,
        db: Database,
        gamedata: GameData,
        tickets: SessionRegistry,
        match_manager: MatchManager,
    ):
        self.config = config
        self.cipher = cipher
        self.db = db
        self.gamedata = gamedata
        self.tickets = tickets
        self.match_manager = match_manager
        self.server: asyncio.AbstractServer | None = None

        self.sessions: set[ClientSession] = set()
        self.online_by_role_id: dict[int, ClientSession] = {}
        self.online_by_name: dict[str, ClientSession] = {}
        self._match_watchers: set[asyncio.Task[None]] = set()
        # Tracks which role_ids have already had stats persisted for (channel_id, room_id, match_session_id)
        self._persisted_match_roles: dict[tuple[int, int, int], set[int]] = {}
        self.channels: dict[int, Channel] = {}
        for ch_cfg in config.get("channels", [{"id": 1, "name": "Ch 1 - Free", "max_players": 200, "state": 1}]):
            cid = int(ch_cfg["id"])
            self.channels[cid] = Channel(
                cid,
                str(ch_cfg["name"]),
                int(ch_cfg.get("max_players", 200)),
                int(ch_cfg.get("state", 1)),
            )

    @property
    def public_ip(self) -> str:
        return str(self.config.get("public_ip", "127.0.0.1"))

    @property
    def realm_port(self) -> int:
        return int(self.config.get("realm_port", 7452))

    def get_status_snapshot(self) -> dict[str, Any]:
        rooms_out = []
        for ch in self.channels.values():
            for rm in ch.rooms.values():
                rooms_out.append({
                    "channel_id": ch.id,
                    "room_id": rm.room_id,
                    "room_name": rm.room_name,
                    "map_id": rm.map_id,
                    "map_name": self.gamedata.get_map(rm.map_id)["name"],
                    "game_mode": rm.game_mode,
                    "mode_name": self.gamedata.get_mode(rm.game_mode)["name"],
                    "players": len(rm.players),
                    "max_players": rm.max_players,
                    "state": "playing" if rm.room_state == 4 else "waiting",
                })
        return {
            "online_players": len(self.online_by_role_id),
            "players": [s.role_name for s in self.online_by_role_id.values()],
            "channels": [
                {"id": c.id, "name": c.name, "players": len(c.players), "rooms": len(c.rooms)}
                for c in self.channels.values()
            ],
            "rooms": rooms_out,
            "active_matches": len(self.match_manager.active_by_room),
        }

    async def start(self) -> None:
        host = str(self.config.get("bind_host", "0.0.0.0"))
        port = self.realm_port
        self.server = await asyncio.start_server(self._handle_client, host, port)
        log.info("Realm Lobby Server listening on %s:%d", host, port)

    async def stop(self) -> None:
        for task in list(self._match_watchers):
            task.cancel()
        if self._match_watchers:
            await asyncio.gather(*self._match_watchers, return_exceptions=True)
            self._match_watchers.clear()
        await self.match_manager.stop_all_async()
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
            self.server = None

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        stream = KFXStream(reader, writer, self.cipher, is_server=True)
        sess = ClientSession(stream=stream)
        self.sessions.add(sess)
        peer = stream.peer_addr
        log.info("[Realm] Client connected: %s", peer)
        try:
            await stream.server_handshake()
            while True:
                try:
                    pkt = await stream.read_packet()
                except (asyncio.IncompleteReadError, ConnectionResetError, EOFError):
                    break
                if not pkt:
                    continue
                try:
                    await self._dispatch(sess, pkt)
                except (asyncio.IncompleteReadError, ConnectionError, EOFError):
                    break
                except Exception:
                    log.exception(
                        "[Realm] Handler error on %s (role=%s, op=0x%02X, len=%d, pkt=%s)",
                        peer,
                        sess.role_name or "-",
                        pkt[0],
                        len(pkt),
                        pkt[:64].hex(),
                    )
        except Exception:
            log.exception("[Realm] Stream error on %s (role=%s)", peer, sess.role_name or "-")
        finally:
            await self._cleanup_session(sess)
            await stream.close()
            log.info("[Realm] Client disconnected: %s (role=%s)", peer, sess.role_name or "-")

    async def _cleanup_session(self, sess: ClientSession) -> None:
        self.sessions.discard(sess)
        if sess.room_id and sess.channel_id:
            await self._leave_room_internal(sess, send_ack=False)
        if sess.channel_id and sess.channel_id in self.channels:
            self.channels[sess.channel_id].players.pop(sess.role_id, None)
            sess.channel_id = 0
        if sess.role_id:
            if self.online_by_role_id.get(sess.role_id) is sess:
                self.online_by_role_id.pop(sess.role_id, None)
            if self.online_by_name.get(sess.role_name.lower()) is sess:
                self.online_by_name.pop(sess.role_name.lower(), None)

    # ------------------------------------------------------------------
    # Packet Dispatcher
    # ------------------------------------------------------------------
    async def _dispatch(self, sess: ClientSession, pkt: bytes) -> None:
        op = pkt[0]
        handlers = {
            0x00: self._on_hide_login_realm,
            0x01: self._on_train_login_realm,
            0x02: self._on_create_role,
            0x03: self._on_login_realm,
            0x04: self._on_channel_list,
            0x05: self._on_select_channel,
            0x06: self._on_leave_channel,
            0x07: self._on_room_list,
            0x08: self._on_channel_player_list,
            0x09: self._on_create_room,
            0x0A: self._on_set_room_info,
            0x0B: self._on_join_room,
            0x0C: self._on_leave_room,
            0x0D: self._on_room_player_list,
            0x0E: self._on_select_team,
            0x0F: self._on_ready_game,
            0x10: self._on_start_game,
            0x11: self._on_join_start_game,
            0x12: self._on_channel_chat,
            0x13: self._on_room_chat,
            0x14: self._on_personal_chat_name,
            0x15: self._on_personal_chat_id,
            0x16: self._on_get_item_list,
            0x17: self._on_set_using_item_list,
            0x18: self._on_set_role_info,
            0x19: self._on_one_role_full_info,
            0x1A: self._on_world_role_order,
            0x1B: self._on_buy_item,
            0x1C: self._on_goto_want_position,
            0x1D: self._on_find_player,
            0x1E: self._on_find_room,
            0x1F: self._on_invite_player,
            0x20: self._on_reply_invite,
            0x21: self._on_email_list,
            0x22: self._on_email_content,
            0x23: self._on_send_email,
            0x24: self._on_takeout_item,
            0x25: self._on_delete_email,
            0x26: self._on_relation_list,
            0x27: self._on_add_relation,
            0x28: self._on_delete_relation,
            0x29: self._on_player_leave_game,
            0x2A: self._on_player_appeal,
            0x2B: self._on_present_item,
            0x2D: self._on_public_or_group_chat,
            0x2E: self._on_kick_player,
            0x2F: self._on_nominate_owner,
            0x30: self._on_finish_task,
            0x31: self._on_quest_task,
            0x32: self._on_quest_bonus,
            0x34: self._on_world_faction_order,
            0x35: self._on_faction_member_list,
        }
        handler = handlers.get(op)
        if handler is None:
            log.debug("[Realm] Unhandled C2S opcode 0x%02X len=%d from %s", op, len(pkt), sess.stream.peer_addr)
            return
        await handler(sess, pkt)

    # ------------------------------------------------------------------
    # Auth & Role Creation (0x00, 0x01, 0x02, 0x03)
    # ------------------------------------------------------------------
    def _bind_ticket(self, sess: ClientSession, role_id_field: int, cookie_field: int) -> bool:
        """
        Remember: KFXClient::execLoginRealm passes (ctrl+0x3f4=cookie, ctrl+0x3f8=role_id),
        which FUN_10720f10 / FUN_10720d10 pack as:
          +0x01 = role_id_field (ctrl+0x3f8)
          +0x05 = cookie_field  (ctrl+0x3f4)
        """
        ticket = self.tickets.lookup(cookie_field, role_id_field)
        if ticket is None:
            # Fallback if a direct client passes (cookie, role_id) swapped
            ticket = self.tickets.lookup(role_id_field, cookie_field)
        if ticket is None:
            return False
        sess.account_id = ticket.account_id
        sess.username = ticket.username
        sess.cookie = ticket.cookie
        role = self.db.get_role_by_account(ticket.account_id)
        if role:
            sess.role_id = int(role["role_id"])
            sess.role_name = str(role["role_name"])
            self.online_by_role_id[sess.role_id] = sess
            self.online_by_name[sess.role_name.lower()] = sess
        return True

    async def _on_hide_login_realm(self, sess: ClientSession, pkt: bytes) -> None:
        """C2S 0x00 HideLoginRealmRequest (used when bCreateRole=True)."""
        if len(pkt) < 9:
            return
        role_id_f, cookie_f = struct.unpack_from("<II", pkt, 1)
        if not self._bind_ticket(sess, role_id_f, cookie_f):
            await sess.stream.send_packet(encode_simple_result(0x00, 0))
            return
        log.info("[Realm] HideLogin OK user=%s account=%d", sess.username, sess.account_id)
        await sess.stream.send_packet(encode_simple_result(0x00, 1))

    async def _on_train_login_realm(self, sess: ClientSession, pkt: bytes) -> None:
        """C2S 0x01 TrainLoginRealmRequest."""
        if len(pkt) < 9:
            return
        role_id_f, cookie_f = struct.unpack_from("<II", pkt, 1)
        ok = self._bind_ticket(sess, role_id_f, cookie_f)
        await sess.stream.send_packet(encode_simple_result(0x01, 1 if ok else 0))

    async def _on_create_role(self, sess: ClientSession, pkt: bytes) -> None:
        """C2S 0x02 CreateNewRoleRequest (49 bytes)."""
        if len(pkt) < 0x31 or sess.account_id == 0:
            await sess.stream.send_packet(encode_simple_result(0x02, 0))
            return
        role_name = unpack_cstr(pkt, 1, 32)
        body_type, head_type, coat_type, trousers_type = struct.unpack_from("<IIII", pkt, 0x21)
        role = self.db.create_role(sess.account_id, role_name, body_type, head_type, coat_type, trousers_type)
        if role is None:
            log.info("[Realm] CreateRole FAILED name=%r account=%d", role_name, sess.account_id)
            # Result 2 = duplicate name / invalid
            await sess.stream.send_packet(encode_simple_result(0x02, 2))
            return
        sess.role_id = int(role["role_id"])
        sess.role_name = str(role["role_name"])
        self.online_by_role_id[sess.role_id] = sess
        self.online_by_name[sess.role_name.lower()] = sess
        log.info("[Realm] CreateRole OK role_id=%d name=%s body=%d", sess.role_id, sess.role_name, body_type)
        await sess.stream.send_packet(encode_simple_result(0x02, 1))

    async def _on_login_realm(self, sess: ClientSession, pkt: bytes) -> None:
        """C2S 0x03 LoginRealmRequest (43 bytes)."""
        if len(pkt) < 9:
            return
        role_id_f, cookie_f = struct.unpack_from("<II", pkt, 1)
        if not self._bind_ticket(sess, role_id_f, cookie_f):
            await sess.stream.send_packet(encode_login_realm_respond(0, 0, ""))
            return
        role = self.db.get_role_by_account(sess.account_id)
        if role is None:
            await sess.stream.send_packet(encode_login_realm_respond(0, 0, ""))
            return
        sess.role_id = int(role["role_id"])
        sess.role_name = str(role["role_name"])
        self.online_by_role_id[sess.role_id] = sess
        self.online_by_name[sess.role_name.lower()] = sess
        log.info("[Realm] LoginRealm OK role_id=%d name=%s", sess.role_id, sess.role_name)
        # param_2=0 so LoginRealmEvent does not overwrite m_sCurChannelName with role_name
        await sess.stream.send_packet(encode_login_realm_respond(1, 0, ""))
        # Also push channel list and welcome announcement
        await self._send_channel_list(sess)
        ann = str(self.config.get("registration", {}).get("announcement", "")).strip()
        if ann:
            await sess.stream.send_packet(encode_system_announce_respond(1, 5, ann))

    # ------------------------------------------------------------------
    # Channels (0x04, 0x05, 0x06, 0x08)
    # ------------------------------------------------------------------
    async def _send_channel_list(self, sess: ClientSession) -> None:
        ch_list = [
            {
                "id": ch.id,
                "name": ch.name,
                "max_players": ch.max_players,
                "state": ch.state,
            }
            for ch in sorted(self.channels.values(), key=lambda c: c.id)
        ]
        await sess.stream.send_packet(encode_channel_list_respond(ch_list))

    async def _on_channel_list(self, sess: ClientSession, _pkt: bytes) -> None:
        await self._send_channel_list(sess)

    async def _on_select_channel(self, sess: ClientSession, pkt: bytes) -> None:
        """C2S 0x05 SelectChannelRequest (2 bytes: op, u8 channel_id)."""
        if len(pkt) < 2 or sess.role_id == 0:
            await sess.stream.send_packet(encode_join_channel_respond(0))
            return
        ch_id = pkt[1]
        if ch_id not in self.channels:
            ch_id = next(iter(self.channels.keys()))
        if sess.channel_id and sess.channel_id in self.channels:
            self.channels[sess.channel_id].players.pop(sess.role_id, None)
        ch = self.channels[ch_id]
        ch.players[sess.role_id] = sess
        sess.channel_id = ch_id
        role = self.db.get_role_by_id(sess.role_id)
        log.info("[Realm] %s joined channel %d (%s)", sess.role_name, ch_id, ch.name)
        await sess.stream.send_packet(encode_join_channel_respond(1, role))
        # Immediately push ChannelPlayerList (excluding self) so AddZeroedChannelPlayerList trims
        # any stale zeroed slot[1] appended by PutPlayerInfo's AddZeroed(1)
        await self._send_channel_player_list(sess)

    async def _on_leave_channel(self, sess: ClientSession, _pkt: bytes) -> None:
        if sess.room_id:
            await self._leave_room_internal(sess, send_ack=False)
        if sess.channel_id and sess.channel_id in self.channels:
            self.channels[sess.channel_id].players.pop(sess.role_id, None)
            sess.channel_id = 0
        await sess.stream.send_packet(encode_simple_result(0x06, 1))

    async def _send_channel_player_list(self, sess: ClientSession) -> None:
        ch = self.channels.get(sess.channel_id)
        if ch is None:
            await sess.stream.send_packet(encode_channel_player_list_respond([]))
            return
        # m_sChannelPlayerList[0] is strictly self (from JoinChannelRespond); [1..N] are OTHER players
        players = []
        for rid in list(ch.players.keys()):
            if rid == sess.role_id:
                continue
            r = self.db.get_role_by_id(rid)
            if r:
                players.append(r)
        await sess.stream.send_packet(encode_channel_player_list_respond(players))

    async def _on_channel_player_list(self, sess: ClientSession, _pkt: bytes) -> None:
        await self._send_channel_player_list(sess)

    # ------------------------------------------------------------------
    # Rooms (0x07, 0x09..0x11, 0x29, 0x2E, 0x2F)
    # ------------------------------------------------------------------
    def _build_room_player_dict(self, sess: ClientSession) -> dict[str, Any]:
        role = self.db.get_role_by_id(sess.role_id) or {}
        d = dict(role)
        d["role_id"] = sess.role_id
        d["role_name"] = sess.role_name
        d["team_id"] = sess.team_id
        d["ready"] = sess.ready
        d["in_game"] = sess.in_game
        return d

    def _get_current_room(self, sess: ClientSession) -> Room | None:
        ch = self.channels.get(sess.channel_id)
        if not ch or not sess.room_id:
            return None
        return ch.rooms.get(sess.room_id)

    async def _broadcast_room(self, rm: Room, payload: bytes, *, exclude_role_id: int = 0) -> None:
        for rid, s in list(rm.players.items()):
            if rid == exclude_role_id:
                continue
            try:
                await s.stream.send_packet(payload)
            except Exception:
                pass

    async def _on_room_list(self, sess: ClientSession, _pkt: bytes) -> None:
        ch = self.channels.get(sess.channel_id)
        rooms = [rm.to_dict() for rm in ch.rooms.values()] if ch else []
        await sess.stream.send_packet(encode_room_list_respond(rooms))

    async def _on_create_room(self, sess: ClientSession, pkt: bytes) -> None:
        """
        C2S 0x09 CreateRoomRequest (87 bytes):
          +0x01 32B room_name
          +0x21 32B password
          +0x41 u32 game_mode
          +0x45 u32 map_id
          +0x49 u32 random_flag
          +0x4D u32 max_players
          +0x51 u8  enable_join_in_game
          +0x52 u8  is_faction_game
          +0x53 u32 weapon_limit
        """
        ch = self.channels.get(sess.channel_id)
        if ch is None or len(pkt) < 0x57 or sess.role_id == 0:
            await sess.stream.send_packet(encode_create_room_respond(205, 0))
            return
        if sess.room_id:
            await self._leave_room_internal(sess, send_ack=False)

        room_name = unpack_cstr(pkt, 0x01, 32) or f"{sess.role_name}'s Room"
        password = unpack_cstr(pkt, 0x21, 32)
        game_mode, map_id, random_flag, max_players = struct.unpack_from("<IIII", pkt, 0x41)
        enable_join = pkt[0x51]
        is_faction = pkt[0x52]
        weapon_limit = struct.unpack_from("<I", pkt, 0x53)[0]

        if game_mode not in self.gamedata.modes:
            game_mode = int(self.gamedata.get_map(map_id).get("default_mode", 1)) if map_id in self.gamedata.maps else 1
        # Enforce KFXMapMode.csv validity (and resolve Random map_id <= 0)
        map_id = self.gamedata.pick_map_for_mode(game_mode, map_id, reroll=(map_id <= 0))
        mode_cfg = self.gamedata.get_mode(game_mode)
        max_players = max(2, min(16, max_players or int(mode_cfg.get("default_player_limit", 16))))

        rid = ch.allocate_room_id()
        rm = Room(
            room_id=rid,
            channel_id=ch.id,
            room_name=room_name,
            password=password,
            owner_id=sess.role_id,
            map_id=map_id,
            game_mode=game_mode,
            max_players=max_players,
            time_limit=int(mode_cfg.get("default_time_limit", 20)),
            shoot_limit=int(mode_cfg.get("default_kill_limit", 100)),
            game_limit=int(mode_cfg.get("default_bout_limit", 5)),
            point_limit=int(mode_cfg.get("default_point_limit", 0)),
            enable_join_in_game=enable_join,
            is_faction_game=is_faction,
            random_flag=random_flag,
            weapon_limit=weapon_limit,
            room_state=2,
        )
        sess.room_id = rid
        sess.team_id = 0
        sess.ready = 0
        sess.in_game = 0
        rm.players[sess.role_id] = sess
        rm.refresh_waiting_state()
        ch.rooms[rid] = rm

        log.info("[Realm] Room #%d created by %s: %r map=%d mode=%d", rid, sess.role_name, room_name, map_id, game_mode)
        # Client enters InRoomState directly on 0x09; follow with 0x0B (preserves m_sRoomList[0]) + 0x0E
        await sess.stream.send_packet(encode_create_room_respond(1, rid))
        await sess.stream.send_packet(encode_current_room_info_respond(rm.to_dict()))
        await sess.stream.send_packet(encode_room_player_list_respond([self._build_room_player_dict(sess)]))

    async def _on_set_room_info(self, sess: ClientSession, pkt: bytes) -> None:
        """C2S 0x0A SetRoomInfoRequest (109 bytes)."""
        rm = self._get_current_room(sess)
        if rm is None or rm.owner_id != sess.role_id or len(pkt) < 0x4D:
            await sess.stream.send_packet(encode_simple_result(0x0A, 206))
            return
        req_map_id = struct.unpack_from("<i", pkt, 0x29)[0]
        req_mode = struct.unpack_from("<i", pkt, 0x2D)[0]
        if req_mode in self.gamedata.modes:
            rm.game_mode = req_mode
        rm.random_flag = struct.unpack_from("<i", pkt, 0x31)[0]
        # KFXGUIRoomSettingPanel sends map_id=0 with random_flag=2 when Random is chosen
        rm.map_id = self.gamedata.pick_map_for_mode(rm.game_mode, req_map_id, reroll=(req_map_id <= 0))
        rm.max_players = max(2, min(16, pkt[0x35] or rm.max_players))
        rm.time_limit = pkt[0x36]
        rm.game_limit = pkt[0x37]
        rm.is_faction_game = pkt[0x38]
        rm.shoot_limit = struct.unpack_from("<i", pkt, 0x3D)[0]
        rm.point_limit = struct.unpack_from("<i", pkt, 0x41)[0]
        rm.balance_flag = pkt[0x45]
        rm.enable_join_in_game = pkt[0x46]
        rm.auto_aim_flag = pkt[0x47]
        rm.weapon_limit = struct.unpack_from("<i", pkt, 0x49)[0]
        rm.refresh_waiting_state()

        await sess.stream.send_packet(encode_simple_result(0x0A, 1))
        await self._broadcast_room(rm, encode_current_room_info_respond(rm.to_dict()))

    async def _send_room_ready_sync(self, sess: ClientSession, rm: Room) -> None:
        """AddRoomPlayerList zeroes nReadyFalg; send 0x14 for each currently ready player."""
        for p in rm.players.values():
            if p.ready:
                await sess.stream.send_packet(encode_ready_game_info_respond(p.role_id, 1))

    async def _on_join_room(self, sess: ClientSession, pkt: bytes) -> None:
        """C2S 0x0B JoinRoomRequest (37 bytes: op, u32 room_id, char password[32])."""
        ch = self.channels.get(sess.channel_id)
        if ch is None or len(pkt) < 5 or sess.role_id == 0:
            await sess.stream.send_packet(encode_join_room_respond(207))
            return
        room_id = struct.unpack_from("<I", pkt, 1)[0]
        password = unpack_cstr(pkt, 5, 32) if len(pkt) >= 37 else ""
        # room_id == 0 means QuickJoin
        rm = ch.rooms.get(room_id)
        if room_id == 0:
            for candidate in ch.rooms.values():
                can_enter = candidate.room_state == 2 or (candidate.room_state == 4 and candidate.enable_join_in_game)
                if can_enter and len(candidate.players) < candidate.max_players and not candidate.password:
                    rm = candidate
                    break
        if rm is None:
            await sess.stream.send_packet(encode_join_room_respond(230))  # room does not exist
            return
        if len(rm.players) >= rm.max_players:
            await sess.stream.send_packet(encode_join_room_respond(231))  # room full
            return
        if rm.room_state == 4 and not rm.enable_join_in_game:
            await sess.stream.send_packet(encode_join_room_respond(229))  # cannot join in-game room
            return
        if rm.password and rm.password != password:
            await sess.stream.send_packet(encode_join_room_respond(228))  # invalid room password
            return
        if sess.room_id and sess.room_id != rm.room_id:
            await self._leave_room_internal(sess, send_ack=False)

        # Auto-balance team assignment
        team0 = sum(1 for p in rm.players.values() if p.team_id == 0)
        team1 = sum(1 for p in rm.players.values() if p.team_id == 1)
        sess.room_id = rm.room_id
        sess.team_id = 0 if team0 <= team1 else 1
        sess.ready = 0
        sess.in_game = 0
        rm.players[sess.role_id] = sess
        rm.refresh_waiting_state()

        log.info("[Realm] %s joined Room #%d (team=%d)", sess.role_name, rm.room_id, sess.team_id)
        await sess.stream.send_packet(encode_join_room_respond(1, rm.to_dict()))
        plist = [self._build_room_player_dict(p) for p in rm.players.values()]
        await sess.stream.send_packet(encode_room_player_list_respond(plist))
        await self._send_room_ready_sync(sess, rm)
        await self._broadcast_room(
            rm,
            encode_someone_join_room_respond(self._build_room_player_dict(sess)),
            exclude_role_id=sess.role_id,
        )

    async def _leave_room_internal(self, sess: ClientSession, *, send_ack: bool = True) -> None:
        ch = self.channels.get(sess.channel_id)
        rm = ch.rooms.get(sess.room_id) if (ch and sess.room_id) else None
        sess.room_id = 0
        sess.ready = 0
        sess.in_game = 0
        if rm is not None:
            was_in_game = sess.role_id in rm.players and rm.room_state == 4
            rm.players.pop(sess.role_id, None)
            if was_in_game:
                self.match_manager.remove_player(rm.channel_id, rm.room_id, sess.role_id, reason="left_room")
            if not rm.players:
                ch.rooms.pop(rm.room_id, None)  # type: ignore[union-attr]
                await self.match_manager.stop_match_async(rm.channel_id, rm.room_id, notify_match_end=False)
                log.info("[Realm] Room #%d closed (empty)", rm.room_id)
            else:
                rm.refresh_waiting_state()
                await self._broadcast_room(rm, encode_someone_leave_room_respond(sess.role_id))
                if rm.owner_id == sess.role_id:
                    new_owner = next(iter(rm.players.keys()))
                    rm.owner_id = new_owner
                    rm.players[new_owner].ready = 0
                    await self._broadcast_room(rm, encode_room_owner_change_respond(new_owner, 0))
                    await self._broadcast_room(rm, encode_current_room_info_respond(rm.to_dict()))
        if send_ack:
            await sess.stream.send_packet(encode_simple_result(0x0D, 1))

    async def _on_leave_room(self, sess: ClientSession, _pkt: bytes) -> None:
        await self._leave_room_internal(sess, send_ack=True)

    async def _on_room_player_list(self, sess: ClientSession, _pkt: bytes) -> None:
        rm = self._get_current_room(sess)
        plist = [self._build_room_player_dict(p) for p in rm.players.values()] if rm else []
        await sess.stream.send_packet(encode_room_player_list_respond(plist))
        if rm is not None:
            await self._send_room_ready_sync(sess, rm)

    async def _on_select_team(self, sess: ClientSession, pkt: bytes) -> None:
        rm = self._get_current_room(sess)
        if rm is None or len(pkt) < 5:
            await sess.stream.send_packet(encode_simple_result(0x12, 215))
            return
        team_id = struct.unpack_from("<i", pkt, 1)[0]
        sess.team_id = 1 if team_id else 0
        await sess.stream.send_packet(encode_simple_result(0x12, 1))
        await self._broadcast_room(rm, encode_someone_change_team_respond(sess.role_id, sess.team_id))

    async def _on_ready_game(self, sess: ClientSession, pkt: bytes) -> None:
        rm = self._get_current_room(sess)
        if rm is None or len(pkt) < 5:
            return
        ready_flag = struct.unpack_from("<i", pkt, 1)[0]
        sess.ready = 1 if ready_flag else 0
        await self._broadcast_room(rm, encode_ready_game_info_respond(sess.role_id, sess.ready))

    def _build_match_roster_entry(self, sess: ClientSession) -> dict[str, Any]:
        """Build a canonical player roster entry for UE2MatchServer from DB role + equipped loadout."""
        role = self.db.get_role_by_id(sess.role_id) or {}
        resolved = self.db.get_resolved_loadout(sess.role_id) if sess.role_id else {}
        loadout_dict = {
            "major_weapons": [t[1] for t in resolved.get("major", []) if t[1] > 0],
            "minor_weapons": [t[1] for t in resolved.get("minor", []) if t[1] > 0],
            "melee_weapons": [t[1] for t in resolved.get("knife", []) if t[1] > 0],
            "grenades": [t[1] for t in resolved.get("grenade", []) if t[1] > 0],
        }
        return {
            "role_id": sess.role_id,
            "role_name": sess.role_name,
            "name": sess.role_name,
            "team_id": sess.team_id,
            "session_cookie": sess.cookie,
            "cookie": sess.cookie,
            "level": int(role.get("level", 1)),
            "body_type": int(role.get("body_type", 1)),
            "head_type": int(role.get("head_type", 6554721)),
            "coat_type": int(role.get("coat_type", 6620247)),
            "trousers_type": int(role.get("trousers_type", 6685803)),
            "major_weapon_id": int(role.get("major_weapon_id", 65537)),
            "loadout": loadout_dict,
        }

    def _persist_player_match_stats(
        self,
        channel_id: int,
        room_id: int,
        match_session_id: int,
        role_id: int,
        pstats: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """Persist match stats for `role_id` at most once per match session; return updated role row."""
        key = (channel_id, room_id, match_session_id)
        done = self._persisted_match_roles.setdefault(key, set())
        if role_id in done:
            return self.db.get_role_by_id(role_id)
        done.add(role_id)
        if pstats is not None:
            return self.db.add_match_stats(
                role_id,
                kills=int(pstats.get("kills", 0)),
                deaths=int(pstats.get("deaths", 0)),
                victory=int(pstats.get("victory", 0)),
                deuce=int(pstats.get("deuce", 0)),
                defeated=int(pstats.get("defeated", 0)),
                head_kills=int(pstats.get("head_kills", pstats.get("headshots", 0))),
                knife_kills=int(pstats.get("knife_kills", 0)),
                special_kills=int(pstats.get("special_kills", 0)),
                honor_gain=int(pstats.get("honor_gain", 50)),
                gp_gain=int(pstats.get("gp_gain", 200)),
            )
        return self.db.add_match_stats(role_id, honor_gain=50, gp_gain=200)

    async def _on_ue2_match_end(self, channel_id: int, room_id: int, results: dict[str, Any]) -> None:
        """Async callback invoked by UE2MatchServer when a multiplayer match finishes."""
        ch = self.channels.get(channel_id)
        rm = ch.rooms.get(room_id) if ch else None
        match_sess_id = rm.active_match_session if rm is not None else 0
        players_stats: dict[int, dict[str, Any]] = results.get("players", {}) if isinstance(results, dict) else {}

        log.info(
            "[Realm] UE2 match ended room=(%d,%d) reason=%s scores=%s players=%d",
            channel_id,
            room_id,
            results.get("end_reason", "completed") if isinstance(results, dict) else "completed",
            results.get("team_scores", [0, 0]) if isinstance(results, dict) else [0, 0],
            len(players_stats),
        )

        # Persist real combat stats to SQLite and push S2C 0x1E to each online participant
        for rid_raw, pstats in players_stats.items():
            rid = int(rid_raw)
            role = self._persist_player_match_stats(channel_id, room_id, match_sess_id, rid, pstats)
            target_sess = self.online_by_role_id.get(rid)
            if role and target_sess is not None:
                target_sess.in_game = 0
                target_sess.ready = 0
                try:
                    await target_sess.stream.send_packet(encode_game_end_update_role_respond(role))
                except Exception:
                    pass

        if rm is not None:
            for p in rm.players.values():
                p.in_game = 0
                p.ready = 0
            rm.room_state = 2
            rm.refresh_waiting_state()
            await self._broadcast_room(rm, encode_current_room_info_respond(rm.to_dict()))
            plist = [self._build_room_player_dict(p) for p in rm.players.values()]
            await self._broadcast_room(rm, encode_room_player_list_respond(plist))

    async def _watch_standalone_match(self, rm: Room, host_sess: ClientSession, inst: Any) -> None:
        """Poll a local standalone CS.exe process until exit, then grant rewards and reset room state."""
        try:
            proc = inst.proc
            while proc is not None and proc.poll() is None:
                await asyncio.sleep(0.5)
            self.match_manager.active_by_room.pop((rm.channel_id, rm.room_id), None)
            if rm.room_state == 4:
                rm.room_state = 2
                rm.refresh_waiting_state()
            role = self._persist_player_match_stats(
                rm.channel_id, rm.room_id, inst.session_id, host_sess.role_id, None
            ) if host_sess.role_id else None
            if role and host_sess in self.sessions:
                try:
                    await host_sess.stream.send_packet(encode_game_end_update_role_respond(role))
                except Exception:
                    pass
            if rm.players:
                await self._broadcast_room(rm, encode_current_room_info_respond(rm.to_dict()))
                plist = [self._build_room_player_dict(p) for p in rm.players.values()]
                await self._broadcast_room(rm, encode_room_player_list_respond(plist))
        except asyncio.CancelledError:
            pass
        except Exception:
            log.exception("[Realm] Standalone match watcher error for room #%d", rm.room_id)

    async def _on_start_game(self, sess: ClientSession, _pkt: bytes) -> None:
        """C2S 0x10 StartGameRequest (room owner launches match)."""
        rm = self._get_current_room(sess)
        if rm is None or rm.owner_id != sess.role_id:
            return
        # Guarantee map_id is valid for game_mode (and resolve Random if needed)
        valid_map = self.gamedata.pick_map_for_mode(rm.game_mode, rm.map_id, reroll=(rm.map_id <= 0))
        if valid_map != rm.map_id:
            rm.map_id = valid_map
            await self._broadcast_room(rm, encode_current_room_info_respond(rm.to_dict()))

        participants = [p for p in rm.players.values() if p.role_id == rm.owner_id or p.ready]
        roster = [self._build_match_roster_entry(p) for p in participants]

        inst, ready, status_msg = await self.match_manager.start_match_async(
            rm.channel_id,
            rm.room_id,
            rm.map_id,
            rm.game_mode,
            rm.max_players,
            shoot_limit=rm.shoot_limit,
            time_limit=rm.time_limit,
            roster=roster,
            on_match_end=self._on_ue2_match_end,
            player_name=sess.role_name,
            team_id=sess.team_id,
        )
        if not ready:
            rm.room_state = 2
            rm.refresh_waiting_state()
            err_pkt = encode_game_start_command(212, inst.connect_ip, inst.connect_port)
            for p in participants:
                await p.stream.send_packet(err_pkt)
            await self._broadcast_room(rm, encode_chat_content_respond(0, 1, "CSG Server", status_msg))
            await self._broadcast_room(rm, encode_current_room_info_respond(rm.to_dict()))
            return

        rm.active_match_session = inst.session_id
        self._persisted_match_roles.pop((rm.channel_id, rm.room_id, inst.session_id), None)
        rm.room_state = 4  # sInGame
        if inst.uses_udp_connect:
            # S2C 0x15 +0x01 MUST be nResult=1 for InRoomState.GameStartCommond to run `open ip:port`
            cmd_pkt = encode_game_start_command(1, inst.connect_ip, inst.connect_port)
            for p in participants:
                p.in_game = 1
                await p.stream.send_packet(cmd_pkt)
            await self._broadcast_room(rm, encode_current_room_info_respond(rm.to_dict()))
            log.info(
                "[Realm] Room #%d MATCH STARTED mode=%s session=%d addr=%s:%d map=%s players=%d",
                rm.room_id, inst.mode, inst.session_id, inst.connect_ip, inst.connect_port, inst.map_file, len(participants),
            )
            return

        # Legacy local_standalone opt-in path
        dismiss_pkt = encode_game_start_command(212, inst.connect_ip, inst.connect_port)
        for p in participants:
            await p.stream.send_packet(dismiss_pkt)
        await self._broadcast_room(rm, encode_chat_content_respond(0, 1, "CSG Server", status_msg))
        await self._broadcast_room(rm, encode_current_room_info_respond(rm.to_dict()))
        if inst.proc is not None:
            task = asyncio.create_task(self._watch_standalone_match(rm, sess, inst))
            self._match_watchers.add(task)
            task.add_done_callback(self._match_watchers.discard)

    async def _on_join_start_game(self, sess: ClientSession, _pkt: bytes) -> None:
        """C2S 0x11 JoinStartGameRequest (join a match already in progress)."""
        rm = self._get_current_room(sess)
        if rm is None:
            return
        entry = self._build_match_roster_entry(sess)
        inst = self.match_manager.get_match(rm.channel_id, rm.room_id)
        if inst is not None:
            self.match_manager.register_player(rm.channel_id, rm.room_id, entry)
        else:
            inst, ready, status_msg = await self.match_manager.start_match_async(
                rm.channel_id,
                rm.room_id,
                rm.map_id,
                rm.game_mode,
                rm.max_players,
                shoot_limit=rm.shoot_limit,
                time_limit=rm.time_limit,
                roster=[entry],
                on_match_end=self._on_ue2_match_end,
                player_name=sess.role_name,
                team_id=sess.team_id,
            )
            if not ready:
                await sess.stream.send_packet(encode_game_start_command(212, inst.connect_ip, inst.connect_port))
                await sess.stream.send_packet(encode_chat_content_respond(0, 1, "CSG Server", status_msg))
                return
            rm.active_match_session = inst.session_id
            rm.room_state = 4
        if inst.uses_udp_connect:
            sess.in_game = 1
            await sess.stream.send_packet(encode_game_start_command(1, inst.connect_ip, inst.connect_port))
            plist = [self._build_room_player_dict(p) for p in rm.players.values()]
            await self._broadcast_room(rm, encode_room_player_list_respond(plist))
        else:
            await sess.stream.send_packet(encode_game_start_command(212, inst.connect_ip, inst.connect_port))
            await sess.stream.send_packet(encode_chat_content_respond(0, 1, "CSG Server", inst.status_message))

    async def _on_player_leave_game(self, sess: ClientSession, _pkt: bytes) -> None:
        """C2S 0x29 PlayerLeaveGameRequest (player returns from UE2 match to room)."""
        sess.in_game = 0
        sess.ready = 0
        await sess.stream.send_packet(encode_simple_result(0x2F, 1))

        rm = self._get_current_room(sess)
        pstats: dict[str, Any] | None = None
        match_sess_id = 0
        if rm is not None:
            match_sess_id = rm.active_match_session
            live_res = self.match_manager.get_match_results(rm.channel_id, rm.room_id)
            if live_res and isinstance(live_res.get("players"), dict):
                pstats = live_res["players"].get(sess.role_id)
            self.match_manager.remove_player(rm.channel_id, rm.room_id, sess.role_id, reason="player_left")

        role = self._persist_player_match_stats(
            sess.channel_id,
            rm.room_id if rm else 0,
            match_sess_id,
            sess.role_id,
            pstats,
        )
        if role:
            await sess.stream.send_packet(encode_game_end_update_role_respond(role))

        if rm is not None:
            still_playing = any(p.in_game for p in rm.players.values())
            if not still_playing:
                rm.room_state = 2
                rm.refresh_waiting_state()
                await self.match_manager.stop_match_async(rm.channel_id, rm.room_id, notify_match_end=False)
            await self._broadcast_room(rm, encode_current_room_info_respond(rm.to_dict()))
            plist = [self._build_room_player_dict(p) for p in rm.players.values()]
            await self._broadcast_room(rm, encode_room_player_list_respond(plist))
            for p in list(rm.players.values()):
                if p.ready:
                    await self._broadcast_room(rm, encode_ready_game_info_respond(p.role_id, 1))

    async def _on_kick_player(self, sess: ClientSession, pkt: bytes) -> None:
        """C2S 0x2E RoomOwnerKickOtherRequest."""
        rm = self._get_current_room(sess)
        if rm is None or rm.owner_id != sess.role_id or len(pkt) < 5:
            return
        target_id = struct.unpack_from("<I", pkt, 1)[0]
        target = rm.players.get(target_id)
        if target is None or target_id == sess.role_id:
            return
        # 0x36 alone transitions kicked player to InhallState and removes them on all peers;
        # do NOT follow with 0x10 or 0x0D (avoids blank "[Tip] left the room" & redundant ack)
        await self._broadcast_room(rm, encode_someone_kicked_respond(target_id))
        rm.players.pop(target_id, None)
        target.room_id = 0
        target.ready = 0
        target.in_game = 0
        rm.refresh_waiting_state()

    async def _on_nominate_owner(self, sess: ClientSession, pkt: bytes) -> None:
        """C2S 0x2F NominateRoomOwnerRequest."""
        rm = self._get_current_room(sess)
        if rm is None or rm.owner_id != sess.role_id or len(pkt) < 5:
            return
        target_id = struct.unpack_from("<I", pkt, 1)[0]
        if target_id not in rm.players:
            return
        rm.owner_id = target_id
        rm.players[target_id].ready = 0
        # Send ONLY 0x37 + 0x0B (do NOT also send 0x11, which prints a duplicate chat notice)
        await self._broadcast_room(rm, encode_someone_nominated_owner_respond(target_id, 0))
        await self._broadcast_room(rm, encode_current_room_info_respond(rm.to_dict()))

    # ------------------------------------------------------------------
    # Chat (0x12, 0x13, 0x14, 0x15, 0x2D)
    # ------------------------------------------------------------------
    async def _on_channel_chat(self, sess: ClientSession, pkt: bytes) -> None:
        ch = self.channels.get(sess.channel_id)
        if ch is None or len(pkt) < 6:
            return
        msg_len = struct.unpack_from("<I", pkt, 1)[0]
        msg = unpack_cstr(pkt, 5, min(msg_len, len(pkt) - 5))
        out = encode_chat_content_respond(sess.role_id, 0, sess.role_name, msg)
        for s in list(ch.players.values()):
            try:
                await s.stream.send_packet(out)
            except Exception:
                pass

    async def _on_room_chat(self, sess: ClientSession, pkt: bytes) -> None:
        rm = self._get_current_room(sess)
        if rm is None or len(pkt) < 6:
            return
        msg_len = struct.unpack_from("<I", pkt, 1)[0]
        msg = unpack_cstr(pkt, 5, min(msg_len, len(pkt) - 5))
        out = encode_chat_content_respond(sess.role_id, 1, sess.role_name, msg)
        await self._broadcast_room(rm, out)

    async def _on_personal_chat_name(self, sess: ClientSession, pkt: bytes) -> None:
        if len(pkt) < 0x26:
            return
        dst_name = unpack_cstr(pkt, 1, 32)
        msg_len = struct.unpack_from("<I", pkt, 0x21)[0]
        msg = unpack_cstr(pkt, 0x25, min(msg_len, len(pkt) - 0x25))
        target = self.online_by_name.get(dst_name.lower())
        if target is None:
            await sess.stream.send_packet(encode_personal_chat_result_respond(0, dst_name))
            return
        await target.stream.send_packet(encode_chat_content_respond(sess.role_id, 2, sess.role_name, msg))
        await sess.stream.send_packet(encode_personal_chat_result_respond(1, target.role_name))

    async def _on_personal_chat_id(self, sess: ClientSession, pkt: bytes) -> None:
        if len(pkt) < 10:
            return
        dst_id, msg_len = struct.unpack_from("<II", pkt, 1)
        msg = unpack_cstr(pkt, 9, min(msg_len, len(pkt) - 9))
        target = self.online_by_role_id.get(dst_id)
        if target is None:
            await sess.stream.send_packet(encode_personal_chat_result_respond(0, ""))
            return
        await target.stream.send_packet(encode_chat_content_respond(sess.role_id, 2, sess.role_name, msg))
        await sess.stream.send_packet(encode_personal_chat_result_respond(1, target.role_name))

    async def _on_public_or_group_chat(self, sess: ClientSession, pkt: bytes) -> None:
        if len(pkt) < 10:
            return
        chat_type, msg_len = struct.unpack_from("<II", pkt, 1)
        msg = unpack_cstr(pkt, 9, min(msg_len, len(pkt) - 9))
        out = encode_chat_content_respond(sess.role_id, chat_type, sess.role_name, msg)
        for s in list(self.online_by_role_id.values()):
            try:
                await s.stream.send_packet(out)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Inventory, Loadout & Shop (0x16, 0x17, 0x1B, 0x2B)
    # ------------------------------------------------------------------
    async def _on_get_item_list(self, sess: ClientSession, _pkt: bytes) -> None:
        if sess.role_id == 0:
            return
        loadout = self.db.get_resolved_loadout(sess.role_id)
        inv = self.db.get_inventory(sess.role_id)
        await sess.stream.send_packet(encode_get_item_list_respond(loadout, inv))

    async def _on_set_using_item_list(self, sess: ClientSession, pkt: bytes) -> None:
        """
        C2S 0x17 SetUsingItemListRequest (0xB5 = 181 bytes):
          +0x01 i32 head_idx
          +0x05 i32 coat_idx
          +0x09 i32 trousers_idx
          +0x0D 5*i32 major_idx
          +0x21 5*i32 minor_idx
          +0x35 5*i32 grenade_idx
          +0x49 5*i32 knife_idx
          +0x5D i32 armor_idx
          +0x61 i32 shoes_idx
          +0x65 20*i32 baggage_idx
        """
        if sess.role_id == 0 or len(pkt) < 0xB5:
            await sess.stream.send_packet(encode_simple_result(0x19, 217))
            return
        vals = struct.unpack_from("<45i", pkt, 1)
        head_idx, coat_idx, trousers_idx = vals[0], vals[1], vals[2]
        major_idx = list(vals[3:8])
        minor_idx = list(vals[8:13])
        grenade_idx = list(vals[13:18])
        knife_idx = list(vals[18:23])
        armor_idx, shoes_idx = vals[23], vals[24]
        baggage_idx = list(vals[25:45])

        self.db.set_loadout_from_indices(
            sess.role_id,
            head_idx, coat_idx, trousers_idx,
            major_idx, minor_idx, grenade_idx, knife_idx,
            armor_idx, shoes_idx, baggage_idx,
        )
        await sess.stream.send_packet(encode_simple_result(0x19, 1))
        # Broadcast appearance update if player is inside a room
        rm = self._get_current_room(sess)
        if rm is not None:
            role = self.db.get_role_by_id(sess.role_id)
            if role:
                await self._broadcast_room(rm, encode_change_item_in_room_respond(role))

    async def _on_buy_item(self, sess: ClientSession, pkt: bytes) -> None:
        """C2S 0x1B PlayerBuyItemRequest (13 bytes: op, u32 item_type, u32 item_time, u32 buy_type)."""
        if sess.role_id == 0 or len(pkt) < 13:
            return
        item_type, item_time, buy_type = struct.unpack_from("<iii", pkt, 1)
        res, item, role = self.db.buy_item(sess.role_id, item_type, item_time, buy_type)
        iid = int(item["item_id"]) if item else 0
        itype = int(item["item_type"]) if item else item_type
        idays = int(item["left_days"]) if item else 0
        iget = int(item["item_get_type"]) if item else 1
        mp = int(role["money_point"]) if role else 0
        gc = int(role["game_cash"]) if role else 0
        log.info("[Realm] %s BuyItem type=%d time=%d buy=%d -> res=%d (CSP=%d GP=%d)", sess.role_name, item_type, item_time, buy_type, res, mp, gc)
        await sess.stream.send_packet(encode_player_buy_item_respond(res, iid, itype, idays, iget, mp, gc))

    async def _on_present_item(self, sess: ClientSession, pkt: bytes) -> None:
        """
        C2S 0x2B PresentItemRequest (KFXClient.dll!0x10723d70):
          +0x00 u8  0x2B
          +0x01 i32 nItemType
          +0x05 i32 nItemTime
          +0x09 32B sRecvRoleName
          +0x29 i32 nBuyType (0=CSP, 1=GP)
          +0x2D i32 content_len (optional)
          +0x31 UTF-8 sContent
        """
        if sess.role_id == 0 or len(pkt) < 0x2D:
            return
        item_type, item_time = struct.unpack_from("<ii", pkt, 1)
        recv_name = unpack_cstr(pkt, 0x09, 32)
        buy_type = struct.unpack_from("<i", pkt, 0x29)[0]
        content = ""
        if len(pkt) >= 0x31:
            content_len = struct.unpack_from("<I", pkt, 0x2D)[0]
            if len(pkt) > 0x31 and content_len > 0:
                content = unpack_cstr(pkt, 0x31, min(content_len, len(pkt) - 0x31))

        recv_role = self.db.get_role_by_name(recv_name)
        role = self.db.get_role_by_id(sess.role_id)
        if recv_role is None or role is None:
            await sess.stream.send_packet(encode_present_item_respond(247, int(role["money_point"]) if role else 0, int(role["game_cash"]) if role else 0))
            return
        price_info = self.gamedata.get_item_price(item_type, item_time, buy_type)
        if not price_info:
            await sess.stream.send_packet(encode_present_item_respond(261, int(role["money_point"]), int(role["game_cash"])))
            return
        currency, price = price_info
        delta_csp = -price if currency == "csp" else 0
        delta_gp = -price if currency == "gp" else 0
        if (currency == "csp" and int(role["money_point"]) < price) or (currency == "gp" and int(role["game_cash"]) < price):
            await sess.stream.send_packet(encode_present_item_respond(254, int(role["money_point"]), int(role["game_cash"])))
            return
        updated = self.db.update_role_currency(sess.role_id, delta_gp=delta_gp, delta_csp=delta_csp)
        left_val = self.gamedata.item_time_to_left_value(item_type, item_time)
        self.db.send_email(
            sess.role_id, sess.role_name, int(recv_role["role_id"]), 1,
            f"Gift from {sess.role_name}", content or f"{sess.role_name} sent you a gift!",
            item_id=1, item_type=item_type, item_days=left_val,
        )
        target_sess = self.online_by_role_id.get(int(recv_role["role_id"]))
        if target_sess:
            await target_sess.stream.send_packet(bytes([0x25]))
        await sess.stream.send_packet(encode_present_item_respond(1, int(updated["money_point"]), int(updated["game_cash"])))  # type: ignore[index]

    # ------------------------------------------------------------------
    # Role Info, Rankings, Find & Invite (0x18, 0x19, 0x1A, 0x1C..0x20, 0x34, 0x35)
    # ------------------------------------------------------------------
    async def _on_set_role_info(self, sess: ClientSession, pkt: bytes) -> None:
        if sess.role_id == 0:
            await sess.stream.send_packet(encode_simple_result(0x1A, 0))
            return
        constellation = struct.unpack_from("<i", pkt, 1)[0] if len(pkt) >= 5 else 0
        area = unpack_cstr(pkt, 5, 32) if len(pkt) >= 37 else ""
        qq = struct.unpack_from("<i", pkt, 37)[0] if len(pkt) >= 41 else 0
        intro = unpack_cstr(pkt, 41, 64) if len(pkt) >= 42 else ""
        self.db.update_role_profile(sess.role_id, constellation, area, qq, intro)
        await sess.stream.send_packet(encode_simple_result(0x1A, 1))

    async def _on_one_role_full_info(self, sess: ClientSession, pkt: bytes) -> None:
        if len(pkt) < 5:
            return
        target_id = struct.unpack_from("<I", pkt, 1)[0]
        role = self.db.get_role_by_id(target_id)
        await sess.stream.send_packet(encode_request_role_info_respond(1 if role else 0, role))

    async def _on_world_role_order(self, sess: ClientSession, _pkt: bytes) -> None:
        roles = self.db.list_roles(limit=50)
        await sess.stream.send_packet(encode_world_role_order_respond(roles))

    async def _on_world_faction_order(self, sess: ClientSession, _pkt: bytes) -> None:
        await sess.stream.send_packet(encode_world_faction_order_respond([], 0))

    async def _on_faction_member_list(self, sess: ClientSession, _pkt: bytes) -> None:
        await sess.stream.send_packet(encode_faction_member_list_respond([]))

    async def _on_find_player(self, sess: ClientSession, pkt: bytes) -> None:
        if len(pkt) < 2:
            return
        name = unpack_cstr(pkt, 1, 32)
        target = self.online_by_name.get(name.lower())
        role = self.db.get_role_by_name(name)
        if role is None:
            await sess.stream.send_packet(encode_find_player_respond(0))
            return
        ch_id = target.channel_id if target else 0
        rm_id = target.room_id if target else 0
        pwd_flag = 0
        if target and ch_id in self.channels and rm_id in self.channels[ch_id].rooms:
            pwd_flag = 1 if self.channels[ch_id].rooms[rm_id].password else 0
        await sess.stream.send_packet(
            encode_find_player_respond(
                1, role, self.public_ip, self.realm_port, ch_id, rm_id, pwd_flag, online=target is not None
            )
        )

    async def _on_find_room(self, sess: ClientSession, pkt: bytes) -> None:
        if len(pkt) < 5:
            return
        rid = struct.unpack_from("<I", pkt, 1)[0]
        for ch in self.channels.values():
            if rid in ch.rooms:
                await sess.stream.send_packet(
                    encode_find_room_respond(1, ch.rooms[rid].to_dict(), ch.id, self.public_ip, self.realm_port)
                )
                return
        await sess.stream.send_packet(encode_find_room_respond(0))

    async def _on_goto_want_position(self, sess: ClientSession, pkt: bytes) -> None:
        ch = self.channels.get(sess.channel_id)
        ch_name = ch.name if ch else ""
        await sess.stream.send_packet(struct.pack("<BI", 0x20, 1) + pack_cstr(ch_name, 32))

    async def _on_invite_player(self, sess: ClientSession, pkt: bytes) -> None:
        if len(pkt) < 5:
            return
        target_id = struct.unpack_from("<I", pkt, 1)[0]
        target = self.online_by_role_id.get(target_id)
        if target is None:
            await sess.stream.send_packet(struct.pack("<BII", 0x23, 0, u32(target_id)) + pack_cstr("", 32))
            return
        rm = self._get_current_room(sess)
        if rm is not None:
            await target.stream.send_packet(
                encode_someone_invite_me_respond(
                    sess.role_id,
                    sess.role_name,
                    rm.room_id,
                    rm.channel_id,
                    1,
                    1 if rm.password else 0,
                    self.public_ip,
                    self.realm_port,
                )
            )
        await sess.stream.send_packet(struct.pack("<BII", 0x23, 1, u32(target_id)) + pack_cstr(target.role_name, 32))

    async def _on_reply_invite(self, _sess: ClientSession, _pkt: bytes) -> None:
        pass

    # ------------------------------------------------------------------
    # Email (0x21..0x25)
    # ------------------------------------------------------------------
    async def _on_email_list(self, sess: ClientSession, _pkt: bytes) -> None:
        emails = self.db.list_emails(sess.role_id) if sess.role_id else []
        await sess.stream.send_packet(encode_email_list_respond(1, emails))

    async def _on_email_content(self, sess: ClientSession, pkt: bytes) -> None:
        if len(pkt) < 5 or sess.role_id == 0:
            return
        email_id = struct.unpack_from("<i", pkt, 1)[0]
        em = self.db.get_email(sess.role_id, email_id)
        await sess.stream.send_packet(encode_email_content_respond(1 if em else 0, em))

    async def _on_send_email(self, sess: ClientSession, pkt: bytes) -> None:
        if len(pkt) < 0x6A or sess.role_id == 0:
            await sess.stream.send_packet(encode_send_email_result_respond(0, ""))
            return
        email_type, content_len = struct.unpack_from("<ii", pkt, 1)
        recv_name = unpack_cstr(pkt, 9, 32)
        title = unpack_cstr(pkt, 0x29, 64)
        content = unpack_cstr(pkt, 0x69, min(content_len, len(pkt) - 0x69))
        recv_role = self.db.get_role_by_name(recv_name)
        if recv_role is None:
            await sess.stream.send_packet(encode_send_email_result_respond(0, recv_name))
            return
        self.db.send_email(sess.role_id, sess.role_name, int(recv_role["role_id"]), email_type, title, content)
        await sess.stream.send_packet(encode_send_email_result_respond(1, recv_role["role_name"]))
        target = self.online_by_role_id.get(int(recv_role["role_id"]))
        if target:
            await target.stream.send_packet(bytes([0x25]))

    async def _on_takeout_item(self, sess: ClientSession, pkt: bytes) -> None:
        if len(pkt) < 13 or sess.role_id == 0:
            return
        email_id = struct.unpack_from("<i", pkt, 1)[0]
        item = self.db.takeout_email_item(sess.role_id, email_id)
        await sess.stream.send_packet(encode_takeout_item_result_respond(1 if item else 0, email_id, item))

    async def _on_delete_email(self, sess: ClientSession, pkt: bytes) -> None:
        if len(pkt) < 5 or sess.role_id == 0:
            return
        email_id = struct.unpack_from("<i", pkt, 1)[0]
        ok = self.db.delete_email(sess.role_id, email_id)
        await sess.stream.send_packet(encode_delete_email_result_respond(1 if ok else 0, email_id))

    # ------------------------------------------------------------------
    # Relations (0x26..0x28)
    # ------------------------------------------------------------------
    async def _on_relation_list(self, sess: ClientSession, _pkt: bytes) -> None:
        rels = self.db.list_relations(sess.role_id) if sess.role_id else []
        await sess.stream.send_packet(encode_relation_list_respond(rels, set(self.online_by_role_id.keys())))

    async def _on_add_relation(self, sess: ClientSession, pkt: bytes) -> None:
        if len(pkt) < 37 or sess.role_id == 0:
            await sess.stream.send_packet(encode_add_relation_result_respond(0, None, 0, False))
            return
        rel_type = struct.unpack_from("<i", pkt, 1)[0]
        target_name = unpack_cstr(pkt, 5, 32)
        target_role = self.db.get_role_by_name(target_name)
        if target_role is None or not self.db.add_relation(sess.role_id, int(target_role["role_id"]), rel_type):
            await sess.stream.send_packet(encode_add_relation_result_respond(0, None, rel_type, False))
            return
        online = int(target_role["role_id"]) in self.online_by_role_id
        await sess.stream.send_packet(encode_add_relation_result_respond(1, target_role, rel_type, online))

    async def _on_delete_relation(self, sess: ClientSession, pkt: bytes) -> None:
        if len(pkt) < 5 or sess.role_id == 0:
            return
        target_id = struct.unpack_from("<I", pkt, 1)[0]
        rel_type = self.db.delete_relation(sess.role_id, target_id)
        # S2C 0x2D +0x05 is deleted_role_id (client searches friend/blacklist by nRoleID)
        await sess.stream.send_packet(encode_delete_relation_result_respond(1 if rel_type is not None else 0, target_id))

    # ------------------------------------------------------------------
    # Appeal & Quests (0x2A, 0x30..0x32)
    # ------------------------------------------------------------------
    async def _on_player_appeal(self, sess: ClientSession, _pkt: bytes) -> None:
        await sess.stream.send_packet(encode_simple_result(0x31, 1))

    async def _on_finish_task(self, sess: ClientSession, _pkt: bytes) -> None:
        await sess.stream.send_packet(encode_simple_result(0x3E, 1))

    async def _on_quest_task(self, sess: ClientSession, pkt: bytes) -> None:
        if len(pkt) < 5 or sess.role_id == 0:
            return
        task_id = struct.unpack_from("<i", pkt, 1)[0]
        q = self.gamedata.quests.get(task_id)
        if q:
            self.db.upsert_quest(sess.role_id, task_id, int(q.get("id_step", 1)), 1)
            await sess.stream.send_packet(encode_player_quest_task_respond(1, task_id))
        else:
            await sess.stream.send_packet(encode_player_quest_task_respond(0, task_id))

    async def _on_quest_bonus(self, sess: ClientSession, pkt: bytes) -> None:
        if len(pkt) < 13 or sess.role_id == 0:
            return
        task_id, step, select_idx = struct.unpack_from("<iii", pkt, 1)
        q = self.gamedata.quests.get(task_id)
        role = self.db.get_role_by_id(sess.role_id)
        if not q or not role:
            cur_honor = int(role["honor_point"]) if role else 0
            cur_lvl = int(role["level"]) if role else 1
            await sess.stream.send_packet(
                encode_player_quest_bonus_respond(task_id, step, cur_honor, cur_lvl, 0, 0, 0, 0)
            )
            return
        honor = int(q.get("bonus_exp", 0))
        bonuses = q.get("bonuses", [])
        item_type = 0
        if bonuses:
            chosen = bonuses[select_idx % len(bonuses)]
            item_type = int(chosen["item_type"])
            self.db.add_item(sess.role_id, item_type, left_days=int(chosen.get("days", 7)), get_type=3)
        if honor > 0:
            role = self.db.add_match_stats(sess.role_id, honor_gain=honor) or role
        self.db.upsert_quest(sess.role_id, task_id, step, 2)
        await sess.stream.send_packet(
            encode_player_quest_bonus_respond(
                task_id,
                step,
                int(role["honor_point"]),
                int(role["level"]),
                1 if q.get("random_bonus") else 0,
                item_type,
                1 if item_type else 0,
                1,
            )
        )

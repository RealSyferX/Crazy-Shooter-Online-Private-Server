"""
Asyncio UDP UE2.5 (UT2004 build 3369 / CSO Malaysia) Match Server Host & Port Manager.

Manages live multiplayer room matches on UDP 7777..7795:
- `UE2MatchServer` (`asyncio.DatagramProtocol` bound to `0.0.0.0:<udp_port>`):
    * Multiplexes multiple real `CS.exe` UDP clients on one port keyed by `(ip, port)`.
    * Pipes datagrams through `bitstream.py` -> `control.py` (`HELLO/CHALLENGE/LOGIN/USES/WELCOME/JOIN`)
      -> `replication.py` (`TeamInfo/GRI/PRI/KFX*Player/KFXPawn/KFXWeap*`) -> `combat.py`
      (`ServerMove`, 3D hitscan shooting, damage, kills, deaths, respawn, scoreboard).
    * Drives a 30Hz asyncio tick loop flushing ACKs, reliable retransmits, keepalives,
      dirty actor deltas (position/rotation/velocity/HP/PRI/GRI), reload/respawn timers,
      client inactivity timeouts, and match-end detection.
    * Supports late join (`register_player` while match is live) and clean disconnect cleanup.
    * Invokes an async (or sync) `on_match_end(channel_id, room_id, results)` callback when
      the match finishes or all players leave.
- `UE2HostManager`:
    * Allocates free UDP ports in `[port_range_start..port_range_end]`.
    * Creates, starts, queries, and stops `UE2MatchServer` instances per `(channel_id, room_id)`
      with zero orphan sockets.
"""

from __future__ import annotations

import asyncio
import ctypes
import inspect
import logging
import os
import socket
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Set, Tuple

from .bitstream import (
    CHTYPE_ACTOR,
    CHTYPE_CONTROL,
    DEFAULT_KEEPALIVE_INTERVAL,
    DEFAULT_RESEND_INTERVAL,
    UE2ConnectionState,
    decode_raw_packet,
)
from .combat import (
    DEFAULT_RESPAWN_DELAY,
    MatchWorld,
    WeaponDatabase,
    get_default_weapon_db,
)
from .control import (
    DEFAULT_GAME_CLASS,
    GAME_MODE_TO_CLASS,
    BoundPlayerInfo,
    ControlChannelHandler,
    ControlState,
    ParsedLoginURL,
)
from .map_loader import MapLoader, MapSpawnData, load_map_spawns
from .packagemap import DEFAULT_GAME_DIR, PackageMap
from .replication import ReplicationManager

log = logging.getLogger("csg.ue2.host")

# ---------------------------------------------------------------------------
# Constants & Shared Read-Only Asset Caches
# ---------------------------------------------------------------------------

DEFAULT_BIND_HOST: str = "0.0.0.0"
DEFAULT_PORT_START: int = 7777
DEFAULT_PORT_END: int = 7795
DEFAULT_TICK_HZ: float = 100.0
DEFAULT_CLIENT_TIMEOUT: float = 30.0
DEFAULT_POST_END_FLUSH_SECONDS: float = 0.25
UDP_SOCKET_BUF_BYTES: int = 1048576  # 1 MiB kernel SO_RCVBUF / SO_SNDBUF

# Windows 1ms multimedia timer ref-counter so asyncio.sleep() achieves <2ms jitter
_WIN_TIMER_REFCOUNT: int = 0


def _acquire_high_res_timer() -> bool:
    """Request 1ms Windows multimedia timer resolution (no-op on non-Windows)."""
    global _WIN_TIMER_REFCOUNT
    if sys.platform != "win32":
        return False
    try:
        if _WIN_TIMER_REFCOUNT == 0:
            ctypes.windll.winmm.timeBeginPeriod(1)  # type: ignore[attr-defined]
        _WIN_TIMER_REFCOUNT += 1
        return True
    except Exception:
        return False


def _release_high_res_timer() -> None:
    """Release a prior `_acquire_high_res_timer()` reference."""
    global _WIN_TIMER_REFCOUNT
    if sys.platform != "win32" or _WIN_TIMER_REFCOUNT <= 0:
        return
    _WIN_TIMER_REFCOUNT -= 1
    if _WIN_TIMER_REFCOUNT == 0:
        try:
            ctypes.windll.winmm.timeEndPeriod(1)  # type: ignore[attr-defined]
        except Exception:
            pass

_PACKAGE_MAP_CACHE: Dict[Tuple[str, str], PackageMap] = {}
_MAP_LOADER_CACHE: Dict[str, MapLoader] = {}

_GAME_CLASS_TO_MODE: Dict[str, int] = {
    cls_name.lower(): mode_id for mode_id, cls_name in GAME_MODE_TO_CLASS.items()
}
for _mid, _cls in list(GAME_MODE_TO_CLASS.items()):
    _GAME_CLASS_TO_MODE[_cls.rsplit(".", 1)[-1].lower()] = _mid


def get_cached_package_map(
    map_name: str,
    game_dir: str = DEFAULT_GAME_DIR,
) -> PackageMap:
    """Return a cached UE2.5 `PackageMap` for `(game_dir, map_name)`."""
    norm_dir = os.path.abspath(game_dir)
    stem = os.path.splitext(os.path.basename(map_name or "DF-DiTieZhan"))[0]
    key = (norm_dir.lower(), stem.lower())
    cached = _PACKAGE_MAP_CACHE.get(key)
    if cached is not None:
        return cached
    pkgmap = PackageMap(map_name=stem, game_dir=norm_dir)
    _PACKAGE_MAP_CACHE[key] = pkgmap
    return pkgmap


def get_cached_map_spawns(
    map_name: str,
    game_dir: str = DEFAULT_GAME_DIR,
) -> MapSpawnData:
    """Return cached `.ut2` `MapSpawnData` for `(game_dir, map_name)`."""
    norm_dir = os.path.abspath(game_dir)
    loader = _MAP_LOADER_CACHE.get(norm_dir.lower())
    if loader is None:
        loader = MapLoader(game_dir=norm_dir)
        _MAP_LOADER_CACHE[norm_dir.lower()] = loader
    return loader.load(map_name)


def is_udp_port_available(port: int, bind_host: str = DEFAULT_BIND_HOST) -> bool:
    """Return True if UDP `(bind_host, port)` can be bound cleanly right now."""
    hosts = ("0.0.0.0", "127.0.0.1") if bind_host in ("0.0.0.0", "") else (bind_host,)
    for host in hosts:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            sock.bind((host, int(port)))
        except OSError:
            return False
        finally:
            sock.close()
    return True


def _resolve_game_mode_and_class(
    game_mode: Optional[int],
    game_class: Optional[str],
) -> Tuple[int, str]:
    """Normalize `(game_mode, game_class)` consistently."""
    if game_class:
        gc = str(game_class).strip()
        inferred = _GAME_CLASS_TO_MODE.get(gc.lower())
        if inferred is not None:
            if game_mode is None or int(game_mode) not in GAME_MODE_TO_CLASS:
                return inferred, GAME_MODE_TO_CLASS[inferred]
            return int(game_mode), gc
        mode = int(game_mode) if (game_mode is not None and int(game_mode) in GAME_MODE_TO_CLASS) else 1
        return mode, gc
    mode = int(game_mode) if (game_mode is not None and int(game_mode) in GAME_MODE_TO_CLASS) else 1
    return mode, GAME_MODE_TO_CLASS.get(mode, DEFAULT_GAME_CLASS)


def _normalize_roster_entry(entry: Any) -> Optional[Dict[str, Any]]:
    """Normalize a Realm room player dict or object into a canonical roster dict."""
    if entry is None:
        return None

    def _get(*keys: str, default: Any = None) -> Any:
        if isinstance(entry, dict):
            for k in keys:
                if k in entry and entry[k] is not None:
                    return entry[k]
            return default
        for k in keys:
            v = getattr(entry, k, None)
            if v is not None:
                return v
        return default

    rid_raw = _get("role_id", "id")
    if rid_raw is None:
        return None
    try:
        role_id = int(rid_raw)
    except (TypeError, ValueError):
        return None

    name = str(_get("role_name", "name", default=f"Player{role_id}")).strip() or f"Player{role_id}"
    team_raw = _get("team_id", "team", default=0)
    try:
        team_id = 1 if int(team_raw) == 1 else 0
    except (TypeError, ValueError):
        team_id = 0

    sess_raw = _get("session_cookie", "cookie", "session", default=None)
    session_cookie: Optional[int] = None
    if sess_raw is not None and str(sess_raw) != "":
        try:
            session_cookie = int(sess_raw)
        except (TypeError, ValueError):
            session_cookie = None

    loadout_raw = _get("loadout", default={})
    loadout = dict(loadout_raw) if isinstance(loadout_raw, dict) else {}

    major_raw = _get("major_weapon_id", "weapon_id", default=None)
    if major_raw is None:
        majors = loadout.get("major_weapons") or loadout.get("nMajorWeapons")
        if isinstance(majors, (list, tuple)):
            for w in majors:
                if int(w or 0) > 0:
                    major_raw = int(w)
                    break
    major_weapon_id = int(major_raw) if (major_raw is not None and int(major_raw) > 0) else 65537

    return {
        "role_id": role_id,
        "role_name": name,
        "name": name,
        "team_id": team_id,
        "session_cookie": session_cookie,
        "level": int(_get("level", "nLevel", default=1) or 1),
        "armor": int(_get("armor", "armor_points", default=0) or 0),
        "body_type": int(_get("body_type", default=1) or 1),
        "head_type": int(_get("head_type", default=0) or 0),
        "coat_type": int(_get("coat_type", default=0) or 0),
        "trousers_type": int(_get("trousers_type", default=0) or 0),
        "major_weapon_id": major_weapon_id,
        "loadout": loadout,
    }


class _LiveRosterView:
    """Dynamic iterable view over `UE2MatchServer.roster` so late-joiners are seen live."""

    def __init__(self, roster_dict: Dict[int, Dict[str, Any]]) -> None:
        self._roster = roster_dict

    def __iter__(self) -> Iterator[Dict[str, Any]]:
        return iter(list(self._roster.values()))

    def __len__(self) -> int:
        return len(self._roster)


# ---------------------------------------------------------------------------
# Per-Peer UDP Client State
# ---------------------------------------------------------------------------

@dataclass
class UE2ClientPeer:
    """Tracks one connected `CS.exe` client keyed by UDP `(ip, port)`."""

    addr: Tuple[str, int]
    conn: UE2ConnectionState
    control: ControlChannelHandler
    connected_at: float = field(default_factory=time.monotonic)
    last_activity: float = field(default_factory=time.monotonic)
    joined: bool = False
    disconnected: bool = False
    disconnect_reason: str = ""
    role_id: Optional[int] = None
    player_name: str = ""
    team_id: int = 0
    session_cookie: Optional[int] = None


# ---------------------------------------------------------------------------
# UE2MatchServer (asyncio.DatagramProtocol for one live multiplayer room)
# ---------------------------------------------------------------------------

class UE2MatchServer(asyncio.DatagramProtocol):
    """
    Clean-room asyncio UDP UE2.5 Match Server hosting one live multiplayer room.

    Accepts multiple real `CS.exe` clients on `bind_host:udp_port`, drives the
    full UE2.5 handshake + Actor replication + authoritative FPS combat at 30Hz,
    and invokes `on_match_end(channel_id, room_id, results)` upon completion.
    """

    def __init__(
        self,
        *,
        channel_id: int = 1,
        room_id: int = 1,
        udp_port: int = DEFAULT_PORT_START,
        bind_host: str = DEFAULT_BIND_HOST,
        map_name: str = "DF-DiTieZhan",
        map_file: Optional[str] = None,
        map_id: int = 1,
        game_mode: int = 1,
        game_class: Optional[str] = None,
        shoot_limit: int = 50,
        time_limit: int = 15,
        max_players: int = 16,
        respawn_delay: float = DEFAULT_RESPAWN_DELAY,
        tick_hz: float = DEFAULT_TICK_HZ,
        client_timeout: float = DEFAULT_CLIENT_TIMEOUT,
        resend_interval: float = DEFAULT_RESEND_INTERVAL,
        keepalive_interval: float = DEFAULT_KEEPALIVE_INTERVAL,
        post_end_flush_seconds: float = DEFAULT_POST_END_FLUSH_SECONDS,
        idle_shutdown_seconds: float = 0.0,
        roster: Optional[Iterable[Any]] = None,
        on_match_end: Optional[Callable[[int, int, Dict[str, Any]], Any]] = None,
        game_dir: str = DEFAULT_GAME_DIR,
        server_name: str = "CSG Multiplayer Server",
        package_map: Optional[PackageMap] = None,
        map_spawns: Optional[MapSpawnData] = None,
        weapon_db: Optional[WeaponDatabase] = None,
        strict_challenge: bool = False,
        friendly_fire: bool = False,
        auto_end_when_empty: bool = True,
    ) -> None:
        self.channel_id: int = int(channel_id)
        self.room_id: int = int(room_id)
        self.bind_host: str = str(bind_host or DEFAULT_BIND_HOST)
        self.udp_port: int = int(udp_port)
        self.game_dir: str = os.path.abspath(game_dir)
        self.server_name: str = str(server_name)

        resolved_map = map_file or map_name or "DF-DiTieZhan"
        self.map_name: str = os.path.splitext(os.path.basename(resolved_map))[0]
        self.map_id: int = int(map_id)
        self.game_mode, self.game_class = _resolve_game_mode_and_class(game_mode, game_class)

        self.shoot_limit: int = max(0, int(shoot_limit))
        self.time_limit: int = max(0, int(time_limit))
        self.max_players: int = max(1, int(max_players))
        self.respawn_delay: float = max(0.0, float(respawn_delay))
        self.tick_hz: float = max(1.0, float(tick_hz))
        self.client_timeout: float = max(1.0, float(client_timeout))
        self.resend_interval: float = float(resend_interval)
        self.keepalive_interval: float = float(keepalive_interval)
        self.post_end_flush_seconds: float = max(0.0, float(post_end_flush_seconds))
        self.idle_shutdown_seconds: float = max(0.0, float(idle_shutdown_seconds))
        self.strict_challenge: bool = bool(strict_challenge)
        self.auto_end_when_empty: bool = bool(auto_end_when_empty)
        self.on_match_end = on_match_end

        # UE2.5 package map, map spawns, and weapon database
        self.package_map: PackageMap = (
            package_map
            if package_map is not None
            else get_cached_package_map(self.map_name, game_dir=self.game_dir)
        )
        self.map_spawns: MapSpawnData = (
            map_spawns
            if map_spawns is not None
            else get_cached_map_spawns(self.map_name, game_dir=self.game_dir)
        )
        self.weapon_db: WeaponDatabase = (
            weapon_db
            if weapon_db is not None
            else get_default_weapon_db(game_dir=self.game_dir)
        )

        # Authoritative Replication & Combat World
        self.replication: ReplicationManager = ReplicationManager(
            self.package_map,
            game_mode=self.game_mode,
            map_id=self.map_id,
            time_limit=self.time_limit,
            goal_score=self.shoot_limit,
            respawn_delay=self.respawn_delay,
            server_name=self.server_name,
        )
        self.world: MatchWorld = MatchWorld(
            map_name=self.map_name,
            map_id=self.map_id,
            game_mode=self.game_mode,
            shoot_limit=self.shoot_limit,
            time_limit=self.time_limit,
            respawn_delay=self.respawn_delay,
            replication=self.replication,
            map_spawns=self.map_spawns,
            weapon_db=self.weapon_db,
            game_dir=self.game_dir,
            friendly_fire=friendly_fire,
        )
        self.world.attach_replication(self.replication)

        # Realm room roster (live-updatable for late join)
        self.roster: Dict[int, Dict[str, Any]] = {}
        self._roster_view: _LiveRosterView = _LiveRosterView(self.roster)
        if roster is not None:
            for entry in roster:
                self.register_player(entry)

        # Active UDP clients keyed by (ip, port)
        self.clients: Dict[Tuple[str, int], UE2ClientPeer] = {}
        self.role_to_addr: Dict[int, Tuple[str, int]] = {}
        self.claimed_role_ids: Set[int] = set()
        self._recently_disconnected: Dict[Tuple[str, int], float] = {}

        # Asyncio transport & lifecycle state
        self.transport: Optional[asyncio.DatagramTransport] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._tick_task: Optional[asyncio.Task[None]] = None
        self._end_callback_task: Optional[asyncio.Task[None]] = None
        self._closed_event: Optional[asyncio.Event] = None
        self._high_res_timer_held: bool = False
        self.running: bool = False
        self.started_at: float = 0.0
        self.ever_had_players: bool = False
        self._match_end_notified: bool = False
        self._match_ended_at: Optional[float] = None
        self._last_results: Optional[Dict[str, Any]] = None

        # Telemetry counters
        self.datagrams_in: int = 0
        self.datagrams_out: int = 0
        self.bytes_in: int = 0
        self.bytes_out: int = 0

    # ------------------------------------------------------------------
    # Properties & Roster / Late-Join Management
    # ------------------------------------------------------------------

    @property
    def port(self) -> int:
        return self.udp_port

    @property
    def match_ended(self) -> bool:
        return self.world.match_ended

    @property
    def active_player_count(self) -> int:
        return sum(1 for p in self.clients.values() if p.joined and not p.disconnected)

    @property
    def active_peer_count(self) -> int:
        return sum(1 for p in self.clients.values() if not p.disconnected)

    def register_player(self, player_info: Any) -> Optional[Dict[str, Any]]:
        """
        Register (or update) a Realm player in this room's expected roster.
        Safe to call both before match start AND while the match is live (late join).
        """
        norm = _normalize_roster_entry(player_info)
        if norm is None:
            return None
        rid = norm["role_id"]
        self.roster[rid] = norm
        log.debug(
            "Room (%d,%d) UDP:%d registered roster player role_id=%d name=%r team=%d session=%s",
            self.channel_id,
            self.room_id,
            self.udp_port,
            rid,
            norm["name"],
            norm["team_id"],
            norm["session_cookie"],
        )
        return norm

    add_roster_player = register_player

    def get_match_results(self) -> Dict[str, Any]:
        """Return match results enriched with room/channel/port metadata."""
        res = self.world.get_match_results()
        res["channel_id"] = self.channel_id
        res["room_id"] = self.room_id
        res["udp_port"] = self.udp_port
        return res

    def remove_player_by_role(
        self,
        role_id: int,
        *,
        reason: str = "player_left",
    ) -> bool:
        """
        Remove a player by Realm `role_id` (e.g. on TCP `PlayerLeaveGameRequest`).
        Disconnects their active UDP peer if connected and triggers match-end check.
        """
        rid = int(role_id)
        addr = self.role_to_addr.get(rid)
        if addr is not None and addr in self.clients:
            peer = self.clients[addr]
            if not peer.disconnected:
                peer.control.send_disconnect(reason)
                self._flush_peer(peer)
                self._disconnect_peer(peer, reason=reason)
                return True
        # Even if UDP already closed or never connected, update MatchWorld
        removed = self.world.remove_player(rid) is not None
        self.claimed_role_ids.discard(rid)
        if removed:
            self._check_empty_match_end()
        return removed

    kick_player = remove_player_by_role

    # ------------------------------------------------------------------
    # Start / Stop Lifecycle
    # ------------------------------------------------------------------

    async def start(self, loop: Optional[asyncio.AbstractEventLoop] = None) -> int:
        """Bind the UDP socket and launch the 30Hz asyncio tick loop. Returns bound port."""
        if self.running and self.transport is not None:
            return self.udp_port

        self._loop = loop or asyncio.get_running_loop()
        self._closed_event = asyncio.Event()
        transport, _ = await self._loop.create_datagram_endpoint(
            lambda: self,
            local_addr=(self.bind_host, self.udp_port),
        )
        self.transport = transport
        sockname = transport.get_extra_info("sockname")
        if sockname and len(sockname) >= 2:
            self.udp_port = int(sockname[1])

        self.running = True
        if not self._high_res_timer_held:
            self._high_res_timer_held = _acquire_high_res_timer()
        self.started_at = time.monotonic()
        self.world.started_at = self.started_at
        self._tick_task = self._loop.create_task(
            self._tick_loop(),
            name=f"ue2-match-{self.channel_id}-{self.room_id}-udp{self.udp_port}",
        )
        log.info(
            "UE2MatchServer listening on %s:%d room=(%d,%d) map=%s mode=%s (%d) "
            "tick=%.0fHz shoot_limit=%d time_limit=%d roster=%d",
            self.bind_host,
            self.udp_port,
            self.channel_id,
            self.room_id,
            self.map_name,
            self.game_class,
            self.game_mode,
            self.tick_hz,
            self.shoot_limit,
            self.time_limit,
            len(self.roster),
        )
        return self.udp_port

    async def stop(
        self,
        *,
        notify_match_end: bool = False,
        reason: str = "server_stopped",
    ) -> Dict[str, Any]:
        """Stop the 30Hz tick loop, notify peers, close UDP socket cleanly (zero orphans)."""
        was_running = self.running
        self.running = False

        if notify_match_end and not self.world.match_ended:
            self.world.end_match(reason=reason)

        # Send graceful disconnect/final packets to any remaining peers before closing socket
        for peer in list(self.clients.values()):
            if not peer.disconnected:
                try:
                    if not self.world.match_ended:
                        peer.control.send_disconnect(reason)
                    self._flush_peer(peer)
                except Exception:
                    pass

        # Cancel & await tick task (guard against self-cancellation if called from tick loop)
        cur_task = asyncio.current_task()
        if self._tick_task is not None and self._tick_task is not cur_task:
            self._tick_task.cancel()
            try:
                await self._tick_task
            except asyncio.CancelledError:
                pass
        self._tick_task = None

        # Close UDP transport cleanly and await OS socket release (Windows ProactorEventLoop)
        closed_ev = self._closed_event
        had_transport = self.transport is not None
        self.close_transport()
        if had_transport and closed_ev is not None and not closed_ev.is_set():
            try:
                await asyncio.wait_for(closed_ev.wait(), timeout=0.5)
            except asyncio.TimeoutError:
                pass

        # Notify match end if requested and not yet delivered
        results = self.get_match_results()
        if notify_match_end and not self._match_end_notified:
            await self._invoke_match_end_callback(results)
        elif self._end_callback_task is not None and self._end_callback_task is not cur_task:
            if not self._end_callback_task.done():
                try:
                    await self._end_callback_task
                except Exception:
                    pass

        self.clients.clear()
        self.role_to_addr.clear()
        self.claimed_role_ids.clear()

        if was_running:
            log.info(
                "UE2MatchServer stopped room=(%d,%d) udp=%d in=%d out=%d",
                self.channel_id,
                self.room_id,
                self.udp_port,
                self.datagrams_in,
                self.datagrams_out,
            )
        return results

    def close_transport(self) -> None:
        """Synchronously close the UDP transport & cancel the tick task (zero orphan sockets)."""
        self.running = False
        if self._high_res_timer_held:
            self._high_res_timer_held = False
            _release_high_res_timer()
        if self._tick_task is not None and not self._tick_task.done():
            self._tick_task.cancel()
        if self.transport is not None:
            try:
                self.transport.close()
            except Exception:
                pass
            self.transport = None

    # ------------------------------------------------------------------
    # asyncio.DatagramProtocol Callbacks
    # ------------------------------------------------------------------

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]
        sock = transport.get_extra_info("socket")
        if sock is not None:
            # Raise kernel UDP buffers (1 MiB) so fast multi-client bursts never drop
            for opt in (socket.SO_RCVBUF, socket.SO_SNDBUF):
                try:
                    sock.setsockopt(socket.SOL_SOCKET, opt, UDP_SOCKET_BUF_BYTES)
                except OSError:
                    pass
            # Disable Windows SIO_UDP_CONNRESET (0x9800000C) so an ICMP Port Unreachable
            # from one disconnecting peer cannot disrupt recvfrom for other players!
            if hasattr(socket, "SIO_UDP_CONNRESET"):
                try:
                    sock.ioctl(socket.SIO_UDP_CONNRESET, False)
                except OSError:
                    pass

    def error_received(self, exc: Exception) -> None:
        # Windows emits ConnectionResetError (WinError 10054) when a client closes UDP
        if isinstance(exc, ConnectionResetError):
            log.debug("UDP ICMP ConnectionResetError on port %d (ignored): %s", self.udp_port, exc)
            return
        log.warning("UDP transport error on port %d: %s", self.udp_port, exc)

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if exc is not None:
            log.debug("UDP transport closed on port %d with error: %s", self.udp_port, exc)
        self.transport = None
        if self._closed_event is not None:
            self._closed_event.set()

    @staticmethod
    def _is_fresh_control_open_packet(data: bytes) -> bool:
        """Return True iff `data` contains a Channel 0 `bOpen=1` (fresh HELLO) bunch."""
        decoded = decode_raw_packet(data)
        if decoded is None:
            return False
        _, _, bunches = decoded
        return any(
            b.ch_index == 0 and b.b_open and (b.ch_type == CHTYPE_CONTROL or b.b_reliable)
            for b in bunches
        )

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        if not self.running or not data:
            return
        now = time.monotonic()
        self.datagrams_in += 1
        self.bytes_in += len(data)

        peer = self.clients.get(addr)
        if peer is None:
            disc_at = self._recently_disconnected.get(addr)
            if disc_at is not None and (now - disc_at) < 3.0:
                if not self._is_fresh_control_open_packet(data):
                    # Ignore trailing ACKs / keepalives / in-flight datagrams from a just-closed peer
                    return
                self._recently_disconnected.pop(addr, None)
            peer = self._create_peer(addr, now)
        elif peer.disconnected:
            if not self._is_fresh_control_open_packet(data):
                # Ignore trailing ACKs / keepalives from a disconnecting peer
                return
            # Genuine fresh HELLO reconnect from the same ephemeral UDP port
            self.clients.pop(addr, None)
            self._recently_disconnected.pop(addr, None)
            peer = self._create_peer(addr, now)

        peer.last_activity = now

        try:
            bunches = peer.conn.receive_raw_packet(data, now=now)
        except Exception:
            log.exception("Failed decoding raw UDP packet (%dB) from %s", len(data), addr)
            return

        state_changed_others = False
        for bunch in bunches:
            try:
                if bunch.ch_index == 0 or bunch.ch_type == CHTYPE_CONTROL:
                    prev_joined = peer.joined
                    peer.control.handle_bunch(bunch)
                    if peer.joined and not prev_joined:
                        state_changed_others = True
                elif bunch.ch_type == CHTYPE_ACTOR or bunch.ch_index > 0:
                    if peer.joined and not peer.disconnected:
                        rpcs = self.replication.receive_actor_bunch(peer.addr, bunch)
                        if rpcs:
                            state_changed_others = True
                    else:
                        log.debug(
                            "Ignoring pre-JOIN actor bunch ch=%d from %s",
                            bunch.ch_index,
                            addr,
                        )
            except Exception:
                log.exception(
                    "Error processing UE2 bunch %r from %s",
                    bunch,
                    addr,
                )

            if peer.disconnected:
                break

        # Event-driven ZERO-WAIT relay: if this datagram moved a pawn, fired a weapon,
        # joined, or changed any actor state, encode dirty deltas immediately (O(1) skip
        # on clean actors) and push to all peers without waiting for the next tick!
        if state_changed_others:
            self.replication.replicate_dirty_all()

        # Immediately flush sender (ACKs, handshake CHALLENGE/USES/WELCOME, RPC replies)
        self._flush_peer(peer, now=now)

        # Immediately flush all other peers with newly queued movement/combat deltas
        if state_changed_others:
            for other_addr, other in list(self.clients.items()):
                if other_addr == addr or other.disconnected:
                    continue
                if other.conn.out_queue:
                    self._flush_peer(other, now=now)

        # If combat hit kill_limit during this datagram, flush & notify promptly
        if self.world.match_ended and not self._match_end_notified:
            self._handle_world_match_ended(now)

    # ------------------------------------------------------------------
    # Peer Creation & Control Channel Callbacks
    # ------------------------------------------------------------------

    def _create_peer(self, addr: Tuple[str, int], now: float) -> UE2ClientPeer:
        conn = UE2ConnectionState(
            resend_interval=self.resend_interval,
            keepalive_interval=self.keepalive_interval,
        )
        peer_holder: List[UE2ClientPeer] = []

        def _cb_login(
            handler: ControlChannelHandler,
            parsed_url: ParsedLoginURL,
            bound: BoundPlayerInfo,
        ) -> Any:
            return self._on_client_login(peer_holder[0], handler, parsed_url, bound)

        def _cb_join(handler: ControlChannelHandler) -> None:
            self._on_client_join(peer_holder[0], handler)

        def _cb_disconnect(handler: ControlChannelHandler, reason: str) -> None:
            self._on_client_disconnect(peer_holder[0], reason)

        control = ControlChannelHandler(
            conn,
            self.package_map,
            map_name=self.map_name,
            game_class=self.game_class,
            roster=self._roster_view,
            claimed_role_ids=self.claimed_role_ids,
            strict_challenge=self.strict_challenge,
            on_login=_cb_login,
            on_join=_cb_join,
            on_disconnect=_cb_disconnect,
            client_addr=addr,
        )
        peer = UE2ClientPeer(
            addr=addr,
            conn=conn,
            control=control,
            connected_at=now,
            last_activity=now,
        )
        peer_holder.append(peer)
        self.clients[addr] = peer
        log.info(
            "New UDP peer %s connected to room=(%d,%d) port=%d",
            addr,
            self.channel_id,
            self.room_id,
            self.udp_port,
        )
        return peer

    def _on_client_login(
        self,
        peer: UE2ClientPeer,
        handler: ControlChannelHandler,
        parsed_url: ParsedLoginURL,
        bound: BoundPlayerInfo,
    ) -> Any:
        if self.world.match_ended:
            return "Match has already ended"

        # Enforce room capacity (allow reconnecting player with same role_id)
        active_count = sum(
            1
            for p in self.clients.values()
            if not p.disconnected
            and p.addr != peer.addr
            and p.control.state in (ControlState.WELCOMED, ControlState.JOINED)
        )
        if active_count >= self.max_players and bound.role_id not in self.role_to_addr:
            return "Server is full"

        peer.role_id = bound.role_id
        peer.player_name = bound.name
        peer.team_id = bound.team_id
        peer.session_cookie = bound.session_cookie
        return bound

    def _on_client_join(
        self,
        peer: UE2ClientPeer,
        handler: ControlChannelHandler,
    ) -> None:
        if peer.joined or peer.disconnected:
            return

        bound = handler.player
        if bound is None:
            bound = BoundPlayerInfo(
                role_id=peer.role_id or 1,
                name=peer.player_name or "Player",
                team_id=peer.team_id,
                session_cookie=peer.session_cookie,
                matched_by="fallback",
            )
            handler.player = bound

        role_id = int(bound.role_id)

        # If this role_id was previously connected from an older UDP endpoint, cleanly evict it
        old_addr = self.role_to_addr.get(role_id)
        if old_addr is not None and old_addr != peer.addr:
            old_peer = self.clients.get(old_addr)
            if old_peer is not None and not old_peer.disconnected:
                log.info(
                    "Evicting stale UDP peer %s for reconnecting role_id=%d (%s) from %s",
                    old_addr,
                    role_id,
                    bound.name,
                    peer.addr,
                )
                self._disconnect_peer(old_peer, reason="reconnected_elsewhere", check_empty=False)

        # Pull extra roster metadata (level, armor, loadout) if available
        roster_entry = self.roster.get(role_id) or {}
        level = int(roster_entry.get("level", 1) or 1)
        armor = int(roster_entry.get("armor", 0) or 0)
        weapon_id = int(bound.major_weapon_id or roster_entry.get("major_weapon_id", 65537) or 65537)
        loadout = bound.loadout or roster_entry.get("loadout") or {}

        # 1. Register player in authoritative MatchWorld (picks real .ut2 PlayerStart!)
        pstate = self.world.add_player(
            role_id=role_id,
            name=bound.name,
            team_id=bound.team_id,
            client_id=peer.addr,
            body_type=bound.body_type,
            head_type=bound.head_type,
            coat_type=bound.coat_type,
            trousers_type=bound.trousers_type,
            weapon_id=weapon_id,
            level=level,
            armor=armor,
            loadout=loadout,
        )

        # 2. Create UE2 replicated actors (PRI, PC, KFXPawn, KFXWeap*, KFXWeapAttachment)
        self.replication.register_client(
            peer.addr,
            peer.conn,
            role_id=pstate.role_id,
            player_name=pstate.name,
            team_id=pstate.team_id,
            session_id=int(bound.session_cookie or 0),
            level=pstate.level,
            body_type=pstate.body_type,
            head_type=pstate.head_type,
            coat_type=pstate.coat_type,
            trousers_type=pstate.trousers_type,
            weapon_id=pstate.weapon_id,
            clip_ammo=pstate.ammo,
            reserve_ammo=pstate.reserve_ammo,
            health=pstate.hp,
            armor=pstate.armor,
            spawn_location=pstate.pos,
            spawn_rotation=pstate.rot,
            loadout=pstate.loadout,
        )

        # Preserve prior scoreboard stats if this player reconnected mid-match
        if pstate.kills > 0 or pstate.deaths > 0:
            self.replication.update_pri_state(
                pstate.role_id,
                kills=pstate.kills,
                deaths=pstate.deaths,
                score=float(pstate.kills),
            )

        # 3. Spawn initial actors for this client + replicate new player to existing peers
        opened = self.replication.spawn_initial_actors_for_client(
            peer.addr,
            weapon_id=pstate.weapon_id,
            spawn_rotation=pstate.rot,
        )

        peer.joined = True
        peer.role_id = pstate.role_id
        peer.player_name = pstate.name
        peer.team_id = pstate.team_id
        self.role_to_addr[pstate.role_id] = peer.addr
        self.claimed_role_ids.add(pstate.role_id)
        self.ever_had_players = True

        log.info(
            "Player %r (role_id=%d, team=%d) JOINED room=(%d,%d) UDP:%d at spawn=%s "
            "(opened %d actor channels, active_players=%d)",
            pstate.name,
            pstate.role_id,
            pstate.team_id,
            self.channel_id,
            self.room_id,
            self.udp_port,
            tuple(round(c, 1) for c in pstate.pos),
            opened,
            self.active_player_count,
        )

    def _on_client_disconnect(self, peer: UE2ClientPeer, reason: str) -> None:
        self._disconnect_peer(peer, reason=reason, check_empty=True)

    def _disconnect_peer(
        self,
        peer: UE2ClientPeer,
        *,
        reason: str = "disconnected",
        check_empty: bool = True,
    ) -> None:
        if peer.disconnected:
            return
        peer.disconnected = True
        peer.disconnect_reason = reason
        self._recently_disconnected[peer.addr] = time.monotonic()

        was_joined = peer.joined
        peer.joined = False
        rid = peer.role_id

        # Remove from replication (queues channel closes to remaining peers)
        if peer.addr in self.replication.clients:
            self.replication.remove_client(peer.addr)

        if rid is not None:
            if self.role_to_addr.get(rid) == peer.addr:
                self.role_to_addr.pop(rid, None)
            self.claimed_role_ids.discard(rid)
            if was_joined:
                self.world.remove_player(rid)

        log.info(
            "Peer %s (role_id=%s, name=%r) disconnected from room=(%d,%d) reason=%s (remaining=%d)",
            peer.addr,
            rid,
            peer.player_name,
            self.channel_id,
            self.room_id,
            reason,
            self.active_player_count,
        )

        # Immediately push actor-destroy bunches to remaining peers
        now = time.monotonic()
        for other_addr, other in list(self.clients.items()):
            if other_addr != peer.addr and not other.disconnected and other.conn.out_queue:
                self._flush_peer(other, now=now)

        if check_empty:
            self._check_empty_match_end()

    def _check_empty_match_end(self) -> None:
        if (
            self.auto_end_when_empty
            and self.ever_had_players
            and not self.world.match_ended
            and self.active_peer_count == 0
        ):
            log.info(
                "All players left room=(%d,%d) UDP:%d -> ending match",
                self.channel_id,
                self.room_id,
                self.udp_port,
            )
            self.world.end_match(reason="all_players_left")
            self._handle_world_match_ended(time.monotonic())

    # ------------------------------------------------------------------
    # Packet Sending & 30Hz Simulation Tick Loop
    # ------------------------------------------------------------------

    def _send_raw(self, raw: bytes, addr: Tuple[str, int]) -> None:
        transport = self.transport
        if transport is None or transport.is_closing():
            return
        try:
            transport.sendto(raw, addr)
            self.datagrams_out += 1
            self.bytes_out += len(raw)
        except OSError as exc:
            log.debug("sendto(%s) failed on UDP %d: %s", addr, self.udp_port, exc)

    def _flush_peer(
        self,
        peer: UE2ClientPeer,
        *,
        now: Optional[float] = None,
        force_keepalive: bool = False,
    ) -> int:
        ts = time.monotonic() if now is None else now
        packets = peer.conn.flush(now=ts, force_keepalive=force_keepalive)
        for pkt in packets:
            self._send_raw(pkt, peer.addr)
        return len(packets)

    def _flush_all_peers(self, now: float) -> None:
        for peer in list(self.clients.values()):
            self._flush_peer(peer, now=now)

    async def _tick_loop(self) -> None:
        interval = 1.0 / self.tick_hz
        next_deadline = time.perf_counter()
        try:
            while self.running:
                now_mono = time.monotonic()
                try:
                    self._tick_once(now_mono)
                except Exception:
                    log.exception(
                        "Error in UE2MatchServer tick room=(%d,%d) UDP:%d",
                        self.channel_id,
                        self.room_id,
                        self.udp_port,
                    )

                next_deadline += interval
                now_perf = time.perf_counter()
                sleep_time = next_deadline - now_perf
                if sleep_time > 0.0:
                    await asyncio.sleep(sleep_time)
                else:
                    # Resync deadline if OS stalled past 2 tick intervals (avoid catch-up burst)
                    if sleep_time < -interval * 2.0:
                        next_deadline = now_perf
                    await asyncio.sleep(0)
        except asyncio.CancelledError:
            pass

    def _tick_once(self, now: float) -> None:
        # 1. Advance combat timers (match clock, reloads, auto-respawns, auto-fire, win check)
        if not self.world.match_ended:
            self.world.tick(now=now)

        # 2. Replicate dirty actor properties (movement deltas, HP, PRI, GRI, weapon state)
        self.replication.replicate_dirty_all()

        # 3. Check peer inactivity timeouts
        for addr, peer in list(self.clients.items()):
            if peer.disconnected:
                continue
            if (now - peer.last_activity) > self.client_timeout:
                log.info(
                    "Peer %s (role_id=%s) timed out after %.1fs",
                    addr,
                    peer.role_id,
                    now - peer.last_activity,
                )
                peer.control.send_disconnect("Connection timed out")
                self._flush_peer(peer, now=now)
                self._disconnect_peer(peer, reason="timeout")

        # 4. Flush pending ACKs, reliable retransmits, queued bunches, and keepalives
        for addr, peer in list(self.clients.items()):
            self._flush_peer(peer, now=now)
            if peer.disconnected and not peer.conn.has_pending_output():
                self.clients.pop(addr, None)

        # Prune expired recently-disconnected cooldown entries
        if self._recently_disconnected:
            for d_addr, d_ts in list(self._recently_disconnected.items()):
                if (now - d_ts) >= 3.0:
                    self._recently_disconnected.pop(d_addr, None)

        # 5. Idle shutdown if no player ever joined within configured timeout
        if (
            self.idle_shutdown_seconds > 0.0
            and not self.ever_had_players
            and not self.world.match_ended
            and (now - self.started_at) >= self.idle_shutdown_seconds
        ):
            self.world.end_match(reason="idle_timeout")

        # 6. Check match-end transition
        if self.world.match_ended and not self._match_end_notified:
            self._handle_world_match_ended(now)

    def _handle_world_match_ended(self, now: float) -> None:
        if self._match_end_notified:
            return
        self._match_end_notified = True
        self._match_ended_at = now

        # Flush final dirty state + ClientGameEnded RPCs to all connected clients immediately
        self.replication.replicate_dirty_all(force_reliable=True)
        self._flush_all_peers(now)

        results = self.get_match_results()
        self._last_results = results

        if self.on_match_end is not None and self._loop is not None and not self._loop.is_closed():
            # Schedule outside _tick_loop so if on_match_end calls stop(), it won't self-cancel
            self._end_callback_task = self._loop.create_task(
                self._invoke_match_end_callback(results),
                name=f"ue2-match-end-{self.channel_id}-{self.room_id}",
            )

    async def _invoke_match_end_callback(self, results: Dict[str, Any]) -> None:
        cb = self.on_match_end
        if cb is None:
            return
        try:
            ret = cb(self.channel_id, self.room_id, results)
            if inspect.isawaitable(ret):
                await ret
        except Exception:
            log.exception(
                "Error in on_match_end callback for room=(%d,%d)",
                self.channel_id,
                self.room_id,
            )


# ---------------------------------------------------------------------------
# UE2HostManager (UDP port pool & per-room server registry)
# ---------------------------------------------------------------------------

class UE2HostManager:
    """
    Allocates UDP ports from `[port_range_start..port_range_end]` and manages
    the full lifecycle of `UE2MatchServer` instances per `(channel_id, room_id)`
    with zero orphan sockets.
    """

    def __init__(
        self,
        *,
        port_range_start: int = DEFAULT_PORT_START,
        port_range_end: int = DEFAULT_PORT_END,
        bind_host: str = DEFAULT_BIND_HOST,
        game_dir: str = DEFAULT_GAME_DIR,
        tick_hz: float = DEFAULT_TICK_HZ,
        respawn_delay: float = DEFAULT_RESPAWN_DELAY,
        client_timeout: float = DEFAULT_CLIENT_TIMEOUT,
        server_name: str = "CSG Multiplayer Server",
        on_match_end: Optional[Callable[[int, int, Dict[str, Any]], Any]] = None,
        auto_cleanup_on_end: bool = True,
    ) -> None:
        self.port_range_start: int = int(port_range_start)
        self.port_range_end: int = int(port_range_end)
        if self.port_range_end < self.port_range_start:
            self.port_range_end = self.port_range_start
        self.bind_host: str = str(bind_host or DEFAULT_BIND_HOST)
        self.game_dir: str = os.path.abspath(game_dir)
        self.tick_hz: float = float(tick_hz)
        self.respawn_delay: float = float(respawn_delay)
        self.client_timeout: float = float(client_timeout)
        self.server_name: str = str(server_name)
        self.default_on_match_end = on_match_end
        self.auto_cleanup_on_end: bool = bool(auto_cleanup_on_end)

        self.servers: Dict[Tuple[int, int], UE2MatchServer] = {}
        self._allocated_ports: Set[int] = set()

    # ------------------------------------------------------------------
    # Port Allocation
    # ------------------------------------------------------------------

    def allocate_port(self) -> int:
        """Allocate the first free UDP port in `[port_range_start..port_range_end]`."""
        for port in range(self.port_range_start, self.port_range_end + 1):
            if port in self._allocated_ports:
                continue
            if is_udp_port_available(port, self.bind_host):
                return port
        raise RuntimeError(
            f"No free UDP ports available in range {self.port_range_start}..{self.port_range_end}"
        )

    def active_ports(self) -> Set[int]:
        return set(self._allocated_ports)

    def active_matches(self) -> List[UE2MatchServer]:
        return list(self.servers.values())

    def get_match(self, channel_id: int, room_id: int) -> Optional[UE2MatchServer]:
        return self.servers.get((int(channel_id), int(room_id)))

    # ------------------------------------------------------------------
    # Match Lifecycle
    # ------------------------------------------------------------------

    async def start_match(
        self,
        channel_id: int,
        room_id: int,
        *,
        map_name: str = "DF-DiTieZhan",
        map_file: Optional[str] = None,
        map_id: int = 1,
        game_mode: int = 1,
        game_class: Optional[str] = None,
        shoot_limit: int = 50,
        time_limit: int = 15,
        max_players: int = 16,
        roster: Optional[Iterable[Any]] = None,
        on_match_end: Optional[Callable[[int, int, Dict[str, Any]], Any]] = None,
        respawn_delay: Optional[float] = None,
        client_timeout: Optional[float] = None,
        udp_port: Optional[int] = None,
        strict_challenge: bool = False,
        friendly_fire: bool = False,
    ) -> UE2MatchServer:
        """
        Start a new `UE2MatchServer` for `(channel_id, room_id)`, or reuse the
        already-running server for late join while registering any new roster entries.
        """
        key = (int(channel_id), int(room_id))
        existing = self.servers.get(key)
        if existing is not None:
            if existing.running and not existing.match_ended:
                if roster is not None:
                    for entry in roster:
                        existing.register_player(entry)
                return existing
            await self.stop_match(key[0], key[1], notify_match_end=False)

        chosen_port = int(udp_port) if udp_port is not None else self.allocate_port()
        user_cb = on_match_end if on_match_end is not None else self.default_on_match_end

        async def _wrapped_match_end(ch_id: int, rm_id: int, results: Dict[str, Any]) -> None:
            if user_cb is not None:
                try:
                    ret = user_cb(ch_id, rm_id, results)
                    if inspect.isawaitable(ret):
                        await ret
                except Exception:
                    log.exception("Error in match-end callback for room=(%d,%d)", ch_id, rm_id)

            if self.auto_cleanup_on_end:
                srv = self.servers.get((ch_id, rm_id))
                if srv is not None:
                    # Brief flush window when players are still connected so ClientGameEnded ACKs
                    if srv.active_peer_count > 0 and srv.post_end_flush_seconds > 0:
                        await asyncio.sleep(srv.post_end_flush_seconds)
                    await self.stop_match(ch_id, rm_id, notify_match_end=False)

        server = UE2MatchServer(
            channel_id=key[0],
            room_id=key[1],
            udp_port=chosen_port,
            bind_host=self.bind_host,
            map_name=map_name,
            map_file=map_file,
            map_id=map_id,
            game_mode=game_mode,
            game_class=game_class,
            shoot_limit=shoot_limit,
            time_limit=time_limit,
            max_players=max_players,
            respawn_delay=self.respawn_delay if respawn_delay is None else float(respawn_delay),
            tick_hz=self.tick_hz,
            client_timeout=self.client_timeout if client_timeout is None else float(client_timeout),
            roster=roster,
            on_match_end=_wrapped_match_end,
            game_dir=self.game_dir,
            server_name=self.server_name,
            strict_challenge=strict_challenge,
            friendly_fire=friendly_fire,
        )

        try:
            bound_port = await server.start()
        except Exception:
            server.close_transport()
            raise

        self.servers[key] = server
        self._allocated_ports.add(bound_port)
        return server

    def register_player(
        self,
        channel_id: int,
        room_id: int,
        player_info: Any,
    ) -> bool:
        """Register a late-joining player into an active room's `UE2MatchServer`."""
        srv = self.get_match(channel_id, room_id)
        if srv is None or not srv.running:
            return False
        return srv.register_player(player_info) is not None

    def remove_player(
        self,
        channel_id: int,
        room_id: int,
        role_id: int,
        *,
        reason: str = "player_left",
    ) -> bool:
        """Remove a player from an active room's `UE2MatchServer` by `role_id`."""
        srv = self.get_match(channel_id, room_id)
        if srv is None:
            return False
        return srv.remove_player_by_role(role_id, reason=reason)

    def get_match_results(
        self,
        channel_id: int,
        room_id: int,
    ) -> Optional[Dict[str, Any]]:
        srv = self.get_match(channel_id, room_id)
        return srv.get_match_results() if srv is not None else None

    async def stop_match(
        self,
        channel_id: int,
        room_id: int,
        *,
        notify_match_end: bool = False,
        reason: str = "match_stopped",
    ) -> Optional[Dict[str, Any]]:
        """Stop and remove a room's `UE2MatchServer`, freeing its UDP port cleanly."""
        key = (int(channel_id), int(room_id))
        srv = self.servers.pop(key, None)
        if srv is None:
            return None
        try:
            return await srv.stop(notify_match_end=notify_match_end, reason=reason)
        finally:
            self._allocated_ports.discard(srv.udp_port)

    def stop_match_sync(self, channel_id: int, room_id: int) -> None:
        """Synchronous teardown helper (closes socket & frees port immediately)."""
        key = (int(channel_id), int(room_id))
        srv = self.servers.pop(key, None)
        if srv is None:
            return
        try:
            srv.close_transport()
        finally:
            self._allocated_ports.discard(srv.udp_port)

    async def stop_all(self, *, notify_match_end: bool = False) -> None:
        """Stop all active `UE2MatchServer` instances cleanly with zero orphan sockets."""
        for ch_id, rm_id in list(self.servers.keys()):
            await self.stop_match(ch_id, rm_id, notify_match_end=notify_match_end)
        self._allocated_ports.clear()

    def stop_all_sync(self) -> None:
        """Synchronous teardown of all active servers."""
        for ch_id, rm_id in list(self.servers.keys()):
            self.stop_match_sync(ch_id, rm_id)
        self._allocated_ports.clear()


__all__ = [
    "DEFAULT_BIND_HOST",
    "DEFAULT_PORT_START",
    "DEFAULT_PORT_END",
    "DEFAULT_TICK_HZ",
    "DEFAULT_CLIENT_TIMEOUT",
    "UE2ClientPeer",
    "UE2MatchServer",
    "UE2HostManager",
    "get_cached_package_map",
    "get_cached_map_spawns",
    "is_udp_port_available",
]

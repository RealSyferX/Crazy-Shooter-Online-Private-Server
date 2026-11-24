"""
UE2 Match Server Manager for CSO Malaysia.

Binary finding (verified in retail CSO Malaysia System/Engine.dll, 4,820,992 B):
  Kingsoft compiled the retail client Engine.dll with all four UE2 net-server methods
  stubbed out (ULevel::Listen @ 0x10431330 is `xor eax, eax; ret 4`, NotifyAcceptingConnection
  returns 0, WelcomePlayer and TickNetServer are bare `ret`). Therefore launching retail CS.exe
  with `?Listen` ALWAYS crashes with `Dedicated server can't listen:`.

Supported match_server.mode values in config.json:
  - "ue2_multiplayer" (DEFAULT):
      Hosts real multi-client UE2.5 (build 3369 / CSO Malaysia) matches directly in-process via
      our clean-room asyncio UDP match server (`server/ue2_server/host.py` -> `UE2HostManager`).
      Zero spawning of 2nd CS.exe windows! Multiple real CS.exe clients connect to UDP 7777..7795
      and play live multiplayer (movement, hitscan shooting, kills, deaths, respawns, scoreboard,
      late join, and real stat persistence via `on_match_end`).
  - "external_dedicated":
      Either connects clients to a pre-running external UE2 dedicated server
      (external_ip:external_port) OR spawns a server-compiled UE2 binary (dedicated_server_exe)
      after verifying its Engine.dll does NOT have ULevel::Listen stubbed, then waits for
      UDP port bind before returning ready=True for S2C 0x15 GameStartCommond(nResult=1).
  - "virtual":
      Allocates deterministic session/UDP port without spawning OS processes or binding UDP
      (fast CI / protocol unit tests).
  - "local_standalone" (legacy opt-in):
      Launches a playable standalone CS.exe window without `?Listen` or `-server`.
"""
from __future__ import annotations

import asyncio
import inspect
import logging
import socket
import struct
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote

from .gamedata import GameData
from .ue2_server.host import UE2HostManager, UE2MatchServer

log = logging.getLogger("csg.match")

# Retail client Engine.dll stub for ?Listen@ULevel@@UAEHAAVFString@@@Z:
#   33 C0 C2 04 00  -> xor eax, eax; ret 4
#   31 C0 C2 04 00  -> xor eax, eax; ret 4 (alternate encoding)
_STUB_LISTEN_PREFIXES = (b"\x33\xc0\xc2\x04\x00", b"\x31\xc0\xc2\x04\x00")


def is_client_only_engine_dll(engine_dll: Path) -> bool:
    """
    Inspect a PE Engine.dll export table for `?Listen@ULevel@@UAEHAAVFString@@@Z`.
    Returns True if the exported method is compiled out as `xor eax, eax; ret 4`.
    """
    try:
        data = engine_dll.read_bytes()
        if len(data) < 0x100 or data[:2] != b"MZ":
            return False
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_off + 0x80 > len(data) or data[pe_off : pe_off + 4] != b"PE\x00\x00":
            return False
        num_sec = struct.unpack_from("<H", data, pe_off + 6)[0]
        opt_sz = struct.unpack_from("<H", data, pe_off + 20)[0]
        exp_rva = struct.unpack_from("<I", data, pe_off + 0x78)[0]
        if exp_rva == 0:
            return False
        sec_off = pe_off + 24 + opt_sz
        secs = [struct.unpack_from("<IIII", data, sec_off + i * 40 + 8) for i in range(num_sec)]

        def rva_to_off(rva: int) -> int | None:
            for vsz, sva, rsz, sra in secs:
                if sva <= rva < sva + max(vsz, rsz):
                    return sra + (rva - sva)
            return None

        eo = rva_to_off(exp_rva)
        if eo is None or eo + 40 > len(data):
            return False
        num_names, funcs_rva, names_rva, ords_rva = struct.unpack_from("<IIII", data, eo + 24)
        fo, no, oo = rva_to_off(funcs_rva), rva_to_off(names_rva), rva_to_off(ords_rva)
        if fo is None or no is None or oo is None:
            return False
        for i in range(num_names):
            nrva = struct.unpack_from("<I", data, no + i * 4)[0]
            noff = rva_to_off(nrva)
            if noff is None:
                continue
            end = data.find(b"\x00", noff)
            if end == -1:
                continue
            name = data[noff:end]
            if b"Listen@ULevel" in name:
                ord_i = struct.unpack_from("<H", data, oo + i * 2)[0]
                frva = struct.unpack_from("<I", data, fo + ord_i * 4)[0]
                foff = rva_to_off(frva)
                if foff is None or foff + 5 > len(data):
                    return False
                prologue = data[foff : foff + 5]
                return prologue in _STUB_LISTEN_PREFIXES
    except Exception:
        return False
    return False


def is_udp_port_bound(port: int) -> bool:
    """Return True if any process is currently bound to UDP `port` on 0.0.0.0 or 127.0.0.1."""
    for host in ("0.0.0.0", "127.0.0.1"):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            sock.bind((host, port))
        except OSError:
            return True
        finally:
            sock.close()
    return False


@dataclass
class MatchInstance:
    session_id: int
    room_id: int
    channel_id: int
    map_id: int
    map_file: str
    map_name: str
    game_mode: int
    mode_name: str
    game_class: str
    udp_port: int
    mode: str = "ue2_multiplayer"
    connect_ip: str = "127.0.0.1"
    connect_port: int = 7777
    uses_udp_connect: bool = True
    status_message: str = ""
    started_at: float = field(default_factory=time.time)
    proc: subprocess.Popen[bytes] | None = None
    ue2_server: UE2MatchServer | None = None


class MatchManager:
    def __init__(self, config: dict[str, Any], gamedata: GameData):
        self.gamedata = gamedata
        ms_cfg = config.get("match_server", {})
        self.enabled = bool(ms_cfg.get("enabled", True))
        self.spawn_exe = bool(ms_cfg.get("spawn_dedicated_cs_exe", False))
        self.dedicated_server_exe = str(ms_cfg.get("dedicated_server_exe", "")).strip()
        self.external_ip = str(ms_cfg.get("external_ip", "")).strip()
        self.external_port = int(ms_cfg.get("external_port", 0))
        self.port_start = int(ms_cfg.get("port_range_start", 7777))
        self.port_end = int(ms_cfg.get("port_range_end", 7795))
        self.tick_hz = float(ms_cfg.get("tick_hz", 100.0))
        self.respawn_delay = float(ms_cfg.get("respawn_delay", 3.0))
        self.client_timeout = float(ms_cfg.get("client_timeout", 30.0))
        self.ready_timeout = float(ms_cfg.get("ready_timeout_seconds", 5.0))
        self.max_seconds = int(ms_cfg.get("max_match_seconds", 3600))
        self.bind_host = str(config.get("bind_host", "0.0.0.0"))
        self.public_ip = str(config.get("public_ip", "127.0.0.1"))
        self.server_name = str(config.get("server_name", "CSG Multiplayer Server"))
        self.client_dir = Path(config.get("client_dir", r"C:\Program Files (x86)\CSO Malaysia"))
        self.cs_exe = self.client_dir / "System" / "CS.exe"
        self.engine_dll = self.client_dir / "System" / "Engine.dll"
        self.client_engine_is_stubbed = is_client_only_engine_dll(self.engine_dll)

        cfg_mode = str(ms_cfg.get("mode", "")).strip().lower()
        if cfg_mode in ("ue2_multiplayer", "external_dedicated", "virtual", "local_standalone"):
            self.mode = cfg_mode
        elif self.dedicated_server_exe or (self.external_ip and self.external_port > 0):
            self.mode = "external_dedicated"
        else:
            self.mode = "ue2_multiplayer"

        self.ue2_host = UE2HostManager(
            port_range_start=self.port_start,
            port_range_end=self.port_end,
            bind_host=self.bind_host,
            game_dir=str(self.client_dir),
            tick_hz=self.tick_hz,
            respawn_delay=self.respawn_delay,
            client_timeout=self.client_timeout,
            server_name=self.server_name,
        )

        log.info(
            "MatchManager initialized: mode=%s udp_ports=%d..%d (retail_engine_stubbed=%s)",
            self.mode,
            self.port_start,
            self.port_end,
            self.client_engine_is_stubbed,
        )

        self._next_session_id = 1000
        self.active_by_room: dict[tuple[int, int], MatchInstance] = {}

    def _allocate_port(self) -> int:
        used = {m.udp_port for m in self.active_by_room.values()} | self.ue2_host.active_ports()
        for port in range(self.port_start, self.port_end + 1):
            if port not in used and not is_udp_port_bound(port):
                return port
        for port in range(self.port_start, self.port_end + 1):
            if port not in used:
                return port
        return self.port_start

    def build_standalone_command(
        self,
        map_file: str,
        game_class: str,
        map_id: int,
        player_name: str = "",
        team_id: int = 0,
    ) -> list[str]:
        """
        Build a standalone local match CLI for retail CS.exe (NO ?Listen, NO -server, NO -NULLRENDER).
        Hits KFXGame.u standalone mode (KFXIsKFXServerMode()==false, NetMode==0) without invoking ULevel::Listen.
        """
        opts = [f"game={game_class}", f"mapid={map_id}", f"Team={int(team_id)}"]
        clean_name = "".join(ch for ch in player_name if ch.isalnum() or ch in ("_", "-"))[:24]
        if clean_name:
            opts.append(f"Name={quote(clean_name)}")
        url = f"{map_file}.ut2?" + "?".join(opts)
        return [str(self.cs_exe), url, "-updated", "LOG=NUL"]

    def build_dedicated_command(
        self,
        server_exe: Path,
        map_file: str,
        game_class: str,
        max_players: int,
        udp_port: int,
    ) -> list[str]:
        """Build UE2 dedicated server CLI for a server-compiled UE2 binary (unstubbed Engine.dll / UCC.exe)."""
        url = f"{map_file}.ut2?game={game_class}?MaxPlayers={max_players}?Port={udp_port}?Listen"
        if server_exe.name.lower().startswith("ucc"):
            return [str(server_exe), "server", url, f"-port={udp_port}", "LOG=NUL"]
        return [str(server_exe), url, "-server", "-updated", f"-port={udp_port}", "-nosound", "LOG=NUL"]

    def _make_base_instance(
        self,
        channel_id: int,
        room_id: int,
        map_id: int,
        game_mode: int,
        udp_port: int,
    ) -> MatchInstance:
        self._next_session_id += 1
        map_info = self.gamedata.get_map(map_id)
        mode_info = self.gamedata.get_mode(game_mode)
        return MatchInstance(
            session_id=self._next_session_id,
            room_id=room_id,
            channel_id=channel_id,
            map_id=int(map_info["id"]),
            map_file=str(map_info["map_file"]),
            map_name=str(map_info["name"]),
            game_mode=int(mode_info["id"]),
            mode_name=str(mode_info["name"]),
            game_class=str(mode_info["game_class"]),
            udp_port=udp_port,
            mode=self.mode,
            connect_ip=self.public_ip,
            connect_port=udp_port,
            uses_udp_connect=(self.mode != "local_standalone"),
        )

    async def start_match_async(
        self,
        channel_id: int,
        room_id: int,
        map_id: int,
        game_mode: int,
        max_players: int = 16,
        *,
        shoot_limit: int = 100,
        time_limit: int = 20,
        roster: list[dict[str, Any]] | None = None,
        on_match_end: Callable[[int, int, dict[str, Any]], Any] | None = None,
        player_name: str = "",
        team_id: int = 0,
    ) -> tuple[MatchInstance, bool, str]:
        """
        Start or reuse a match for (channel_id, room_id).
        Returns (MatchInstance, ready, status_message).
        """
        key = (int(channel_id), int(room_id))
        existing = self.active_by_room.get(key)
        if existing is not None:
            still_alive = True
            if existing.ue2_server is not None:
                still_alive = existing.ue2_server.running and not existing.ue2_server.match_ended
                if still_alive and roster:
                    for entry in roster:
                        existing.ue2_server.register_player(entry)
            elif existing.proc is not None:
                still_alive = existing.proc.poll() is None
            if still_alive:
                return existing, True, existing.status_message
            self.active_by_room.pop(key, None)

        if not self.enabled or self.mode == "virtual":
            udp_port = self._allocate_port()
            inst = self._make_base_instance(channel_id, room_id, map_id, game_mode, udp_port)
            inst.uses_udp_connect = True
            inst.status_message = f"Virtual match session={inst.session_id} on {inst.connect_ip}:{inst.connect_port}"
            log.info(
                "Allocated virtual match session=%d room=(%d,%d) map=%s mode=%s udp=%d",
                inst.session_id, channel_id, room_id, inst.map_file, inst.game_class, udp_port,
            )
            self.active_by_room[key] = inst
            return inst, True, inst.status_message

        if self.mode == "ue2_multiplayer":
            map_info = self.gamedata.get_map(map_id)
            mode_info = self.gamedata.get_mode(game_mode)

            async def _on_ue2_end(ch_id: int, rm_id: int, results: dict[str, Any]) -> None:
                self.active_by_room.pop((ch_id, rm_id), None)
                if on_match_end is not None:
                    ret = on_match_end(ch_id, rm_id, results)
                    if inspect.isawaitable(ret):
                        await ret

            try:
                srv = await self.ue2_host.start_match(
                    channel_id,
                    room_id,
                    map_file=str(map_info["map_file"]),
                    map_id=int(map_info["id"]),
                    game_mode=int(mode_info["id"]),
                    game_class=str(mode_info["game_class"]),
                    shoot_limit=int(shoot_limit),
                    time_limit=int(time_limit),
                    max_players=int(max_players),
                    roster=roster,
                    on_match_end=_on_ue2_end,
                )
            except Exception as exc:
                fallback_inst = self._make_base_instance(channel_id, room_id, map_id, game_mode, self.port_start)
                msg = f"Failed to start built-in UE2 multiplayer UDP server: {exc}"
                log.exception(msg)
                return fallback_inst, False, msg

            inst = self._make_base_instance(channel_id, room_id, map_id, game_mode, srv.udp_port)
            inst.mode = "ue2_multiplayer"
            inst.connect_ip = self.public_ip
            inst.connect_port = srv.udp_port
            inst.uses_udp_connect = True
            inst.ue2_server = srv
            inst.status_message = (
                f"UE2.5 Multiplayer Server live on {inst.connect_ip}:{srv.udp_port} "
                f"({inst.map_name} / {inst.mode_name})"
            )
            self.active_by_room[key] = inst
            log.info(
                "Started in-process UE2 multiplayer match session=%d room=(%d,%d) udp=%s:%d map=%s mode=%s roster=%d",
                inst.session_id,
                channel_id,
                room_id,
                inst.connect_ip,
                srv.udp_port,
                inst.map_file,
                inst.game_class,
                len(roster or []),
            )
            return inst, True, inst.status_message

        udp_port = self._allocate_port()
        inst = self._make_base_instance(channel_id, room_id, map_id, game_mode, udp_port)

        if self.mode == "external_dedicated":
            # Case A: Pre-running external UE2 dedicated server
            if not self.dedicated_server_exe and self.external_ip and self.external_port > 0:
                inst.connect_ip = self.external_ip
                inst.connect_port = self.external_port
                inst.udp_port = self.external_port
                inst.uses_udp_connect = True
                inst.status_message = f"Using external UE2 dedicated server at {inst.connect_ip}:{inst.connect_port}"
                log.info("Match session=%d routed to external server %s:%d", inst.session_id, inst.connect_ip, inst.connect_port)
                self.active_by_room[key] = inst
                return inst, True, inst.status_message

            # Case B: Spawn configured server-compiled UE2 binary
            server_exe = Path(self.dedicated_server_exe) if self.dedicated_server_exe else self.cs_exe
            if not server_exe.exists():
                msg = f"Dedicated server binary not found: {server_exe}"
                log.warning(msg)
                return inst, False, msg
            if is_client_only_engine_dll(server_exe.parent / "Engine.dll"):
                msg = (
                    "Refused to spawn retail CS.exe with ?Listen: Engine.dll!ULevel::Listen is stubbed "
                    "(xor eax, eax; ret 4). Set match_server.mode='ue2_multiplayer' or supply a server-compiled UE2 binary."
                )
                log.error(msg)
                return inst, False, msg

            cmd = self.build_dedicated_command(server_exe, inst.map_file, inst.game_class, max_players, udp_port)
            try:
                startupinfo = None
                if hasattr(subprocess, "STARTUPINFO"):
                    startupinfo = subprocess.STARTUPINFO()
                    startupinfo.dwFlags |= getattr(subprocess, "STARTF_USESHOWWINDOW", 1)
                    startupinfo.wShowWindow = 7  # SW_SHOWMINNOACTIVE
                inst.proc = subprocess.Popen(
                    cmd,
                    cwd=str(server_exe.parent),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    startupinfo=startupinfo,
                )
            except Exception as exc:
                msg = f"Failed to spawn dedicated match server: {exc}"
                log.warning(msg)
                return inst, False, msg

            deadline = time.monotonic() + max(0.5, self.ready_timeout)
            bound = False
            while time.monotonic() < deadline:
                if inst.proc.poll() is not None:
                    rc = inst.proc.returncode
                    inst.proc = None
                    msg = f"Dedicated match server exited prematurely (code={rc}) before binding UDP {udp_port}"
                    log.error(msg)
                    return inst, False, msg
                if is_udp_port_bound(udp_port):
                    bound = True
                    break
                await asyncio.sleep(0.1)

            if not bound:
                self._terminate_proc(inst.proc)
                inst.proc = None
                msg = f"Dedicated match server did not bind UDP {udp_port} within {self.ready_timeout:.1f}s"
                log.error(msg)
                return inst, False, msg

            inst.uses_udp_connect = True
            inst.status_message = f"Dedicated UE2 server bound UDP {inst.connect_ip}:{udp_port}"
            log.info(
                "Dedicated UE2 server ready pid=%s session=%d room=(%d,%d) map=%s mode=%s udp=%d",
                inst.proc.pid, inst.session_id, channel_id, room_id, inst.map_file, inst.game_class, udp_port,
            )
            self.active_by_room[key] = inst
            return inst, True, inst.status_message

        # Legacy opt-in: local_standalone (playable local CS.exe match without ?Listen or -server)
        inst.uses_udp_connect = False
        if not self.cs_exe.exists():
            msg = f"CS.exe not found at {self.cs_exe}"
            log.warning(msg)
            return inst, False, msg

        cmd = self.build_standalone_command(inst.map_file, inst.game_class, inst.map_id, player_name, team_id)
        try:
            inst.proc = subprocess.Popen(
                cmd,
                cwd=str(self.cs_exe.parent),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception as exc:
            msg = f"Failed to launch local standalone CS.exe match: {exc}"
            log.warning(msg)
            return inst, False, msg

        await asyncio.sleep(0.35)
        if inst.proc.poll() is not None:
            rc = inst.proc.returncode
            inst.proc = None
            msg = f"Standalone CS.exe exited immediately (code={rc})"
            log.error(msg)
            return inst, False, msg

        inst.status_message = f"Launched local standalone match: {inst.map_name} ({inst.mode_name})."
        self.active_by_room[key] = inst
        return inst, True, inst.status_message

    def register_player(self, channel_id: int, room_id: int, player_info: dict[str, Any]) -> bool:
        """Register a player into an active room's live UE2 multiplayer server (late join)."""
        return self.ue2_host.register_player(channel_id, room_id, player_info)

    def remove_player(
        self,
        channel_id: int,
        room_id: int,
        role_id: int,
        *,
        reason: str = "player_left",
    ) -> bool:
        """Remove a player from an active room's live UE2 multiplayer server."""
        return self.ue2_host.remove_player(channel_id, room_id, role_id, reason=reason)

    def get_match_results(self, channel_id: int, room_id: int) -> dict[str, Any] | None:
        """Fetch live/final combat results for an active room's UE2 match server."""
        return self.ue2_host.get_match_results(channel_id, room_id)

    def start_match(self, channel_id: int, room_id: int, map_id: int, game_mode: int, max_players: int = 16) -> MatchInstance:
        """Synchronous virtual/fallback helper preserved for backwards compatibility."""
        key = (int(channel_id), int(room_id))
        existing = self.active_by_room.get(key)
        if existing is not None:
            return existing
        udp_port = self._allocate_port()
        inst = self._make_base_instance(channel_id, room_id, map_id, game_mode, udp_port)
        self.active_by_room[key] = inst
        return inst

    def get_match(self, channel_id: int, room_id: int) -> MatchInstance | None:
        return self.active_by_room.get((int(channel_id), int(room_id)))

    @staticmethod
    def _terminate_proc(proc: subprocess.Popen[bytes] | None) -> None:
        if proc is None:
            return
        try:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=3)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    async def stop_match_async(
        self,
        channel_id: int,
        room_id: int,
        *,
        notify_match_end: bool = False,
    ) -> dict[str, Any] | None:
        key = (int(channel_id), int(room_id))
        inst = self.active_by_room.pop(key, None)
        results = await self.ue2_host.stop_match(channel_id, room_id, notify_match_end=notify_match_end)
        if inst and inst.proc is not None:
            self._terminate_proc(inst.proc)
            log.info("Stopped match process session=%d room=(%d,%d)", inst.session_id, channel_id, room_id)
        return results

    def stop_match(self, channel_id: int, room_id: int) -> None:
        key = (int(channel_id), int(room_id))
        inst = self.active_by_room.pop(key, None)
        self.ue2_host.stop_match_sync(channel_id, room_id)
        if inst and inst.proc is not None:
            self._terminate_proc(inst.proc)
            log.info("Stopped match process session=%d room=(%d,%d)", inst.session_id, channel_id, room_id)

    async def stop_all_async(self) -> None:
        for key in list(self.active_by_room.keys()):
            await self.stop_match_async(*key, notify_match_end=False)
        await self.ue2_host.stop_all(notify_match_end=False)

    def stop_all(self) -> None:
        for key in list(self.active_by_room.keys()):
            self.stop_match(*key)
        self.ue2_host.stop_all_sync()

    def reap_stale(self) -> None:
        now = time.time()
        for key, inst in list(self.active_by_room.items()):
            if inst.ue2_server is not None:
                if not inst.ue2_server.running:
                    self.active_by_room.pop(key, None)
                elif now - inst.started_at > self.max_seconds:
                    self.stop_match(*key)
            elif inst.proc is not None and inst.proc.poll() is not None:
                self.active_by_room.pop(key, None)
            elif now - inst.started_at > self.max_seconds:
                self.stop_match(*key)

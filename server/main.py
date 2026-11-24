#!/usr/bin/env python3
"""
Unified launcher for the CSG Private Server stack:
  - Bishop Login Gateway (TCP 7451)
  - Realm Lobby / Room / Shop / Bag / Chat / Mail / Quest Server (TCP 7452)
  - HTTP Registration & Launcher API Server (TCP 8080)
  - UE2 Dedicated Match Server Manager (UDP 7777+)
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import signal
import sys
from pathlib import Path
from typing import Any

# Ensure package import works whether run as `python server/main.py` or `python -m server.main`
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from server.api_server import ApiHttpServer
from server.bishop import BishopServer, SessionRegistry
from server.crypto import KSGCipherTable
from server.database import Database
from server.gamedata import GameData
from server.match_manager import MatchManager
from server.realm import RealmServer


def load_config(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


class CSGServerApp:
    def __init__(self, config: dict[str, Any], base_dir: Path = BASE_DIR):
        self.config = config
        self.base_dir = base_dir
        self.data_dir = base_dir / "data"

        ksg_path = self.data_dir / "ksg_table.bin"
        if not ksg_path.exists():
            raise FileNotFoundError(
                f"Missing {ksg_path}. Run `python tools/extract_client_data.py` first."
            )

        self.cipher = KSGCipherTable.from_file(ksg_path)
        self.gamedata = GameData(self.data_dir)

        db_path = Path(config.get("database_path", "csg.db"))
        if not db_path.is_absolute():
            db_path = base_dir / db_path
        self.db = Database(
            db_path,
            self.gamedata,
            default_gp=int(config.get("default_gp", 500000)),
            default_csp=int(config.get("default_csp", 25000)),
        )
        self.tickets = SessionRegistry()
        self.match_manager = MatchManager(config, self.gamedata)
        self.bishop = BishopServer(config, self.cipher, self.db, self.tickets)
        self.realm = RealmServer(config, self.cipher, self.db, self.gamedata, self.tickets, self.match_manager)
        self.http = ApiHttpServer(config, self.db, self.realm)
        self._reaper_task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        await self.bishop.start()
        await self.realm.start()
        self.http.start()
        self._reaper_task = asyncio.create_task(self._reaper_loop())

    async def _reaper_loop(self) -> None:
        try:
            while True:
                await asyncio.sleep(15)
                self.match_manager.reap_stale()
        except asyncio.CancelledError:
            pass

    async def stop(self) -> None:
        if self._reaper_task:
            self._reaper_task.cancel()
            try:
                await self._reaper_task
            except asyncio.CancelledError:
                pass
        self.http.stop()
        await self.realm.stop()
        await self.bishop.stop()
        self.match_manager.stop_all()
        self.db.close()


async def run_forever(config_path: Path, log_level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    cfg = load_config(config_path)
    app = CSGServerApp(cfg, config_path.resolve().parent)
    await app.start()

    log = logging.getLogger("csg.main")
    log.info("==============================================================")
    log.info("  %s READY", cfg.get("server_name", "CSG Private Server"))
    log.info("  Bishop Gateway : %s:%d", cfg.get("public_ip", "127.0.0.1"), int(cfg.get("bishop_port", 7451)))
    log.info("  Realm Server   : %s:%d", cfg.get("public_ip", "127.0.0.1"), int(cfg.get("realm_port", 7452)))
    log.info("  Web / API      : http://%s:%d", cfg.get("public_ip", "127.0.0.1"), int(cfg.get("http_port", 8080)))
    log.info("  Auto-register  : %s", cfg.get("auto_register_on_login", True))
    log.info("==============================================================")

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig_name in ("SIGINT", "SIGTERM"):
        sig = getattr(signal, sig_name, None)
        if sig is not None:
            try:
                loop.add_signal_handler(sig, stop_event.set)
            except NotImplementedError:
                pass

    try:
        await stop_event.wait()
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        log.info("Shutting down CSG Private Server...")
        await app.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description="CSG Clean-Room Private Server for CSO Malaysia")
    parser.add_argument("--config", default=str(BASE_DIR / "config.json"), help="Path to config.json")
    parser.add_argument("--log-level", default="INFO", help="Logging level (DEBUG, INFO, WARNING)")
    args = parser.parse_args()
    try:
        asyncio.run(run_forever(Path(args.config), args.log_level))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

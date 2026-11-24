"""
Bishop Login Gateway Server (TCP 7451).

Handles:
  1. Unencrypted 42-byte KFX key handshake on accept
  2. C2S 0x00 LoginGatewayRequest -> verifies account (or auto-registers if enabled)
  3. Issues a Realm auth ticket (cookie, account_id, role_id) shared with RealmServer
  4. Sends S2C 0x01 LoginGatewayRespond + S2C 0xFA RealmListRespond
"""
from __future__ import annotations

import asyncio
import logging
import secrets
import time
from dataclasses import dataclass
from typing import Any

from .crypto import KSGCipherTable, KFXStream
from .database import Database
from .packets import (
    decode_bishop_login_request,
    encode_bishop_login_respond,
    encode_bishop_realm_list,
)

log = logging.getLogger("csg.bishop")


@dataclass
class AuthTicket:
    cookie: int
    account_id: int
    role_id: int
    username: str
    created_at: float


class SessionRegistry:
    """Shared in-memory auth tickets issued by Bishop and consumed by Realm."""

    def __init__(self) -> None:
        self.tickets_by_cookie: dict[int, AuthTicket] = {}

    def issue(self, account_id: int, role_id: int, username: str) -> AuthTicket:
        cookie = secrets.randbits(31) | 1
        ticket = AuthTicket(
            cookie=cookie,
            account_id=account_id,
            role_id=role_id,
            username=username,
            created_at=time.time(),
        )
        self.tickets_by_cookie[cookie] = ticket
        return ticket

    def lookup(self, cookie: int, role_id: int) -> AuthTicket | None:
        ticket = self.tickets_by_cookie.get(cookie)
        if ticket is None:
            return None
        # Allow matching by cookie (and role_id if role already exists)
        if ticket.role_id != 0 and role_id != 0 and ticket.role_id != role_id:
            return None
        return ticket


class BishopServer:
    def __init__(
        self,
        config: dict[str, Any],
        cipher: KSGCipherTable,
        db: Database,
        tickets: SessionRegistry,
    ):
        self.config = config
        self.cipher = cipher
        self.db = db
        self.tickets = tickets
        self.server: asyncio.AbstractServer | None = None

    def get_realm_entries(self) -> list[dict[str, Any]]:
        public_ip = str(self.config.get("public_ip", "127.0.0.1"))
        realm_port = int(self.config.get("realm_port", 7452))
        entries = []
        for r in self.config.get("realms", [{"id": 1, "name": "CSG MY", "work_state": 1}]):
            entries.append({
                "id": int(r["id"]),
                "name": str(r["name"]),
                "work_state": int(r.get("work_state", 1)),
                "ip": str(r.get("ip", public_ip)),
                "port": int(r.get("port", realm_port)),
            })
        return entries

    async def start(self) -> None:
        host = str(self.config.get("bind_host", "0.0.0.0"))
        port = int(self.config.get("bishop_port", 7451))
        self.server = await asyncio.start_server(self._handle_client, host, port)
        log.info("Bishop Login Gateway listening on %s:%d", host, port)

    async def stop(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
            self.server = None

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        stream = KFXStream(reader, writer, self.cipher, is_server=True)
        peer = stream.peer_addr
        log.info("[Bishop] Client connected: %s", peer)
        try:
            await stream.server_handshake()
            while True:
                try:
                    pkt = await stream.read_packet()
                except (asyncio.IncompleteReadError, ConnectionResetError, EOFError):
                    break
                if not pkt:
                    continue
                opcode = pkt[0]
                try:
                    if opcode == 0x00:
                        await self._on_login_gateway(stream, pkt)
                    else:
                        log.debug("[Bishop] Ignoring unhandled opcode 0x%02X from %s", opcode, peer)
                except (asyncio.IncompleteReadError, ConnectionError, EOFError):
                    break
                except Exception:
                    log.exception(
                        "[Bishop] Handler error on %s (op=0x%02X, len=%d, pkt=%s)",
                        peer, opcode, len(pkt), pkt[:64].hex(),
                    )
        except Exception:
            log.exception("[Bishop] Stream error on %s", peer)
        finally:
            await stream.close()
            log.info("[Bishop] Client disconnected: %s", peer)

    async def _on_login_gateway(self, stream: KFXStream, pkt: bytes) -> None:
        req = decode_bishop_login_request(pkt)
        username = req["username"].strip()
        pw_md5 = req["password_md5"].strip()
        auto_reg = bool(self.config.get("auto_register_on_login", True))

        if not username or not pw_md5:
            await stream.send_packet(encode_bishop_login_respond(0, 0, 0, 0))
            return

        # Maintenance check
        reg_cfg = self.config.get("registration", {})
        acc, status = self.db.verify_account(username, pw_md5, auto_register=auto_reg)
        if acc is None:
            # Result code 2 = wrong password / invalid account
            log.info("[Bishop] Login FAILED user=%s reason=%s", username, status)
            await stream.send_packet(encode_bishop_login_respond(2, 0, 0, 0))
            return

        if reg_cfg.get("maintenance_enabled") and not (reg_cfg.get("maintenance_allow_gm") and acc.get("is_gm")):
            log.info("[Bishop] Login blocked (maintenance) user=%s", username)
            await stream.send_packet(encode_bishop_login_respond(3, 0, 0, 0))
            return

        role = self.db.get_role_by_account(int(acc["account_id"]))
        role_id = int(role["role_id"]) if role else int(acc["account_id"])
        # LoginBishopEvent: param_4 == 0 => sets bCreateRole=1 (needs create role); != 0 => already has role
        has_role = 1 if role is not None else 0
        ticket = self.tickets.issue(int(acc["account_id"]), int(role["role_id"]) if role else 0, username)

        log.info(
            "[Bishop] Login OK user=%s (%s) account_id=%d role_id=%d has_role=%d cookie=%d",
            username, status, acc["account_id"], role_id, has_role, ticket.cookie,
        )
        await stream.send_packet(encode_bishop_login_respond(1, ticket.cookie, role_id, has_role))
        await stream.send_packet(encode_bishop_realm_list(self.get_realm_entries()))

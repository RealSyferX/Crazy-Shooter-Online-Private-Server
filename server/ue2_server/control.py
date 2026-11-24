"""
UE2.5 (UT2004 build 3369 / CSO Malaysia) Control Channel (Channel 0, CHTYPE_Control)
handshake and connection lifecycle handler.

Binary-verified against CSO Malaysia System\\Engine.dll & Core.dll:
  - UControlChannel::ReceivedBunch (0x10539120): loops `Bunch << FString` until
    end-of-bunch or error; multiple FStrings may appear in a single reliable bunch.
  - UNetPendingLevel::UNetPendingLevel (0x105452f0): client sends
      HELLO REVISION=0 MINVER=3180 VER=3369
  - UNetPendingLevel::NotifyReceivedText (0x10544600):
      1. Server replies to HELLO with:
           CHALLENGE VER=3369 CHALLENGE=<int32> STATS=0 SEC=0 GZ=0
      2. Client replies with AUTH, NETSPEED <rate>, and LOGIN RESPONSE=<int32> URL=<url>
         (NO ACCEPTED message in UE2.5; WELCOME is login acceptance).
      3. Server binds player to Realm room roster (?Session=<cookie> primary,
         fallback ?RoleID= / ?Name= / ?Team=), then replies with:
           USES GUID=<32-HEX> PKG=<Pkg> FLAGS=<u32> SIZE=<i32> GEN=<i32> FNAME=<File>
           (one per PackageMap entry in exact UPackageMap::List order)
           WELCOME LEVEL=<MapName> LONE=0 CHALLENGE=<int32> GAME=<GameClass>
      4. Client validates all USES GUID/GEN entries via appFindPackageFile, loads the
         map, and sends exact literal:
           JOIN
      5. Server receives JOIN and triggers Actor channel spawning via `on_join`.
  - Also handles AUTH, NETSPEED (initial & mid-game), SKIP, DLMGR, USERFLAG,
    UPGRADE, FAILURE, FAILCODE, DISCONNECT, and Channel 0 close (`b_close=True`).
"""

from __future__ import annotations

import logging
import os
import random
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union
from urllib.parse import unquote

from .bitstream import (
    CHTYPE_CONTROL,
    ENGINE_MIN_NET_VERSION,
    ENGINE_VERSION,
    BitReader,
    InBunch,
    OutBunch,
    UE2ConnectionState,
    challenge_response,
)

try:
    from .packagemap import PackageMap
except Exception:  # pragma: no cover - optional when testing without packagemap
    PackageMap = Any  # type: ignore[assignment,misc]

log = logging.getLogger("csg.ue2.control")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_GAME_CLASS: str = "KFXGame.KFXMeleeGame"
DEFAULT_NETSPEED: int = 9636
MIN_NETSPEED: int = 1800
MAX_NETSPEED: int = 100000

# Verified from KFXGame.u / KFXGameMode.csv
GAME_MODE_TO_CLASS: Dict[int, str] = {
    1: "KFXGame.KFXMeleeGame",
    2: "KFXGame.KFXSingleGame",
    3: "KFXGame.KFXRoundGame",
    4: "KFXGame.KFXBombGame",
    5: "KFXGame.KFXOccupyGame",
}

# Token regex for UE2 Parse(Stream, Key, Val): matches KEY="quoted" or KEY=nonspace
_KV_PATTERN = re.compile(r'([A-Za-z0-9_]+)=(?:"([^"]*)"|(\S*))')


# ---------------------------------------------------------------------------
# Connection Lifecycle States
# ---------------------------------------------------------------------------

class ControlState(Enum):
    """UE2.5 Control Channel handshake lifecycle state."""

    INIT = "init"                  # Awaiting C2S HELLO
    CHALLENGED = "challenged"      # Sent S2C CHALLENGE; awaiting AUTH/NETSPEED/LOGIN
    WELCOMED = "welcomed"          # Sent S2C USES + WELCOME; awaiting C2S JOIN
    JOINED = "joined"              # Received C2S JOIN; player in match (Actor channels live)
    DISCONNECTED = "disconnected"  # Closed via FAILURE / DISCONNECT / bClose / UPGRADE


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class ParsedLoginURL:
    """Parsed UE2 Browse/Login URL from `LOGIN RESPONSE=... URL=...`."""

    raw_url: str
    map_part: str = ""
    options: Dict[str, str] = field(default_factory=dict)  # lowercase key -> value
    session: Optional[int] = None
    session_raw: Optional[str] = None
    map_id: Optional[int] = None
    name: str = "Player"
    team: Optional[int] = None
    role_id: Optional[int] = None
    player_class: str = ""
    character: str = ""
    password: str = ""
    spectator_only: bool = False
    voice: str = ""
    sex: str = ""

    def get_option(self, key: str, default: Optional[str] = None) -> Optional[str]:
        return self.options.get(key.lower(), default)


@dataclass
class BoundPlayerInfo:
    """Authoritative player identity bound to a UE2 client connection upon LOGIN."""

    role_id: int
    name: str
    team_id: int = 0
    session_cookie: Optional[int] = None
    body_type: int = 1
    head_type: int = 0
    coat_type: int = 0
    trousers_type: int = 0
    major_weapon_id: int = 65537
    loadout: Dict[str, Any] = field(default_factory=dict)
    player_class: str = ""
    character: str = ""
    spectator_only: bool = False
    matched_by: str = "fallback"  # "session" | "role_id" | "name" | "fallback"
    roster_entry: Any = None


# ---------------------------------------------------------------------------
# Wire Helpers (FString Control Bunches)
# ---------------------------------------------------------------------------

def decode_control_bunch(bunch: Union[InBunch, BitReader]) -> List[str]:
    """
    Decode all UE2 FString text messages from a Channel 0 (`CHTYPE_CONTROL`) bunch.
    Matches `Engine.dll!UControlChannel::ReceivedBunch` (0x10539120): loops reading
    FStrings until `at_end()` or `is_error()`.
    """
    reader = bunch.reader() if isinstance(bunch, InBunch) else bunch.clone()
    messages: List[str] = []
    while not reader.at_end() and not reader.is_error():
        start_pos = reader.tell()
        text = reader.read_fstring()
        if reader.is_error():
            break
        # Guard against zero-progress infinite loops on malformed data
        if reader.tell() <= start_pos:
            break
        cleaned = text.rstrip("\r\n")
        if cleaned:
            messages.append(cleaned)
    return messages


def encode_control_messages(
    messages: Sequence[str],
    *,
    b_open: bool = False,
    b_close: bool = False,
    b_reliable: bool = True,
) -> OutBunch:
    """
    Encode one or more text control messages into a single Channel 0 `OutBunch`.
    Callers sending many lines (e.g. 27 USES lines) should prefer one `OutBunch`
    per line via `UE2ConnectionState.queue_control_message()` so `flush()` packs
    them cleanly without exceeding UE2.5's 512-byte single-bunch MTU limit.
    """
    bunch = OutBunch(
        ch_index=0,
        ch_type=CHTYPE_CONTROL,
        b_open=b_open,
        b_close=b_close,
        b_reliable=b_reliable,
    )
    for msg in messages:
        bunch.write_fstring(msg)
    return bunch


# ---------------------------------------------------------------------------
# Control Text Parsers & Formatters (Engine.dll exact text syntax)
# ---------------------------------------------------------------------------

def parse_control_command(line: str) -> Tuple[str, str]:
    """Split a control message into `(COMMAND_UPPER, rest_stripped)`."""
    stripped = line.strip()
    if not stripped:
        return ("", "")
    parts = stripped.split(None, 1)
    cmd = parts[0].upper()
    rest = parts[1].strip() if len(parts) > 1 else ""
    return (cmd, rest)


def parse_kv_params(text: str) -> Dict[str, str]:
    """
    Parse UE2 `KEY=VALUE` parameters (case-insensitive keys returned uppercase).
    Matches UE2 `Parse(Stream, Key, Val)` for space-delimited and quoted values.
    """
    params: Dict[str, str] = {}
    for match in _KV_PATTERN.finditer(text):
        key = match.group(1).upper()
        val = match.group(2) if match.group(2) is not None else (match.group(3) or "")
        params[key] = val
    return params


def _safe_int(val: Optional[str], default: Optional[int] = None) -> Optional[int]:
    if val is None or val == "":
        return default
    try:
        return int(val, 0)
    except ValueError:
        try:
            return int(float(val))
        except ValueError:
            return default


def parse_ue2_url(url: str) -> ParsedLoginURL:
    """
    Parse a UE2 client Browse/Login URL such as:
      `127.0.0.1:7777/Index.ut2?Session=42427321?mapid=1?Name=Hentai?RoleID=1?Class=KFXPawns.KFXPlayerFemale1Blue?Character=zjpwxh?Team=0`
    or relative forms like `/Index.ut2?Name=Foo?Team=1` or `?Name=Foo?Team=0`.
    """
    raw = url.strip()
    if len(raw) >= 2 and raw[0] == '"' and raw[-1] == '"':
        raw = raw[1:-1]

    if "?" in raw:
        map_part, query_part = raw.split("?", 1)
        # UE2 uses '?' as the option delimiter; also tolerate '&' from custom callers
        raw_tokens = re.split(r"[?&]", query_part)
    else:
        map_part = raw
        raw_tokens = []

    options: Dict[str, str] = {}
    for token in raw_tokens:
        tok = token.strip()
        if not tok:
            continue
        if "=" in tok:
            k, v = tok.split("=", 1)
            key = k.strip().lower()
            if key:
                options[key] = unquote(v.strip())
        else:
            options[tok.lower()] = "1"

    session_raw = options.get("session")
    session_int = _safe_int(session_raw, None)
    map_id = _safe_int(options.get("mapid"), None)
    name = options.get("name", "").strip() or "Player"
    team = _safe_int(options.get("team"), None)
    role_id = _safe_int(options.get("roleid"), None)
    player_class = options.get("class", "").strip()
    character = options.get("character", "").strip()
    password = options.get("password", "")
    spec_raw = options.get("spectatoronly", "").strip().lower()
    spectator_only = spec_raw in ("1", "true", "yes")
    voice = options.get("voice", "").strip()
    sex = options.get("sex", "").strip()

    return ParsedLoginURL(
        raw_url=raw,
        map_part=map_part.strip(),
        options=options,
        session=session_int,
        session_raw=session_raw,
        map_id=map_id,
        name=name,
        team=team,
        role_id=role_id,
        player_class=player_class,
        character=character,
        password=password,
        spectator_only=spectator_only,
        voice=voice,
        sex=sex,
    )


def parse_login_line(rest: str) -> Tuple[Optional[int], str]:
    """
    Parse `RESPONSE=<int32> URL=<url>` from a C2S `LOGIN` line.
    Extracts `URL=` up to end-of-line so URLs containing spaces are preserved.
    """
    resp_match = re.search(r"\bRESPONSE\s*=\s*([+-]?\d+)", rest, re.IGNORECASE)
    response_val = _safe_int(resp_match.group(1), None) if resp_match else None

    url_match = re.search(r"\bURL\s*=\s*(.*)$", rest, re.IGNORECASE)
    url_val = url_match.group(1).strip() if url_match else ""
    if len(url_val) >= 2 and url_val[0] == '"' and url_val[-1] == '"':
        url_val = url_val[1:-1]
    return (response_val, url_val)


# -- Exact S2C / C2S Message Formatters -------------------------------------

def format_hello(
    revision: int = 0,
    minver: int = ENGINE_MIN_NET_VERSION,
    ver: int = ENGINE_VERSION,
) -> str:
    return f"HELLO REVISION={int(revision)} MINVER={int(minver)} VER={int(ver)}"


def format_challenge(
    challenge: int,
    *,
    ver: int = ENGINE_VERSION,
    stats: int = 0,
    sec: int = 0,
    gz: int = 0,
) -> str:
    return (
        f"CHALLENGE VER={int(ver)} CHALLENGE={int(challenge)} "
        f"STATS={int(stats)} SEC={int(sec)} GZ={int(gz)}"
    )


def format_uses(
    guid: str,
    pkg: str,
    flags: int,
    size: int,
    gen: int,
    fname: str,
) -> str:
    return (
        f"USES GUID={guid.upper()} PKG={pkg} FLAGS={int(flags)} "
        f"SIZE={int(size)} GEN={int(gen)} FNAME={fname}"
    )


def format_welcome(
    level: str,
    *,
    lone: int = 0,
    challenge: int = 0,
    game: str = DEFAULT_GAME_CLASS,
) -> str:
    clean_level = os.path.splitext(os.path.basename(level))[0] if level else "DF-DiTieZhan"
    if game:
        return (
            f"WELCOME LEVEL={clean_level} LONE={int(lone)} "
            f"CHALLENGE={int(challenge)} GAME={game}"
        )
    return f"WELCOME LEVEL={clean_level} LONE={int(lone)} CHALLENGE={int(challenge)}"


def format_userflag(flag: int) -> str:
    return f"USERFLAG {int(flag)}"


def format_upgrade(
    minver: int = ENGINE_MIN_NET_VERSION,
    ver: int = ENGINE_VERSION,
) -> str:
    return f"UPGRADE MINVER={int(minver)} VER={int(ver)}"


def format_failure(message: str) -> str:
    return f"FAILURE {message}" if message else "FAILURE"


def format_failcode(code: str) -> str:
    return f"FAILCODE {code}" if code else "FAILCODE"


def format_dlmgr(cls: str, params: str = "", compression: int = 0) -> str:
    return f"DLMGR CLASS={cls} PARAMS={params} COMPRESSION={int(compression)}"


def format_netspeed(rate: int) -> str:
    return f"NETSPEED {int(rate)}"


def format_auth(
    cdkey_hash: str = "",
    gm: str = "",
    username: str = "",
    password: str = "",
) -> str:
    return f"AUTH HASH={cdkey_hash} GM={gm} USERNAME={username} PASSWORD={password}"


def format_login(response: int, url: str) -> str:
    return f"LOGIN RESPONSE={int(response)} URL={url}"


def format_join() -> str:
    return "JOIN"


# ---------------------------------------------------------------------------
# Realm Roster Binding Helper
# ---------------------------------------------------------------------------

def _entry_get(entry: Any, *keys: str, default: Any = None) -> Any:
    """Read a field from either a dict or an attribute-bearing object."""
    if isinstance(entry, dict):
        for k in keys:
            if k in entry and entry[k] is not None:
                return entry[k]
        return default
    for k in keys:
        val = getattr(entry, k, None)
        if val is not None:
            return val
    return default


def bind_player_to_roster(
    parsed_url: ParsedLoginURL,
    roster: Optional[Iterable[Any]] = None,
    *,
    claimed_role_ids: Optional[Set[int]] = None,
    default_role_id: int = 1,
) -> BoundPlayerInfo:
    """
    Bind a connecting UE2 client (from `LOGIN URL=...`) to the Realm room roster.

    Matching priority (per CSO Malaysia `KFXGUIController.InRoomState.GameStartCommond`):
      1. `?Session=<nCookie>` matching roster `session_cookie` / `cookie` / `session`
      2. `?RoleID=<id>` matching an unclaimed roster `role_id`
      3. `?Name=<name>` (case-insensitive) matching an unclaimed roster `role_name` / `name`
      4. Direct URL fallback (for standalone CLI smoke launches like `?Name=Hentai?Team=0`)
    """
    claimed = claimed_role_ids if claimed_role_ids is not None else set()
    entries = list(roster) if roster is not None else []

    matched_entry: Any = None
    matched_by = "fallback"

    # 1. Primary: match by ?Session=<nCookie>
    if parsed_url.session is not None:
        for entry in entries:
            entry_sess = _safe_int(
                str(_entry_get(entry, "session_cookie", "cookie", "session", default="")),
                None,
            )
            if entry_sess is not None and entry_sess == parsed_url.session:
                matched_entry = entry
                matched_by = "session"
                break

    # 2. Secondary: match by ?RoleID=<id> (prefer unclaimed entries)
    if matched_entry is None and parsed_url.role_id is not None:
        fallback_match = None
        for entry in entries:
            entry_rid = _safe_int(str(_entry_get(entry, "role_id", "id", default="")), None)
            if entry_rid is not None and entry_rid == parsed_url.role_id:
                if entry_rid not in claimed:
                    matched_entry = entry
                    matched_by = "role_id"
                    break
                if fallback_match is None:
                    fallback_match = entry
        if matched_entry is None and fallback_match is not None:
            matched_entry = fallback_match
            matched_by = "role_id"

    # 3. Tertiary: match by ?Name=<name> (case-insensitive, prefer unclaimed entries)
    if matched_entry is None and parsed_url.name:
        target_name = parsed_url.name.strip().lower()
        fallback_match = None
        for entry in entries:
            entry_name = str(_entry_get(entry, "role_name", "name", default="")).strip()
            entry_rid = _safe_int(str(_entry_get(entry, "role_id", "id", default="")), None)
            if entry_name and entry_name.lower() == target_name:
                if entry_rid is None or entry_rid not in claimed:
                    matched_entry = entry
                    matched_by = "name"
                    break
                if fallback_match is None:
                    fallback_match = entry
        if matched_entry is None and fallback_match is not None:
            matched_entry = fallback_match
            matched_by = "name"

    if matched_entry is not None:
        rid = _safe_int(
            str(_entry_get(matched_entry, "role_id", "id", default=default_role_id)),
            default_role_id,
        )
        assert rid is not None
        name = str(_entry_get(matched_entry, "role_name", "name", default=parsed_url.name))
        team_raw = _entry_get(matched_entry, "team_id", "team", default=None)
        if team_raw is not None:
            team_id = int(team_raw)
        elif parsed_url.team is not None and parsed_url.team in (0, 1):
            team_id = parsed_url.team
        else:
            team_id = 0

        sess_val = _safe_int(
            str(_entry_get(matched_entry, "session_cookie", "cookie", "session", default="")),
            parsed_url.session,
        )
        loadout_val = _entry_get(matched_entry, "loadout", default={})
        if not isinstance(loadout_val, dict):
            loadout_val = {}

        return BoundPlayerInfo(
            role_id=rid,
            name=name or parsed_url.name,
            team_id=team_id,
            session_cookie=sess_val,
            body_type=int(_entry_get(matched_entry, "body_type", default=1)),
            head_type=int(_entry_get(matched_entry, "head_type", default=0)),
            coat_type=int(_entry_get(matched_entry, "coat_type", default=0)),
            trousers_type=int(_entry_get(matched_entry, "trousers_type", default=0)),
            major_weapon_id=int(_entry_get(matched_entry, "major_weapon_id", default=65537)),
            loadout=dict(loadout_val),
            player_class=parsed_url.player_class,
            character=parsed_url.character,
            spectator_only=parsed_url.spectator_only,
            matched_by=matched_by,
            roster_entry=matched_entry,
        )

    # 4. Direct URL fallback (e.g. CLI smoke test without pre-registered Realm roster)
    rid = parsed_url.role_id if parsed_url.role_id is not None else default_role_id
    while rid in claimed:
        rid += 1
    team_id = parsed_url.team if (parsed_url.team is not None and parsed_url.team in (0, 1)) else 0
    return BoundPlayerInfo(
        role_id=rid,
        name=parsed_url.name or f"Player{rid}",
        team_id=team_id,
        session_cookie=parsed_url.session,
        player_class=parsed_url.player_class,
        character=parsed_url.character,
        spectator_only=parsed_url.spectator_only,
        matched_by="fallback",
        roster_entry=None,
    )


# ---------------------------------------------------------------------------
# Control Channel State Machine (Per-Client Channel 0 Handler)
# ---------------------------------------------------------------------------

class ControlChannelHandler:
    """
    Per-client UE2.5 Control Channel (Channel 0, `CHTYPE_Control`) state machine.

    Lifecycle:
      1. Client connects & sends `HELLO REVISION=0 MINVER=3180 VER=3369`
         -> Server sends `CHALLENGE VER=3369 CHALLENGE=<int32> STATS=0 SEC=0 GZ=0`
      2. Client sends `AUTH ...`, `NETSPEED <rate>`, `LOGIN RESPONSE=<int32> URL=<url>`
         -> Server parses URL, binds player to Realm roster, invokes optional `on_login`,
            then sends all `USES` lines from `PackageMap` + `WELCOME LEVEL=... LONE=0 CHALLENGE=... GAME=...`
      3. Client verifies packages, loads map, and sends `JOIN`
         -> Server transitions to `ControlState.JOINED` and invokes `on_join(self)`
            to spawn Actor channels (`KFX*Player`, `GRI`, `TeamInfo`, `PRI`, `KFXPawn`, `KFXWeapon`).
    """

    def __init__(
        self,
        conn: UE2ConnectionState,
        package_map: Optional[PackageMap] = None,
        *,
        map_name: Optional[str] = None,
        game_class: str = DEFAULT_GAME_CLASS,
        uses_lines: Optional[Sequence[str]] = None,
        roster: Optional[Iterable[Any]] = None,
        claimed_role_ids: Optional[Set[int]] = None,
        challenge: Optional[int] = None,
        strict_challenge: bool = False,
        min_net_version: int = ENGINE_MIN_NET_VERSION,
        engine_version: int = ENGINE_VERSION,
        on_login: Optional[
            Callable[["ControlChannelHandler", ParsedLoginURL, BoundPlayerInfo], Any]
        ] = None,
        on_join: Optional[Callable[["ControlChannelHandler"], Any]] = None,
        on_disconnect: Optional[Callable[["ControlChannelHandler", str], Any]] = None,
        on_netspeed: Optional[Callable[["ControlChannelHandler", int], Any]] = None,
        client_addr: Optional[Tuple[str, int]] = None,
    ) -> None:
        self.conn: UE2ConnectionState = conn
        self.package_map: Optional[PackageMap] = package_map
        self.client_addr: Optional[Tuple[str, int]] = client_addr

        resolved_map = map_name
        if not resolved_map and package_map is not None:
            resolved_map = getattr(package_map, "map_name", None)
        self.map_name: str = (
            os.path.splitext(os.path.basename(resolved_map))[0]
            if resolved_map
            else "DF-DiTieZhan"
        )
        self.game_class: str = game_class or DEFAULT_GAME_CLASS
        self._explicit_uses_lines: Optional[List[str]] = (
            list(uses_lines) if uses_lines is not None else None
        )

        self.roster: Optional[Iterable[Any]] = roster
        self.claimed_role_ids: Set[int] = (
            claimed_role_ids if claimed_role_ids is not None else set()
        )

        # Signed 32-bit non-zero challenge value
        if challenge is not None:
            self.challenge: int = int(challenge)
        else:
            self.challenge = random.randint(1, 0x7FFFFFFF)
        self.strict_challenge: bool = strict_challenge
        self.min_net_version: int = int(min_net_version)
        self.engine_version: int = int(engine_version)

        # Callbacks
        self.on_login = on_login
        self.on_join = on_join
        self.on_disconnect = on_disconnect
        self.on_netspeed = on_netspeed

        # Handshake & connection attributes
        self.state: ControlState = ControlState.INIT
        self.client_revision: int = 0
        self.client_minver: int = 0
        self.client_ver: int = 0
        self.challenge_response_received: Optional[int] = None
        self.challenge_verified: bool = False
        self.netspeed: int = DEFAULT_NETSPEED
        self.auth_hash: str = ""
        self.auth_gm: str = ""
        self.auth_username: str = ""
        self.login_url: Optional[ParsedLoginURL] = None
        self.player: Optional[BoundPlayerInfo] = None
        self.disconnect_reason: str = ""
        self.user_flag: int = 0

        # Message audit trails (helpful for logging, debugging, and unit tests)
        self.received_messages: List[str] = []
        self.sent_messages: List[str] = []

    # -- State properties ---------------------------------------------------

    @property
    def is_joined(self) -> bool:
        return self.state == ControlState.JOINED

    @property
    def is_disconnected(self) -> bool:
        return self.state == ControlState.DISCONNECTED

    def get_uses_lines(self) -> List[str]:
        """Return exact S2C `USES` lines from explicit override or `PackageMap`."""
        if self._explicit_uses_lines is not None:
            return list(self._explicit_uses_lines)
        if self.package_map is not None:
            return list(self.package_map.uses_lines())
        return []

    # -- Outgoing S2C Control Helpers ---------------------------------------

    def send_text(self, text: str, *, b_close: bool = False) -> OutBunch:
        """Queue a single reliable Channel 0 (`CHTYPE_CONTROL`) FString bunch."""
        self.sent_messages.append(text)
        log.debug("S2C [%s] CTRL: %s", self.client_addr, text)
        return self.conn.queue_control_message(text, b_open=False, b_close=b_close)

    def send_challenge(self) -> OutBunch:
        line = format_challenge(
            self.challenge,
            ver=self.engine_version,
            stats=0,
            sec=0,
            gz=0,
        )
        return self.send_text(line)

    def send_uses_and_welcome(self) -> List[OutBunch]:
        bunches: List[OutBunch] = []
        for uses_line in self.get_uses_lines():
            bunches.append(self.send_text(uses_line))
        welcome_line = format_welcome(
            self.map_name,
            lone=0,
            challenge=self.challenge,
            game=self.game_class,
        )
        bunches.append(self.send_text(welcome_line))
        return bunches

    def send_userflag(self, flag: int) -> OutBunch:
        self.user_flag = int(flag)
        return self.send_text(format_userflag(self.user_flag))

    def send_upgrade(
        self,
        minver: Optional[int] = None,
        ver: Optional[int] = None,
    ) -> OutBunch:
        mv = self.min_net_version if minver is None else int(minver)
        v = self.engine_version if ver is None else int(ver)
        return self.send_text(format_upgrade(minver=mv, ver=v), b_close=True)

    def send_failure(self, reason: str, *, close: bool = True) -> OutBunch:
        bunch = self.send_text(format_failure(reason), b_close=close)
        if close:
            self._transition_disconnected(reason or "failure")
        return bunch

    def send_failcode(self, code: str, *, close: bool = True) -> OutBunch:
        bunch = self.send_text(format_failcode(code), b_close=close)
        if close:
            self._transition_disconnected(code or "failcode")
        return bunch

    def send_disconnect(self, reason: str = "Server disconnect") -> None:
        if not self.is_disconnected:
            self.send_failure(reason, close=True)

    # -- Incoming C2S Entrypoints -------------------------------------------

    def handle_bunch(self, bunch: InBunch) -> List[str]:
        """
        Process an incoming Channel 0 (`CHTYPE_CONTROL`) `InBunch`.
        Decodes all back-to-back FStrings, dispatches each message, and handles
        channel close (`bunch.b_close`). Returns the list of decoded lines.
        """
        if bunch.ch_index != 0 and bunch.ch_type != CHTYPE_CONTROL:
            log.warning(
                "ControlChannelHandler received non-control bunch: ch=%d type=%d",
                bunch.ch_index,
                bunch.ch_type,
            )
            return []

        messages = decode_control_bunch(bunch)
        for line in messages:
            self.handle_message(line)
            if self.is_disconnected:
                break

        if bunch.b_close and not self.is_disconnected:
            log.info("C2S [%s] Control channel closed by peer (bClose=1)", self.client_addr)
            self._transition_disconnected("channel_closed")

        return messages

    def handle_message(self, line: str) -> None:
        """Dispatch a single decoded C2S control message string."""
        cleaned = line.strip()
        if not cleaned:
            return
        self.received_messages.append(cleaned)
        log.debug("C2S [%s] CTRL: %s", self.client_addr, cleaned)

        if self.is_disconnected:
            return

        cmd, rest = parse_control_command(cleaned)

        if cmd == "HELLO":
            self._on_hello(rest)
        elif cmd == "AUTH":
            self._on_auth(rest)
        elif cmd == "NETSPEED":
            self._on_netspeed(rest)
        elif cmd == "LOGIN":
            self._on_login(rest)
        elif cmd == "JOIN":
            self._on_join(rest)
        elif cmd == "SKIP":
            self._on_skip(rest)
        elif cmd == "DLMGR":
            self._on_dlmgr(rest)
        elif cmd in ("FAILURE", "FAILCODE"):
            self._on_failure(cmd, rest)
        elif cmd == "DISCONNECT":
            self._on_disconnect_cmd(rest)
        else:
            log.debug("C2S [%s] Ignoring unrecognized control message: %r", self.client_addr, cleaned)

    # -- Individual C2S Command Handlers ------------------------------------

    def _on_hello(self, rest: str) -> None:
        params = parse_kv_params(rest)
        self.client_revision = _safe_int(params.get("REVISION"), 0) or 0
        self.client_minver = _safe_int(params.get("MINVER"), 0) or 0
        self.client_ver = _safe_int(params.get("VER"), 0) or 0

        log.info(
            "C2S [%s] HELLO rev=%d minver=%d ver=%d",
            self.client_addr,
            self.client_revision,
            self.client_minver,
            self.client_ver,
        )

        # Reject incompatible older client builds with UPGRADE
        if self.client_ver > 0 and self.client_ver < self.min_net_version:
            log.warning(
                "C2S [%s] Client ver %d < min_net_version %d; sending UPGRADE",
                self.client_addr,
                self.client_ver,
                self.min_net_version,
            )
            self.send_upgrade()
            self._transition_disconnected(f"upgrade_required:{self.client_ver}")
            return

        # Re-sending CHALLENGE on duplicate HELLO while INIT/CHALLENGED is safe & idempotent
        if self.state in (ControlState.INIT, ControlState.CHALLENGED):
            self.state = ControlState.CHALLENGED
            self.send_challenge()

    def _on_auth(self, rest: str) -> None:
        params = parse_kv_params(rest)
        self.auth_hash = params.get("HASH", "")
        self.auth_gm = params.get("GM", "")
        self.auth_username = params.get("USERNAME", "")
        log.debug(
            "C2S [%s] AUTH hash=%s user=%s (accepted)",
            self.client_addr,
            self.auth_hash[:16],
            self.auth_username,
        )

    def _on_netspeed(self, rest: str) -> None:
        tok = rest.split()[0] if rest.split() else ""
        rate = _safe_int(tok, None)
        if rate is None:
            log.debug("C2S [%s] Invalid NETSPEED value: %r", self.client_addr, rest)
            return
        clamped = max(MIN_NETSPEED, min(MAX_NETSPEED, rate))
        self.netspeed = clamped
        log.debug("C2S [%s] NETSPEED=%d (raw=%d)", self.client_addr, clamped, rate)
        if self.on_netspeed is not None:
            self.on_netspeed(self, clamped)

    def _on_login(self, rest: str) -> None:
        if self.state in (ControlState.WELCOMED, ControlState.JOINED):
            log.debug("C2S [%s] Ignoring duplicate LOGIN in state %s", self.client_addr, self.state.value)
            return

        response_val, url_str = parse_login_line(rest)
        self.challenge_response_received = response_val

        expected = challenge_response(self.challenge)
        self.challenge_verified = (response_val is not None and response_val == expected)

        if not self.challenge_verified:
            if self.strict_challenge:
                log.warning(
                    "C2S [%s] LOGIN challenge mismatch: got=%s expected=%d",
                    self.client_addr,
                    response_val,
                    expected,
                )
                self.send_failure("Invalid challenge response", close=True)
                return
            log.debug(
                "C2S [%s] LOGIN challenge mismatch (non-strict, continuing): got=%s expected=%d",
                self.client_addr,
                response_val,
                expected,
            )

        parsed_url = parse_ue2_url(url_str)
        self.login_url = parsed_url

        bound = bind_player_to_roster(
            parsed_url,
            self.roster,
            claimed_role_ids=self.claimed_role_ids,
        )

        # Allow host/match manager to validate or customize the bound player
        if self.on_login is not None:
            decision = self.on_login(self, parsed_url, bound)
            if isinstance(decision, BoundPlayerInfo):
                bound = decision
            elif isinstance(decision, str) and decision:
                self.send_failure(decision, close=True)
                return
            elif isinstance(decision, tuple) and len(decision) >= 2 and not decision[0]:
                self.send_failure(str(decision[1] or "Login rejected"), close=True)
                return
            elif decision is False:
                self.send_failure("Login rejected", close=True)
                return

        self.player = bound
        self.claimed_role_ids.add(bound.role_id)

        log.info(
            "C2S [%s] LOGIN accepted: name=%r role_id=%d team=%d session=%s matched_by=%s challenge_ok=%s",
            self.client_addr,
            bound.name,
            bound.role_id,
            bound.team_id,
            bound.session_cookie,
            bound.matched_by,
            self.challenge_verified,
        )

        self.state = ControlState.WELCOMED
        self.send_uses_and_welcome()

    def _on_join(self, rest: str) -> None:
        if self.state == ControlState.JOINED:
            log.debug("C2S [%s] Ignoring duplicate JOIN", self.client_addr)
            return
        if self.state != ControlState.WELCOMED:
            log.warning(
                "C2S [%s] Received JOIN in unexpected state %s",
                self.client_addr,
                self.state.value,
            )
            if self.player is None:
                # Create a fallback player so late/out-of-order test harnesses still work
                self.player = BoundPlayerInfo(
                    role_id=1,
                    name="Player",
                    team_id=0,
                    matched_by="fallback",
                )

        self.state = ControlState.JOINED
        log.info(
            "C2S [%s] JOIN complete for player=%r (role_id=%s, team=%s)",
            self.client_addr,
            self.player.name if self.player else None,
            self.player.role_id if self.player else None,
            self.player.team_id if self.player else None,
        )
        if self.on_join is not None:
            self.on_join(self)

    def _on_skip(self, rest: str) -> None:
        log.debug("C2S [%s] SKIP %r (no-op)", self.client_addr, rest)

    def _on_dlmgr(self, rest: str) -> None:
        log.debug("C2S [%s] DLMGR %r (no-op)", self.client_addr, rest)

    def _on_failure(self, cmd: str, rest: str) -> None:
        reason = f"{cmd}: {rest}" if rest else cmd
        log.warning("C2S [%s] Client reported %s", self.client_addr, reason)
        self._transition_disconnected(reason)

    def _on_disconnect_cmd(self, rest: str) -> None:
        reason = rest or "client_disconnect"
        log.info("C2S [%s] Client sent DISCONNECT (%s)", self.client_addr, reason)
        self._transition_disconnected(reason)

    def _transition_disconnected(self, reason: str) -> None:
        if self.state == ControlState.DISCONNECTED:
            return
        self.state = ControlState.DISCONNECTED
        self.disconnect_reason = reason
        if self.player is not None:
            self.claimed_role_ids.discard(self.player.role_id)
        if self.on_disconnect is not None:
            self.on_disconnect(self, reason)


__all__ = [
    "DEFAULT_GAME_CLASS",
    "DEFAULT_NETSPEED",
    "MIN_NETSPEED",
    "MAX_NETSPEED",
    "GAME_MODE_TO_CLASS",
    "ControlState",
    "ParsedLoginURL",
    "BoundPlayerInfo",
    "decode_control_bunch",
    "encode_control_messages",
    "parse_control_command",
    "parse_kv_params",
    "parse_ue2_url",
    "parse_login_line",
    "format_hello",
    "format_challenge",
    "format_uses",
    "format_welcome",
    "format_userflag",
    "format_upgrade",
    "format_failure",
    "format_failcode",
    "format_dlmgr",
    "format_netspeed",
    "format_auth",
    "format_login",
    "format_join",
    "bind_player_to_roster",
    "ControlChannelHandler",
    "challenge_response",
]

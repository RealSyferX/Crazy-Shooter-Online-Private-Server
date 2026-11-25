# Crazy Shooter Online (CSO Malaysia) — Clean-Room Private Server

> **Authored by RealSyferX**

A complete, zero-dependency **Python 3** clean-room private server emulator for **Crazy Shooter Online (CSO Malaysia / Kingsoft KFX / Unreal Engine 2.5 build 3369)** — including **Bishop Login Gateway**, **Realm Lobby Server**, **HTTP Launcher API & Dashboard**, and a full **in-process UE2.5 Multiplayer UDP Match Server** with zero-wait movement sync, 3D hitscan combat, kills/deaths, respawns, and scoreboard persistence.

**No client binary modifications required** — works directly with the unmodified retail `CS.exe`.

---

## Highlights & Features

### 1. Bishop Login Gateway (`TCP 7451`)
- Exact 2-byte `KG_SocketStream` framing and 42-byte scrambled key handshake (`KFXClientNetwork.dll`).
- Static mode-0 `KSG_EncodeDecode_Simple` cipher using the 5,679-dword lookup table (`data/ksg_table.bin`) with 32-bit wrapping arithmetic.
- Uppercase MD5 password verification, optional auto-registration on first login, and `RealmListRespond (0xFA)` dispatch.

### 2. Realm Lobby Server (`TCP 7452`)
- Full session ticket binding, Male/Female character creation (`CreateRole` with starter outfits & weapons), channel switching, and live player lists.
- Room lifecycle: create, list, join / quick-join, password protection, map/mode/settings updates, team switching, ready state, host kick, host nomination, and late-join (`JoinStartGameRequest`).
- In-game **Shop & Gifting** (`KFXItem.csv`, GP & CSP currencies), **Equipment / Loadout** sync, **Channel / Room / Private / Broadcast Chat**, **Mail** (with item attachments), **Friends & Blacklist**, **Leaderboards**, and **Quests** (`KFXQuest.csv`).

### 3. Clean-Room UE2.5 Multiplayer UDP Match Server (`UDP 7777–7795`)
Because the retail CSO Malaysia client `Engine.dll` ships with `ULevel::Listen` stubbed out (`xor eax, eax; ret 4`), this project implements a full clean-room **UE2.5 build 3369 UDP match host** directly in Python (`server/ue2_server/`):
- **Control Channel (`CHTYPE_Control`)**: `HELLO -> CHALLENGE -> AUTH/NETSPEED/LOGIN -> 27 USES (real package GUIDs) -> WELCOME -> JOIN`.
- **Actor Replication (`CHTYPE_Actor`)**: `KFXTeamInfo`, `KFX*GameReplicationInfo`, `KFX*PlayerReplicationInfo`, `KFX*Player`, `KFXPawn`, `KFXWeapAttachment`, and `KFXWeap*` (all 5 game modes: Team Death, Death Match, Team Match, Bomb Match, Occupation Match).
- **Ultra-Fast Zero-Wait Sync (`< 5ms` LAN/loopback relay)**:
  - Event-driven immediate unreliable delta relay on every `ShortServerMove` / `ServerMove` / `DualServerMove` (no waiting for tick boundaries).
  - `100 Hz` drift-free simulation loop with Windows 1ms multimedia timer resolution (`timeBeginPeriod(1)`) and 1 MiB UDP kernel buffers.
  - Strict UE2 `ROLE_AutonomousProxy` isolation (never echoes stale movement props back to the owning client) + `ROLE_SimulatedProxy` upright body `(0, Yaw, 0)` with separate `ViewPitch`, `Physics=PHYS_Walking`, and `Base=LevelInfo0` for smooth 60+ FPS velocity extrapolation.
- **Retail Avatar, Collision & Weapon Fidelity**:
  - `PawnAttribute.csv` dimensions & physics (`DrawScale=0.85`, `CollisionHeight=92`, `CollisionRadius=55`, `GroundSpeed=520`, `AirSpeed=650`, `JumpZ=763`) so characters stand flush on floors.
  - Dynamic 62-weapon table from `WeaponAttribute.csv` + `WeaponClass.csv` (`KFXAccessory[0..6]`) so every 1st-person and 3rd-person weapon renders accurately.
  - Real `.ut2` `PlayerStart` spawn extraction across all 12 maps.
- **Authoritative Combat & Persistence**:
  - 3D ray-cylinder hitscan & melee registration (Head `4.0x`, Stomach `1.25x`, Chest `1.0x`, Legs `0.75x`, armor absorption, distance falloff, multi-pellet shotguns, grenade splash).
  - Kill feed (`KFXReceiveLocalizedMessage`), `PRI`/`TeamInfo` scoreboard sync, automatic respawn timers, match win detection, and automatic SQLite stat/GP/Honor persistence + `S2C 0x1E` push on match end.

### 4. HTTP Registration API & Live Dashboard (`TCP 8080`)
- Compatible with `CSO-Malaysia-Launcher-2.1.38.exe` (`/api/auth/register`, `/api/auth/registration-status`, `/api/news`) plus a live browser status dashboard at `http://127.0.0.1:8080/`.

---

## Requirements

- **Python 3.10+** (standard library only — zero third-party `pip` packages required)
- Retail **CSO Malaysia** game client installed (default path in `config.json`: `C:\Program Files (x86)\CSO Malaysia`)

---

## Quick Start (Windows)

1. **Extract client tables** *(already pre-extracted in `data\`; re-run only if your client path differs)*:
   ```powershell
   python tools\extract_client_data.py
   ```

2. **Start the private server**:
   Double-click `Start-Server.bat` or run:
   ```powershell
   python server\main.py
   ```
   Wait until you see:
   ```text
   CSG Local Private Server READY
     Bishop Gateway : 127.0.0.1:7451
     Realm Server   : 127.0.0.1:7452
     Web / API      : http://127.0.0.1:8080
   ```

3. **Launch the game client** *(supports multiple clients on the same PC or over LAN)*:
   Double-click `Play-Local.bat` or run:
   ```powershell
   .\Play-Local.bat 127.0.0.1 7451
   ```
   - With `"auto_register_on_login": true` in `config.json`, typing any new username & password at the login screen automatically creates the account and enters Character Creation.
   - Or register accounts via `http://127.0.0.1:8080/` or `tools\admin_cli.py`.

---

## Hosting on LAN / Internet

1. Open `config.json` and set `"public_ip"` to your LAN IP (e.g. `"192.168.1.50"`) or public IP.
2. Allow **TCP `7451`, `7452`, `8080`** and **UDP `7777–7795`** in Windows Firewall / router port forwarding.
3. Have players launch the client with:
   ```powershell
   .\Play-Local.bat <YOUR_SERVER_IP> 7451
   ```

---

## Admin CLI

```powershell
python tools\admin_cli.py create-account syferx mypass123 --gm
python tools\admin_cli.py list-accounts
python tools\admin_cli.py grant-currency SyferX --gp 1000000 --csp 50000
python tools\admin_cli.py grant-item SyferX 65541 --days 365
```

---

## Automated Verification Suites

Run both end-to-end suites (Bishop/Realm TCP protocol + live 2-player UDP UE2.5 multiplayer simulation):

```powershell
python tests\test_protocol.py
python tests\test_multiplayer_match.py
```

---

## Project Structure

```text
.
├── config.json                  # Server ports, public IP, channels, match_server settings (100Hz)
├── Start-Server.bat             # One-click Windows server launcher
├── Play-Local.bat               # One-click unmodified CS.exe client launcher
├── cso-server.local.ini         # Optional local server reference config
├── PROTOCOL.md                  # Reverse-engineered KFX TCP + UE2.5 UDP protocol specification
├── data/                        # Decoded client tables (maps, modes, items, levels, quests, ksg_table.bin)
├── server/
│   ├── main.py                  # Unified asyncio server entrypoint
│   ├── crypto.py                # 2-byte framing, 42-byte handshake, static mode-0 KSG cipher
│   ├── packets.py               # All Bishop & Realm binary packet codecs
│   ├── bishop.py                # Bishop Login Gateway (TCP 7451)
│   ├── realm.py                 # Realm Lobby Server (TCP 7452)
│   ├── database.py              # SQLite persistence (accounts, roles, inventory, mail, relations, stats)
│   ├── gamedata.py              # Decoded game data loader
│   ├── match_manager.py         # Match lifecycle & UDP port manager
│   ├── api_server.py            # Launcher HTTP JSON API & Web Dashboard (TCP 8080)
│   └── ue2_server/              # Clean-room UE2.5 build 3369 UDP Multiplayer Match Server
│       ├── bitstream.py         # BitReader/BitWriter, packet framing, reliable ACKs/retransmit
│       ├── packagemap.py        # Real .u/.ut2 Package GUIDs & FClassNetCache builder
│       ├── map_loader.py        # Real .ut2 PlayerStart spawn extractor
│       ├── control.py           # Channel 0 handshake (HELLO/CHALLENGE/LOGIN/USES/WELCOME/JOIN)
│       ├── replication.py       # Actor spawning, dirty delta replication, 62-weapon 3P table, RPC codec
│       ├── combat.py            # Authoritative movement, 3D hitscan, damage, kills, respawns, scoreboard
│       └── host.py              # 100Hz + zero-wait event-driven asyncio UDP match server
├── tools/
│   ├── extract_client_data.py   # Extracts KFX CSV tables & KSG cipher table from client files
│   └── admin_cli.py             # CLI account / currency / item management tool
└── tests/
    ├── test_protocol.py         # 9-suite E2E TCP Bishop/Realm & HTTP API test
    └── test_multiplayer_match.py# 6-suite live 2-player UDP UE2.5 match, latency & combat test
```

---

## Author & Credits

**Authored by RealSyferX**

*Built for educational, preservation, and private LAN playtesting of Crazy Shooter Online (CSO Malaysia).*
[Client](https://drive.google.com/file/d/1KcG0GSRxojy-YiwW4OC01iM4urEc8S3X/view?usp=sharing)

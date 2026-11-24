# CSO Malaysia (Kingsoft KFX UE2) — Reverse-Engineered Network & Data Protocol

> **Authored by RealSyferX**

All protocol structures, opcodes, cipher tables, and file formats below were recovered via static analysis (Ghidra 12.2 + REA) of the shipped client artifacts in `C:\Program Files (x86)\CSO Malaysia\`:

- `System\KFXClientNetwork.dll` — TCP framing, key handshake, and `KSG_EncodeDecode_Simple` cipher
- `System\KFXClient.dll` — `KFXBishopClient`, `KFXRealmClient`, `KFXClientNetLib`, and `UKFXNetGUIController`
- `System\KFXClient.u` & `System\KFXGUI.u` — UnrealScript struct layouts & native RPC signatures
- `System\KFXGame.dll` — `AKFXFaeryAgent` and UE2 match server mode
- `CSO-Malaysia-Launcher-2.1.38.exe` — Launcher HTTP JSON API contracts

---

## 1. Transport Layer (`KFXClientNetwork.dll`)

### 1.1 TCP Framing (`KG_SocketStream`, `0x100025f0` / `0x10002670`)
Every TCP packet (both unencrypted handshake and encrypted game packets) is framed as:

```
+-------------------+-------------------------------+
| uint16_le wireLen | payload[wireLen - 2]          |
+-------------------+-------------------------------+
```

- `wireLen = len(payload) + 2`
- Maximum payload length: `< 0xFFDC` (`65500` bytes).

### 1.2 Initial Handshake (`0x10001090` -> `0x10002ec0` -> `0x10002f57`)
Immediately after TCP `accept()` on either Bishop (`7451`) or Realm (`7452`), the server sends a **42-byte (`0x2A`) unencrypted payload** (44 bytes on wire with `wireLen = 44`):

| Offset | Size | Value / Field |
|--------|------|---------------|
| `0x00` | `1` | `0x20` (handshake marker) |
| `0x01` | `1` | `0x00` |
| `0x08` | `4` | `uint32_le(scramble_u32(client_send_key))` — client stores at `this+0x0C` (C2S key) |
| `0x11` | `4` | `uint32_le(scramble_u32(client_recv_key))` — client stores at `this+0x10` (S2C key) |

Client unscramble (`0x10002f57`):
```python
ecx = (~(((v ^ 0x006D23CF) - 0x006D2399) & 0xFFFFFFFF)) & 0x00FFFF00
ebx = ((~(((v ^ 0x2E6D23CF) - 0x2E6D2399) & 0xFFFFFFFF)) & 0xFFFFFFFF) >> 24
edx = ((~(((v ^ 0xFFFFFFCF) + 0x67) & 0xFFFFFFFF)) & 0xFFFFFFFF) << 24
key = (ecx | ebx | edx) & 0xFFFFFFFF
```

### 1.3 Packet Cipher (`0x10003610` -> `FUN_10003580`, `KSG_EncodeDecode_Simple`, mode `0`)
Symmetric XOR cipher using the **5,679-dword** (`0x1000B93C = 5679`) lookup table located in `KFXClientNetwork.dll` at VA `0x10006080` (file offset `0x6080`, 22,716 bytes):

```python
u = seed & 0xFFFFFFFF
dwords = len(buf) >> 2
rem = len(buf) & 3
off = 0
while dwords:
    dwords -= 1
    u = (TABLE[((u + dwords) & 0xFFFFFFFF) % 5679] + 0x2E6D23C1) & 0xFFFFFFFF
    buf[off:off+4] ^= u32_le(u)
    off += 4
u = (u ^ TABLE[rem % 5679]) & 0xFFFFFFFF
for _ in range(rem):
    buf[off] ^= (u & 0xFF)
    off += 1
    u >>= 8
```

- **IMPORTANT (Static Keys in Mode 0):** `CreateSocketStreamPool::Connect` (`0x10001090`) always passes `mode = 0`, which binds both `pfnEncode` (`this+0x14`) and `pfnDecode` (`this+0x18`) to wrapper `0x10003610`. That wrapper copies `*puKey` **by value** into a temporary stack slot before calling `0x10003580`, so `0x10003580`'s internal `seed * 0x1F + 0x8088405` write is discarded on return.
- Consequently, **`client_send_key` and `client_recv_key` are STATIC across every packet on a connection** (both Bishop `7451` and Realm `7452`) — do **NOT** roll keys per packet!
- `(u + dwords)` is a **32-bit unsigned wrapping addition** (`lea eax, [ecx + esi]` before `div 5679`).
- Client encodes C2S with static `client_send_key`, decodes S2C with static `client_recv_key`.
- Server decodes C2S with static `client_send_key`, encodes S2C with static `client_recv_key`.

---

## 2. Bishop Login Gateway Protocol (TCP `7451`)

### C2S `0x00` — `LoginGatewayRequest` (`137` bytes)
| Offset | Type | Field |
|--------|------|-------|
| `0x00` | `u8` | `0x00` |
| `0x01` | `char[32]` | `username` (UTF-8, NUL-terminated) |
| `0x21` | `char[64]` | `UPPERCASE_MD5_HEX(password)` (`FUN_10729590`) |
| `0x61` | `char[32]` | `activate_code` |
| `0x81` | `u32` | `param4` (`0`) |
| `0x85` | `u32` | `param5` (`2`) |

### S2C `0x01` — `LoginGatewayRespond` (`45` bytes)
| Offset | Type | Field |
|--------|------|-------|
| `0x00` | `u8` | `0x01` |
| `0x01` | `i32` | `result` (`1` = success; non-1 = error) |
| `0x21` | `i32` | `cookie` (stored at `UKFXNetGUIController+0x3F4`) |
| `0x25` | `i32` | `role_id` (stored at `UKFXNetGUIController+0x3F8`) |
| `0x29` | `i32` | `has_role` (`0` -> sets `bCreateRole=True`; `1` -> sets `bCreateRole=False`) |

### S2C `0xFA` — `KFXBishopClient::RealmListRespond`
| Offset | Type | Field |
|--------|------|-------|
| `0x00` | `u8` | `0xFA` |
| `0x01` | `u32` | reserved (`0`) |
| `0x05` | `u16` | `count` |
| `0x07` | `40B * count` | `[u8 id, u8 work_state, u16_be port, 4B ip_net, char[32] name]` |

---

## 3. Realm Server Protocol (TCP `7452`)

Note on `LoginRealmRequest` (`0x03`) and `HideLoginRealmRequest` (`0x00`):
`UKFXNetGUIController::execLoginRealm` passes `(cookie, role_id)`, which `FUN_10720f10` / `FUN_10720d10` pack as `offset +0x01 = role_id` and `offset +0x05 = cookie`.

### 3.1 C2S Opcodes Summary
| Op | Name | Size | Key Fields |
|----|------|------|------------|
| `0x00` | `HideLoginRealmRequest` | `9B` | `u32 role_id, u32 cookie` (when `bCreateRole=True`) |
| `0x01` | `TrainLoginRealmRequest` | `9B` | `u32 role_id, u32 cookie` |
| `0x02` | `CreateNewRoleRequest` | `49B` | `char name[32], u32 body (PawnList.csv RoleID: 1=Male, 2=Female), u32 head, u32 coat, u32 trousers` |
| `0x03` | `LoginRealmRequest` | `43B` | `u32 role_id, u32 cookie, u8 p3, u8 p4, char p5[32]` |
| `0x04` | `ChannelListRequest` | `1B` | — |
| `0x05` | `SelectChannelRequest` | `2B` | `u8 channel_id` |
| `0x06` | `LeaveChannelRequest` | `1B` | — |
| `0x07` | `RoomListRequest` | `1B` | — |
| `0x08` | `ChannelPlayerListRequest` | `1B` | — |
| `0x09` | `CreateRoomRequest` | `87B` | `name[32], pass[32], mode, map, rand, maxP, joinInGame(u8), isFaction(u8), weaponLimit` |
| `0x0A` | `SetRoomInfoRequest` | `109B` | Room settings block matching `CurrentRoomInfoRespond` |
| `0x0B` | `JoinRoomRequest` | `37B` | `u32 room_id, char password[32]` (`room_id=0` for quick join) |
| `0x0C` | `LeaveRoomRequest` | `1B` | — |
| `0x0D` | `RoomPlayerRequest` | `1B` | — |
| `0x0E` | `SelectOneTeamRequest` | `5B` | `i32 team_id` |
| `0x0F` | `ReadyGameRequest` | `5B` | `i32 ready_flag` |
| `0x10` | `StartGameRequest` | `1B` | Host launches match |
| `0x11` | `JoinStartGameRequest` | `1B` | Join in-progress match |
| `0x12` | `ChannelChatRequest` | var | `u32 len, char msg[len]` |
| `0x13` | `RoomChatRequest` | var | `u32 len, char msg[len]` |
| `0x14` | `PersonalChatUseNameRequest` | var | `char dst[32], u32 len, char msg[len]` |
| `0x15` | `PersonalChatUseRoleIDRequest` | var | `u32 dst_id, u32 len, char msg[len]` |
| `0x16` | `GetItemListRequest` | `1B` | — |
| `0x17` | `SetUsingItemListRequest` | `181B` | 45 `i32` inventory indices (`head, coat, trousers, major[5], minor[5], grenade[5], knife[5], armor, shoes, baggage[20]`) |
| `0x19` | `OneRoleFullInfoRequest` | `5B` | `u32 role_id` |
| `0x1A`/`0x34` | `WorldRole/FactionOrderRequest` | `1B` | Rankings |
| `0x1B` | `PlayerBuyItemRequest` | `13B` | `i32 item_type, i32 item_time, i32 buy_type` (`0`=CSP, `1`=GP) |
| `0x1D`/`0x1E` | `FindPlayer/FindRoomRequest` | `33B`/`5B` | Search online player/room |
| `0x21`..`0x25` | Email requests | var | List, Content, Send, TakeOutItem, Delete |
| `0x26`..`0x28`, `0x35` | Relation & Faction requests | var | List, Add (`0`=Friend, `1`=Blacklist), Delete |
| `0x29` | `PlayerLeaveGameRequest` | `1B` | Return from UE2 match to room |
| `0x2B` | `PresentItemRequest` | var | `i32 item_type, i32 item_time, char recv[32], i32 buy_type, i32 len, char msg[len]` |
| `0x2D` | `PublicChat` / `GroupChat` | var | `u32 chat_type, u32 len, char msg[len]` |
| `0x2E`/`0x2F` | `KickOther` / `NominateOwner` | `5B` | `u32 target_role_id` |
| `0x30`..`0x32` | Quest/Task requests | var | FinishTask, QuestTask, QuestBonus |

### 3.2 Key S2C Opcodes Summary
- `0x00` `HideLoginRealmRespond`, `0x01` `TrainLoginRealmRespond`, `0x02` `CreateRoleRespond` (`u8 op, u32 res`)
- `0x03` `LoginRealmRespond` (`41B`: `op, u32 res, u32 has_channel, char channel_name[32]` — `has_channel=0` on normal login so `m_sCurChannelName` is not overwritten)
- `0x04` `ChannelListRespond` (`5 + N*41B`)
- `0x05` `JoinChannelRespond` (`285B`: full `KFXRoleInfo` including `nCurBodyType` `1`/`2` @ `+0x89`, `MoneyPoint` [CSP] @ `+0x115`, `GameCash` [GP] @ `+0x119`)
- `0x07` `RoomListRespond` (`5 + N*53B`; `nRoomState`: `2`=waiting, `3`=full, `4`=playing)
- `0x08` `ChannelPlayerListRespond` (`5 + N*46B`; excludes self since `m_sChannelPlayerList[0]` is self)
- `0x09` `CreateRoomRespond` (`9B`; followed by `0x0B` + `0x0E`), `0x0B` `CurrentRoomInfoRespond` (`109B`), `0x0C` `JoinRoomRespond` (`113B`)
- `0x0E` `RoomPlayerListRespond` (`5 + N*152B`; follow with `0x14` for ready players), `0x0F` `SomeOneJionRoomRespond` (`153B`)
- `0x15` `GameStartCommond` (`11B`: `u8 0x15, u32 result [MUST be 1], 4B ip_net, u16_be udp_port`)
- `0x16` `ChatContentRespond` (`+0x01=chat_type, +0x05=role_id`), `0x18` `GetItemListRespond` (`0x2E5 + N*16B`; `nItemLeftDays` = seconds / uses / `-1` permanent; `nItemGetType=0` = Default), `0x1C` `GetWorldRoleOrderRespond` (`+0x20=honor_point, +0x24=level`), `0x1D` `PlayerBuyItemRespond` (`29B`), `0x1E` `GameEndAndUpdataRoleInfoRespond` (`169B`: `+0x21=game_cash, +0x25=level, +0x29=honor_place, +0x2D=honor_point`)
- `0x21` `FindPlayerRespond` (`175B`), `0x22` `FindRoomRespond` (`76B`), `0x24` `SomeoneInviteMeRespond` (`47B`)
- `0x26` `EmailInfoListRespond`, `0x27` `EmailContentRespond` (`+0x2D=nExpend`), `0x29` `TakeOutItemResultRespond` (`+0x09=item_id, +0x0D=item_type`)
- `0x2B` `RelationListRespond` / `0x2C` `AddRelationResultRespond` (`52B` entry: `nRelation [0=Friend, 1=Blacklist], nRoleID, nFactionID, name[32], nFactionIconID, u16 level, u16 state`), `0x2D` `DeleteRelationResultRespond` (`+0x05=deleted_role_id`)
- `0x33` `SystemAnnounceRespond`, `0x36` `SomeOneKickedRespond`, `0x37` `SomeOneNominatedRoomOwnerRespond`, `0x3C` `PlayerQuestTaskRespond`, `0x3D` `PlayerQuestBonusRespond` (`33B`: `8*u32`)

---

## 4. Client Asset Obfuscation & UE2 Match Server

- **`KFXArchive` `.u` / `.ini` files:** 50-byte header starting with `KFXArchive`, followed by payload XORed with `0x9D`.
- **`KFX` `.csv` files:** 3-byte header `KFX`, followed by CSV text XORed with `0x9D` (`KFXMapInfo.csv`, `KFXGameMode.csv`, `KFXItem.csv`, `LevelUpgradeTable.csv`, `KFXQuest.csv`).
- **Client CLI launch:**
  `CS.exe -updated -BishopIP=<IP> -BishopPort=<PORT>`
- **Retail Client `Engine.dll` Server Limitation (Binary-Verified):**
  In the shipped CSO Malaysia client `System\Engine.dll` (`4,820,992` bytes), all four UE2 net-server methods are compiled out as empty stubs (`ULevel::Listen` @ `0x10431330` is `33 C0 C2 04 00` = `xor eax, eax; ret 4`; `NotifyAcceptingConnection` returns `0`; `WelcomePlayer` and `TickNetServer` are bare `ret`). Passing `?Listen` to retail `CS.exe` therefore always crashes with `Dedicated server can't listen:`.
- **Match Launch Modes (`config.json` -> `match_server.mode`):**
  - `ue2_multiplayer` *(default)*: Built-in clean-room Python UE2.5 (build 3369 / CSO Malaysia) asyncio UDP match server (`server/ue2_server/`: `bitstream.py`, `packagemap.py`, `map_loader.py`, `control.py`, `replication.py`, `combat.py`, `host.py`) bound to UDP `7777..7795`. Zero spawning of 2nd `CS.exe` windows! Supports multi-client `HELLO/CHALLENGE/NETSPEED/LOGIN/USES/WELCOME/JOIN`, real `.ut2` `PlayerStart` spawns, `100Hz` + zero-wait event-driven `ShortServerMove`/`ServerMove`/`DualServerMove` sync (`ROLE_AutonomousProxy` non-echo isolation, upright `(0, Yaw, 0)` body rotation + separate `ViewPitch`, `PHYS_Walking` + `Base=LevelInfo0`, `PawnAttribute.csv` `DrawScale=0.85` & `CollisionHeight=92.0`), dynamic 62-weapon `WeaponAttribute.csv` 3rd-person attachments, 3D hitscan combat (headshots/armor/melee/grenades), kills/deaths/respawns, scoreboard `GRI`/`PRI`/`TeamInfo` sync, late join (`JoinStartGameRequest`), and automatic SQLite stat persistence + `S2C 0x1E` push on match end.
  - `external_dedicated`: Routes `S2C 0x15` (`nResult=1`) to a real external UE2 dedicated server (`external_ip:external_port`) or spawns a server-compiled UE2 binary (`dedicated_server_exe`) after verifying its `Engine.dll` does NOT stub `ULevel::Listen` and waiting for UDP bind (`is_udp_port_bound`).
  - `virtual`: Allocates deterministic session/UDP port without spawning OS processes or binding UDP (CI / automated tests).
  - `local_standalone` *(legacy opt-in)*: Spawns playable standalone `CS.exe <MapName>.ut2?game=<GameClass>?mapid=<ID>?Team=<T>?Name=<Player> -updated LOG=NUL` (**no `?Listen`, no `-server`, never `-NULLRENDER`**).
  - Mode 1 (Team Death): `KFXGame.KFXMeleeGame`
  - Mode 2 (Death Match): `KFXGame.KFXSingleGame`
  - Mode 3 (Team Match): `KFXGame.KFXRoundGame`
  - Mode 4 (Bomb Match): `KFXGame.KFXBombGame`
  - Mode 5 (Occupation Match): `KFXGame.KFXOccupyGame`

---

## 5. Launcher HTTP API (`CSO-Malaysia-Launcher-2.1.38.exe`)

- `GET /api/auth/registration-status?launcher=1` — returns registration availability, event rates, announcement, and launcher update metadata.
- `POST /api/auth/register` — JSON `{"username","password","email"}` -> HTTP `201` JSON `{"message":"..."}`.
- `GET /api/news` — JSON `{"news":[...]}`.
- `GET /api/status` — CSG live status snapshot (online players, channels, active rooms & matches).

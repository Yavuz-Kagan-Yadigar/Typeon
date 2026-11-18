# Typeon — Handoff guide (short version)

An AI reading this file knows nothing about the project. It may be a small or local model. So: short sentences, clear rules, step by step.
Project owner: Yavuz. Speaks Turkish. Give short, direct answers.
Every number in this file was checked against the code. Anything not checked is marked "NOT VERIFIED".

---

## 0. THE 10 MOST IMPORTANT RULES (do not break)

1. **Do NOT build.** Do not run `gradlew`, `cargo build`, `cargo check`, `cargo test` or `flatpak-builder`. Build only if the owner says "derle" (build), and only for that job.
2. **Do NOT use git commands to undo.** `git checkout`, `git restore`, `git stash` and `git reset --hard` are forbidden. The working tree holds uncommitted work, and these commands delete it. To undo, reverse the edit by hand. Copy the file to another folder before a big edit.
3. **Do NOT commit or push** unless the owner asks. There is no remote. Branch: `master`.
4. **Compatibility with old versions does NOT matter.** You may break the protocol. Do not write compatibility code. Only note "protocol broken, version must be bumped".
5. **Do not trust comments.** A code comment can be wrong. Look at what the code actually does. (If you write a new comment, follow the style of the comments around it.)
6. **Make small changes.** First use `grep` to find every caller of the function. Fix the root cause in one place. Do not add new libraries.
7. **New Android text** goes into both `res/values/strings.xml` and `res/values-tr/strings.xml`.
8. **Report honestly.** State separately: "compiled / only read / tested on device / failed".
9. **Do not touch:** `service/BatteryLog.kt`; the keyboard fix (`util/KeyboardInsets.kt`, `adjustResize`, input bar); do not add `FLAG_SECURE` to the client (it stays on the server app in release builds); do not add LAN addresses to server records. **Signing:** do NOT add a release signing config to `app/build.gradle`. Gradle produces an unsigned release, and `./sign-release.sh` signs it (private key, v3 lineage).
10. **One test phone is the owner's daily phone** (see `HANDOFF.local.md`). Do not delete, reset, or leave network settings changed. If you changed a setting, put it back.

Release rule: bump the version with `tools/bump-version.sh` (it touches the client and server `build.gradle` (versionCode + versionName), `Linux/Cargo.toml`, `Linux/data/com.p2p.messenger.Typeon.metainfo.xml`, `p2p_messenger_android/app/src/main/cpp/rust/Cargo.toml`, `typeon-server/Cargo.toml`, and the lock files). Then copy the files into `dist/` as e.g. `typeon-client-<version>.apk`. **`sign-release.sh` does the APK signing** (Gradle does not sign). **`tools/sign-update.sh` makes the update signature** (`SHA256SUMS.sig`) with the owner's offline key: the agent does not run it; the owner does (see §8). Regenerate `dist/SHA256SUMS` with the command, do not write it by hand. Every tag, pre-release (`-`) or not, builds release artifacts: debug APKs are debuggable and carry `DebugDbKeyReceiver`, so they stay on test phones built locally.

---

## 1. What the project does

An end-to-end encrypted messaging app that can work without a server. Classical and post-quantum encryption are used together.

Four products:
- **Android client** (Kotlin UI).
- **Linux client** (Rust + GTK4 UI). The **Windows client** is also built from the same `Linux/` crate (`#[cfg(windows)]`). Both are **secondary devices only**: they link to the phone by QR and never create an account.
- **Server** (optional): stores messages for offline contacts. Runs as the Linux program or as the Android app.

**All the real logic is in one Rust core.** Android calls the core through JNI. Linux and Windows call it directly (rlib). Kotlin and GTK are only the UI.

Features: 1:1 messages, groups, edit, delete, reactions, read state, files/media, voice and video calls, whiteboard, multi-device, app lock (AppLock), recovery file.

---

## 2. File map (what is where)

| Path | Contents |
|---|---|
| `typeon-crypto/src/identity.rs` | Device identity, key derivation, `MAX_ACTIVE_DEVICES = 5` |
| `typeon-crypto/src/ratchet.rs` | Double ratchet. `RATCHET_ROTATION_MS = 30 min` |
| `typeon-crypto/src/packet.rs` | `MessagePacket`, `MessageContent` (message types), signature input |
| `typeon-crypto/src/server_proto.rs` | Server message types + default limits (`mailbox_ttl_ms` = 14 days) |
| `typeon-crypto/src/server_seal.rs` | Second seal on the envelope sent to the server |
| `p2p_messenger_android/app/src/main/cpp/rust/src/lib.rs` | Core root (~780 lines): `P2PCore` struct, global `RUNTIME`/`CORE`, module list, `CORE_SRC`. It used to be one 29,000-line file; it is now split into topic modules (line below) |
| same folder, core topic modules (all `impl P2PCore` / `use super::*`) | `core_lock.rs` (core lock), `media_unlocked.rs` (file and label work without the lock), `wire.rs` (libp2p wire types), `util.rs` (helpers, signature inputs, `mono_ms`), `types.rs` (types), `tuning.rs` (constants), `db.rs` (`init_db`, schema, SQLCipher), `pairing.rs` (QR/pairing, `IdentityExchange`), `devices.rs` (device fan-out/authority), `sibling_sync.rs` (sibling devices: sync, read state, history), `contacts.rs` (contacts, block, delete/wipe), `session.rs` (handshake, ratchet rotation), `send.rs` (sending, reactions, edit/delete, Ack), `receive.rs` (`receive_message`), `archive.rs` (message archive, history requests), `persist.rs` (sealed blobs, ratchet persistence), `group_ops.rs` (group operations), `storage.rs` (labels, storage), `network/` (`start_network`, reconnect, retry, direct/server publish route in `publish.rs`), `file_transfer.rs` (file transfer), `poll.rs` (`poll_events`, `process_incoming_envelope`), `recovery.rs` (recovery file), `jni_exports/` (JNI functions `Java_com_p2p_messenger_P2PLib_*`), `core_tests.rs` (tests). Details: TECHNICAL_HANDOFF §1.1 |
| same folder `api.rs` | Plain Rust interface without JNI. Linux and Windows call this |
| same folder `server_client/` | Client side of the server: `mod.rs` (sweeps, errors), `connection.rs` (enroll, rebind), `mailbox.rs` (register, deposit, fetch, ack), `archive.rs`, `blobs.rs` |
| same folder `call/` | Call state and signalling (`signalling.rs`), media transport (`media_link.rs`, encrypted packets, libp2p stream) |
| same folder `whiteboard.rs` | Whiteboard |
| same folder `attachments/` | File chunks, EXIF/GPS stripping (`strip_metadata.rs`), JXL (`jxl_codec.rs`) |
| same folder `update.rs` | Self-update check over Tor (GitHub `releases.atom`), Ed25519 check of `SHA256SUMS`. Details: TECHNICAL_HANDOFF §21 |
| same folder `wire.rs` | libp2p behaviour and wire types |
| same folder `tor.rs` | Tor (arti) client + onion service |
| same folder `group.rs`, `contact.rs` | Group structure and validation; contact and device trust checks |
| `p2p_messenger_android/app/src/main/java/com/p2p/messenger/` | Android Kotlin code |
| ↳ `P2PLib.kt` | JNI `external` function declarations (names match Rust exactly) |
| ↳ `service/P2PService.kt` | Background service. Receives JSON events from the core (`poll_events`), shows notifications |
| ↳ `ui/` | Screens (20 files; main ones): `ChatActivity`, `GroupChatActivity`, `CallActivity`, `AppLockActivity`, `MediaViewerActivity`, `LinkDeviceActivity`, `QrScanActivity` |
| ↳ `util/` | Helpers (42 files; main ones): `AppLock`, `OutgoingMedia` (media cleanup), `KeystoreCrypto`, `IdentityManager`, `NotificationHelper`, `FontOverride` (custom font), `Quote` |
| `trafficvis/` | Traffic visualisation simulator (`traffic_visualization.html`, `selftest.js`) |
| `p2p_messenger_android_server/` | Android app for the server. Screen: `ServerActivity` |
| `typeon-server/src/` | Server logic: `lib.rs` (`ServerCore`, constants), `handlers.rs` (requests), `store/` (SQLite: `mod.rs` schema, `mail.rs` mailboxes and `seq`, `enrollments.rs`, `archive.rs`, `blobs.rs`), `blobs.rs`, `limits.rs`, `sweep.rs`, `config.rs`, `relay_streams.rs`, `jni.rs`, `bin/typeon-server.rs` (CLI) |
| `tools/` | `sign-update.sh` (owner's offline update signing), `bump-version.sh` |
| `Linux/src/` | Desktop client (Linux + Windows, same crate `typeon-linux`). `core.rs` core bridge, `ui/*.rs` screens, `prefs.rs`/`theme.rs`/`font.rs`/`audio.rs`/`qr.rs`/`util.rs` helpers, `call_media.rs` calls (GStreamer), `keyring.rs` + `secrets.rs` key storage (Secret Service: GNOME Keyring / KDE Wallet). **Windows files:** `win.rs` (tray icon, notifications, autostart, fonts), `keyring_win.rs` (DPAPI vault key), `audio_win.rs` (WASAPI recording); on Windows `main.rs` routes the `audio`/`keyring` modules to these |
| `Linux/packaging/` | Flatpak packaging (`README.md`). `Linux/packaging/windows/`: Windows cross-build/package scripts (`build.sh`, `package.sh`, `package-msys2.sh`, `fetch-sysroot.py`) and `TEST-NOTES.md` |
| `AGENTS.md` | Shared rules for agents + build recipes (Linux, Windows cross-build) |
| `reviews/` | Review notes. Old ones are in `reviews/archive/` (`reviews/archive/ALL_OPEN_FINDINGS.md` = items deliberately left open, not to be debated again) |
| `Description.md` | Protocol design spec (English, draft v0.2). Sections: 1 identity, 2 trust, 3 encryption, 4 discovery + server, 5 groups, 6 open decisions, 7 prototype scope. Parts are behind the code (see its status note) |
| `SECURITY.md` | Security summary (English). **Partly out of date**: if it conflicts, trust the code |
| `Mesaj-Akisi-Senaryosu.md` | Worked example of the send/ack/edit/file flow. Good source for Ack behaviour |
| `.claude/skills/typeon-adb-debug/SKILL.md` | Phone testing guide with adb (the password there is old; the correct one is in this file) |
| `sign-release.sh` | Re-signs an APK |
| `dist/` | Release files |

To find a behaviour: `grep -n "fn function_name" p2p_messenger_android/app/src/main/cpp/rust/src/*.rs` (the core is split into modules, not one file). Do not read a big file in full; read it in parts.
If you change a JNI function, `jni_exports/` and `P2PLib.kt` (and `api.rs` if needed) must change together. If you add a new core `.rs` file, add it both to the `mod` list in `lib.rs` and to `CORE_SRC` (the tests that scan the sources).

---

## 3. Logic, step by step

### 3.1 Identity
- Person = **Identity**. A person has 1–5 **Devices**.
- `identity_id` = fingerprint of the first device. It never changes.
- Contacts and groups are keyed by `identity_id`. The 1:1 chat archive is keyed by device fingerprint.
- Signatures: Ed25519 **and** ML-DSA-87 (both are verified). Key exchange: X25519 **and** ML-KEM-1024. Encryption: ChaCha20-Poly1305.
- A new contact is added first time by QR or by a typed code (TOFU: trust on first contact). After that every packet is checked to see whether its device is a known device (`check_incoming_device` in `contact.rs`). A new or suspicious device raises a `device_alert` event.

### 3.2 Sending a message (in order)
1. `send_message` → `send_message_content_inner` (`send.rs`).
2. If there is no connection, `ensure_connected` tries to connect.
3. If there is no ratchet, a handshake is done (`initiate_handshake_with`).
4. If 30 min have passed, the ratchet is renewed (`maybe_rotate_ratchet`).
5. The message is encrypted, hybrid-signed, and sent over the direct envelope protocol if the peer is connected. It is deposited on the server when the direct path is down, when the message is critical (handshake, rotation, call signal), or when there is no Ack after 1.5 s. Otherwise it stays in the retry queue (`network/publish.rs`). Gossipsub no longer exists.
6. Types that wait for an Ack are written to the `awaiting_confirmation` list and to the DB (`pending_durable_retries`, `pending_group_messages`).
7. Retry: first after 15 s (`ACK_RETRY_INITIAL_MS`), then with backoff up to 120 s (`ACK_RETRY_MAX_MS`). A packet that was decrypted but not taken (or whose copy no longer decrypts) makes the receiver send `ResendRequest`; the sender re-encrypts it under the same `message_id` (at most every quarter of the message's age, 30 s to 25 min). Pending packets are re-encrypted only on a chain generation change, a handshake redo or such a request; otherwise the same bytes are offered again, and every regeneration withdraws the previous server copy. It gives up after **7 days** (`TEXT_RETRY_GIVE_UP_MS`).

### 3.3 Receiving a message
1. `receive_message` decrypts with the ratchet.
2. It **writes to the archive first** (`archive_message`). If that succeeds it sends an Ack. If it fails the packet is not taken and no Ack is sent; the receiver sends `ResendRequest` and the sender re-encrypts the packet.
3. If the same `message_id` arrives a second time, it is dropped.
4. Rate limit: at most 60 packets per 10 s (`RATE_LIMIT_MAX_PER_WINDOW`); 600 on an established connection.
5. Types that do **not** get an Ack (on purpose): `Ack`, `Seen`, `TypingIndicator`, `AddressAnnounce`, `SiblingHistoryResponse`. (`HistorySyncResponse` does get an Ack.)
6. If an edit/delete arrives before its target message, it waits in a buffer.

### 3.4 Multiple devices
- Each device makes **its own key**. The second device links by QR. The primary device signs a `DeviceAdd`.
- Primary device = the device whose fingerprint equals `identity_id`. Adding a device (`sign_device_add`), removing one, and deleting the account only work **on the primary device**; on another device they fail with "Only the primary device can do this".
- The primary device's secret key never leaves it. After linking, the two devices work independently.
- The other side sends every message separately to all active devices of the contact.
- My own messages reach my other device through `SiblingEcho` (text, edit, delete).
- History is fetched page by page with `SiblingHistoryRequest`.
- Read state syncs between devices with `ReadStateSync` (retried up to 7 days, sent only when a newer received message exists).
- A pairing code makes a contact of one identity only; a contact from a code whose device never proves itself is removed after 2 × `PAIRING_WINDOW_MS`. Contact add/remove ordering between siblings uses generations, not clocks. The root ignores contact removal and foreign-founded group changes coming from linked devices.
- A non-primary device gets contact and group info through `DeviceSync`/`SyncPayload`.

### 3.5 Groups
- A group message is one separate encrypted copy for every active device of every member (there is no shared group key).
- Members are stored by `identity_id`. The founder (`founder_identity_id`) adds and removes members. `GroupUpdate` is versioned and signed (`validate_group_update`, `apply_change` in `group.rs`).
- Missing updates are resent periodically by `group_sync_sweep`.

### 3.6 Network
- libp2p. Transport: Noise + yamux. **No gossipsub** (removed in c798a6f): envelopes go point to point. Discovery: Kademlia (client mode). Relay: Circuit Relay v2. Identify on. DCUtR and mDNS are not in the build.
- Custom protocols: `/p2pmessenger/envelope/1.0.0`, `/p2pmessenger/ack/1.0.0`, `/p2pmessenger/keepalive/1.0.0` (and `1.1.0`), `/p2pmessenger/filexfer/1.0.0`, `/typeon/server/1.0.0`, `/typeon/media/1.0.0` (calls), `/typeon/relay/1.0.0`.
- **The internet is reached only through the Tor onion service.** mDNS and UPnP are not in the build. There is no TCP listener and no TCP dial: inbound onion streams reach the swarm in-process (`tor::OnionListen`). This is intended, so IP addresses do not leak. Do not "fix" it.
- Tor states (`TorStatus`): `Disabled`, `Bootstrapping`, `Ready`, `Failed`.
- `start_network` starts the network. `poll_events` returns events as JSON.
- Reconnect: `reconnect_sweep` every 15 s. `dial_with_relay_fallback` dials onion, direct and relay circuits concurrently.
- Keepalive interval: 2 s with the screen on, 20 s idle, 60 s in power saving.
- Files: sent in chunks, per-file key, download from several sources at once, up to 4 GB.
- EXIF, GPS and device info are removed from sent images and videos (`attachments.rs` and `OutgoingMedia.kt`). Orientation is kept.

### 3.7 Server (optional)
- What it does: while the recipient is offline it **writes the encrypted envelope to disk**, and gives it over when the recipient comes back.
- Three operations: `Deposit` (leave), `Fetch` (take), `Ack` (may delete).
- Default retention: **14 days** (`mailbox_ttl_ms`, `server_proto.rs`). An enrolled device that is idle for 30 days is put to sleep (`ENROLLMENT_IDLE_MS`). Per-device quotas are `budget / max_devices` (6/10 blob, 3/10 archive, 1/10 mail, capped at the defaults); archive and blobs stop at 90 % of the budget. Default maximum 16 enrollments (`DEFAULT_MAX_ENROLLMENTS`; the Android server app sets the same 16 in `jni.rs`). At most 60 public enrollments per hour. The public join code lasts **3 days** and is renewed (`PUBLIC_CODE_TTL_MS`).
- The server cannot read content: the envelope is already end-to-end encrypted, with a second seal on top. The session mailbox name comes from the static DH of the two devices' long-term KEM X25519 keys (fixed per pair, not changed on rotation; `server_seal::session_mailbox`). The seal key comes from the ratchet root.
- The server can see: size, time, and which PeerId reads which mailbox. This is a known and accepted limit.
- The server can delay or drop messages but cannot forge them. So: a normal message goes direct when the peer is connected. The server copy is made only if there is no Ack after 1.5 s (`ACK_SUSPECT_MS`). The handshake (`Handshake`, `IdentityExchange`) and ratchet renewal notices always go to both (`network/publish.rs`).
- A server item that cannot be opened or processed is not Acked. The mailbox cursor stays 5 min before it, it is fetched again every 45 s, then skipped (`SERVER_HOLD_GRACE_MS`; details in TECHNICAL_HANDOFF §13.4).
- Envelopes fetched from the server enter the message path with `source = None`, so the server's address is not written into the contact address book.
- The server's **onion address is its identity.** It must be kept on update. Uninstalling and reinstalling the app deletes the onion address.
- "Keep history on the server" is a separate option, off by default. The archive is encrypted with the root key (not forward-secret; an accepted cost).
- Server protocol version **8** (`SERVER_PROTOCOL_VERSION`). Archive buckets are hashes of purge secrets, so the operator cannot delete history it cannot name.
- SQLite tables (`store/`, schema version 5): `enrollments, invites, mailboxes, mailbox_readers, mail, mail_seq, mail_acks, archive, blobs, blob_chunks, blocked_keys, meta`.

### 3.8 Local data
- Database: SQLCipher, file `p2p_messenger.db`. Schema is in `init_db` (`db.rs`).
- Main tables: `identities, own_devices, contacts, groups, messages, message_reactions, message_seen, ratchet_states, skipped_message_keys, remote_devices, files, device_addrs, device_onion_addrs, pending_durable_retries, pending_group_messages, blocked_identities, deleted_identities, removed_contacts, removed_groups, app_meta, acked_packets, own_prekeys, peer_prekeys, pending_sibling_ops`.
- Columns added later are added with `ALTER TABLE`; `CREATE TABLE IF NOT EXISTS` does not change an old table.
- AppLock: the passcode is derived with PBKDF2-HMAC-SHA256, 600,000 iterations; app password minimum 8 characters (`util/AppLock.kt`).
- Recovery file: all secret keys, encrypted with Argon2id (`RecoveryFile`).
- Android backup is off.

### 3.9 Calls
- Signalling goes through ratchet messages. Media goes through a separate libp2p stream, each packet encrypted with its own AEAD (`call/`). Direct, or through a relay/server.
- The video flag has an HEVC bit. The Linux side uses GStreamer.
- Group call: `start_group_call`.
- Android event: `type = "call"`, `action = "invite"` rings the phone.

### 3.10 Android event types (`P2PService.maybeNotify`)
`sync`, `device_linked`, `history_restore_incomplete`, `account_deleted`, `self_revoked`, `read_state_sync`, `call` (`action="invite"` rings), `message`, `group_message`, `delete`, `device_alert`, `group_delete`, `edit`, `group_edit`, `file_offer`, `pairing_failed`, `core_panic`.

---

## 4. Common mistakes

- If you change the signature input or the packet format, all devices must re-pair. Bump the version.
- Wake lock: one object, and each acquire has a matching release. A leak used to drain the battery.
- Do not keep depositing the same handshake on the server. The server quota fills and store-and-forward locks up.
- Gossipsub is gone. Do not add topic subscriptions or a gossip publish path. Route changes go in `network/publish.rs try_publish_raw_via`.
- Self-update: a release without `SHA256SUMS.sig` counts as not published. Do not change `UPDATE_KEY` or the verify logic without the owner.
- Linux GTK: `AdwActionRow` is already a `GtkListBoxRow`. Do not put it inside another `ListBoxRow`, or the `activated` signal never arrives.
- Linux notifications need an installed `.desktop` file and a notification service.
- The Android incremental Kotlin build cache sometimes gives an old APK. If it says "no change", check `lastUpdateTime` with `dumpsys package`.
- If the arti (Tor) state breaks, `tor.rs` deletes `state/` and `hss/` and restarts once. `keystore/` (the onion identity) is **not** deleted.
- A debug APK does not match the release signature on the device (`INSTALL_FAILED_UPDATE_INCOMPATIBLE`). Re-sign with `./sign-release.sh giris.apk cikis.apk`. Gradle's `assembleRelease` output is **unsigned**; always sign it with this script before distribution.
- **Message text in notifications is off by default** (the "show messages in notifications" switch in Settings). When off, the notification only says "New message": neither the sender nor the text is shown.
- The `SYSTEM_ALERT_WINDOW` permission was **removed**; the call screen does not open with it. Do not add it back.
- **Uninstall and reinstall the app:** identity, contacts and ratchet (and the onion address on the server) are deleted. Do not do it.
- `FLAG_SECURE`: **not** in the client (owner rule, do not add); present in the server app's non-debug build (`ServerActivity`). `SECURITY.md` was updated to match.

---

## 5. Build (only if the owner says "derle")

```bash
export JAVA_HOME=~/tools/jdk-21 ANDROID_HOME=~/Android/Sdk \
       ANDROID_NDK_HOME=~/Android/Sdk/ndk/30.0.16138531
export PATH=$JAVA_HOME/bin:~/.cargo/bin:$PATH
cd p2p_messenger_android && ./gradlew assembleDebug     # or assembleRelease
```
- JDK 21 is required (JDK 25 on the system does not work).
- Do not add `--offline` to `assembleRelease` (lint cache is not present). Do not turn lint off.
- `assembleRelease` produces an **unsigned** APK (Gradle does not sign release). Before publishing, sign with `./sign-release.sh <apk> <output.apk>`. The script uses the newest build-tools, and it is the same for both apps (client and server).
- `-x cargoNdkBuild` does not rebuild Rust.
- Linux: `cd Linux && cargo check`.
- Flatpak: `Linux/packaging/README.md`. Command: `flatpak run org.flatpak.Builder --user --force-clean --disable-rofiles-fuse --repo=repo build-dir com.p2p.messenger.Typeon.yml`, then `flatpak build-bundle repo typeon.flatpak com.p2p.messenger.Typeon`. `build-bundle` returns success even if the build failed: check the build's exit code.

## 6. Testing on the device (adb)

Device serials and which phone is the owner's daily one: `HANDOFF.local.md` (local only, gitignored).

- AppLock passcodes: the owner keeps them. They are not written in the repo (AGENTS.md rule). Ask the owner if you need one.
- Loop: take a screenshot → read it → `adb shell input tap x y`.
- When the keyboard opens the button positions change; take a new screenshot.
- With text in the passcode field, `uiautomator dump` returns nothing; send `KEYCODE_ENTER` instead of pressing Unlock.
- To read the database, use `sqlcipher3-binary` (Python venv). Key: `files/debug_db_key.hex`.
- Log search strings: `Metin gönderiliyor`, `Metin alındı`, `Sunucuya bırakılıyor`, `Sunucudan N zarf çekildi`. (These are the app's own Turkish log messages, kept as is.)

## 7. How to work

1. Read the question. Find the relevant function with `grep`.
2. Find every caller. Fix the root cause.
3. Make a small change. No build (unless the owner says "derle").
4. Write a short note: which file, which line, why, what was verified, what was not.
5. Do not make things up. Say "I don't know, this file needs to be read".
6. Ambiguous decisions belong to the owner: list the options briefly, state your recommendation, and ask.

## 8. NOT VERIFIED / take care

- Findings under `reviews/` are historical. Line numbers may have moved. Read the line before fixing it.
- `SECURITY.md` and `Description.md` are behind the code in places. If they conflict, the code is right.
- Every function name in this file exists in the code, but read the function before changing its behaviour.
- Update signing (`tools/sign-update.sh`, offline Ed25519 key): the owner runs it. Give the owner the command with `!` (e.g. `! cd <repo> && echo y | tools/sign-update.sh vX`), then refresh `dist/SHA256SUMS`. Never put the private key in the repo.
- Last checked against code: 2026-11-15, HEAD `50bb608`, version 7.4.6-beta.2. Details of the newest round: TECHNICAL_HANDOFF §21.

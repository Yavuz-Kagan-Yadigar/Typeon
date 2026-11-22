# Typeon — Technical Handover Document (Architecture, Security, Runtime Algorithms)

This document is the technical companion to `HANDOFF.md` (working rules, file map). Every claim below was verified against the source code; file/function names are given. In case of conflict, the **code** is right (`SECURITY.md` and `Description.md` are partly out of date).

**Last updated: 2026-11-22 (HEAD `09ad037`).** The core (`p2p_messenger_core`) is no longer a single `lib.rs`: it has been split into 24 topic modules (§1.1). In this document code locations are given as `file.rs function_name` (core files: `p2p_messenger_android/app/src/main/cpp/rust/src/`); line numbers are not given because they drift. To find them: `grep -n "fn name" p2p_messenger_android/app/src/main/cpp/rust/src/*.rs`. Released versions (tag `v8.0.0`): client 8.0.0 (code 68), server app 8.0.0 (code 59), Linux/Windows desktop 8.0.0, server protocol 8, server DB schema 6. `master` is ahead of 8.0.0 by the commits in §23. Sections 19–20 are history; §21 is the self-update/gossipsub-removal round, §22 the 7.5.0/8.0.0 round and §23 the newest.

Contents: 1 Layers (1.1 module map, 1.2 desktop client) · 2 Crypto primitives · 3 Identity and trust · 4 Session setup (handshake) · 5 Ratchet · 6 Message packet · 7 Send path · 8 Receive path · 9 Delivery/retry · 10 Multi-device · 11 Group · 12 Network layer · 13 Server · 14 Local storage · 15 Files/media · 16 Calls · 17 Threat model · 18 Constants table · 19 2026-10-20/21 fix round · 20 2026-11-05..11 changes · 21 2026-11-12..15 (self-update, gossipsub removed) · 22 2026-11-15..18 (7.5.0, 8.0.0, inspection fix pass) · 23 2026-11-21..22 (Padmé, stickers, quick reactions, disappearing messages)

---

## 1. Layers

```
┌────────────────────────────────────────────────────────────────┐
│ UI:  Android Kotlin (ChatActivity, P2PService…)                 │
│      | GTK4 + libadwaita (Linux and Windows, same crate)        │
├────────────────────────────────────────────────────────────────┤
│ Bridge: JNI (jni_exports/, P2PLib.kt) | api.rs (desktop,      │
│        no JNI)                                                  │
├────────────────────────────────────────────────────────────────┤
│ Core (crate p2p_messenger_core): P2PCore — struct in lib.rs,   │
│   `impl P2PCore` split into 24 topic modules (§1.1)            │
│   business logic, DB, libp2p swarm, Tor, server client, calls  │
├────────────────────────────────────────────────────────────────┤
│ typeon-crypto: identity, ratchet, packet, server_proto, seal   │
├────────────────────────────────────────────────────────────────┤
│ libp2p (noise, yamux, kad, identify, relay, req-resp; no gossipsub) │
│ arti (Tor client + onion service) · SQLCipher · ml-kem/ml-dsa   │
└────────────────────────────────────────────────────────────────┘
          (optional) typeon-server: store-and-forward
```

- **One `P2PCore` instance**, behind the global `core_lock()` mutex (`core_lock.rs core_lock`; for read-only state queries `core_lock_read`). Every JNI/api call enters through `catch_panic` (`jni_exports/mod.rs catch_panic`, which runs inside `RUNTIME.enter()`) and then `core_lock()`, in that order; `api.rs` applies the same order. So the core is **single-locked and event-versioned**: no parallel work, and long operations hold the lock (the `lock_watch` module in `core_lock.rs` watches lock duration; holds longer than 10 s are logged). File and sticker jobs that run with the lock released are in `media_unlocked.rs`.
- Network events are processed by **polling**: the Kotlin `P2PService` loop calls `poll_events()` (`poll.rs poll_events`); the core drains swarm events with `swarm.next().now_or_never()` without blocking and returns a JSON event list.
- The desktop client (Linux/Windows) calls the same core as an rlib through `api.rs`; there is no second copy of the protocol.

### 1.1 Core module map (`p2p_messenger_android/app/src/main/cpp/rust/src/`)

`lib.rs` holds only: the `P2PCore` struct, the global `RUNTIME`/`CORE`/`NET_WAKE`, `MAX_ATTACHMENT_SIZE`, the module list and `CORE_SRC`. Each submodule sees the crate root with `use super::*;`; items that were private became `pub(crate)`; the root modules re-export, so `crate::name` paths did not change. Tests that scan the source text read `crate::CORE_SRC` (`concat!(include_str!(...))` in `lib.rs`; **if a new core file is added, it must be added there too**).

| File | Contents (main) |
|---|---|
| `lib.rs` | `P2PCore` struct, `RUNTIME`/`CORE`/`NET_WAKE`, module declarations, `CORE_SRC` |
| `core_lock.rs` | `core_lock`, `core_lock_read`, `core_lock_poll`, `lock_watch` (lock monitoring), `wait_for_network_activity` |
| `media_unlocked.rs` | file/sticker jobs without the lock: `prepare_and_send_file_unlocked`, `send_sticker_unlocked`, `import_sticker_frames_unlocked` |
| `wire.rs` | libp2p wire types (keepalive, ack, envelope) and the combined `P2PBehaviour` |
| `util.rs` | small free helpers: `group_msg_tag`/`group_msg_id_bound`, `handshake_signing_input`, `group_update_signing_input`, `group_tie_hash`, `verify_hybrid_signature(_with)`, `seal_with`, `founder_transfer_floor`, `clamp_received_times`, `mono_ms` |
| `types.rs` | key bundles, device records, summaries, transfer state, `PREKEY_ROTATE_MS` |
| `tuning.rs` | timeout/limit/protocol constants (most of §18) |
| `db.rs` | `P2PCore::new`, `init_db` (schema + `migrate`), `meta_*`, SQLCipher key (`db_key_pragma`) and migration |
| `pairing.rs` | own identity, pairing by QR/code, first-contact secrets, `IdentityExchange` (`process_identity_exchange`) |
| `devices.rs` | device fan-out (`fanout_targets`), device authority signatures, device linking/notices |
| `sibling_sync.rs` | sibling device sync: roster/`DeviceSync` (`build_sync_payloads`), read state (`sync_read_state`), history (`build_sibling_history_response`, `apply_sibling_reply`) |
| `contacts.rs` | contacts, blocking, device alerts (`evaluate_sender_device`), profile, account/contact deletion, `wipe_all_local_state` |
| `session.rs` | connections, prekeys, handshakes, ratchet rotation (`initiate_handshake_with`, `process_handshake_init`, `maybe_rotate_ratchet`, `note_undecryptable`) |
| `send.rs` | sending (`send_message_content_inner`), reactions, seen, edit/delete, Ack, typing |
| `receive.rs` | `receive_message` and dispatch of decrypted content (`dispatch_received_content*`) |
| `archive.rs` | history requests, message archive (`archive_message`), edit/delete in the archive, `pending_sibling_ops`, group author proof |
| `persist.rs` | sealed local blobs (`seal_local_blob`), ratchet/skipped-key persistence, durable retries |
| `group_ops.rs` | group create/update/membership, founder chain (`heal_founder_chain`), group message fan-out, `process_group_update` |
| `storage.rs` | labels (stickers), storage limits and pruning |
| `network/mod.rs` | swarm start (`start_network`), radio/power modes, relays, reconnection, retried publish (`try_publish_raw_via`, `retry_unconfirmed_messages`) |
| `file_transfer.rs` | file offers, chunked download, chunk service |
| `poll.rs` | `poll_events`, early-packet buffer, rate limit, `process_incoming_envelope` |
| `recovery.rs` | recovery file export/import |
| `jni_exports/mod.rs` | Android JNI bindings (`Java_com_p2p_messenger_P2PLib_*`) and helpers (`catch_panic`) |
| `core_tests.rs` | crate-level tests (`#[cfg(test)]`) |

Large files were split again on 2026-11-15 (c7af0f6). They are now directories with `mod.rs` plus topic files. Paths below are relative to `src/`:

| Directory | Files |
|---|---|
| `call/` | `mod.rs` (`CallSession`, call state), `signalling.rs`, `media_link.rs` (media stream, `/typeon/media/1.0.0`), `tests.rs` |
| `network/` | `mod.rs` (`start_network`, swarm build, behaviours), `connections.rs`, `power.rs` (radio saver, power save, metered/node modes), `publish.rs` (envelope route selection, retries) |
| `server_client/` | `mod.rs` (`ServerCore` client, sweeps, error handling), `connection.rs` (Hello/Enroll/Rebind, request handling, Push), `mailbox.rs` (Register, Deposit, Fetch, Ack, session mailbox), `archive.rs` (archive put/fetch/restore), `blobs.rs` (blob upload), `tests.rs` |
| `attachments/` | `mod.rs`, `jxl_codec.rs`, `strip_metadata.rs` (EXIF/GPS strip), `tests.rs` |
| `jni_exports/` | `mod.rs` (`catch_panic`), `account.rs`, `contacts.rs`, `files.rs`, `groups.rs`, `history.rs`, `linking.rs`, `messages.rs`, `net.rs`, `pruning.rs`, `servers.rs`, `stickers.rs` |

Single files outside the module split: `api.rs` (non-JNI interface), `whiteboard.rs`, `tor.rs` (arti + `OnionListen`), `group.rs`, `contact.rs`, `update.rs` (self-update check, §21).

### 1.2 Desktop client (`Linux/`, crate `typeon-linux`) — Linux and Windows

The same GTK4 + libadwaita crate is built for both platforms; platform code is split with `#[cfg(windows)]` / `#[cfg(unix)]` (`main.rs`, `app.rs`, `font.rs`, `secrets.rs`, `util.rs`, `call_media.rs`, `ui/window.rs`, `ui/settings.rs`). For Windows, `main.rs` redirects the `audio` and `keyring` modules to other files with `#[cfg_attr(windows, path = "audio_win.rs" / "keyring_win.rs")]`.

- **Secondary device only, link-only.** The welcome page (`ui/onboarding.rs welcome_page`) offers only "Link to my phone"; account creation and recovery-file restore were removed from the desktop (`core::create_identity` only generates the device's own key pair for linking). No primary or authority role: an unreachable desktop must not break the other devices (owner rule, `AGENTS.md`). `1a180c3`: from the pending-link page (`awaiting_link`), a confirmed "delete and exit" returns to the setup screen.
- **Vault key:** on Linux, Secret Service (GNOME Keyring / KDE Wallet, `keyring.rs` + `secrets.rs`); on Windows, DPAPI (`keyring_win.rs`: `CryptProtectData`/`CryptUnprotectData`, sealed key stored in the data directory as `vault-key.dpapi`; the data directory is `main.rs data_directory` = `glib::user_data_dir()/typeon`, which is `%LOCALAPPDATA%\typeon` on Windows — the directory path is given by `AGENTS.md` and relies on GLib's Windows behaviour; it was not separately verified in code).
- **Windows-specific:** `win.rs` — our own `Shell_NotifyIconW` tray icon (`install_tray`: left click opens, right click gives Open/Quit), balloon notifications (`win::notify`; `app::post_notification` calls this on Windows; gio `send_notification` is not called because it creates GLib's second, menu-less icon), autostart (`set_autostart`: HKCU `...\Run`, with the `--background` argument), custom font (`register_font` → `pango_font_map_add_font_file`). Closing the window hides it to the tray (`set_hide_on_close`); the main menu "Quit" exits (`ui/window.rs`). Voice messages: GStreamer `wasapi2src` (`audio_win.rs`); calls: in `call_media.rs`, `wasapi2src`, `mfvideosrc`, encoders `mfh265enc`/`mfh264enc`/`openh264enc`, decoders `d3d11h26{4,5}dec`/`openh264dec`.
- **Core-side Windows difference:** `util.rs mono_ms` uses `GetTickCount64` on Windows (no CLOCK_BOOTTIME); `rust/build.rs` links the sysroot's static lcms2 for libjxl.
- **Build (only if the owner says "derle"):** on Linux, `Linux/packaging/README.md` (Flatpak, inside the GNOME SDK); on Windows, `Linux/packaging/windows/build.sh`/`package.sh` (cross-compiled on Linux with llvm-mingw + MSYS2 CLANG64 sysroot) or `package-msys2.sh`; details in `AGENTS.md`.

---

## 2. Crypto primitives (all verified)

| Purpose | Algorithm | Location |
|---|---|---|
| Signature | **Ed25519 + ML-DSA-87**, both produced and both verified | `util.rs verify_hybrid_signature` / `verify_hybrid_signature_with` |
| Key agreement | **X25519 + ML-KEM-1024** (outputs combined) | `ratchet.rs` |
| KDF | HKDF-SHA256, labelled (`p2pmsg-v0.x-…`) + transcript hash | `derive_keys`, `kem_key` |
| AEAD | ChaCha20-Poly1305 (message: nonce = message number; local rows: random 12-byte nonce) | `encrypt_next`, `seal_with` |
| Fingerprint | SHA3-256(ed25519‖mldsa‖x25519‖mlkem), fixed lengths (32, 2592, 32, 1568) | `identity.rs compute_fingerprint` |
| Recovery file | Argon2id + ChaCha20-Poly1305 | `export_recovery` |
| AppLock | PBKDF2-HMAC-SHA256, 600,000 iterations (old 120,000 is still read, `LEGACY_ITERATIONS`); password min 8 chars (`MIN_PASSWORD_LENGTH`) | `util/AppLock.kt` |
| Local DB | SQLCipher; key = HKDF(storage_key, `typeon-db-sqlcipher-v1`) | `db_key_pragma` |

Important details:
- An X25519 shared secret that is not "contributory" (small-order point) is rejected (`x25519()` in ratchet.rs).
- ML-KEM decapsulation never returns an error (wrong key → random bytes); so rotation is tried on a **copy**, and state is persisted only if the packet decrypts in the new chain (see §5).
- All secret symmetric fields (`root_key`, `ck_send`, `ck_recv`, skipped keys, message key) are wiped with `zeroize`; the libraries are built with the `zeroize` feature.
- Signature inputs are **domain-separated and length-prefixed**: `p2pmsg-v0.4-handshake`, `p2pmsg-v0.6-packet` (packet), `p2pmsg-v0.7-identity-exchange`, `p2pmsg-v0.4-prekey`, `p2pmsg-v0.1-founder-transfer`.

---

## 3. Identity and trust model

### 3.1 Structure
- **Device**: generates its own 4 key pairs. `device_fingerprint` = hash of the keys.
- **Identity**: `identity_id` = fingerprint of the first device (never changes). At most `MAX_ACTIVE_DEVICES = 5` active devices per identity (`identity.rs`).
- Contact (`Contact`) and group membership are kept by `identity_id`. The 1:1 chat key is per device; if a person has several devices, `canonical_peer_key` reduces them to one chat (the `min` device of the identity).
- **Primary device** = the device whose fingerprint equals `identity_id`. Adding a device (`sign_device_add`), revoking, and account deletion work **only on it** ("Only the primary device can do this").

### 3.2 First contact (pairing)
1. A shows its QR: `QrPacket` (CBOR, `version=3`): `device_name, identity_id, device_fingerprint, rendezvous_node (onion multiaddr), known_relays, pairing_nonce(16 bytes)`.
2. B scans. B takes A's identity **from the QR** (TOFU), but does not yet know the keys.
3. Both sides send `IdentityExchange` (`send_identity_exchange_opts`): all 4 public keys + `pairing_proof = SHA3-256("typeon-pairing-nonce"‖length(nonce, u32 BE)‖nonce‖sender_fp)` + hybrid signature (`identity_exchange_signing_input`: the signature covers the **recipient device's fingerprint** and the **timestamp**; label `p2pmsg-v0.7-identity-exchange`; the signed fields also cover `revokes_digest` and `identity_exchange_extras_digest` (device_add, device_add_signer, link_consent, link_consent_pq, prekey)). The sender rounds the timestamp to **10-minute buckets** (`now - now % HANDSHAKE_REDO_MIN_INTERVAL_MS`): re-sends stay byte-identical, and the server removes duplicates.
4. The receiving side (`process_identity_exchange`) checks in order: is it from our own device → reject; `keys_match_fingerprint` → reject if not; **timestamp window** (same as `HandshakeInit`: if in the past, `HANDSHAKE_MAX_AGE_MS` = 7 days; if in the future, `HANDSHAKE_MAX_SKEW_MS` = 10 min; outside this is rejected **before the signature**); verify the hybrid signature (the signature binds the recipient fp → a packet replayed to another device is rejected); is the device revoked → reject; is the identity claim tied to the device (`identity_id == fp` or a signed `DeviceAdd`); device trust decision via `evaluate_sender_device`; then the `DeviceRecord` is written.
5. First-contact messages travel through a mailbox sealed with the shared secret (`first_contact_mailbox_id`, secret = pairing nonce); the server cannot derive a fingerprint from the mailbox name.
6. A pairing code makes a contact of one identity only; a contact from a code whose device never proves itself is removed after 2 × `PAIRING_WINDOW_MS`. Contact add/remove ordering between siblings uses generations, not clocks. The root ignores contact removal and foreign-founded group changes coming from linked devices. At most 32 revokes per IdentityExchange.

### 3.3 Trust decision flow (summary)
Every incoming packet/handshake first looks for the sending device in `known_remote_devices`; if absent, "Unknown sender device" → the packet goes to the `early_handshakes`/`early_packets` buffer (for a pending IdentityExchange; only while a pairing is in progress or the contact is known; at most 64 devices in the buffer, 3 inits per device, 4 per claimed identity, and 16 of the 64 slots for claims that are neither a pairing in progress nor a device the contact already lists) or is dropped. If an unknown/new device belongs to a contact, a `device_alert` event is produced and the user's decision is awaited (`check_incoming_device`, `contact.rs`). `is_blocked(identity)` / `is_blocked_device(fp)` are checked at the start of every path.

---

## 4. Session setup (HandshakeInit)

Only **single round-trip, asynchronous** (the other side does not need to be online).

**Initiator** (`initiate_handshake_with` → `DeviceRatchetState::initiate`):
1. Choose the peer's KEM key: the recipient's **signed prekey** if present (`peer_prekeys`), otherwise the long-term KEM key (`recipient_prekey_id = 0`).
2. Generate a fresh X25519 + ML-KEM-1024 pair. `dh = X25519(own_eph, peer_x25519)`, `(ct, ss) = ML-KEM.Encaps(peer_kyber)`.
3. `ikm = dh ‖ ss`. `transcript = SHA256(init_x ‖ init_kyber ‖ ct ‖ resp_x ‖ resp_kyber)`.
4. `HKDF(ikm)` → labels `p2pmsg-v0.2-root`, `…a-to-b`, `…b-to-a` (+ transcript) → `root_key, ck_send, ck_recv`.
5. `HandshakeInit{ sender ids, x25519, kyber_pub, ct, timestamp, recipient_prekey_id, sender_prekey, signature }` is published. The signature **binds the recipient fp and the prekey ids** (`handshake_signing_input`).
6. State is persisted immediately, `has_responded_to_peer_key = true`.

**Responder** (`process_handshake_init` → `respond`):
1. If the sender is unknown, buffer it; if revoked, reject; `sender_identity_id` must match the record.
2. Verify the signature (recipient fp = our own active fp).
3. **Replay protection (H37):** the timestamp must be within ±`HANDSHAKE_MAX_SKEW_MS` (10 min) (if old, a window of `HANDSHAKE_MAX_AGE_MS` = 7 days applies); if the same classical signature was already seen in the window, it is ignored (`recent_handshake_sigs`, persistent). Also, any init **older than a handshake already accepted** is ignored (not only those outside the skew window), and an init **older than the current session** (`handshake.timestamp < existing.last_rotation`, outside the collision window) is ignored — the sender has changed those keys.
4. If it is a first contact with `recipient_prekey_id == 0` and a prekey exists, it is **rejected** and a new handshake is started (id 0 is accepted only in the link window).
5. **Simultaneous handshake collision** (90 s): if we have our own initiator state and `own_fp < sender_fp`, keep ours; otherwise accept theirs (the smaller fingerprint wins).
6. `respond` with our own prekey/KEM secret → the same keys are derived, `has_responded_to_peer_key = false`, written to `ratchet_states`. The rotating mailbox topic is derived from the root key (no subscription; gossipsub is gone).

Because the responder is deterministic, it **always rotates before its first send** (`is_fresh_responder`), so a replayed init cannot force a repeat of key and nonce.

**Self-repair:** `note_undecryptable` — if 3 undecryptable packets arrive within 2 min (and the session is not new), the handshake is renewed; `maybe_redo_handshake` and `UNDECRYPTABLE_REDO_MIN_INTERVAL_MS` = 2 min rate-limit it.

---

## 5. Double ratchet (`typeon-crypto/src/ratchet.rs`)

**State** `DeviceRatchetState`: `root_key, prev_root_key, ck_send, ck_recv, own_x25519_secret, own_kyber_secret, peer_x25519_pubkey, peer_kyber_pubkey, send_message_number, recv_message_number, prev_chain_length, last_rotation, has_responded_to_peer_key, pending_rotation_ct, skipped_keys, old_recv`.

**Symmetric step** (`chain_step`): `message_key = HKDF(ck, "p2pmsg-v0.1-msgkey")`, `next_ck = HKDF(ck, "p2pmsg-v0.1-chainkey")`. Nonce = 12 bytes, the last 4 bytes are `message_number` (safe because the chain key is single-use). If the counter overflows, "Chain exhausted".

**DH/KEM rotation** (`perform_dh_ratchet`, 30 min = `RATCHET_ROTATION_MS`):
- Only the side that has **not yet answered the peer's current key** (`!has_responded_to_peer_key`) triggers it; after 30 min, or if fresh responder, `should_rotate()` is true. There is no deterministic "who starts" rule (Signal model).
- Generates a fresh X25519 + ML-KEM pair; agrees against the peer's **current** public keys; `ikm = root_key ‖ dh ‖ ss`; new root/chains are derived; counters reset; the old root is kept as `prev_root_key` for **one generation**; the old receive chain is kept as `old_recv` (with its skipped keys).
- The rotation announcement (`rotation_kyber_ciphertext` + new `ratchet_pubkey`) is **added to every outgoing packet** (`pending_rotation_ct`) until the peer proves that it decrypted a packet in the new chain.

**Receiver** (`decrypt`):
1. If an announcement is present and the new X25519 key differs from the recorded one: derive the rotation read-only (`derive_rotation`), try the packet on the new chain, and call `apply_rotation` only if it decrypts (`rotated = true`). Nothing is written otherwise (a wrong or old announcement cannot break the session); an announcement that does not open reads as `DecryptFailed` (diverged). The first packet on the new chain closes the old chain at the header's `prev_chain_length` (`close_old_recv`).
2. Otherwise decrypt in the current chain (`chain_decrypt`): if `message_number < next`, use `skipped_keys`; otherwise advance. Upper bounds: `MAX_SKIP_AHEAD = 2.000` steps (cost bound for HKDF before authentication), at most `MAX_SKIPPED_KEYS = 1000` cached (the oldest are dropped).
3. On failure, the old chain (`old_recv`) is tried → packets sent before the rotation are not lost.
4. The chain is not advanced until AEAD verification succeeds (on error the cursor is removed).

Persistence: after every successful step, `persist_ratchet_state` runs (if it cannot write, the packet is **not sent**: "Session state could not be written"). Skipped keys are stored encrypted in a separate table (`skipped_message_keys`).

---

## 6. Message packet and envelope

```
NetworkEnvelope (CBOR) =
   IdentityExchange | Handshake(HandshakeInit) | Message(MessagePacket)

MessagePacket {
  header = SignedHeader (CBOR bytes carried **as they are**)
    { sender_identity_id, sender_device_fingerprint, message_id(UUIDv4),
      ratchet_pubkey (filled only on rotation), message_number, prev_chain_length,
      rotation_kyber_ciphertext (on rotation), sent_at_ms }
  ciphertext   = ChaCha20-Poly1305( CBOR(MessageContent), AAD = raw header bytes )
  signature_classical (Ed25519), signature_pq (ML-DSA-87)
}
signature input = raw header bytes ‖ ciphertext ‖ recipient_fp (length-prefixed, label "p2pmsg-v0.6-packet")
```
- **The header is built first** (`SignedHeader::new`): the signature covers these raw bytes, and the ratchet AEAD covers the same bytes as **associated data** → the receiver only acts on the header the sender encrypted; a packet with a modified header does not pass the tag.
- The signature is **bound to the recipient**: an A→M packet is also valid on B but cannot break the session (a deliberate protocol break).
- `MessageContent` (CBOR enum): `Text{…, expire_secs}, Reaction, Edit, Delete, HistorySyncRequest/Response, Ack, FileOffer{…, expire_secs}, TypingIndicator, Seen, ProfileUpdate, GroupUpdate, GroupSyncRequest, LeaveGroupRequest, AddressAnnounce, DeviceLinkGrant, DeviceAddNotice, ReadStateSync, DeviceRevokeNotice, FirstContactSecret{secret, group_id}, DeviceSync, SiblingEcho, SiblingHistoryRequest/Response, AccountDeleted, Call{call_id, action, group_id, video, media_key, stream_id, sent_at_ms, participants}, WbOps/WbDigest/WbPageRequest/WbPage, ResendRequest{target_message_id…}`. `Call.action` (`CallAction`): `Invite, Accept, Reject, Hangup, Busy, Ended, Joined`. `SiblingEchoBody`: `Text, Edit, Delete, GroupLeft, Reaction, File, Sticker, StickerRemoved, ContactRemoved, StickersRequest, Blocked, ContactDeviceRevoked, DeviceLeaving`.
- Envelope upper bound `MAX_ENVELOPE_BYTES = 1 MiB`.
- **Strict CBOR:** three parsers reject trailing bytes from a peer (6a603c7): `MessageContent::from_cbor` (`content: trailing bytes`; at most `MAX_NESTING` = 32 levels of nesting), `SignedHeader` deserialize (`header: trailing bytes`; recursion limit 4), `RatchetPublicKeys::from_bytes` (`Ratchet public key: trailing bytes`; ≤ 2048 bytes, key lengths exactly 32 and 1568). Trailing bytes are refused, but CBOR re-encodings (unknown keys, non-minimal lengths) of the same signed packet still parse.

---

## 7. Send path (algorithm)

`send_message` → `send_message_content_inner(peer_fp, content, …)` (`send.rs`):

```
1. Error if ratchets are not loaded.
2. ensure_connected(peer)           # if no connection, dial immediately
3. If no ratchet, initiate_handshake_with(peer)
4. needs_delivery_confirmation = whether the content type is one that gets an Ack
5. if the content is anything but TypingIndicator or Call, or the ratchet is a fresh responder: maybe_rotate_ratchet(peer)
        -> if rotated, regen_pending_for_peer (regenerate pending items with the new chain; the message being re-sent is skipped)
        (a reader that only sends `Seen` must still rotate, or it would never recover; typing and call signals never trigger a rotation)
6. rotation_ct = fresh rotation ?? state.pending_rotation_ct
7. Build the header (n, prev_len = state.next_send_numbers()); (ciphertext, n, prev_len) = state.encrypt_next(CBOR(content), AAD = header.raw())
8. persist_ratchet_state(sync) — if it fails, the state is rolled back and the packet is NOT sent ("Session state could not be written, packet not sent")
9. Sign raw header bytes ‖ ciphertext ‖ recipient fp (Ed25519 + ML-DSA, `packet_signing_input`)
10. Write "sent / pending" to the archive (for text; if that fails the packet is NOT sent)
11. if needs_confirm: publish_with_ack_tracking(...)
    else:             publish_envelope(...)
```

**Route selection** (`network/publish.rs try_publish_raw_via`; gossipsub is removed, c798a6f):
- Mailbox id: `Handshake/IdentityExchange` → `p2p_msg_<recipient_fp>`; a packet announcing a rotation → `p2p_rt_<hex>` from the **old** root (the peer does not know the new root yet); others → `p2p_rt_<hex>` from the current root (`topic_for_root_key`, HKDF `p2pmsg-v0.1-gossip-topic`, 16 bytes). These strings are now only mailbox-id inputs, not pub/sub topics.
- `direct = mapped PeerId connected?` (`direct_peer_for`; for IdentityExchange/Handshake also the connection the exchange arrived on, `pairing_reply_peer`). `critical = handshake | identityexchange | rotation | call signal`.
- **Order in `try_publish_raw_via`:** (1) blocked recipient or deleted account → `Permanent`; (2) CBOR size: an envelope whose bytes + 4096 exceed `MAX_ENVELOPE_BYTES` → `Permanent` ("Envelope too large"); (3) **server deposit first** when `!direct || critical || (no Ack since ACK_SUSPECT_MS = 1.5 s)` (`try_server_deposit`); (4) if `direct` and `allow_direct`, the direct send `/p2pmessenger/envelope/1.0.0` request-response (`send_envelope_direct`); on success the call returns `Ok`; (5) if no copy was deposited yet and the peer was `direct`, the deposit is tried now (direct send failed).
- **Nothing left:** the envelope goes to `pending_envelopes` and is resent by `poll_events` (same bytes, no re-encryption).
- Error classes: `Permanent` (blocked, deleted account, envelope within 4 KiB of 1 MiB) → status `Failed`; `Transient` → `pending_envelopes` queue + status `Pending`.

---

## 8. Receive path (algorithm)

Sources: direct envelope request (`/p2pmessenger/envelope/1.0.0`), server `Push`/`Batch`, the pending-envelope resend loop.

`process_incoming_envelope`:
1. **Duplicate guard:** a per-process keyed hash of the raw bytes (not shown to the network); if seen in the last 10 min (`INBOUND_DEDUP_WINDOW_MS`, `INBOUND_DEDUP_MAX_ENTRIES` 8192, the older half goes on overflow) it is skipped, and for a `Message` the Ack is sent again **only if the message is really in the archive** (`reack_if_already_handled`). A first pass that failed is remembered for only 30 s (also every `IdentityExchange`), so a retry can succeed; a failed server item stays an `Err` so it is held, not acked.
2. Decode CBOR. Blocked identity/device → drop silently.
3. `IdentityExchange` → `process_identity_exchange`. `Handshake` → `process_handshake_init` (unknown sender → `early_handshakes`).
4. `Message`: if there is no ratchet but the device is known and active, verify the signature and put it in `early_packets`; otherwise `receive_message`.

`receive_message` (`receive.rs`):
```
1. The sending device must be known (else "Unknown sender device") and active (a revoked one gets `answer_revoked_sibling`); header `sender_identity_id` must equal the record's identity
2. Verify the hybrid signature over header bytes ‖ ciphertext ‖ our own active fp
3. ratchet.decrypt(...) on a snapshot of the state [see §5]. If a rotation was applied: the state is written at once (`persist_ratchet_state_replacing_skipped`; if that fails the snapshot is restored and the packet fails), then pending packets of the old chain are regenerated on the new one (`regen_pending_for_peer`, except the one this packet answers)
4. If it cannot be decrypted: reack_if_already_handled() ? -> duplicate delivery, Ack again, event "noop"
                             else note_undecryptable(sender) (re-handshake after 3 within 2 min; not for `KeyNotFound`, and not for a packet sent before the session began)
                             and for `KeyNotFound` of a packet younger than 7 days: ask_resend (`ResendRequest`)
5. If successful: PeerId mapped (record_peer_id_if_known); old receive chain closed at prev_chain_length; skipped keys + ratchet state written in one transaction without fsync (on failure: rollback of memory, packet fails, no Ack); used skipped keys deleted; last-seen time (`touch_device_seen`)
6. CBOR -> MessageContent (a variant this version cannot parse is Acked and ignored: event "noop"); times are clamped with clamp_received_times
7. Per-type handling:
   Text(1:1): already in archive? -> Ack only; else archive_message(); if SUCCESSFUL, Ack; if it fails, no Ack and the packet is not taken (the receiver sends `ResendRequest`, see §9)
   Text(group): sender_may_post_to_group? if not, REJECT; author_proof (device signature) is verified
   Edit/Delete: apply if target exists, otherwise buffer_edit_or_delete (replayed when target arrives)
   Reaction/Seen/…: their tables
8. Return a JSON event for the UI ({"type":"message",...})
```
`Ack` on the receive side: removes it from `awaiting_confirmation`, status `Delivered`.

---

## 9. Delivery reliability

- **Types that get an Ack** (`needs_delivery_confirmation`): `Text, Edit, Delete, Reaction, HistorySyncRequest/Response, FileOffer, GroupUpdate, LeaveGroupRequest, GroupSyncRequest, ProfileUpdate, DeviceLinkGrant, DeviceAddNotice, DeviceRevokeNotice, FirstContactSecret, DeviceSync, SiblingEcho, ReadStateSync, SiblingHistoryRequest, AccountDeleted, WbDigest`. **Types that do not get an Ack:** `Ack, Seen, TypingIndicator, AddressAnnounce, SiblingHistoryResponse`, call/WbOps.
- `awaiting_confirmation[message_id]` = `PendingConfirmation{envelope, next_retry_at, retry_interval_ms, first_sent_at, original_sent_at, regen_content, chain_stamp…}`; it is also written to the `pending_durable_retries` table (it restarts even if the process dies).
- `retry_unconfirmed_messages` (periodic):
  - if there is no Ack in the first 1.5 s, the connection is marked "suspect" and an early server deposit is tried;
  - interval `15 s` (`ACK_RETRY_INITIAL_MS`) → ×2 → at most `120 s`;
  - a packet that was decrypted but not taken (or whose copy no longer decrypts) makes the receiver send `ResendRequest`; the sender re-encrypts it under the same `message_id` (at most every quarter of the message's age, 30 s to 25 min; the receiver deduplicates by `message_id`). Pending packets are re-encrypted (`regen_content`) only on a chain generation change (`chain_stamp`), a handshake redo or such a request; otherwise the same bytes are offered again for up to 7 days, and every regeneration withdraws the previous server copy. A restart restores pending packets with their stored envelope when the chain is unchanged;
  - after `TEXT_RETRY_GIVE_UP_MS` = **7 days** it gives up, status `Failed`;
  - sync packets (`SiblingEcho, ReadStateSync, DeviceSync, WbDigest`) follow the same rule (no 25-minute drop);
- In radio-saving mode (`radio_saver`), retries older than 60 s are held while the window is closed.
- Receive rate limit: 60 packets per 10 s window (`RATE_LIMIT_MAX_PER_WINDOW`), 600 for an established connection; also `MAX_DEFERRED_INCOMING = 2000`, `MAX_UNKNOWN_INBOUND = 16`.

---

## 10. Multi-device

**Linking (secondary → primary)** (spec §1.5):
1. The secondary device generates its keys; `DeviceLinkRequest` QR is shown (fingerprint + nonce only, no public keys). The two screens show a nine-digit compare code: PBKDF2-HMAC-SHA256 (100 000 iterations, salt `typeon-link-code-v2`) over fingerprint + nonce.
2. The primary scans the QR → sets `pending_link_target`/`pending_link_nonce`, and sends `IdentityExchange` to the secondary.
3. The secondary gives **its own consent signature** with `link_consent` (+PQ); in `process_identity_exchange` the primary produces a signed `DeviceAdd` with `sign_device_add(fp, consent)`; `add_has_consent` verifies the new device's consent.
4. The primary sends `DeviceLinkGrant{nonce, identity_id, device_add, sync}` plus continuation parts as `DeviceSync` (ratchet-encrypted). `broadcast_device_add_to_contacts` sends a `DeviceAddNotice` (with full keys) to every contact; `sync_to_siblings`.
5. The secondary adopts `identity_id`; its own keys stay the same.

**Runtime:**
- Contacts send each message to **every active device** of the recipient identity, as a separate packet (`fanout_targets`).
- My own sent messages are forwarded to siblings as `SiblingEcho{Text|Edit|Delete|Reaction|File|GroupLeft}`; because the same `message_id` is used, an edit/delete targets the same bubble.
- Sibling history (`sibling_sync.rs`): see the **Sibling history** block below. Read state: `ReadStateSync` (watermark, `sync_read_state` / `apply_incoming_read_watermark`; retried up to 7 days, sent only when a newer received message exists). Also: sibling journal (`sibling_journal`, replayed with the backfill), time-cut backfill with `covered_to`, roster part digests, block and device-revoke echoes. The link completes on the grant's Ack.
- `pending_sibling_ops` table: sibling operations that arrive before their target are buffered.
- Revocation: `DeviceRevoke` (signed); packets from a revoked device are rejected and `answer_revoked_sibling` is used.
- Authority: only the identity's root (primary) device adds, removes, or deletes.

**Sibling history (history backfill)** — two triggers, one response builder `sibling_sync.rs build_sibling_history_response`:
- *Automatic* (`request_sibling_backfill`): debounced by `SIBLING_BACKFILL_INTERVAL_MS` (30 min); only to **connected** siblings (a request sent to an offline sibling was re-deposited on the server and kept the radio on overnight); `since_timestamp` = since the last answered request from that sibling (`sibling_backfill_since`, with `SIBLING_BACKFILL_SINCE_MARGIN_MS` = 10 min as clock-skew margin), `SIBLING_BACKFILL_PER_CONVERSATION` (30) per conversation. In an unscoped (all conversations) reply the row limit `SIBLING_BACKFILL_MAX_ENTRIES` (300) is divided among the conversations/groups.
- *User press* "Fetch older history" (`request_older_sibling_history`): one conversation, window `[after_timestamp, before_timestamp)`, `HISTORY_SYNC_MAX_MESSAGES` (200) per page; sent to each connected sibling and recorded in `sibling_fetch_open[(sibling, before, after)]`. The response (`SiblingHistoryResponse{entries, window, more}`) **echoes** the window; only a response whose echo matches an open press counts as a user fetch (the match is consumed; a restart clears `sibling_fetch_open`, and in that case a lost press is reopened: `reopen_fetch_cursor`). `more` means the responder cut the page, and the older remainder of the window is requested again from the same sibling.
- **Budget:** text rows are charged against the `HISTORY_SYNC_MAX_TEXT_BYTES` (512 KiB) budget (for the 1 MiB envelope limit). In an unscoped reply, a row that does not fit is **skipped** (one long message must not cut off the later conversations); in a scoped press, the reply ends there (`more = true`), because older rows below a skipped row would become a permanent hole.
- **Attachments and reactions** (dcd2cb6): `SiblingHistoryEntry` gained two fields: `file: Option<Box<MessageContent>>` (always a `FileOffer`; `file_id` = `message_id`, the recipient downloads the file from that sibling) and `reactions: Vec<(reacting_identity, emoji, reacted_at_ms)>` (empty emoji = removal, kept for its timestamp). `sibling_file_entries` only sends `status = 'complete'` files, in the `created_at` window, the newest `limit` of them; the file key (`unwrap_file_key`), `chunk_hashes`, header/quote fields and label info go with the offer. The recipient writes the row with `apply_sibling_file` like `receive_file_offer`, then turns its direction/conversation/date into the sibling's. Attachment rows are not text bubbles: `apply_sibling_reply` puts only `file.is_none()` and non-empty texts into the event JSON, and the chat is reloaded.
- **Budget rule, attachments** (670ab45): an attachment is charged as `512 + header + chunk_hashes` bytes plus the preview; if the budget does not fit, the **preview (preview_jpeg) is dropped first** — the file still arrives and shows with a generic icon until downloaded; if even the preview-less form does not fit, the row is skipped. A reaction carrier row is charged `128 + id + reactions` bytes.
- **Fetch cursor problem with an earlier press** (926d724): an earlier press had moved the fetch cursor below the rows whose text it delivered; the attachments and reactions of those rows never appeared in any later window. Now the responder adds, **after** the window rows (with the remaining budget), the attachments (`sibling_file_entries`) and reactions (`sibling_reaction_entries`, text-less carrier rows) of rows sent since the window's end (`before`). The recipient (`apply_sibling_reply`) keeps only attachment and reaction carriers (`file.is_some() || text empty`) from outside the window; text rows stay within the window; for a reaction carrier **no row is written** (the reaction is applied only to a row that is already there).
- **Recipient side** (`apply_sibling_history`): `file` is accepted only if it is a `FileOffer` and `file_id == message_id`; deduplication is **per conversation** (another conversation's row must not suppress this one); reactions are applied only when the row is present (`present`) (at most 256 reactions, emoji ≤ 64, reacting identity ≤ 128 bytes, `apply_reaction`); unless it is a user press, rows below the user-cleared history floor (`history_floor`) are not written; nothing is written back to a left/unknown group. The window request is capped on the responder at `HISTORY_FETCH_WINDOW_MS` = 30 days (`receive.rs`, `SiblingHistoryRequest` arm); the request is answered only if it came from a device of our own identity; `SiblingHistoryRequest` is always acked.
- **Contact avatars** (dcd2cb6): `build_sync_payloads` adds a separate `SyncPayload` part for each contact with an avatar (up to about 250 KB; `devices` empty: an unknown contact is not created from such a part); before, a linked device got an avatar only if the contact sent a `ProfileUpdate`. Linux (`Linux/src/app.rs`, `ui/chats.rs`) refreshes contacts on the sync event.

---

## 11. Group

- Updates (GRP fix pass): a `GroupUpdate` is taken only from its signer or one of my own devices. The sibling sync carries `removed_groups` (bounded 4096), so a removed group is not re-created by a stale update. A founder transfer wins its version tie. Only the root founder device acts on a `LeaveGroupRequest` at once; another founder device defers it 2 min (`LEAVE_REQUEST_DEFER_MS`). A new member gets a full state (with the picture) after its Add. Delete/removal notices are given up after 7 days. Rows of an unknown group id expire after 1 day, and non-member rows are dropped when the group arrives locally. `sendGroupMessage` (JNI) returns `{"message_id","status"}`.

**Structure** (`group.rs`): `Group{group_id, name, founder_identity_id, members[GroupMember{identity_id, added_at, added_by}], version, avatar_jpeg, founder_chain}`. The `group_id` format is `group-<16..48 hex>`; the hex part derives from the founder identity + a nonce (`group_id_for_founder`), so an unknown group id that cannot be tied to its founder is rejected. Member limit `MAX_GROUP_MEMBERS`, `member_devices` ≤ members × 5.

**First-contact secret is now per group:** `FirstContactSecret{secret, group_id}` — the device's secret is the first 16 bytes of `SHA-256("typeon-group-first-contact-v1" ‖ master ‖ group_id)` (`own_group_contact_secret(group_id)`); the founder stores it under `gf:<fp>:<group_id>` and distributes it **only to the members of that group**. The old **personal** secret was removed: members now reach **their own group's** mailbox, not a single personal first-contact mailbox; this mailbox is kept only while the device is in the group (`first_contact_secrets`).

**Change types** (`GroupChange`): `Add(id)`, `Remove(id)`, `Rename(name)`, `AvatarUpdate(Option<bytes>)`, `Delete`, `TransferFounder(id)`. Only the **current founder** can sign all of them (there is no separate authority mechanism; members cannot change anything on their own). If a member wants to leave, `leave_group` sends `LeaveGroupRequest` to all active devices of the founder (with Ack), removes the group locally with `remove_group_locally` (the version and founder are written to `removed_groups`, pending queues and the whiteboard are deleted), and mirrors `SiblingEchoBody::GroupLeft` to siblings. When the founder receives this request, it publishes `Remove` via `remove_from_group` (this function runs only on the founder: "Only the founder can remove members"). **The founder cannot leave**; it can delete the group for everyone (`Delete`) or hand over the authority with `TransferFounder`.

**Validation** (`validate_group_update`): the signer identity = `founder_identity_id` (otherwise `NotFounder`); the signing device must be active; `new_version > group.version` (otherwise `StaleOrOutOfOrderVersion`, treated as harmless and acknowledged); `new_version <= version + 4096` (`MAX_VERSION_JUMP`). `apply_change`: `Remove` cannot remove the founder; a `TransferFounder` target that is not a member is ignored (the version still advances).

**Equal-version conflict (H78):** two founder devices can sign the same version. For an update at a version the recipient already holds, if `group_tie_hash` (SHA-256 over group id + version + change + name + member list + signer) is **larger**, the recipient takes the update again; `Delete` and a "resend" that repeats the same members/name are also taken. So every member ends in the **same** state at the same version; the losing founder device receives its sibling's update and makes its next change as `max(seen version)+1`.

**Receive steps** (`group_ops.rs process_group_update`):
1. Group id format → is the signing device known? → hybrid signature over `group_update_signing_input` (group id, version, change, name, members, member devices, signer identity + device).
2. Name ≤ 256 bytes; member list within the limit and its elements must be fingerprint-hex.
3. If the group is not present locally: a group we **left** (`removed_groups`) cannot come back with a new version without an `Add` of us; an unknown group that does not include us is **rejected**.
4. Founder chain: the `FounderTransfer` chain is walked with `heal_founder_chain` (each link is the old founder's hybrid signature, `founder_transfer_signing_input`); `founder_transfer_floor` prevents rollback; the chain is bounded by `MAX_FOUNDER_CHAIN`.
5. `Delete` → `remove_group_locally`. Otherwise `sync_members` + `apply_change`; if it `Remove`s us, the group is deleted locally.
6. `member_devices` + `member_device_proofs`: a member's device keys are vouched by the founder (`adopt_vouched_member_devices`); the update is a **delta**: only **new or changed** devices since the last update are carried (a newly added member gets the full list). A missing member or a version gap makes the member request the **full state** from the founder with `GroupSyncRequest` (the founder answers each member at most once every 10 min, `sign_group_resync`); `first_contact_secret` (16 bytes) is stored under the key `gf:<fp>:<group_id>` → a member that has not matched yet can open that group's first-contact mailbox.

**Founder devices and resend:** every update the founder signs also goes to **the founder's own sibling devices** (`send_group_update_to_siblings`), so two founder devices do not sign the same version. The founder can also resend the group to everyone (`resend_group_to_all`; Android `P2PLib.resendGroupToAll`): the current signed state is sent again to **every member device**.

**Sending a group message** (`group_ops.rs send_group_message`): check membership → generate `local_id` (`<8-byte tag hex><-uuid>`; tag = `util.rs group_msg_tag(group, author identity, "-<uuid>")`; the receiver checks with `group_msg_id_bound` that the identity belongs to the author: another member cannot produce a message with a colliding id, and edit/delete are bound to the author) → `sign_group_author`: device signature, giving `author_proof = "device_fp:classical_sig_hex:pq_sig_hex"` (`group_author_statement(group_id, message_id, identity, device, text)`) → write to the archive → for **each other member** `send_group_message_to_member`: a separate 1:1 packet to each active device of the member (`send_message_content`). If a member's active device is not yet known, the content is written to the `pending_group_messages` queue (per member `MAX_PENDING_GROUP_MESSAGES_PER_MEMBER`; if it overflows, the oldest is dropped; persisted in the DB), and `group_sync_sweep` retries periodically. Finally `SiblingEcho` is mirrored to sibling devices.

**Receive** (`receive_message` Text arm): `sender_may_post_to_group` (reject if not a member) → if the same `group_message_local_id` is already in the archive, only Ack → if `group_author_proof_valid` (does the device belong to that identity + signature) passes, `author_proof` is stored → archive → Ack. Edit/Delete are bound to the author with the same `author_proof`.

**Missing history:** `HistorySyncRequest{group_id, …}` / `HistorySyncResponse` from other members; the server archive is an optional source (§13).

---

## 12. Network layer

**Swarm setup** (`network/`: `mod.rs`, `connections.rs`, `power.rs`, `publish.rs`; `start_network`):
- Identity: the libp2p Ed25519 key is in `files/libp2p_identity.key` (protobuf; if corrupt a new one is generated; if unreadable, a temporary one for that run). This is **separate from the Typeon device identity**; the PeerId comes from this key and appears in the server record.
- Transport: `ArtiDialTransport` (dial `.onion` over Tor) → noise → yamux, and `tor::OnionListen` (listen only) → noise → yamux. There is no TCP listener and no TCP dial: inbound onion streams reach the swarm in-process (`tor::OnionListen`, `MAX_INBOUND_ONION_STREAMS = 64`); `TOR_LIBP2P_PORT` (42611) is only the onion virtual port. A stopped onion service is relaunched automatically. Inbound upgrades must finish within 30 s (`INBOUND_UPGRADE_SECS`); above `MAX_UNKNOWN_INBOUND` = 16 unknown inbound connections the oldest are closed. So there are no direct clearnet connections, in or out.
- **No gossipsub, no topic subscriptions** (c798a6f). The libp2p feature list in `Cargo.toml` is `tcp, noise, yamux, kad, identify, tokio, macros, dns, request-response, cbor, relay`.
- kad: `Mode::Client` (does not route for others); if node mode is on, relay server behaviour is added (`relay::Behaviour` only when `node_mode`). On Android the node-mode switch is stored and passed to the core; relay-server behaviour is built at `start_network`, so it takes full effect after a restart.
- mDNS, UPnP and dcutr are **not in the build** (`wire.rs`: "removed: onion-only transport"); relay client on; `identify` on.
- Request-response behaviours: `envelopes` (`/p2pmessenger/envelope/1.0.0`), `acks` (`/p2pmessenger/ack/1.0.0`, AckBatch ≤256), `keepalive` (`1.0.0`/`1.1.0`), `file_chunks` (`/p2pmessenger/filexfer/1.0.0`), `server_rpc` (`/typeon/server/1.0.0`), `stream` (libp2p-stream: `/typeon/media/1.0.0`, `/typeon/relay/1.0.0`).

**Tor** (`tor.rs`): `TorClient::create_unbootstrapped` + `launch_onion_service` (nickname `p2pmsg`). If `bootstrap()` fails, it retries forever, starting with a 2 s wait and growing to 60 s. State: `Disabled` → `Bootstrapping` → `Ready` (onion address obtained) / `Failed`. On `corrupted data in persistent state` errors, `state/` and `hss/` are deleted and it starts once more; `keystore/` (the onion identity) is kept. `set_dormant` for radio saving.

**Poll model** (Kotlin `P2PService`): a separate `HandlerThread`; interval `nextPollDelayMs`: 1 s while a chat is open; 2–3 s and increasing when idle; 5 s with screen off and the core busy; 30 s when fully idle (12 empty polls) (`DEEP_IDLE`, wake lock released). Each poll runs `poll_events()`: radio window / Tor dormant decision → `call_sweep` → drain swarm events → dedup → `process_incoming_envelope` → keepalive/reconnect/retry sweeps → JSON events.

**Discovery / reconnection:** the QR's `rendezvous_node`, the `device_addrs`/`device_onion_addrs` tables, `AddressAnnounce`, relays (`known_relays`, ≤10), `dial_with_relay_fallback` (onion, direct and relay circuits are dialed concurrently). `reconnect_sweep` every 15 s (fast window 3 s/60 s); for a failing target, exponential back-off from 15 s to 10 min (in power-saving mode ≤3 hours). **Fan-out filter:** a device not seen for 7 days (`STALE_PEER_RETRY_HORIZON_MS`) is excluded from `fanout_targets`/`sibling_active_devices`/`contact_device_targets` (so an abandoned old phone does not fill the server mailbox with 5000 items); if none has been seen recently, all active devices are used.

**Keepalive:** interval 2 s (fast) / 20 s (idle) / 60 s (power save); `KEEPALIVE_FAILURES_BEFORE_DISCONNECT` = 3 consecutive errors = disconnected (the timeout rule for slow Tor links is documented next to it in `tuning.rs`); 3 timeouts in the server RPC = disconnected.

**Radio window:** `RADIO_WINDOW_MS` 8 min (Wi-Fi 4 min), `RADIO_AWAKE_MS` 30 s, `TOR_FULL_WAKE_MS` 45 min. **Bulk dial protection:** `BULK_PARALLEL_CONNECTIONS` 3, `BULK_DIAL_MIN_INTERVAL_MS` 6 s (back-off up to `BULK_DIAL_MAX_BACKOFF_MS` 120 s), `BULK_STRIKES_TO_DROP` 3 strikes within `BULK_STRIKE_WINDOW_MS` 60 s drop the dial; after `BULK_MAX_DROPS_BEFORE_GIVEUP` 3 drops, a `BULK_GIVEUP_COOLDOWN_MS` 5-minute cool-down.

---

## 13. Server (store-and-forward)

### 13.1 Protocol
`/typeon/server/1.0.0`, libp2p request-response with CBOR. Wire limits: request ≤ 1 MiB (hard codec limit; anything larger is silently truncated), response ≤ 10 MiB → so `MAX_DEPOSIT_BYTES = 900 KiB`; an envelope above that is never tried on the server (direct envelope path only).

`ServerRequest`: `Hello{version}` (version **8**, `SERVER_PROTOCOL_VERSION`; version history in `server_proto.rs`: 2 `Registered`, 4 blob `upload_secret`, 5 session/relay mailbox id from the proof key (`key_bound_mailbox_id`), 6 24-byte upload secret + author tag, 7 the blob id hashes only the bytes after the tag, 8 archive bucket id = hash of a per-bucket purge secret; `ArchivePurge{purge_secrets}`), `Enroll{…}`, `Rebind{…}`, `Register{add, drop, proofs}`, `Deposit{mailbox, sealed}`, `Fetch{cursors, max_items, max_bytes}`, `Ack{acks:[(mailbox, seq)]}`, `Cancel{mailbox, seqs}`, `ArchivePut/Probe/Fetch/Purge`, `BlobPut/Finish/Delete`; server → client: `Notify`, `Push{item}`.
`ServerResponse`: `Welcome{version, challenge, enrolled, enrollment_id, limits, server_name}`, `Enrolled{enrollment_id, limits}`, `Deposited{seq}`, `Batch{items, more}`, `ArchiveProbed`, `ArchiveBatch`, `Registered{proof_needed, refused}` (the reply to `Register`; if every mailbox is accepted it is a plain `Ok`; no old `ProofNeeded`), `Ok`, `Err(code)`. Error codes (`ServerErrorCode`): `NotEnrolled, BadInvite, BadSignature, Stale, UnknownMailbox, TooLarge, QuotaExceeded, RateLimited, Revoked, BadDirection, Unsupported, Internal, BadHash, BlobIncomplete`. `MailItem.seq` increases **per mailbox** (see §13.3).

### 13.2 Enrolment (server side `typeon-server/src/handlers.rs`)
Every request first passes `check_rate` (`handle_request`): a per-peer budget of `requests_per_minute` = 1800 units per `RATE_WINDOW_MS` (60 s); a request costs `1 + n/8` units (`limits.rs request_cost`; `n` = list lengths, proofs ×64, archive bytes), `Enroll`/`Rebind` cost 30, file chunks use their own budget `CHUNKS_PER_MINUTE` = 600. Over budget → `RateLimited`.
- `Hello`: version ≠ `SERVER_PROTOCOL_VERSION` (8) → `Unsupported`. Otherwise a random 32-byte `challenge` is stored on the connection and `Welcome{version, challenge, enrolled, enrollment_id, limits, server_name}` is returned. `enrolled` and `enrollment_id` are set only when this PeerId's record is `Active` (a revoked record reads as not enrolled, so the client goes to `Enroll` and gets `Revoked`).
- `Enroll`, in this order: version (`Unsupported`); `|now − ts_ms| ≤ ENROLL_MAX_SKEW_MS` = 5 min (`Stale`); the invite-token hash has uses left (`BadInvite`, before any expensive work); the connection's single-use challenge is taken with `take()` and compared in constant time (`BadSignature`); `verify_budget(Enroll)` (per peer 4 per window, server-wide 120 per window → `RateLimited`); the hybrid signature `enroll_signing_input(version, server_peer_id, client_peer_id, token, enroll_pk, enroll_pk_pq, challenge, ts)` is verified (**a failed signature spends one use of a counted invite**; the public code has none to spend); only after that, if the new key or the key of this PeerId's earlier record is in `blocked_keys` → `Revoked`; for the public code (`uses_left == -1`): at most `MAX_PUBLIC_ENROLLMENTS_PER_HOUR` = 60 enrolments of any kind in the last hour, and the code may hold at most ¾ of `max_enrollments` active places (a PeerId that is already active is exempt) → `QuotaExceeded`; active enrolments (not idle for 30 days) reach `max_enrollments` (default 16) → `QuotaExceeded` (again exempt for an already active PeerId). A repeat enrol of the same PeerId keeps its `enrollment_id` and quota counters. `enroll_with_invite` consumes the use and writes the record in one transaction (`Ok(false)` → `BadInvite`).
- `Rebind`, in this order: `ts` window (`Stale`); the challenge is taken (`BadSignature`); record unknown → `NotEnrolled`; budget: 4 per `enrollment_id` per window and `verify_budget(Rebind)` (120 per window server-wide, a pool separate from `Enroll` so a flood of bad `Enroll`s cannot lock enrolled devices out) → `RateLimited`; hybrid signature by the record's own `enroll_pk` over `rebind_signing_input(enrollment_id, server_peer_id, new_peer_id, challenge, ts)` (`BadSignature`); **only then** `Revoked` (record revoked or key blocked), so someone who knows the id but not the key learns nothing about the status. The record then moves to the new PeerId; the invite is not consumed.
- **Revoke = block.** Revoking puts the record's `enroll_pk` into `blocked_keys` (`store/enrollments.rs`). The same key cannot come back, but a reinstall (new PeerId, new enrol key) with a usable invite can re-enrol. A real ban means rotating the join code. Uninstalling the server app deletes the onion identity and every enrolled device's token.
- Authenticated requests (`handle_authenticated`): no record → `NotEnrolled`; revoked → `Revoked`. List sizes are capped by `max_mailboxes` (512 default), `Register` proofs ≤ 64, `ArchivePut` ≤ 256 records (`TooLarge`); ids must pass `is_safe_id` (`BadDirection`).

### 13.3 Mailbox semantics (`store/mail.rs`; enrolment in `store/enrollments.rs`, archive in `store/archive.rs`, blobs in `store/blobs.rs`; schema `SCHEMA_VERSION` = 6; tables `enrollments, invites, mailboxes, mailbox_readers, mail, mail_seq, mail_acks, archive, blobs, blob_chunks, blocked_keys, meta`)
- **`Register{add, drop, proofs}`:** the number of proofs for ids in `add` is charged to `verify_budget(Register)` (64 per peer per window, no server-wide pool) → `RateLimited`. A proof is a hybrid signature over `register_signing_input(mailbox, enrollment_id, server_peer_id)` by the mailbox key (derived from `mailbox_proof_seeds`). The server stores a **per-reader** key hash (`mailbox_readers.key_hash`). For each id in `add`: already registered by this owner → idempotent; else the owner's reader count is at `max_mailboxes` → `refused`; no verified proof → `proof_needed`; an id with the `mk_` prefix must equal `key_bound_mailbox_id(proof key)` → otherwise `refused`; at most `MAX_READERS_PER_KEY` = 2 readers per key per mailbox: a newcomer with the same key replaces the same-key reader seen longest ago, only if that reader was idle for 7 days (`READER_EVICT_IDLE_MS`), otherwise `refused`. A proof that did not verify counts as `refused`. If nothing is refused or unproven the reply is a plain `Ok`, otherwise `Registered{proof_needed, refused}`. Accepted ids go into `live_interest[peer]` (the target of Push/Notify); `drop` removes the owner's reader row, runs `delete_fully_acked` and removes its ack row.
- **`Deposit`**, in this order: `sealed` over `min(max_item_bytes, MAX_DEPOSIT_BYTES)` (`TooLarge`); no other **active** registered reader (`mailbox_has_other_reader`) → `UnknownMailbox`; the depositor's `bytes_mail > max_mail_bytes` → `QuotaExceeded`; the total disk budget (`total_budget_exceeded`; mail may use the whole budget, archive and blobs stop at 90 %: `MAIL_RESERVE_DIVISOR` = 10) → `QuotaExceeded`; this depositor's un-acked rows in this mailbox ≥ `max_items_per_mailbox` (5000) or its bytes in it plus the new row > `max_mail_bytes / MAIL_BOX_SHARE` (8) → `QuotaExceeded`; per (PeerId, mailbox) more than `DEPOSIT_BYTES_PER_BOX_WINDOW` = 16 MiB per `DEPOSIT_WINDOW_MS` = 1 hour → `QuotaExceeded`. A row costs `sealed.len() + mailbox_id.len() + 128` bytes (`mail_row_bytes`), charged to the **depositor**. If the same `(mailbox, depositor, sha256(sealed))` exists, no row is written, the TTL is refreshed and the old `seq` is returned (idempotent, not charged, no push). Otherwise `seq` comes from the per-mailbox counter `mail_seq` (`INSERT … ON CONFLICT DO UPDATE SET last = last + 1 RETURNING last`; first value = `meta.mail_seq_base` + 1; the row is never deleted, so a cursor never ends up above new mail); `expires_at = now + mailbox_ttl_ms` (14 days).
- **`Fetch{cursors, max_items, max_bytes}`:** per `(mailbox, after_seq)` it returns rows with `seq > after_seq` and `depositor != requester`, only when the requester is a registered reader of that mailbox, in `seq` order. Clamps: items 1..=64, bytes 1..=512 KiB; the first item always goes out even if it is over `max_bytes`; `more = true` when the batch was cut. A Fetch clears the pending Notify of that peer.
- **`Ack{acks}`:** only the highest `seq` per mailbox counts; only a registered reader's ack is taken; the value is clamped to the mailbox's `MAX(seq)` and stored in `mail_acks` only if it advances. Then `delete_fully_acked`: a row is deleted when at least one non-depositor reader has acked it and every **active** non-depositor reader has acked it. A deletion sets `mail_recount_due` (bytes are charged back to the depositor on the next 5 s tick). The whole request runs in one transaction; a failure returns `Internal`.
- **`Cancel{mailbox, seqs}`:** the depositor deletes its own rows (`depositor = requester` in the query).
- **Sweep.** Every 5 s tick (`maybe_sweep`): when the DB `data_version` changed, peers that were revoked or blocked lose their `live_interest` and relay links; mail bytes are recounted if due; `resend_notifies`; a connection with no active enrolment is dropped after `UNENROLLED_GRACE_MS` = 60 s (not in node mode). Every `SWEEP_INTERVAL_MS` = 60 s: old connection and window state is pruned, then the clock guard: if the wall clock differs from where the monotonic clock says it should be by more than `CLOCK_JUMP_MS` (24 h), the TTL sweep is held for `CLOCK_JUMP_HOLD_MS` (1 h); after that the new time is accepted and a forward step moves the stored deadlines (`shift_deadlines`) so nothing expires because of the step; a wall clock before 2026-01-01 (`SANE_WALL_FLOOR_MS`) skips the sweep. Then: `sleep_idle_enrollments` (idle 30 days), `sweep_expired_mail`, `sweep_expired_archive` (13 months), `blobs_to_gc` (`blob_ttl_ms` 30 days), blob byte recount, `prune_dead_rows`, `incremental_vacuum`.
- **Notification** (`notify_owner_of`): for each connected, active peer other than the depositor that has the mailbox in `live_interest`: `Push{item}` (inline) when the sealed item is ≤ `PUSH_INLINE_MAX` = 64 KiB **and** exactly one item is un-acked for that reader; otherwise `Notify`, sent once until the peer fetches. Unanswered `Notify`s repeat after `NOTIFY_RESEND_MS` = 20 s, doubling per try up to 16× (320 s), checked every 5 s.

### 13.4 Client-side flow (`server_client/mod.rs`)
**Connection lifecycle:** when the server connects, `Hello` → `Welcome`; if `enrolled`, `server_sweep_at = 0` (immediately `Register` + `Fetch`); otherwise `begin_enrollment`: if already enrolled, `Rebind` (persistent `enrollment_id` + enroll key); if there is a token, `Enroll` (server-specific Ed25519 secret key of 32 bytes + ML-DSA-87 **seed**; if absent, the error "Enrollment key in old format"). If the connection drops, `enrolled=false` and `registered` is cleared.
**Sweep** every `SERVER_SWEEP_INTERVAL_MS` = 15 s: if enrolled, refresh the mailbox registrations (`Register`, mailboxes derived from ratchet roots + first-contact mailboxes); `Fetch` at least every `SERVER_FETCH_SWEEP_INTERVAL_MS` = 5 min, and immediately on `Notify`/`Push`.
**Fetch processing** (`Batch{items, more}`):
1. If the item's mailbox is not one of ours, skip; if `seq ≤` the recorded cursor, skip.
2. Open: session mailbox → `open_envelope(root_key, mailbox, peer_fp)`; first-contact mailbox → `open_first_contact(secret, mailbox, kem_sk…)`.
3. If it opens, the raw envelope goes into `incoming.push((None, raw))` and onto the **normal `process_incoming_envelope` path** (`source = None`). **An item that does not open is not Acked; the mailbox cursor stays before it; it is held for 5 min (`SERVER_HOLD_GRACE_MS`), re-fetched every 45 s (`SERVER_HOLD_REFETCH_MS`); when the time runs out it is skipped. A first-contact item that does not open is skipped at once; after two skips in a row a mailbox gets no hold grace until a hold clears. The cursor is never moved to that item's `seq`.** If processing a fetched item fails (`server_item_failed`), the cursor is rolled back in the same way.
4. For each mailbox, the highest (successful) `seq` is persisted as the cursor (`persist_cursor`) and `Ack{acks}` is sent; if `more && progress`, Fetch again immediately.
**`Push`:** a single item is handled through the same path as a one-item `Batch`; if more than 30 `Push`es arrive from the server within 5 s, it behaves like `Notify` and falls back to bulk fetch.
In radio saver, a `Notify` after an empty fetch counts once per radio window.
**Deposit side** (`server_client/mailbox.rs try_server_deposit`): see §7. On `Deposited{seq}`, `server_deposit_locations[(server, message_id)] = (mailbox, seq)` is stored (for `Cancel`). If the envelope was cancelled while being deposited, the returned `seq` is cancelled at once.
**Error handling** (`handle_server_error`):
| Code | Behaviour |
|---|---|
| `UnknownMailbox` | That (server, mailbox) is marked "unknown", and the pause **doubles on each consecutive reply**: 60 s (`SERVER_UNKNOWN_MAILBOX_TTL_MS`) << `min(streak, 6)`, at most 60 min (`SERVER_UNKNOWN_MAILBOX_MAX_TTL_MS`); the streak is kept in `server_unknown_streak[(server, mailbox)]`; **deposits in flight at the same time** count as one step while the pause lasts; a successful `Deposited` to that mailbox clears the streak (fb5fecd; before this, for a device never registered on the server, every 2-minute retry re-deposited unacked packets over Tor, keeping the LTE radio on 60–75 % overnight). The envelope stays on the pending-envelope retry queue. Account deletion/wipe (`contacts.rs wipe_all_local_state`) also clears the streak |
| `NotEnrolled` | `enrolled=false`, `Hello` again; if during `Rebind`, the `enrollment_id` is deleted ("add a new join code") |
| `Revoked` | the `enrollment_id` is deleted, "operator revoked" |
| `QuotaExceeded` (Deposit) | that mailbox only is paused: 5 min (`SERVER_DEPOSIT_BACKOFF_MS`), doubling to at most 60 min (in the same `server_unknown_mailboxes` map); the envelope stays on the retry queue. A depositor may hold at most `max_mail_bytes/8` and put at most 16 MiB/h into one mailbox |
| `RateLimited`, `Internal` | treated as temporary; back-off of 5 min on deposit (`SERVER_DEPOSIT_BACKOFF_MS`) |
| `BadInvite` (Enroll) | the token is deleted |
| `BadHash` (BlobFinish) | permanent: stored bytes do not match `enc_sha256`; the same Finish will never work |
| others (`TooLarge`, `BadSignature`…) | permanent; the blob/archive work is dropped |
Timeout/connection error (`handle_server_failure`): deposit back-off; the envelope stays on the retry queue and the direct path is tried again. Every envelope has at least one path (direct, server or retry queue); the server is never the only delivery path.

### 13.5 Server-side privacy and sealing
- The session mailbox is **fixed** per device pair (`server_client/mailbox.rs session_mailbox`): a static DH between the two devices' long-lived KEM X25519 keys, plus HKDF over the ordered fingerprints (`server_seal::session_mailbox_secret`, `p2pmsg-v0.6-session-mailbox:`); it does not change on rotation and is not derived from root_key/topic (X25519 only, no static ML-KEM). The mailbox id is a **hash of the proof key** derived from this secret: `mk_<hex16>` (`server_client/mailbox.rs key_bound_mailbox_id` → `server_proto::key_bound_mailbox_id(mailbox_key_hash(...))`); the call relay mailbox uses the same form from `pair_key`. For an `mk_` mailbox the server accepts no other key (§13.3): knowing the id is not enough to become a reader. The sealing key still comes from the ratchet root (the recipient tries the current and the previous root). The first-contact mailbox = HKDF(secret, `p2pmsg-v0.5-first-contact-mailbox:`‖fp) — the secret can be the pairing nonce, the link nonce, or the **per-group** first-contact secret (see §11); the first-contact mailbox has the form `mb_<hex16>` (not key-bound); its reader proof key comes from the reading device's own Ed25519 signing key (`server_client/mailbox.rs own_server_mailboxes`, `mailbox_proof_seeds`).
- `seal_envelope`: ChaCha20-Poly1305(HKDF(root_key, `p2pmsg-v0.1-server-seal`), AAD = mailbox‖0‖sender_fp, CBOR(envelope)). The server knows the AAD but not the key.
- `seal_first_contact`: shared secret (`p2pmsg-v0.5-first-contact-seal`) + the recipient's KEM key if present; opening with `open_first_contact(secret, mailbox, kem_sk_x25519, kem_sk_mlkem, sealed)`.
- **Padmé padding** (c8ca950, `typeon-crypto/src/server_seal.rs`): `seal_envelope`, `seal_first_contact` and `seal_archive_record` pad the plaintext (`0x80` marker + zeros, Padmé rounding, `MIN_PADDED_LEN` 512) **inside** the AEAD; `unpad` runs after the open. Caps keep an item within the wire limit (`ENVELOPE_PAD_CAP` = `MAX_DEPOSIT_BYTES` − nonce − tag; `ARCHIVE_PAD_CAP` = half of `MAX_DEPOSIT_BYTES` − nonce − tag). The server sees only size classes (overhead up to ~12 %). Items sealed before this change do not open (protocol break). Blob chunks and `sent_at_ms` are not padded.
- The server database holds no identity/fingerprint/content; `enrollments` holds only `enroll_pk`, `enroll_pk_pq`, `peer_id`, status, and counters.

### 13.6 Archive and blobs (verified in code)
- Restore and group history (GRP fix pass): a server restore keeps the deleted/edited marks. "Fetch older history" in a group asks at most 3 members (founder first, then the longest-standing). Held rows are not re-verified; a signed tombstone replaces a held original. A Delete is acked only after it is applied.**Archive — server:** `archive_put` writes records keyed by `(bucket, record_id)`; on conflict it **overwrites only if `rev` is larger** (`WHERE excluded.rev > archive.rev`), so an old revision cannot overwrite a newer one. `record_id` ≤128 bytes, bucket must pass `is_safe_id`, record ≤900 KiB; `max_archive_bytes` (1 GiB) and the total disk budget are checked; the per-record `owner` byte counter is recalculated.
**Archive — client:** records are queued with `queue_archive_record` **only if `store_history` is on with a server open and the root archive key exists** (plain text waits sealed locally with `seal_local_blob`); an `ArchivePut` batch closes at 50 records (`SERVER_ARCHIVE_BATCH`) or when the sealed bytes exceed `MAX_DEPOSIT_BYTES/2`. Restore: `ArchiveProbe(buckets)` (restore reads at most 4096 pages per conversation) → non-empty buckets (newest first if `before_ms` is given) → `ArchiveFetch{bucket, before_ms}` paged (if `more`, `before_ms` = the oldest `sent_at_ms` on the page) → `merge_server_archive`: each record is opened with `open_archive_record(ark, conv_key, record_id, rev, bucket, sent_at_ms, sealed)` (the AAD binds these fields); `note_archive_rev` **rejects a `rev` older than one already seen** (`server_archive_revs` table); if a message with the same `record_id` already exists locally it is **skipped** (so the server archive never changes an existing message, it only fills in the missing ones); for a non-group, it is written to the conversation with `resolve_active_device_for_identity(conv_key)`. The result is a `history_backfilled{count, source:"server"}` event. Records that cannot be decrypted or parsed are skipped.
**Blob — client** (`queue_blob_upload` / `server_flush_blobs`): queued only if `route_messages` is on with a server open; **only one blob is uploaded at a time** (the one at the head of the queue); the state is persisted in the `server_blob_uploads` table. Chunks are read from the encrypted file on disk with `chunk_size`, and `window` of them are kept in flight (start 4, min 2, max 40; it grows while RTT stays under twice the base and below 80 % of the 90 s timeout, and halves on a timeout). When all chunks are done, `BlobFinish` is sent with the SHA-256 of the encrypted file. If the server changes, the upload starts again from the beginning. Blob `Internal` answers back off 15 s → 30 min and drop the upload after about 3 h. An upload stays on its server unless that server has been down 30 min.
**Blob id and group tag:** the upload secret is 24 bytes = 8-byte author tag + 16 bytes; only the derived blob id goes into `FileOffer`. In a group file the tag is now **different per file**: `util.rs group_msg_tag(group_id, author_identity, rest)` = the first 8 bytes of SHA-256(`typeon-group-msg-id-v2` ‖ group ‖ 0 ‖ author ‖ 0 ‖ rest); in a file, `rest` = the hash part of the identity (`blob_id_hash_hex`), and in text `-<uuid>`. So the server cannot link two files of one author from their tags (I-42). The receiver recalculates with `util.rs group_msg_id_bound` that the identity belongs to that author. Result: server protocol 6 → 7 (**protocol break**).
**Blob — server:** `BlobPut` writes the chunk to the file at `offset = chunk_index × (chunk_size + 16)` (random access; chunk ≤768 KiB; owner check; both the single-blob offset and the per-record `bytes_blob` cannot exceed `max_blob_bytes` 4 GiB; if the same chunk comes again it returns `Ok`; while the hash is running it returns `RateLimited`). `BlobFinish`: owner must match; the number of received chunks must not be less than `total_chunks` (otherwise `BlobIncomplete`: not permanent, the client re-uploads from chunk 0); at most `MAX_HASH_JOBS` = 4 hash jobs at the same time (otherwise `RateLimited`); the hash is computed in the background as a stream, and the reply goes out when the hash finishes. **On mismatch the file is deleted and `BadHash` is returned.** A completed blob is served with the `filexfer` protocol (`serve_chunk`; chunk rate limit 600/min; relay/cold budgets separate); garbage collected after `blob_ttl` (30 days); a blob lives at most 60 days after upload whatever is served, and an incomplete upload at most 7 days.

### 13.7 Data-directory lock, DB encryption, archive lifetime
- **Process lock:** a `server.lock` file in the data directory is locked with `flock` (held for the whole life of `ServerCore`, `_dir_lock`); a second server cannot open the same directory ("this data directory is in use by another server process").
- **DB encryption:** the Android server app opens the DB with **SQLCipher** — the key is 32 random bytes, wrapped by an AES-GCM key in the Android Keystore that cannot be exported (`DbKey.get`), and given to the core as 64 hex characters via `ServerLib.setDbKey`. An old plain DB is migrated to an encrypted DB **once** on first open (`sqlcipher_export`); if no key arrives the server **stops** (fail-closed; it never falls back to a plain DB). The Linux `typeon-server` **stays plain**; if `TYPEON_SERVER_DB_KEY` (64 hex) is given, it is opened encrypted the same way (the plain DB is still migrated once).
- **Archive lifetime:** archive rows are deleted **13 months** after they were last written (`ARCHIVE_TTL_MS` = 13×30 days; `sweep_expired_archive`, runs with the mailbox sweep, quota counters are recalculated).
- **PIN lock (server app, `ServerLock.kt`):** the whole screen (join code, device list, settings) is behind a PIN; PBKDF2-HMAC-SHA256, 600,000 iterations (PINs saved before are read with 300,000, `KEY_ITERATIONS`), at least 6 characters; after 5 wrong attempts an increasing wait (30 s, then exponential); locks at once when the screen turns off, and 30 s after leaving the app.

---

## 14. Local storage and key management

- **DB:** `p2p_messenger.db`, SQLCipher (`rusqlite` bundled-sqlcipher-vendored-openssl). `PRAGMA key = x'…'` (from HKDF), `WAL`, `synchronous=NORMAL`, `secure_delete=ON`. An old plain DB is encrypted on first open (one-time migration).
- **Key chain (Android):** `KeystoreCrypto` — an AES-256 key in the Android Keystore (StrongBox → TEE); the secret key bundle produced by Rust (`SecretKeyBundle`) and the `storage_key` are wrapped with this key and written to file (`IdentityManager`, `ArchiveKeyManager`). **The AppLock password is NOT used for DB or key derivation**; it is only a UI gate (a PBKDF2 hash is stored; the lock is asked again when the process dies). So device root/memory access or a Keystore attack bypasses AppLock; this is a known limit.
- **Linux:** the vault key is in Secret Service (GNOME Keyring / KDE Wallet, `keyring.rs`; the vault `secrets.rs`, optional password). **Windows:** the vault key is in a DPAPI-sealed file (`keyring_win.rs`, `vault-key.dpapi`). Both are only the secondary-device vault (§1.2).
- **Row encryption:** history, skipped keys, ratchet state, and file keys are also sealed with `seal_with` (random-nonce ChaCha20-Poly1305) (`ratchet_states.sealed` etc.).
- **Tables:** see HANDOFF §3.8. New columns are added with `ALTER TABLE` in `migrate` (`db.rs init_db`): **every `ALTER TABLE` error other than `duplicate column name` fails `init_db`** (so a missing column cannot silently break later INSERTs; 6a603c7); `CREATE INDEX` and fill steps that can fail because of the data stay best-effort. The server DB follows the same contract (`typeon-server/src/store/mod.rs init_schema`, `add_column`; `user_version` is stamped only after success, so the next open retries).
- **Recovery file:** `RecoveryFile{kdf:"argon2id", m/t/p, salt, nonce, ciphertext}`; password ≥12 characters; contents: identity, all device secret keys, root archive key, data (limit 64 MiB; if exceeded, the newest 6500 messages). Export writes Argon2id m = 64 MiB, t = 2, p = 1 (16-byte salt). On import the parameters are checked before any work: m ≤ `MAX_RECOVERY_ARGON2_M_COST_KIB` (128 MiB), t ≤ 10, p ≤ 4, and m × t ≤ 4 × (64 MiB × 2); a larger file is "Corrupt recovery file (Argon2 parameters out of range)".
- **Backup** off (`allowBackup=false`); `FLAG_SECURE` in the client only where the owner allows it (release builds; `P2PApplication.setSecure`): link-device QR, QR scan, camera and lock screens; every screen on API < 33; chat screen and media viewer while a disappearing message is shown; the image editor dialog. Ordinary chat, list and settings screens are not protected. The server app sets it in release builds.

---

## 15. Files and media

- Storage and files (GRP/STO fix pass): the storage limit counts received attachments only; sent files are neither counted nor evicted; failed partials count toward it and are evicted first. "Cache" includes `sticker_cache`. `shutdown()` deletes `plain_cache` and wipes the key fields. Chunk answers are capped at blob chunk size + 4 KiB. Serving budget: 3 × file size + 16 MiB per (peer, file) per day, then `Busy`. At most 3 automatic resumes (`files.auto_resumes`, reset by progress). No fsync per chunk: a resume re-checks every chunk group against the offer's hashes and `finalize_download` syncs once. An orphan `.enc` sweep runs at start. A 1:1 offer's packet id is the file id; new columns `files.sent_at_ms`, `send_status`, `auto_resumes`. JPEG: a JFIF APP0 is kept only without a thumbnail; JPEG XL container allow-list `ftyp/jxll/jxlc/jxlp/jxli`. JPEG XL decoding: the header must parse from the first 64 KiB, all frames count against the budget, GIF/frame conversion stops after 60 s, allocation cap 256 MiB on Android. Sticker sync: `SiblingEchoBody::StickerRemoved` carries a list of ids (one echo per multi-delete; `deleteStickers` JNI).

- `FileOffer` (metadata, Acked) → the recipient asks for chunks with `/p2pmessenger/filexfer/1.0.0` (`FileChunkRequest/Response`). A random key per file; chunks are encrypted. Multi-source download (sender, siblings, server `alt_source_peer_ids`), automatic resume, identity-verified recovery. `FileChunkResponse::Busy` = the server's rate limit; the client retries the same source after `DOWNLOAD_RETRY_DELAY_MS`. Limit 4 GiB (`MAX_ATTACHMENT_SIZE`).
- Server blob: chunks stay encrypted with the file key on the server; `BlobPut/Finish`, `blob_ttl 30 days`.
- Privacy on sending: metadata stripping (`attachments/mod.rs`) covers **JPEG, PNG, JPEG XL and WebP**; for other formats (HEIC/AVIF, TIFF, GIF, RIFF files that are not WebP, MP4/MOV, audio, documents) EXIF/GPS is **not stripped** in the core. ICC profiles are kept by design (Android `OutgoingMedia.kt` also re-encodes/remuxes; Linux `prepare_outgoing` does the same). A visual (non-JPEG/PNG) that cannot be re-encoded (undecodable HEIC, animated WebP, GIF over the limit, alpha on API 26–27) and video that cannot be remuxed go out unchanged on both clients only if the user confirms "send with metadata?". If JPEG/PNG metadata cannot be parsed, the file is **rejected** (fail-closed), not sent dirty. Orientation is kept.

---

## 16. Calls and whiteboard

### 16.1 Call state machine (`call/mod.rs`, one `CallSession`; signalling in `call/signalling.rs`, media in `call/media_link.rs`)
`CallPhase`: `Outgoing`, `Incoming`, `Active`. Only one call at a time (`"A call is already in progress"`).

**Start:** `start_call(peer)`: invites **all devices** that have a ratchet inside `fanout_targets(peer)`. Group: `group_call_devices` = the active and **recently seen** devices of the other members. Each participant generates a **fresh random** `my_key` (32 bytes) and `my_sid` (8 bytes) per call (`CallSession::new`) and opens the media engine with `media_start`.

**Signal** = `MessageContent::Call{call_id, action, group_id, video, media_key, stream_id, sent_at_ms, participants}`, through the normal ratchet/E2E path; while `call_signal_sending=true` it counts as `critical` (both server and direct). In `Invite` and `Accept`, the key is **per recipient**: `media_key = pair_key(my_key, recipient_fp) = HKDF(my_key, "typeon-call-pair-v1"‖recipient_fp)`, `stream_id = my_sid`. Because each recipient gets a separate key, a member cannot seal packets as if it were another member.

**Group invite carries participants (C10):** the group `Invite`'s `participants` = the fingerprints of **all devices the caller rang** (≤ `MAX_INVITE_PARTICIPANTS` = 1024). The recipient also exchanges keys with members it considers "stale": devices in the list that are active devices of the group's members are added to the invite (excluding its own device).

**Recipient rules** (`handle_call_signal`):
- `Invite`: key lengths 32/8; `sent_at_ms` within ±60 s (`INVITE_MAX_AGE_MS`; a late invite does not ring); if this `call_id` is already over, ignore it; for a group call, the sender must be a member. **Glare:** if both sides call 1:1 at the same time, the smaller `call_id` wins (`ours < call_id` → the incoming is ignored, otherwise ours is ended and the incoming accepted). If we are in another call, reply `Busy`.
- `Accept`: `call_id` must match; if the sender was invited, or (group and member) it is added to the list; `Outgoing` → `Active`; in 1:1, `Hangup` goes to our other devices (stop ringing); `media_add_remote(peer, key, sid)`. In a group, a new member who joins an active call later gets an `Accept` reply with the key.
- `Reject/Busy/Hangup`: the participant is removed; the call ends according to the 1:1/group/phase combination (`over`). For an unanswered 1:1 incoming call, "📞 Missed call" is written to the archive.
- Timeouts: ringing 45 s (`RING_TIMEOUT_MS`, both directions); when active, if no media arrives from anyone for 30 s the call is `lost` (`MEDIA_LOST_MS`; each participant sends a status packet every second).

**Group call offers (7.5.0, call/mod.rs):** a running group call is kept as a `GroupOffer` (`GROUP_OFFERS`) so a member who was absent can join from the group chat with **Attend** (`start_group_call` joins the offer). The caller re-invites absent members every 30 s for 5 min (`REINVITE_FOR_MS`, `REINVITE_EVERY_MS`), then every 2 min (`REINVITE_LATE_EVERY_MS`; each Invite is also left on the server). An offer without a new Invite for `OFFER_TTL_MS` (150 s) is gone even if `Ended` was lost; after the inviter's Hangup it lives `OFFER_HANGUP_GRACE_MS` (40 s). `CallAction::Ended` (sent by the last participant to every member device) drops the offer and the ring on every re-invited device. `CallAction::Joined` goes only to my own other devices: they stop ringing and hide Attend while this device is in the call (`SIBLING_CALLS`, `silence_siblings`). A `Busy` from a sibling also stops the ring. A Hangup that overtakes its Invite is remembered (`EARLY_HANGUP`).

### 16.2 Media path
Kotlin does the coding (Opus audio; video H.264/HEVC — flag bit; on Linux/Windows an HEVC sender switches to H.264 for the rest of the call when a receiver asks), and the core's `media_send(kind, payload)` **encrypts independently of the core lock and of the poll loop** and pushes to per-link channels; tokio tasks write to long-lived libp2p-stream streams.
- **Packet:** `[ver=1][stream_id 8][seq u64 BE]` + ChaCha20-Poly1305(`[kind][sent_ms u32][payload]`), AAD = header (17 bytes), nonce = `stream_id[..4]‖seq`. `kind`: 1 audio, 2 video, 3 report, 4 status.
- **Path (per target device):** if there is a live direct connection, the `/typeon/media/1.0.0` stream; otherwise the server relay stream `/typeon/relay/1.0.0`, with address = `server_client::key_bound_mailbox_id(pair_key)`; the server does **not store** it, it forwards only if the target is connected at that moment (frame: `[u16 mailbox len][mailbox][u32 len][data]`). If the file `call_force_relay` exists, the relay is forced for testing (debug builds only). Call signals ride the ratchet path (direct libp2p or store-and-forward) and are sent once: no Ack, no retry. A device dropped as silent (30 s without a packet, counted from its Accept when it never sent one) gets an Invite of the call; a device already in the call answers such an Invite with an Accept. An Accept for a call known to be over gets a Hangup. `Ended` is accepted only from the offer's inviter or a device in the ringing call. The never-ring memory holds 256 entries.
- **Receive** (`media_on_packet`): from the header, `sid`+`seq` → open with the key of the matching `Remote`; replay/order window for the last 64 `seq` (`is_new`); `STATE`/`REPORT` are consumed in the core; audio/video go to Kotlin as `[kind][slot][payload]` into `inbox` (≤64; when full, the oldest **video** is dropped and a keyframe is requested for that slot).
- **Congestion:** on the sending side the queue limit is 16 for audio and 6 for video (`LINK_QUEUE` 48); when full, packets are dropped (live media: late = useless). The receiver sends `REPORT{queue_ms, request_keyframe}` every 500 ms; if the queue is over 400 ms the sender holds audio (drops below 150 ms; held at most 5 s, `AUDIO_HOLD_MAX_MS`); `media_backlog` tells Kotlin to lower video fps/bitrate.
- Frame ≤256 KiB (`MAX_FRAME`).

### 16.3 Whiteboard (`whiteboard.rs`)
`WbOps` (signed strokes `WbStroke`) for 1:1 or group; page integrity with `WbPageSig`/`WbPageDigest`. Sync: a state summary with `WbDigest` (Acked, with `regen_content`); on a difference, `WbPageRequest` → `WbPage`. A group board is cleared with `wb_delete_board` when the group is deleted or left.

**The digest is a per-stroke content hash:** the page digest is the stroke count plus a SHA-256 (32 bytes) over the sorted per-stroke hashes (`wb_digest_item`; the stroke hash covers id + page + tone + thickness + points) → two copies with the same id but different content are **not equal**. `WbOps` go to connected devices only; offline devices get the digest (at most one per board per 15 s; a replaced one is withdrawn from the server). Strokes of departed participants are deleted when a digest is built or compared. Each erase record costs 1/256 of a budget unit.

---

## 17. Threat model (summary)

**Protected:** content confidentiality and integrity (E2E + PQ hybrid), forward secrecy (30-min rotation + chain key deletion), post-compromise recovery (rotation), sender identity (hybrid signature, bound to the recipient), replay (message_id dedup, consumed keys, handshake signature/time window), IP privacy (onion only; no clearnet dial), content privacy from the server (double seal, blinded mailbox name).

**Accepted / known limits:**
- The server operator sees volume (item sizes only as Padmé classes, §13.5), timing, and the PeerId↔mailbox mapping (the peer graph); it can delay or drop a message but cannot forge it (this is why the direct path is preferred whenever it is up, and the server copy is a fallback).
- The server archive is not forward-secret; the server can offer an old edit revision to a device that restores from scratch.
- `Handshake`/`IdentityExchange` stay readable on the server (the sender's name is visible); they carry only public keys + signatures.
- Noise transport is classical X25519 (the content is already hybrid).
- First contact is TOFU; QR/code verification depends on the user.
- AppLock is only a UI lock (it is not tied to key derivation).
- If the primary device is compromised, the identity is compromised (the authority root).
- If no prekey is used in the handshake (id 0), the first messages rely only on the long-term KEM; the responder rotates before its first send.

---

## 18. Constants (code values)

| Constant | Value | Location |
|---|---|---|
| `RATCHET_ROTATION_MS` | 30 min | ratchet.rs |
| `MAX_SKIPPED_KEYS` / `MAX_SKIP_AHEAD` | 1000 / 2.000 | ratchet.rs |
| `MAX_ACTIVE_DEVICES` | 5 | identity.rs |
| `ACK_RETRY_INITIAL_MS` / `ACK_RETRY_MAX_MS` | 15 s / 120 s | tuning.rs |
| `ACK_SUSPECT_MS` | 1.5 s | tuning.rs |
| `MAX_UNCONFIRMED_AGE_MS` | 25 min (= `RATCHET_ROTATION_MS` − 5 min) | tuning.rs |
| `TEXT_RETRY_GIVE_UP_MS` | 7 days | tuning.rs |
| `HANDSHAKE_MAX_SKEW_MS` / `HANDSHAKE_MAX_AGE_MS` / `HANDSHAKE_COLLISION_WINDOW_MS` | 10 min / 7 days (= `TEXT_RETRY_GIVE_UP_MS`) / 90 s | tuning.rs |
| `HANDSHAKE_REDO_MIN_INTERVAL_MS` (IdentityExchange time bucket) | 10 min | tuning.rs |
| `UNDECRYPTABLE_BEFORE_REHANDSHAKE` / `_WINDOW_MS` / `_REDO_MIN_INTERVAL_MS` | 3 / 2 min / 2 min | tuning.rs |
| `PREKEY_ROTATE_MS` | 7 days | types.rs |
| `INBOUND_DEDUP_WINDOW_MS` / `_MAX_ENTRIES` | 10 min / 8192 | tuning.rs |
| `RATE_LIMIT_WINDOW_MS` / `_MAX_PER_WINDOW` / `_MAX_ESTABLISHED` | 10 s / 60 / 600 | tuning.rs |
| `RECONNECT_SWEEP_INTERVAL_MS` | 15 s | tuning.rs |
| `KEEPALIVE_FAST_INTERVAL_MS` / `_IDLE_` / `_POWER_SAVE_INTERVAL_MS` | 2 / 20 / 60 s | tuning.rs |
| `MAX_ENVELOPE_BYTES` | 1 MiB | tuning.rs |
| `SERVER_PROTOCOL_VERSION` | 8 | typeon-crypto/src/server_proto.rs |
| `MAX_DEPOSIT_BYTES` | 900 KiB | server_proto.rs |
| `SERVER_DEPOSIT_BACKOFF_MS` | 5 min | server_client/mod.rs |
| `SERVER_UNKNOWN_MAILBOX_TTL_MS` / `_MAX_TTL_MS` | 60 s (doubles on each consecutive `UnknownMailbox`, 6 steps) / 60 min | server_client/mod.rs |
| `SERVER_SWEEP_INTERVAL_MS` / `SERVER_FETCH_SWEEP_INTERVAL_MS` | 15 s / 5 min | server_client/mod.rs |
| `SERVER_HOLD_GRACE_MS` / `SERVER_HOLD_REFETCH_MS` | 5 min / 45 s | server_client/mod.rs |
| `SERVER_ARCHIVE_BATCH` | 50 records | server_client/mod.rs |
| `SIBLING_BACKFILL_INTERVAL_MS` / `_SINCE_MARGIN_MS` | 30 min / 10 min | tuning.rs |
| `SIBLING_BACKFILL_PER_CONVERSATION` / `_MAX_ENTRIES` | 30 / 300 | tuning.rs |
| `HISTORY_SYNC_MAX_TEXT_BYTES` / `HISTORY_SYNC_MAX_MESSAGES` | 512 KiB / 200 | tuning.rs |
| `HISTORY_FETCH_MAX_PAGES` | 20 | tuning.rs |
| `mailbox_ttl_ms` | 14 days | server_proto.rs ServerLimits |
| `MAX_ATTACHMENT_SIZE` | 4 GiB | lib.rs |
| `MAX_CONTACTS` | 500 | tuning.rs |
| `PENDING_LINK_RETRY_HORIZON_MS` / `LINK_REQUEST_WINDOW_MS` | 1 hour / 1 hour (the second is set equal to the first) | tuning.rs |
| `PAIRING_WINDOW_MS` / `PAIRING_NONCE_REUSE_MS` | 30 min / 5 min | tuning.rs |
| `RATE_LIMIT_MAX_UNKNOWN_TOTAL` (unknown peers, total) | 300 / 10 s | tuning.rs |
| `MAX_ARCHIVE_PUT_RECORDS` | 256 | server_proto.rs |
| `MAX_FETCH_BATCH_ITEMS` / `MAX_FETCH_BATCH_BYTES` | 64 / 512 KiB | server_proto.rs |
| `MAX_BLOB_CHUNK_BYTES` / `BLOB_UPLOAD_SECRET_LEN` / `BLOB_TAG_LEN` | 768 KiB / 24 / 8 | server_proto.rs |
| `MAX_READERS_PER_KEY` / `READER_EVICT_IDLE_MS` | 2 / 7 days | typeon-server/src/store/mail.rs |
| `SCHEMA_VERSION` (server DB) | 6 | typeon-server/src/store/mod.rs |
| `PUBLIC_CODE_TTL_MS` (public join code lifetime) | 3 days (renewed, §21) | typeon-server/src/lib.rs |
| `DEFAULT_MAX_ENROLLMENTS` / `MAX_PUBLIC_ENROLLMENTS_PER_HOUR` / `ENROLLMENT_IDLE_MS` | 16 / 60 / 30 days | typeon-server/src/lib.rs |
| `NOTIFY_RESEND_MS` / `CHUNKS_PER_MINUTE` / `MAX_HASH_JOBS` | 20 s / 600 / 4 | typeon-server/src/lib.rs, limits.rs, blobs.rs |
| `ARCHIVE_TTL_MS` (server archive row) | 13 months (13×30 days) | typeon-server/src/store/mod.rs |
| `MAX_INVITE_PARTICIPANTS` / `RING_TIMEOUT_MS` / `MEDIA_LOST_MS` / `INVITE_MAX_AGE_MS` | 1024 / 45 s / 30 s / 60 s | call/mod.rs |
| `REINVITE_FOR_MS` / `REINVITE_EVERY_MS` / `REINVITE_LATE_EVERY_MS` / `OFFER_TTL_MS` / `OFFER_HANGUP_GRACE_MS` | 5 min / 30 s / 2 min / 150 s / 40 s | call/mod.rs |
| `DISAPPEAR_MAX_SECS` / `DISAPPEAR_UNREAD_SECS` | 4 weeks / 1 day | typeon-crypto/src/packet.rs |
| `MIN_PADDED_LEN` (Padmé floor for server-visible items) | 512 bytes | typeon-crypto/src/server_seal.rs |
| AppLock PBKDF2 | 600,000 it. | AppLock.kt |
| Server PIN PBKDF2 | 600,000 it. (300,000 for PINs saved before) | ServerLock.kt |
| `MIN_PASSWORD_LENGTH` (app password) | 8 | AppLock.kt |

Note: these constants change over time. Before relying on a number, verify it with `grep -n "CONSTANT_NAME"`.

---

## 19. 2026-10-20/21 fix round (protocol and behaviour changes)

_Historical section: `SERVER_PROTOCOL_VERSION` v4 and the code locations here are the state of that day; the current version is 7 (§13, §20) and the locations are in the modules of §1.1._

Source: `reviews/archive/MERGED_REVIEWS.md`, reports `reviews/fixpass-2026-10-20/report_*.md`. Not compiled, not tried on a device. Compatibility with old versions is not pursued.

**PROTOCOL BREAKS**
- **Server protocol v4** (`SERVER_PROTOCOL_VERSION`): `Register` → `Registered{proof_needed, refused}` (permanently rejected ones in `refused`); `Welcome` carries `enrollment_id`; `enroll_signing_input` also binds the client PeerId + `enroll_pk` + `enroll_pk_pq`; v4 blob requests carry an `upload_secret`, and the blob id is a hash of this secret.
- **Archive wire record id** = `HKDF(archive key, conversation, message id)` (keyed; previously derived in the open). DB: `server_blob_uploads.server_id` column. `sent_at_ms` is still in the clear (decision pending).
- **Packet signature input** is tagged and framed (`"p2pmsg-v0.5-packet"`; in the 3rd round `"p2pmsg-v0.6-packet"` and **raw header bytes**); **DeviceAdd/DeviceRevoke/consent** signature bytes use `"typeon-device-auth-v1"`. Result: **ALL devices must re-link, ALL contacts must re-pair**; the version must be bumped.
- **2nd round (2026-10-21):** session mailbox id (now fixed per pair, see §13.5); `ServerErrorCode::BadHash`; `FileChunkResponse::Busy`; the pairing nonce proof is length-prefixed; `DeviceAdd`/`DeviceRevoke` `signature_pq` is required (no `serde(default)`). The version must be bumped, and all devices updated.
- **3rd round (2026-10-21, this round):** `MessagePacket.header` is now carried as **raw CBOR bytes** (`SignedHeader`) — the signature covers those bytes (`p2pmsg-v0.6-packet`), and the same bytes are the ratchet AEAD's **associated data**; the `IdentityExchange` signature covers the **recipient device's fingerprint + the timestamp** (`p2pmsg-v0.5-identity-exchange`); `FirstContactSecret.group_id` added (per-group first-contact secret; personal secret removed); `GroupSyncRequest` new message type; `member_devices` is now a **delta**; `Call.participants` added; the whiteboard digest is a **per-stroke content hash**. Result: **ALL devices must re-link, ALL contacts must re-pair**; the version must be bumped.
- `Contact.avatar_jpeg` uses `serde_bytes` (sibling sync).
- `SiblingHistoryRequest.since_timestamp` field added.

**BEHAVIOUR**
- The server `Ack`/cursor advances **after** a message is processed (`commit_server_fetches`); while there are unprocessed or deferred incoming items, there is no `Fetch`/`Ack`.
- `ArchivePut` ≤ 256 records. `Enroll`/`Rebind` global verification budget (120/min). `RateLimited` counts as a temporary error.
- **Tor mandatory:** with Tor off, `start_network` returns an error (no network). `get_node_address` is onion-only; empty until the onion service is up. The QR/manual code is also not produced until then (`Err`).
- **Pairing window 30 min** (`PAIRING_WINDOW_MS`; it was 24 h before), at most 6 concurrent nonces.
- If JPEG/PNG metadata cannot be parsed, sending is rejected (fail-closed).
- If the server history is **turned off, the server archive is deleted** (purge).
- New rate limits: mail from the server 600/10 s (`source=None` budget), unknown peers total 300/10 s; server `CHUNKS_PER_MINUTE` 600.
- Node mode is only the relay service; no DHT contribution (D-03/H-16; the application string was corrected).
- Linux: after 60 s without activity, power save (`set_power_save`), metered network (`gio::NetworkMonitor`) notice.
- When the connection/contact limit is reached, a `pairing_failed` (`contact_limit`) event is raised; clients tell the user.
- A server panic is reported as a `core_panic` event (no restart).
- **Message text in notifications is OFF by default** (`NotificationPrefs.showMessageText` = false): when off, the notification only says "New message" — neither the sender nor the text is shown; the user can turn it on in Settings.
- **`SYSTEM_ALERT_WINDOW` permission removed** (client `AndroidManifest.xml`): the call screen does not open with this permission.
- **Release APK is not signed by Gradle** (no `signingConfig`): only `sign-release.sh` signs it (private key, v3 signature chain; newest build-tools; the same script for both apps).

**Owner rule (D-21):** no `FLAG_SECURE` on ordinary client chat/list/settings screens, and none is to be added there. Later owner-approved exceptions (§14, §23) exist; the server app (`ServerActivity`) uses it in release (non-debug) builds.

---

## 20. 2026-11-05..11 changes (after ef2f806, HEAD e916a13)

Source: `git log ef2f806..HEAD`; review decisions in `reviews/glm5-2026-11-05/`, `reviews/qwen-2026-11-06/`. Versions: client 6.0.7 (code 51), server app 6.0.1 (code 44), Linux/Windows 6.1.4. Compatibility with old versions is not pursued.

**PROTOCOL / WIRE BREAKS**
- **Server protocol 6 → 7** (6c9d437): the blob id now hashes only the upload-secret bytes after the tag (`blob_id_hash_hex`, `typeon-blob-id-v3`); in a group file the author tag is **different per file** (`group_msg_tag(group, author, rest)`, `typeon-group-msg-id-v2`; I-42). Group message id is `<tag><-uuid>`; the receiver recalculates with `group_msg_id_bound`. An old version's blob/group id does not match (§13.6).
- **Per-mailbox `seq`** (6a603c7): the server's `mail.seq` is no longer a global AUTOINCREMENT but a per-mailbox counter in the `mail_seq` table; server DB `SCHEMA_VERSION` 3 → 4, with migration for old rows (`mail_seq_base`). The server migrates a DB opened by an old version; client cursors stay valid (§13.3). The field meaning of `MailItem.seq` changed.
- **Strict CBOR** (6a603c7): `MessageContent`, `SignedHeader`, `RatchetPublicKeys` reject trailing bytes (§6).
- `SiblingHistoryEntry` has two new fields: `file`, `reactions` (§10). Both are `serde(default)` (when empty, not written with `skip_serializing_if`): an entry from an older sender is read as empty.
- A version bump is required; owner rule: no compatibility code is written.

**MULTI-DEVICE (sibling history, §10)**
- dcd2cb6 / 670ab45 / 926d724: a linked device's history now carries attachments (audio, labels, files), all reactions, and contact avatars; if the budget does not fit, the preview is dropped first; a "fetch history" press also brings the attachments/reactions of rows that an earlier press left below its cursor.
- 1a180c3 (Linux): from the pending-link page, a confirmed "delete and exit" returns to the setup screen.

**SERVER / NETWORK**
- fb5fecd: the `UnknownMailbox` pause doubles (60 s → at most 60 min), a successful deposit resets the streak; prevents a connected device that is not registered on the server from re-depositing unacked packets over Tor every 2 min (§13.4).
- 6a603c7 (server): `Rebind` reports `Revoked` only after the signature is verified (§13.2). 6c9d437: `init_schema` fails on `ALTER` errors other than `duplicate column name` and does not stamp `user_version`; the reader limit is **per key**, 2 (§13.3).
- 6a603c7 (core): the same principle in `db.rs init_db` (§14); `unknown_group_has_room` returns **closed** (no room) if the DB is missing or the query errors (`group_ops.rs`); sticker frame size u64 + `saturating_mul`; 6c9d437: download-resume candidates are limited to rows with `length(chunk_hashes) > 0` (old offers without chunk hashes were rejected by `download_file` every time; I-41).

**CORE STRUCTURE**
- 447e83e: `lib.rs` (~29,000 lines) split into 24 topic modules (§1.1); the `P2PCore` struct and module list are in `lib.rs`; submodules use `use super::*`; private items are `pub(crate)`; `lib.rs` is now ~930 lines. Tests that scan source read `crate::CORE_SRC`. A new core file must be added to `CORE_SRC`. On Windows `mono_ms` uses `GetTickCount64`; `rust/build.rs` links static `lcms2` for the Windows target.

**DESKTOP (Linux + Windows, §1.2)**
- e916a13: a Windows client from the same `Linux/` crate (`x86_64-pc-windows-gnullvm`; DPAPI vault key, `win.rs` tray/notifications/autostart/font, WASAPI/Media Foundation/D3D11 call elements). **Desktops are link-only secondary devices**: account creation and recovery-file restore were removed; the welcome page offers only "Link to my phone". `AGENTS.md` holds the rules and build recipes.

**ANDROID UI (outside the core)**
- 8527802: custom font (`util/FontOverride.kt`): system font aliases and `p2p-imported-font` map to the imported font; `sDefaultTypeface` is replaced; it is re-applied to TextViews on every layout pass in every `Activity` window.
- fb5fecd: a label (`sendSticker`/`sendGroupSticker`), file, photo, and voice message reply to the first quote in the input with the `reply` field (JNI `sendSticker`/`sendGroupSticker` new `reply_to_*` parameters; `jni_exports.rs sticker_reply_to`, `media_unlocked.rs send_sticker_unlocked`; Kotlin `util/Quote.kt`); the quote shows the quoted message's own words (not a quote inside it). The chat list's bottom padding only leaves room for the typing indicator.
- 6a603c7: settings/contacts JNI calls run off the main thread; avatar and wallpaper import is size-bounded; media is recognised by magic bytes: mislabelled MP4/MOV/HEIC/TIFF/MKV/AVI is remuxed or asks for "send with metadata?"; 6c9d437: metadata is stripped from m4a audio files; settings show the app version, and the server code paste screen shows the warning about adding a gate.

**NOT VERIFIED:** everything in this round was checked by reading the source; build and device results were taken from commit messages (6c9d437: host tests crypto 37, server 51, core 124; Linux check; two debug APKs built — not re-run while writing this document). On Windows, the pairing problem on a real device has not been diagnosed (`Linux/packaging/windows/TEST-NOTES.md`).

---

## 21. 2026-11-12..15 changes (after e916a13, HEAD 50bb608)

Source: `git log e916a13..HEAD`. Facts below were read from the code on 2026-11-15. Nothing was compiled or run on a device in this pass (AGENTS.md: no build without "derle"). Compatibility with old versions is not pursued.

**PROTOCOL / WIRE BREAKS**
- **Gossipsub removed** (c798a6f): no pub/sub, no topic subscriptions, no `subscribe` at start. Delivery order is now: direct envelope request-response (`/p2pmessenger/envelope/1.0.0`) → server deposit → `pending_envelopes` retry queue (§7, §12). IdentityExchange/Handshake replies go back on the connection they came in on (`pairing_reply_peer`, `network/publish.rs direct_peer_for`). Strings `p2p_msg_` / `p2p_rt_` remain only as mailbox-id inputs.
- **Server protocol 8** (47bb856): archive bucket id = hash of a per-bucket purge secret; `ArchivePurge{purge_secrets}`. The operator cannot delete history it cannot name (§13.1, §13.6).
- **Server DB `SCHEMA_VERSION` 5** (c798a6f), raised to **6** by the inspection pass (c2c871d: row-overhead charging, indexes, transactional acks). Change details are in `typeon-server/src/store/mod.rs`; read them before touching the schema.
- Revokes: packets carry the newest 64 revokes (plus the target's own); the local list stays complete (47bb856).
- **ml-kem 0.3.4** (seed-stored keys; old expanded keys still load through `ratchet::mlkem_dk_from_bytes`); `kem` dropped as a direct dependency; `ml-dsa` 0.1.2.
- Contact deletion syncs to linked devices (5f25e4b). This is new behaviour, not a wire break.

**SERVER**
- Public join code: **3-day lifetime** (`PUBLIC_CODE_TTL_MS`), renewed by the server when it expires (0167c7b). Defaults: `DEFAULT_MAX_ENROLLMENTS` 16 active enrolments (changed from 64 on 2026-11-15); `MAX_PUBLIC_ENROLLMENTS_PER_HOUR` 60; idle enrolment dropped after `ENROLLMENT_IDLE_MS` 30 days. The Android server app sets `config.max_enrollments = DEFAULT_MAX_ENROLLMENTS` (`typeon-server/src/jni.rs`) and splits its disk budget over it (`ServerConfig::apply_storage_budget`); the headless binary reads `TYPEON_SERVER_MAX_DEVICES` (default 16). A stale comment in `blobs.rs` still mentions a fixed `EXPECTED_DEVICES = 8`: the constant no longer exists.
- Installed binary check (47bb856): `install-staged` verifies the update signature, hash and version before the root `ExecStartPre` replaces the binary.
- Per-device quotas (Linux server and Android server app): `budget / max_devices` split 6/10 blob, 3/10 archive, 1/10 mail, capped at the defaults; default 16 devices (84 GiB library default; the Linux binary defaults the budget to 16 GiB). Archive and blobs stop at 90 % of the budget.
- Known limit (NET-17): a server can show a newly restored device an older revision of an archived message (edited or deleted text), because the revision high-water mark is local to the device that saw it.
- `typeon-server` source split: `store.rs` → `store/{mod,mail,enrollments,archive,blobs,tests}.rs`; `lib.rs` → `handlers.rs`, `blobs.rs`, `config.rs`, `limits.rs`, `relay_streams.rs`, `sweep.rs`, `jni.rs`.

**SELF-UPDATE (new, 518d464 → 870b02c → 47bb856; 7.4.x)**
- `update.rs` (core): once every 20 h (`CHECK_EVERY`) each app reads the project's GitHub `releases.atom` over Tor (no API rate limit). The release tag with a `-` is a beta; without the beta flag only plain versions count (`pick_tags`, `is_newer`).
- Trust chain: the download is checked against `SHA256SUMS`; `SHA256SUMS` is checked against `SHA256SUMS.sig`, an Ed25519 signature made **offline** by the owner with `tools/sign-update.sh`. The public key is pinned as `UPDATE_KEY` in `update.rs`. A release without the signature counts as not published. `tools/sign-update.sh` checks that the GitHub tag matches the local tag, that the assets match `SHA256SUMS` and `dist/`, and that the APKs carry the release certificate; a build that CI poisoned from a clean commit is still not caught. TLS uses webpki roots, not the OS store.
- Downloads are resumable (`.part` file plus HTTP range). State lives in one directory per app: `beta`, `last-check`, `status`, and the verified download.
- Android: `service/SelfUpdate.kt` (client) and `SelfUpdate.kt` (server app) run through WorkManager. The daily check runs only on unmetered networks. Install goes through PackageInstaller with `USER_ACTION_NOT_REQUIRED` and update ownership (API 34+): after the first confirmed install, updates install silently; the confirm screen appears only when Android requires it.
- Android UI: the chat activities are `singleTop`; re-binding keeps state for the same peer and resets it for another peer.
- Linux: the Flatpak restart is detached on the host (f412d91). Windows and headless server use the same core check.
- Rollback floor: the update dir holds a `stable-floor` file, raised to the running version when it is stable and to every stable tag whose signature verifies. A rollback (beta build, beta off, desktop/server) goes only to a stable tag not older than the floor. A `waiting` result re-checks after 3 h (`WAIT_RETRY`). HTTP header and chunk-size lines are capped at 16 KiB.
- Status line and "check now" button in settings, and a beta-off rollback (870b02c; Linux only, the Android JNI `checkUpdate` passes `downgrade=false`).

**CLIENT**
- Pending-link page (`awaiting_link`) on desktop: confirmed "delete and exit" returns to setup (1a180c3, carried from §20).
- Desktop says goodbye on quit (7170907): a keepalive `bye` is sent, and peers park the device until it reconnects. Verified in code on 2026-11-22: `wire.rs` keepalive `bye` field, `session.rs BYE_WAIT`, `api.rs` waits up to 2.5 s for the goodbyes.
- App password minimum 8 characters (`AppLock.MIN_PASSWORD_LENGTH`); mandatory server PIN at 600,000 iterations (47bb856).
- `targetSdk` 35 and `compileSdk` 35 for client and server app (47bb856). Edge-to-edge opt-out.
- AppLock PBKDF2 600,000 (c798a6f). Legacy 120,000 still read.
- Chat: 100-item history pages with date pill (f7313f6); desktop 200-bubble cap (8e5cbd5); slide-in animation for new messages (176468d, ccbb9aa).
- Calls: split mic/speaker pills with device picker (c72b2a8, 541de9f, 55341bf). Desktop: speaker pick mid-call no longer silences the call (15e1444).
- Desktop stickers and parity features (bbd98f3): sticker fetch from the phone, reactions, forward, picker, storage.

**REPO / TOOLING**
- Source split (c7af0f6; compile fixes in b10034e): `Linux/src/ui/chat.rs` → `ui/chat/`; core `attachments.rs`, `call.rs`, `network.rs`, `server_client.rs`, `jni_exports.rs` → directories (§1.1); Android `SettingsFragment.kt`, `ChatActivity.kt`, `GroupChatActivity.kt` → `Settings*.kt`, `ChatActivity*.kt`, `GroupChatActivity*.kt`; server `store.rs`/`lib.rs` split as above.
- Comments and log/error strings: Turkish → English (d752646, the many `docs:` commits). Protocol spec (`Description.md`) and this document are in English.
- Review files moved to `reviews/archive/root` (47bb856). Personal config and screenshot untracked (`.gitignore`).
- Release CI: every tag, pre-release (`-`) included, builds release artifacts (pre-releases built debug from 50bb608 until 2026-11-15; dropped because a debug APK is debuggable and carries `DebugDbKeyReceiver`). Release APKs are still unsigned by Gradle; `sign-release.sh` signs them.
- Version bump touches: `p2p_messenger_android/app/build.gradle` (versionCode + versionName), `p2p_messenger_android_server/app/build.gradle`, `Linux/Cargo.toml`, `Linux/data/com.p2p.messenger.Typeon.metainfo.xml`, `p2p_messenger_android/app/src/main/cpp/rust/Cargo.toml`, `typeon-server/Cargo.toml`, plus the lock files. `tools/bump-version.sh` does this.

**NOT VERIFIED in this pass:** the Windows client status after the split, and every server `SCHEMA_VERSION` 5/6 migration step (read `store/mod.rs` before touching it).

---

## 22. 2026-11-15..18 changes (7.5.0, 8.0.0, inspection fix pass)

Source: `git log 77b1719^..1e6f4df`, commit messages and code read on 2026-11-22. Compatibility with old versions is not pursued. 8.0.0 (1e6f4df) is a version bump on top of c2c871d; every device needs it.

**7.5.0 (77b1719) and the days after**
- Group calls: **Attend** pill, `CallAction::Ended`, `CallAction::Joined`, sibling Busy stops the ring, re-invite load fixes (§16.1). Sender names in groups use the whiteboard colours (30 % saturation, value 100 % dark / 50 % light theme).
- Call media: frame rate gate bug (15 → 24 fps), VRR, audio jitter buffer and 24 kbps default, keyframe request after link loss.
- Chat: a quote is inserted only once and drawn once per preview line; "Resend" menu item (also for attachments).
- Linked devices learn contacts and group state paired on another device (323f594); re-scanning an active contact device lifts the siblings' removed marker (c1293a7).
- Release CI builds release artifacts for every tag (§21).

**Inspection 2026-11-16 fix pass (c2c871d, 291 findings, protocol breaks)**
- *Delivery:* pending packets are no longer re-encrypted and re-deposited every 25 min. A peer that cannot open a packet sends `MessageContent::ResendRequest`; the sender re-encrypts under the same `message_id`; a real regeneration withdraws the old server copy (§9).
- *Ratchet:* old receive chain closed at `prev_chain_length`; a failed rotation reads as diverged; skipped keys written in one transaction; bounded CBOR collections; rotation before every packet except typing and call signals.
- *Sibling sync:* journal of non-additive operations (`sibling_journal`) replayed with the backfill; time-cut backfill with `covered_to`; roster part digests; block and device-revoke echoes (`SiblingEchoBody::Blocked`, `ContactDeviceRevoked`); link completes on the grant's Ack; the root ignores destructive sync from linked devices; `SiblingEchoBody::DeviceLeaving` (a logging-out linked device asks the root to revoke it, `api.rs announce_leaving`).
- *Network:* in-process `tor::OnionListen` transport (no loopback TCP listener), capped codecs, onion service relaunch, per-mailbox hold strikes, blob back-off, server request limits.
- *Groups and files:* `GroupUpdate` only from its signer, `removed_groups` sync, restored rows keep delete/edit state, per-file serve budget, auto-resume cap, orphan cleanup, `sent_at_ms` on file offers, group send status.
- *Calls and whiteboard:* re-invite of dropped participants, H.264 fallback request, nine-digit PBKDF2 link compare code, 32-byte page digest.
- *Storage and update:* rollback floor, metadata strip allow-lists, JXL decode limits, key wipe at shutdown, recovery trim notice. Block keeps addresses so unblock can re-handshake.
- *Server:* per-mailbox depositor share and hourly cap, budget split per device, indexes, transactional acks, Notify back-off, blob GC caps; **schema 6**.
- *Android:* Opus decoder configured and started again (incoming call audio was silent), ringtone vibration usage, proximity lock, audio focus, looping ringtone, Doze alarm receiver, wipe marker (`LocalWipe`), debug hooks `.so` only in the debug source set, group send status, `singleTop` chat screens.
- *Desktop (Linux and Windows):* link page decided by the core only, read receipts only while the chat is watched, voice recording stops at Stop, single-instance lock, update toast, sandbox/package hardening, pinned MSYS2 sysroot (`sysroot.lock`), self-revoke on log out, Windows erase releases the instance lock.

---

## 23. 2026-11-21..22 changes (after 8.0.0, on `master`, unreleased)

Source: `git log 1e6f4df..HEAD` (13 commits), code read on 2026-11-22. Built and device-tested up to 3ea296c; cbea2c9, e3a1d2f, 3d7b80f, 09ad037, ad52a7c are not confirmed compiled.

**PROTOCOL / WIRE BREAKS**
- **Padmé padding of server-visible items** (c8ca950): see §13.5. Items stored on a server before the change no longer open.
- **`expire_secs: Option<u32>`** on `MessageContent::Text`, `SiblingEchoBody::Text` and `FileOffer` (d3696d1). A receiver keeps only values in `1..=DISAPPEAR_MAX_SECS` (`packet::disappear_secs`). Bump the version before release.

**Disappearing messages** (d3696d1, cbea2c9, 3d7b80f, 09ad037, fa23d2f)
- Mode is per chat and per device (`app_meta` keys `dm:<canonical peer>` / `dm:group:<id>`; `archive.rs disappear_mode`, `set_disappear_mode`; JNI `getDisappearMode`, `setDisappearMode`; api `disappear_mode`, `set_disappear_mode`). The chat top bar has a **clock** button: tap while off opens the picker (30 s, 5 min, 1 h, 8 h, 24 h, 1 week, 4 weeks), tap while on turns the mode off. (A 3-second hold on Send was used in d3696d1 and removed in cbea2c9; some code comments still say "held Send".)
- The core stamps the timer on every outgoing text, file, voice and sticker (`send_message`, `prepare_and_send_file_unlocked`, group paths). The UI passes `expire_secs` explicitly: `Some(0)` is an ordinary message even with the mode on (retries, a send right after turning it off); `None` means the chat's mode (forwards).
- Countdown: a sent row counts from the send (`first_expiry("sent", …)`). A received row counts from when it is on **this device's** screen (`start_expiry`, called through JNI/api `startDisappearCountdown`; a sibling's read does not start it, and a desktop read does not start the phone's). Until then it holds `expire_at_ms = now + max(expire_secs, DISAPPEAR_UNREAD_SECS)` (1 day, 09ad037; before it was 4 weeks). `start_expiry` only moves `expire_at_ms` earlier (`MIN`), so a repeat call never extends a timer.
- `expire_due` / `expire_due_files` (poll loop) delete the text and keep a tombstone (`is_deleted = 1`), so late copies, history fetches and sibling backfills cannot restore the row. `expiry_filter(false)` leaves disappearing rows out of history answers, recovery and chat previews; `queue_archive_record` is skipped for them, so they never reach the server archive.
- Files: `files.expire_secs` / `expire_at_ms`. A sent file has `expire_secs = 0` once hidden but its encrypted `.enc` stays until the cap, so an offline receiver can still download. `file_expiry_filter` hides gone files from attachment lists.
- UI: Android `ui/Disappear.kt` and `SimpleChatAdapter` (pulsing accent edge in 8 steps, time left, slide-off); no copy, forward, quote, save, open-with, add-sticker or selection; `FLAG_SECURE` while one is on screen (chat screens, `MediaViewerActivity` with `EXTRA_PROTECTED`); notifications never show the content. Desktop `ui/chat/disappear.rs` shows only "Disappearing message, view on primary device".
- Remote-revoke wipe also clears `sticker_folders` and `sticker_folder_items`.

**Quick reactions** (c6eb469, ad52a7c): `P2PCore::top_reactions` (`send.rs`) returns my 5 most used emojis (`message_reactions` where `reactor_identity_id` is me, ties to the most recent), padded with 👍 ❤️ 😂 😮 😢. Android `util/ReactionPicker.kt` (bar right of the bubble, else left, else above/below; overshoot animation); desktop `ui/chat/reactions.rs` (popover, position Right).

**Sticker folders** (4871353, fa23d2f): device-local, like favorites. Tables `sticker_folders(id, name, created_at)` and `sticker_folder_items(folder_id, sticker_id)` (`db.rs`); `storage.rs` and `jni_exports/stickers.rs` (new/rename/delete/add/remove). Deleting a folder deletes only the list. Android `ui/StickerPicker.kt`: cell-sized decodes, a 64 MB drawable cache (`2 * STICKER_CACHE_BYTES`), stills decoded once, animations in their own queue. The core keeps sticker conversions up to 64 MiB encrypted (`media_unlocked.rs`, other conversions 4 MiB), so big GIFs are not converted again after every start. Desktop `ui/chat/composer.rs`: the popover holds the only strong reference to its state.

**Whiteboard** (fbd5aba): erase-only packets and erased strokes in page sync no longer mark a board unread (`whiteboard.rs wb_unread`). The `whiteboard` event carries a `new` flag; Android posts a silent notification (`NotificationHelper.showWhiteboardNotification`, `alert = false`, one id per board so it replaces itself) unless that chat is open (chat name only when message text is shown); the desktop posts at most one notice per chat per 2 min.

**Seen-by** (d3696d1, e3a1d2f): the seen-by avatar row on desktop and the Android seen dialog use `list_seen_by` / `seen_by_json` (`send.rs`). `sibling_sync.rs`: a read watermark comes from one device, so only copies still awaiting an Ack **for that `peer_fp`** hide a read. Before, an offline second device of the reader hid every message in groups, and in 1:1 a pending copy to an offline primary hid reads from the secondary.

**Android UI:** the Tor/network reconnect button left the chat screens (Settings keeps it). Chat screens crashed on open twice (cc8d765: sticker grid read resources too early; 3ea296c: disappearing mode read before the chat was bound); both were found only on a device.

**NOT VERIFIED in this pass:** the commits listed above as not confirmed compiled; the group disappearing countdown on desktop.

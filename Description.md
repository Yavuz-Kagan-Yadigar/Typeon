# Typeon P2P Messaging Protocol — Draft v0.2

> **Status note (2026-11-22, HEAD `09ad037`, released 8.0.0).** This is a design spec. Where it
> disagrees with the code, the code is right. Current differences:
> - Gossipsub is removed. Delivery is direct envelope → server deposit → retry queue (sections 4.4, 7). The "gossipsub topic" wording below means a mailbox id only.
> - Server protocol version 8, server DB schema 6. Public join code expires after 3 days and is renewed; limits: 16 active enrolments, 60 public enrolments per hour.
> - **Device authority is root-only**: only the identity's first (primary) device signs `DeviceAdd` and `DeviceRevoke`, and deletes the account. Sections 1.5 and 1.6 below describe an earlier, wider design (any Active device may revoke); the linking QR carries only the fingerprint and a nonce (no KEM keys).
> - Desktop clients (Linux, Windows) are link-only secondary devices.
> - App lock PBKDF2 is 600,000 iterations; app password minimum 8 characters.
> - Self-update uses a signed release list (Ed25519, offline owner key). See `TECHNICAL_HANDOFF.md` §21.
> - Server-visible items are padded (Padmé); messages can carry a disappearing timer; group calls re-invite absent members. See section 8 below.
>
> Full implementation details: `TECHNICAL_HANDOFF.md`.

## 1. Identity

**v0.2 decision: a two-layer identity model.**

```
Identity (person)  →  1..N Device (device)
```

- **Identity**: who the user is. Contacts and groups trust an Identity, not a device.
- **Device**: each physical device generates its own key pair (see 1.2) and has
  its own fingerprint. One Identity may have several Devices
  (phone + laptop + desktop).

```
Identity {
  identity_id: bytes[32],          // fingerprint of the first device, NEVER changes
  devices: [
    {
      device_fingerprint: bytes[32],
      device_name: string,          // "Ahmet's phone"
      added_at: timestamp,
      status: Active | Revoked,
    }
  ],                                 // max 5 Active devices (see note below)
  primary_device: bytes[32] | null, // see 1.6, authority to add/remove devices
}
```

**Decision: at most 5 Active devices per Identity.** Reason: the cost of pairwise
multi-device messaging (section 1.7.1) grows multiplicatively with device count
(N_A × N_B encryptions/sends). 5 devices is a reasonable real-world ceiling
(phone, laptop, desktop, tablet, spare phone) and keeps the cost predictable.
`Revoked` devices do not count; when a 6th Active device is wanted, one of the
existing devices must first be revoked.

- `identity_id` is fixed to the fingerprint of the person's first device and
  never changes. When someone talks to this person, they always trust the same
  `identity_id`; they do not check which device is currently active.
- Contacts (Contact) and groups are now stored by **identity_id, not
  device_fingerprint** (see the updates in sections 2 and 5).

### 1.1 Key pairs

Each **device** (Device) holds two separate key pairs for two purposes:

| Purpose | Algorithm | Use |
|---|---|---|
| Signing (authentication) | Ed25519 + ML-DSA-87 (hybrid) | Message/packet signing, basis of the fingerprint |
| Key exchange (KEM) | X25519 + ML-KEM-1024 (hybrid) | Session key derivation, forward secrecy |

**Why hybrid (classical + PQ together)?**
- Pure PQ algorithms (ML-DSA, ML-KEM) are relatively new. If a cryptanalytic
  break is found, the classical algorithm (Ed25519/X25519) is a fallback layer.
- Security = both the classical AND the post-quantum security must be broken
  (the combined key is derived by hashing the outputs of both algorithms).
- This matches Signal's PQXDH approach and general industry practice.

### 1.2 Fingerprint (device identity)

```
fingerprint = SHA3-256( sign_pubkey_ed25519 || sign_pubkey_mldsa || kem_pubkey_x25519 || kem_pubkey_mlkem )
```

- Raw fingerprint: 32 bytes.
- Format shown to the user: **Base32, in groups of 5, uppercase**.
  Example: `XJ4K2-9QWRT-7YHBM-3ZPLC-VN8DF-...` (about 52 characters total, 8 groups)
- Short verification code (for reading aloud): **8 groups of 5-digit numbers**
  derived from the first 16 bytes of the fingerprint (`format_short_code`; 8 bytes
  would have made collision search feasible). Similar to Signal's "safety number"
  format, it makes comparison by eye easier.
- **Identity code** (the "my contact code" shown to the user): `identity_id` is
  shown in the same format. In TOFU matching, this code is now shared, not the
  fingerprint of a single device.

### 1.3 QR content (first pairing package)

The QR code carries a CBOR (compact binary) encoded structure with these fields:

```
PairingPackage {
  version: u8,
  device_name: string,           // user-friendly name, e.g. "Ahmet's phone"
  sign_pubkey_ed25519: bytes[32],
  sign_pubkey_mldsa: bytes[~2592],
  kem_pubkey_x25519: bytes[32],
  kem_pubkey_mlkem: bytes[~1568],
  fingerprint: bytes[32],        // derived from the above, for verification
  known_nodes: [Multiaddr],      // node list this device knows (max ~10)
  timestamp: u64,
}
```

QR capacity is a real constraint. ML-DSA/ML-KEM public keys are much larger than
classical keys (ML-KEM-1024 ~1568 bytes, ML-DSA-87 ~2592 bytes). In this raw form
they may not fit in a single QR code.

**Decision (v0.1): fingerprint-only QR.**
```
QRPackage {
  version: u8,
  device_name: string,
  identity_id: bytes[32],        // v0.2: the person's identity is now carried
  device_fingerprint: bytes[32], // this device's own fingerprint
  rendezvous_node: Multiaddr,    // one known address, enough to connect
  known_relays: [Multiaddr],     // relay addresses to dial through
  pairing_nonce: bytes,          // bearer secret, see 1.4
}                                // code: version 3
```
- The QR stays small, and scanning is instant and reliable. Multi-QR / gallery
  methods were tried but postponed because of ordering risk and scanning friction.
  If needed later, they can be added as an "offline full transfer mode".
- The full public keys are downloaded from the other side once the connection is
  set up. The hash of the downloaded keys is compared with the `fingerprint` in the
  QR; if they do not match, the connection is rejected. This adds an extra
  round trip but does not weaken security (the fingerprint is already the
  primary verification point of TOFU).

### 1.4 Manual entry format

```
identity_id|device_fingerprint|nonce|device_name|rendezvous_node
```
A single-line, `|`-separated pairing code with 5 fields (`process_manual_entry`).
`nonce` is hex (the pairing code is a bearer secret, see below). The old
"node address + contact code in Base32" pair no longer exists.

The device shows both the QR and this text on its own settings screen (copyable).

**Pairing code lifetime (specification gap closed):** the `nonce` of a QR/manual
code is a bearer secret. It is valid for **30 minutes** (`PAIRING_WINDOW_MS`) and
allows **an unlimited number of scans** within that time (at most 30 min / 5 min =
6 nonces valid at the same time, `PAIRING_NONCE_REUSE_MS`). Anyone who sees the
code can start a pairing until it expires; the user must be told this clearly.

### 1.5 Adding a device (new Device, to an existing Identity)

When a user wants to add a second device (e.g. a laptop):

```
1. The new device generates its own key pair → it becomes its own device_fingerprint.
2. The new device shows a "add device QR":
   DeviceLinkRequest {                    // code: version 3
     device_fingerprint: bytes[32],
     device_name: string,
     nonce: bytes[16],                    // proves the grant answers THIS QR
     rendezvous_node + known_relays,      // no public keys: they arrive in IdentityExchange
   }
   Both screens also show a nine-digit compare code (PBKDF2 over fingerprint + nonce).
3. The primary device READS this QR (so approval is given by the
   existing device, not the reverse direction. This makes an attacker's
   "add a fake device" request meaningless, because approval always comes from
   an already trusted device).
4. The existing device signs a DeviceAdd packet:
   DeviceAdd {
     identity_id: bytes[32],
     new_device_fingerprint: bytes[32],
     added_by: bytes[32],            // fingerprint of the approving device
     signature: bytes,
   }
5. DeviceAdd is sent to the new device over the direct connection AND propagated
   to all contacts/groups that trust identity_id (see sync in 1.7).
6. The new device is now part of identity_id; contacts recognise it as a message
   recipient too.
```

### 1.6 Device removal / revocation (Revoke)

- **Implemented rule: only the primary (root) device revokes** another device of
  the same Identity (`status: Revoked`); the same holds for adding a device and for
  deleting the account. A linked device that logs out sends `DeviceLeaving` and the
  root revokes it. (The earlier draft let any Active device revoke. It was dropped
  so an unreachable or compromised secondary cannot cut off the others, and desktops
  are link-only.) Losing the primary device is a recovery-file case (1.8).
- Revocation is propagated to all other Active devices and known contacts/groups
  through a signed `DeviceRevoke` packet.
- A revoked device is treated as no longer able to produce valid signatures or
  encryption. The other side rejects new messages from that device (past messages
  are not affected; this is consistent with the fingerprint-change logic in 2.2).
- **Last-device revocation is blocked**: an Identity must keep at least one Active
  device (otherwise the identity becomes unrecoverable). Exception: adding a new
  device with the recovery file from 1.8.

### 1.7 Synchronisation between devices

When a new Device is added, or consistency between existing devices is needed,
the following data is synchronised:

```
SyncPayload {
  contacts: [SyncedContact],     // see section 2.1
  groups: [Group],               // see section 5.2 (serialised Group records)
  siblings: [SyncedDevice],      // the other devices of the same identity
  sibling_proofs: [DeviceAddProof], // proof for every sibling except the first device
  archive_root_key: bytes?,      // server archive root key (belongs to the identity)
  name_changed_at_ms: u64,       // timestamp of the last account-name change
  own_revokes: [DeviceRevoke],   // revocations of this identity's devices
  blocked: [identity_id],        // blocked identities
  removed_groups: [group_id],    // groups left or deleted (so a stale update cannot bring them back)
}
// Note: ratchet state and message history are NOT carried in SyncPayload; devices
// set up their own device-pair ratchets (1.7.1), and history is requested
// separately with `SiblingHistoryRequest/Response`. The code has no
// "history sync on/off" setting.
```

- Sync is carried over the device's own 1:1 ratchet session established between
  devices (so device-to-device traffic uses the same encryption/signing mechanism
  as user-to-user traffic; no separate channel is invented).
- The first sync is a full copy; afterwards only the **delta** (changes) is sent
  (new contacts, new groups, ratchet progress).
- Message history is not sent in `SyncPayload`; it is requested separately with
  `SiblingHistoryRequest/Response`. (The "history sync on/off" setting from the
  old draft was not implemented.)

#### 1.7.1 Ratchet state sync and conflict resolution

This is the **riskiest** part of full synchronisation: if two devices talk to the
same person at the same time, the ratchet chain could conflict. The solution is
similar to Signal's Sesame approach:

```
Instead of one logical ratchet for each (Identity_A ↔ Identity_B) pair,
EVERY device of Identity_A holds a SEPARATE ratchet session with EVERY device of Identity_B:

  (device_A1 ↔ device_B1), (device_A1 ↔ device_B2),
  (device_A2 ↔ device_B1), (device_A2 ↔ device_B2), ...
```

- So "messaging between people" is really modelled as the **sum of pairwise ratchet
  sessions between device pairs**. This is the same principle as the group
  messaging logic in section 5 (pairwise), applied to "the devices of the same
  person" instead of "group members".
- When sending a message, the sending device sends a separately encrypted copy,
  using its own ratchet session, to **every Active device** of the recipient Identity.
- There is **no** conflict risk, because each device pair runs its own independent
  ratchet chain. The case "two devices wrote at the same time" becomes, in daily
  use, "the same message was encrypted and sent twice on two different device
  pairs"; the ratchet mathematics is not broken.
- The cost: N_A devices × N_B devices of encryption/sending (for small N, e.g. 2×2,
  the cost is negligible).
- The read status / "my other device has also seen this message" sync **has been
  brought into the v0.2 scope** (designed below). It is not a new architectural
  layer; it needs only a small addition to the two existing mechanisms (normal
  messaging + SyncPayload).

**Read receipt to the other side** (part of normal message traffic):
```
Seen {                           // `MessageContent::Seen`; the reader is the packet's sender_identity_id
  target_message_id: string,
  group_message_local_id: string?,  // set for group messages
}
```
It is sent encrypted and signed like other `MessagePacket`s; no separate channel is
invented. **Which device it was read on is not shown in the interface.** However,
every `MessagePacketHeader` carries `sender_device_fingerprint` in the clear (see
section 3.3), so a `Seen` packet reveals which device saw it at the network/server
level. As soon as **any** of the person's Active devices reads the message, a single
"seen" state is triggered for that person.

**Display format**: simple, one line per person.

```
{display_name}  seen  {read_at}

example:
Ahmet  seen  14:32
```

- In a 1:1 chat: the moment the other side reads it from **any device**, a single
  "seen" mark appears (which device it was does not matter and is not shown).
- In a group chat: the "all seen" summary is complete once **at least one device
  of every member** has read it; a per-person list can be viewed if requested, but
  device details are still not shown.
- `display_name` is the alias the receiving side gave that person (section 2.1
  `Contact.display_name`).

**"Read" sync between your own devices**
(a small addition to the `SyncPayload` in section 1.7):
```
// In code: a separate `ReadStateSync` message (not a SyncPayload field) — a persistent
// "read" watermark; sent store-and-forward to sibling devices and to the other side.
ReadStateSync { ... }
```
When a device is the first to read a message, the `Seen` packet goes to the other
side, and at the same time the "this message was read" information is added to its
own `SyncPayload` delta. The only thing other devices (such as a laptop) learn during
sync is "this message is already read". Which device did the reading is not carried;
only the state (read/unread) is synchronised.

### 1.8 Identity recovery file (per person)

Against the case where the user loses their **last device** (the exception to the
rule in 1.6 that "at least one Active device must remain"):

```
RecoveryFile (CBOR; downloaded by the user and stored safely) {
  kdf: "argon2id", m/t/p (Argon2 parameters),
  salt, nonce,
  ciphertext,                    // identity secret keys (identity_id + device keys)
                                   // encrypted with ChaCha20-Poly1305
}
```

- This file contains the identity's secret keys + `RecoveryData` (the code has no
  `master_seed` concept; keys are encrypted directly).
- At first setup the user downloads this file, protected by a password (Argon2id +
  ChaCha20-Poly1305), and keeps it somewhere offline (USB, a recovery phrase written
  on paper, etc.).
- In case of loss: the file and password are entered on a new device → it continues
  as a new Device under the same `identity_id` → an automatic `DeviceAdd`
  notice goes to all old Active devices (if any).
- **Note**: if this file is captured, an attacker can impersonate that identity. It
  must therefore be presented as a "last resort only"; for daily use, device-to-device
  approval (1.5) should be the preferred path.

---

## 2. Trust Model (TOFU + Security Number Change)

### 2.1 Local record (table kept on each device)

**v0.2 update**: a Contact no longer holds a single fingerprint; it holds an
`identity_id` and the list of **known (Active) devices** of that identity:

```
Contact {
  contact_id: uuid,                    // local, specific to this user
  display_name: string,                // alias given by the user
  trusted_identity_id: bytes[32],      // person identity recorded at TOFU time
  known_devices: [
    {
      device_fingerprint: bytes[32],
      verified: bool,                  // whether this specific device was verified
      first_seen: timestamp,
      status: Active | Revoked,
    }
  ],
  last_device_change: timestamp | null,
  ratchet_states: [DeviceRatchetState],// see section 3, separate per device pair
}
```

### 2.2 Device change flow (per fingerprint, identity_id fixed)

As long as `identity_id` stays the same (that is, the other side is still
recognised as the same "person"), adding or removing a device is an **expected and
signed** event. The `DeviceAdd`/`DeviceRevoke` packets in sections 1.5/1.6 carry it,
and those packets are already signed by an existing trusted device. In this case
**no alarm is shown to the user**, only a notice:
"[Contact] added a new device: [device_name]".

**A real alarm case** is an unsigned or unexpected change:

```
When a connection is set up, the incoming (identity_id, device_fingerprint) pair is checked:

  identity_id is unknown (seen for the first time)
    → TOFU: record it, verified = false, continue normally

  identity_id is known, device_fingerprint is in known_devices AND Active
    → normal, silent continuation

  identity_id is known, device_fingerprint is NEW but arrived with a valid signed
  DeviceAdd packet (approved by an existing Active device)
    → silently added to known_devices, only an informational notice is shown

  identity_id is known, device_fingerprint is NEW and there is NO signed DeviceAdd
  (that is, someone is directly saying "it's me" with a new key, with no approval chain)
    → BLOCK (new messages sent or received stop)
    → warning screen to the user:
        - "An unrecognised new device was seen for [Contact], not approved"
        - short code of the old/known device vs short code of the new device
        - "Reject" (default) / "Re-verify and accept"
        - if accepted: added to known_devices, verified = false,
          last_device_change = now
    → OLD messages/ratchet states are kept; only the session with the new device
      starts with a new DeviceRatchetState
```

Code detail for the first case: a new identity becomes a contact only if the sender
proved it read a code this device shows (`pairing_proof_valid`), the contact was not
deleted on this device (only a scanned or typed code brings it back), and the contacts
table is below `MAX_CONTACTS`. Otherwise it is refused, with no alert.

This distinction matters: the **signed DeviceAdd chain** ensures that adding each
new device in a multi-device setup does not needlessly flood the user with alarms,
yet an unchained or unexpected key change is still caught and blocked at full
strength. So MITM/impersonation protection stays as strict as in the design before
section 1, and only the "legitimate multi-device" case gets a frictionless path.

### 2.3 Verification (optional but encouraged step)

The user can compare two short codes (their own Identity + the other side's
Identity, the `identity_id` short code defined in section 1.2) face to face or over
a trusted voice channel. The system works without this step (TOFU gives sufficient
security; you only trust who the person was at first contact). But verification
guarantees that the first contact was not fake too. Verification is done at the
Identity level; there is no need to verify each device separately (the DeviceAdd
chain already spreads Identity verification to the devices).

---

## 3. Message Encryption and Forward Secrecy

### 3.1 Session setup (hybrid KEM)

On the first connection a two-sided "hybrid handshake" is performed:

```
1. X25519 ECDH  → shared_secret_classic
2. ML-KEM-1024  → shared_secret_pq (encapsulate/decapsulate)
3. root_key = HKDF( shared_secret_classic || shared_secret_pq, salt=none (None) )
   (code: `Hkdf::new(None, ikm)`; labels `p2pmsg-v0.2-root/a-to-b/b-to-a`, message/chain key `p2pmsg-v0.1-msgkey/chainkey`, KEM sealing `p2pmsg-v0.5-*` — bound to the transcript)
```

### 3.2 Double Ratchet (forward secrecy + break-in recovery)

Signal's Double Ratchet algorithm is adapted so that the KEM step is PQ-hybrid:

- **Symmetric ratchet**: a message key is advanced with every message (HKDF chain).
  Even if one message key is compromised, earlier and later ones are not affected.
- **DH ratchet → KEM ratchet**: the parties generate a new X25519 + ML-KEM pair and
  exchange keys again. This step provides "break-in recovery" (even if someone
  steals a past key, they cannot read future messages).

  **Decision (v0.1): every 30 minutes** (time-based, independent of message count).
  PQ-KEM steps are heavier than classical DH, so renewing on every message would be
  pointless cost. 30 minutes is a reasonable balance: it fires a few times in an
  active chat and does not run needlessly in an idle chat. It is not hard-coded; it
  can be left as a tunable parameter later.

### 3.3 Each message packet

```
MessagePacket {
  header: {
    sender_identity_id: bytes[32],   // v0.2: person identity (whose message it is)
    sender_device_fingerprint: bytes[32], // v0.2: which device sent it
    message_id: string,              // sender-chosen id (acks, dedup, resend)
    ratchet_pubkey: bytes,           // sender's ratchet public keys; only filled on a rotation
    message_number: u32,
    prev_chain_length: u32,
    rotation_kyber_ciphertext: bytes?, // set while a KEM rotation is announced
    sent_at_ms: u64,                 // signed send time
  },                                 // the header travels as raw CBOR bytes; the signature covers those bytes
  ciphertext: bytes,               // AEAD (ChaCha20-Poly1305), header bytes as associated data
  signature_classical: bytes,      // Ed25519 and
  signature_pq: bytes,             // ML-DSA-87, over header bytes ‖ ciphertext ‖ recipient device fingerprint
}
```

- **Why the signature?** Encryption provides confidentiality but alone does not
  cryptographically prove *who sent* the message (KEM is symmetric). The signature
  guarantees that relays/nodes or an attacker cannot modify the packet, and that the
  sender really holds the claimed device fingerprint.
- A node/relay carries this packet blindly: it cannot decrypt `ciphertext`; if it
  changes the `signature`, verification fails on the receiving side and the packet
  is rejected.
- **v0.2 multi-device rule**: the sending side sends a separate `MessagePacket` to
  **every Active device** of the recipient Identity (each one encrypted with its own
  device-pair `DeviceRatchetState`, see section 1.7.1). The receiving side does not
  need to know that the same logical message went to the other devices of the
  Identity; each device receives its own copy independently.

---

## 4. Discovery and Addressing

### 4.1 Node list sharing

Each device carries a small subset (~10, most recently seen/most trusted) of the
node addresses it knows in the QR pairing package. The new user takes this list and
adds it to their own DHT bootstrap list.

### 4.2 Discovery (WAN) — NO DHT record

**Implemented state (code wins):** there is no signed DHT record (`put_record`).
Kademlia always runs in `Mode::Client`: it only bootstraps/queries, never enters
anyone's routing table, and publishes no records. Address discovery runs through the
QR's `rendezvous_node`, `device_addrs`/`device_onion_addrs`, `AddressAnnounce`,
relays and (if present) the server; the network is onion-only (no TCP listener or TCP dial; inbound
onion streams reach the swarm in-process). The old draft below is the target and is not implemented:

```
DHT_Entry { key: device_fingerprint, value: { multiaddrs, last_updated, signature } }
```

### 4.3 Node mode (optional)

- **Peer mode** (default): encrypted traffic is only for the device's own connections.
- **Node mode** (the user turns it on): only the **Circuit Relay v2 service** — it
  blindly carries encrypted traffic between two peers behind symmetric NAT.
  It makes **no** contribution to the Kademlia routing table (DHT is in client mode;
  `set_node_mode` only enables relay/auto-download behaviour).

### 4.4 Server mode (optional, outside the spec — added later)

Node mode and relays, as the name says, **store nothing**: Circuit Relay v2 only
builds a live circuit while both sides are connected at that moment. So while the
recipient is offline, durability rests entirely with the sending side
(`awaiting_confirmation`, retries for up to 7 days (`TEXT_RETRY_GIVE_UP_MS`; the
server adds a 14-day TTL)). For a phone that stays off for a week, or a newly set up
device, that is not enough.

For this there is a separate **server** option (see `typeon-server/` at the repo
root). The one-sentence difference from a relay: the server writes the envelope to DISK.

```
Deposit { mailbox_id, sealed }   -> server stores the envelope
Fetch   { cursors }              -> recipient fetches everything after its cursor on return
Ack     { mailbox_id, seq }      -> processed, can be deleted
```

- `mailbox_id` is derived from the same HKDF topic string the client computes
  (`p2pmsg-v0.1-gossip-topic`; the name is historical, there is no gossipsub any more),
  blinded so the server cannot read a fingerprint from a mailbox name.
- `sealed` is the envelope encrypted a SECOND time with a SEPARATE key derived from
  the ratchet `root_key`. Otherwise the `sender_device_fingerprint` that
  `MessagePacketHeader` carries in the clear would be readable in the server's database.
- Joining uses a public code (`typeon-server:<address>#<token>`) that the operator
  publishes (QR, link or plain text). People join on their own, without talking to
  the operator. The code lasts 3 days and the server renews it (`PUBLIC_CODE_TTL_MS`).
  The Sybil gate is an hourly enrolment ceiling (60), a default cap of 16 active
  enrolments, and the operator's ability to rotate the code at any moment. Rotating
  the code does not affect enrolled devices. For narrow cases (a set number of uses /
  per day), single-use invites still exist.
- Enrolment (`Enroll`) is done with the operator-issued invite token and a fresh key
  pair generated ONLY FOR THAT SERVER — the device's identity keys never go to the
  server. The signature is HYBRID (Ed25519 + ML-DSA-87, both verified), the same as
  in the rest of the app.
- The server path does NOT replace the direct path: handshakes and ratchet rotation
  announcements always go by both paths. Ordinary messages go direct when the peer is
  connected, and are copied to the server when there is no acknowledgement after
  1.5 seconds (or when the direct path is down). A censoring or broken server slows
  delivery; it cannot block it.

Storing history on the server is a SEPARATE and default-off option: delivery
envelopes cannot be used as history (the ratchet keys are forward-secret and
deleted), so the archive is re-encrypted with a long-lived "root archive key" — and
that layer is NOT forward-secret. For the detailed rationale and threat model see
`SECURITY.md`.

---

## 5. Group Messaging

### 5.1 Model decision: pairwise encryption

The target scale is small (2–15 people), and membership management is in the hands
of a single authority (the founder). At this scale the complexity that the **Sender
Keys** model brings (key rotation on membership change, tracking "who knew which
key when") is unnecessary. Instead, the existing 1:1 Double Ratchet infrastructure is
reused as it is:

```
When sending a group message:
  the sending device encrypts the message separately for EACH member of the group,
  using its own 1:1 ratchet session, and sends it directly to that member.

  Group of N members → each message is encrypted N-1 times, and N-1 separate packets go out.
```

- Advantage: no new cryptography; the existing security guarantees (forward
  secrecy, fingerprint verification, security-number change detection) carry over to
  the group context with no change.
- Cost: bandwidth/CPU that grows linearly with N — acceptable for a 15-person group,
  a problem for groups of hundreds (that scale is not a target).
- If scale grows later, moving to Sender Keys can be treated as a **separate protocol
  version** (outside the v0.1 scope, but the architecture does not rule it out — the
  group identity/membership model below is designed to allow it).

### 5.2 Group identity and membership

```
Group {
  group_id: string,                    // `group-<16 hex>`, random, made by the founder
  name: string,
  avatar_jpeg: bytes?,
  founder_identity_id: string,         // founder, the single authority (can be handed over, see below)
  founder_chain: [FounderTransfer],    // signed hand-overs, newest last (at most 8)
  members: [
    {
      identity_id: bytes[32],            // v0.2: membership is per person (not per device)
      added_at: timestamp,
      added_by: bytes[32],               // must always be founder_identity_id
    }
  ],
  created_at: timestamp,
  version: u32,                        // increases every time the membership list changes
}
```

**Decisions:**
- Only `founder_identity_id` can add or remove members. No other member has this
  authority. **v0.2 update**: since the founder may now have several devices (section
  1), the "founder lost their device" problem is solved at the **identity level**, not
  the group level. If the founder loses their phone, the recovery file (section 1.8) continues
  under the same `founder_identity_id`; a linked device of the founder can sign group
  updates too (`send_group_update_to_siblings`), but cannot take the identity's root authority. The problem, which previously needed a separate "backup founder"
  mechanism, is now solved as a natural result of the general identity/device model.
- A membership change is sent as a `GroupUpdate` packet signed by the founder, pairwise
  to all current (and any newly added) members — and to **every Active device** of
  each member separately (consistent with the pairwise device-pair logic in section 1.7.1):

```
GroupUpdate {
  group_id: uuid,
  new_version: u32,
  change: Add(identity_id) | Remove(identity_id) | Rename(string) | AvatarUpdate(bytes?)
          | Delete | TransferFounder(identity_id),
  group_name, members,                 // the state after the change
  member_devices, member_device_proofs, // device keys of members, vouched by the founder (delta)
  signed_by: string,                   // must be founder_identity_id
  signed_by_device: string,            // which founder device signed it
  signature, signature_pq,             // Ed25519 + ML-DSA-87
  founder_chain,
}
```

- If `signed_by == founder_identity_id` does not hold, the receiving side rejects the
  `GroupUpdate`. This stops someone who is not the founder from sending a fake
  membership change (signature verification uses the existing Dilithium+Ed25519
  signature mechanism, section 3.3). It is also separately verified that
  `signed_by_device` is a known/Active device of the founder (section 2.2).

### 5.3 Member removal and forward secrecy

When a member is removed from the group:
- The 1:1 ratchet sessions with the remaining members are not affected (they are
  already separate).
- Group-specific messaging with the removed member (with **all of their devices**)
  stops (the founder no longer sends them `GroupUpdate` or group messages).
- **Note**: the removed member can still read the past messages they received before
  removal (they have a local copy). This is an unavoidable limit of a p2p/end-to-end
  model: with no central server, "delete the history" cannot be enforced. The user
  must be clear about this.

### 5.4 Group discovery / invite flow

- There is **no** separate group-invite QR/manual artefact. The founder
  (`invite_to_group`) sends a pairwise `GroupUpdate(Add)` over the existing 1:1
  connection.
- The invited person receives the `GroupUpdate(Add)` packet over this 1:1 connection
  and creates/updates the group locally.

### 5.5 Group interaction with multi-device members

- When a group member adds a new device (section 1.5), their group membership is
  extended automatically. The founder is not asked for approval again, because
  `identity_id` is already registered as a member; the new device simply joins the
  message traffic as part of that Identity.
- If a member revokes one of their own devices (section 1.6), the group follows the
  current state automatically — group messages are no longer sent to that device.

---

## 6. Open Decisions

1. **QR content**: full public keys, or fingerprint + later fetch?
   → **Decided**: fingerprint-only (see section 1.3).
2. **Ratchet renewal frequency**: → **Decided**: 30 minutes (see section 3.2).
3. **Multi-device support**: → **Decided**: full synchronisation, two-layer
   Identity/Device model (see sections 1, 2.2, 3.3, 5.5).
4. **Founder device loss**: → **Decided**: solved at the identity level; the recovery
   file (section 1.8) is the way back when the primary device is lost (see the note in section 5.2).
5. **Node incentive model — decision: volunteer only.**
   The use case is small scale (a group of friends, a known number of people); node
   mode is kept on by the project owner on their own device. No reciprocity or
   incentive mechanism is needed; if scale grows (use between strangers), this
   decision can be re-evaluated.

   **Effect on bootstrap**: for a small, trusted group the full DHT is not
   required — in v0.1 a single "known node" (your always-on device) is enough as the
   bootstrap point. Kademlia is still not removed from the code (so it is ready if the
   network grows), but the practical flow simplifies to: a new user → gets your
   node's address via QR/manual entry → connects to it → discovers the others over
   the DHT. If the single node is offline (the constraint v0.1 accepts), new discovery
   stops; at small scale this is an acceptable trade-off.
6. **Read status sync**: → **Decided**: brought into the v0.2 scope, a `ReadStateSync`
   watermark message plus `Seen` (normal message traffic) + `SyncPayload` (see section 1.7.1).
7. **Device count limit**: → **Decided**: at most 5 Active devices per Identity
   (see section 1).

---

## 7. Minimum Scope for the Prototype (v0.1 target)

The multi-device/sync protocol is fully designed at protocol level (section 1), but
in the **prototype the implementation order** must still be staged — otherwise
reaching the first working version is needlessly delayed. The protocol is one piece;
code delivery is in two stages:

**Status (2026-10-20): every box below is implemented; only the Kademlia DHT record /
node-mode DHT contribution (sections 4.2/4.3) was deliberately not done. File
transfer, voice/video calls, whiteboard, edit/delete, reactions/replies, typing
indicator and profile were also SHIPPED, and they are OUTSIDE this spec's threat-model
scope — they have their own encryption paths, and their requirements are not defined
in this document.**

**Stage A — foundation (tested with a single-device assumption, but the code is written
to the Identity/Device split and runs only in the special case "1 Identity = 1 Device"):**
- [x] Identity/Device model, fingerprint generation and display
- [x] QR pairing (identity_id + device_fingerprint + one node address)
- [x] Manual node/contact entry
- [ ] Two devices finding each other over libp2p + Kademlia DHT (not done: discovery goes via QR/address/relay/server)
- [x] Session setup with hybrid KEM
- [x] 1:1 messaging with Double Ratchet (text, one line)
- [x] Device/identity change detection and warning screen (section 2.2)
- [x] Node mode on/off (on Linux desktop first, Android later)
- [x] Group creation, invite, pairwise group messaging (section 5)

**Stage B — multi-device (added on top of Stage A):**
- [x] DeviceAdd/DeviceRevoke flow (sections 1.5/1.6)
- [x] Sync between devices: SyncPayload (contacts, groups) (section 1.7)
- [x] Device-pair based DeviceRatchetState and pairwise multi-device sending (section 1.7.1)
- [x] Identity recovery file (`typeon-recovery-*.bin`, password-protected) (section 1.8)
- [ ] Message history sync (optional, user preference) (not in SyncPayload; `SiblingHistoryRequest/Response` exists, no setting)
- [x] Read status (`Seen` + separate `ReadStateSync` message) (section 1.7.1)

File transfer and voice/video calls are OUTSIDE the v0.1/v0.2 scope (added later; see
the status note above).

---

## 8. Additions after v0.2 (implemented; outside the original scope)

These were added later. The wire details are in `TECHNICAL_HANDOFF.md`; the threat model is in `SECURITY.md`.

**Server-visible size padding (2026-11-21).** Everything a store-and-forward server stores that the client seals (mailbox envelopes, first-contact items, archive records) is padded inside the AEAD: `plaintext ‖ 0x80 ‖ 0x00…`, rounded up with Padmé (Nikitin et al., 2019), at least 512 bytes, never past the wire cap. The server sees a size class, not the length. It does not hide timing or item counts.

**Disappearing messages.** A chat has an optional disappearing mode, set per device (30 s to 4 weeks). While it is on, every message sent in the chat (text, file, voice, sticker) carries `expire_secs`. A receiver deletes the message `expire_secs` after it is on its own screen (local clock); an unopened message goes after 1 day, or after its own timer when longer. The sender's copy counts from sending. Such rows never enter history answers, recovery files, chat previews or the server archive, and an expired row stays as a tombstone so late copies cannot bring it back. Clients block copy, forward, quote and save, and the Android client sets `FLAG_SECURE` while one is shown; desktops show only a placeholder. It is a convenience, not a guarantee: a receiver can still photograph the screen or run a modified client.

**Quick reactions.** Double tap (double click on desktop) on a message opens a bar of the user's five most used reaction emojis plus a button for the full picker. The list is computed locally from stored reactions.

**Stickers.** Stickers are lossy JPEG XL files kept encrypted on the device, shared with linked devices (`SiblingEchoBody::Sticker`, `StickersRequest`), with local-only favorites and folders.

**Group calls.** A running group call is offered again to absent members (every 30 s for 5 minutes, then every 2 minutes) so they can join later ("Attend"). `CallAction::Ended` tells every member the call is over; `CallAction::Joined` tells the user's other devices to stop ringing.

**Self-update.** Every app checks the project's GitHub `releases.atom` over Tor about every 20 hours and installs an update only when `SHA256SUMS` carries the owner's offline Ed25519 signature (`SHA256SUMS.sig`).

**Desktop clients.** Linux (GTK4) and Windows builds are secondary devices only: they link to a phone by QR, never create an account, and never hold device authority.

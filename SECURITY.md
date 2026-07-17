# Security & Network Architecture

Plain-language summary of how this app protects messages, and how devices find
and talk to each other. Written after a full security audit pass; the four
fixes it produced are called out below alongside what was already correct and
what is a known, accepted limitation.

---

## 1. The short version

- Every message is encrypted **end-to-end** with a key that a passive
  eavesdropper (or a compromised relay, since there are no servers) cannot
  derive.
- Every cryptographic operation that matters — key exchange *and* signing —
  is **hybrid**: it combines a classical algorithm (X25519 / Ed25519) with a
  post-quantum algorithm (ML-KEM / ML-DSA). An attacker has to break **both**
  to read your messages or forge your identity, including a future attacker
  with a working quantum computer.
- There is **no central server**. Devices find each other over the local
  network (mDNS) and the internet (a Kademlia DHT + gossipsub), and talk
  directly, peer-to-peer.
- Trust in a contact is established once, on first contact ("Trust On First
  Use" / TOFU) — normally by scanning their QR code in person — and then
  cryptographically enforced on every message after that.

---

## 2. Identity and keys

Each **device** (not each person) generates its own key material the first
time the app runs:

| Purpose | Algorithm | Notes |
|---|---|---|
| Signing (proving "this message came from me") | Ed25519 **+** ML-DSA-87 | Both signatures are produced and checked on every signed packet |
| Key exchange (deriving a shared secret) | X25519 **+** ML-KEM-1024 | Both secrets are mixed into every derived key |

A person's public identity (`identity_id`) is the fingerprint of their first
device. Additional devices (laptop, second phone) can be added later and are
tied to that same identity — contacts trust the *identity*, not a single
device.

**Fingerprint** = `SHA3-256(sign_pubkey_ed25519 || sign_pubkey_mldsa || kem_pubkey_x25519 || kem_pubkey_mlkem)`, shown to the user as Base32 in grouped blocks so two people can read it aloud and compare it (a "safety number", same idea as Signal).

### Why hybrid, and why upgrade to Category 5

Post-quantum algorithms are mathematically newer than X25519/Ed25519 and
haven't had 20+ years of public cryptanalysis. Running classical and PQ
algorithms *together*, and requiring both to hold, means a future break of
either one alone doesn't compromise the app — this is the same approach
Signal uses in PQXDH and is the current industry-standard way to become
"post-quantum safe" without betting everything on algorithms that are still
relatively young.

The original design used **ML-KEM-768 / ML-DSA-65** (NIST Security Category
3, roughly equivalent to AES-192). This audit upgraded both to
**ML-KEM-1024 / ML-DSA-87** (Category 5, roughly equivalent to AES-256) for
extra margin — a deliberate choice to prioritize long-term safety margin over
the modest extra bandwidth/CPU cost of the larger keys and signatures. Because
the wire format (CBOR) is self-describing rather than fixed-byte-offset, this
upgrade required no protocol/schema changes — only swapping the parameter set.

The two crates used (`ml-kem`, `ml-dsa` from RustCrypto) implement the actual
FIPS 203 / FIPS 204 standards. An earlier version of this project used
`pqcrypto-kyber` / `pqcrypto-dilithium`, which were dropped for two reasons:
they're unmaintained (RUSTSEC-2024-0380, RUSTSEC-2024-0381) and they
implement a pre-standardization draft of Kyber/Dilithium that is
byte-incompatible with the final FIPS specs.

---

## 3. First contact (pairing) and trust

A person you've never talked to before is added by scanning their QR code
(or, as a fallback, typing in the values manually). The QR code carries their
identity, their current device's fingerprint and public keys, and a network
address to reach them at.

This is a **Trust On First Use** model: the very first time you see someone's
identity, you're trusting that the QR code (or manual entry) you scanned
really came from them — there's no third party vouching for it. This is why
in-person QR scanning is the intended normal path; anyone who can hand you a
fake QR code can impersonate someone at that first step. After that first
handshake, every future message is cryptographically tied back to the keys
you trusted at pairing time, so an attacker without those keys cannot take
over the conversation later.

### What happens after pairing: the device-trust decision tree

Once you trust an identity, that identity's devices are handled with a
specific decision tree, evaluated on every incoming connection/message:

- **New identity you've never seen** → TOFU: trust it, this is pairing.
- **Known, active device you've already trusted** → silently accepted.
- **A new device added to an identity you already trust, and the addition
  was signed by that identity's existing trusted key** → silently accepted
  (this is how "add my laptop" is supposed to work — no re-scan needed).
- **A new device you've never seen, with no valid signature proving the
  identity's existing devices vouched for it** → flagged to the user as an
  unverified new device, and **not** auto-trusted.

**Audit fix:** the incoming-identity-exchange path (the very first packet
exchanged with someone) previously skipped this decision tree entirely and
unconditionally trusted whatever it received. It now runs through the same
check as QR/manual pairing, and silently drops anything that lands in the
"unverified new device" bucket instead of auto-registering it.

### Revoking a device

Every `DeviceRecord` has an `is_active` flag. Previously this flag existed
but nothing ever set it to false or checked it — a device could never
actually be revoked at the protocol level, even though the UI implied it
could be blocked.

**Audit fix:** this is now real. Long-pressing a contact offers "revoke this
device," which:
- marks that specific device fingerprint inactive,
- tears down its Double Ratchet session and any pending/skipped message keys,
- and — critically — is now actually **enforced**: both the handshake path
  and the normal message-receive path reject anything from a revoked device
  fingerprint outright.

This is a *soft* action distinct from "delete contact": the person and your
chat history stay; only that one device is cut off from sending or receiving
anything further. (Deleting a contact remains the "wipe everything" option.)

---

## 4. Sending a message: the Double Ratchet

Once two devices have paired, messages between them use a **Double Ratchet**
(the same core design as Signal), with one deliberate difference:

- Every message gets a fresh symmetric key derived from a constantly
  advancing hash chain, so compromising one message's key doesn't expose any
  other message (forward secrecy within a session).
- **Every 30 minutes**, instead of just ratcheting the existing chain
  forward, the app re-runs a **full hybrid key exchange** — a brand new
  X25519 + ML-KEM-1024 handshake — and rotates onto the result. Standard
  Double Ratchet implementations only do a classical Diffie-Hellman step on
  rotation; doing a full PQ exchange on every rotation means an attacker
  would need to break the PQ scheme *repeatedly, at 30-minute intervals*, not
  just once at the start of a conversation, to read anything.
- Message payloads are encrypted with ChaCha20-Poly1305 (authenticated
  encryption) using the ratchet-derived key.

Every signed packet (handshakes, group changes, device-add authorizations)
is checked with `verify_hybrid_signature`, which — as of this audit —
**requires both** the Ed25519 and ML-DSA components to be present and valid;
previously either signature could be empty and verification would still
pass, silently downgrading a message to classical-only security if the PQ
signature was ever missing.

### Groups

**Audit fix:** group membership changes (`GroupUpdate` — add/remove a member,
rename, change avatar) previously traveled as a mostly-plaintext top-level
packet, authenticated only with a classical Ed25519 signature. It's now
carried *inside* the same ratchet-encrypted message channel as everything
else (so it's confidential and gets the hybrid PQ handshake protection too),
and is signed with **both** Ed25519 and ML-DSA before being trusted — matching
every other signed operation in the app. The inner signature still matters
even though the outer transport is now also encrypted/authenticated: it's
what proves the change was authorized by the group's founder specifically,
not just sent by whoever relayed it.

---

## 5. Network architecture (how devices find each other)

Built on [libp2p](https://libp2p.io/), with no central server or relay:

- **Local network discovery — mDNS.** On the same Wi-Fi/LAN, devices
  broadcast their presence and find each other automatically, no internet
  needed.
- **Wide-area discovery — Kademlia DHT.** Devices can also announce
  themselves and look each other up over the internet via a distributed hash
  table. Nodes can run in `Server` mode (participate in routing for others)
  or `Client` mode (look things up without helping route), toggleable as
  "Node Mode" in settings.
- **Transport security — Noise protocol.** The underlying TCP connection
  between two peers is wrapped in a Noise handshake (via `libp2p-noise`),
  giving every connection transport-layer encryption and authentication
  independent of the application-layer message encryption described above.
  This is defense in depth: even if something were wrong at the
  application layer, the transport itself isn't sending plaintext over the
  wire.
- **Message delivery — gossipsub.** Once a message is ratchet-encrypted, it's
  published to a gossipsub topic named after the *recipient's device
  fingerprint* (`p2p_msg_<fingerprint>`), and only that device is meaningfully
  able to make sense of it.
- **Peer metadata — identify.** Standard libp2p peer-info exchange (what
  protocols/addresses a peer supports), feeding discovered addresses into
  Kademlia.

### What this design does *not* hide (accepted, known limitations)

Being end-to-end encrypted is not the same as being untraceable. These are
known properties of the current design that were reviewed in this audit and
deliberately left as-is (out of scope for "encrypt the messages" — they'd
require a substantially different transport/anonymity design, e.g. onion
routing, to fix):

- **Gossipsub topic names leak recipient metadata.** Because the topic name
  is derived from the recipient's device fingerprint, anyone else
  participating in that swarm can observe *that* messages are flowing to a
  given fingerprint, and roughly when, even though they can't read the
  contents. This is a traffic-analysis / metadata exposure, not a
  confidentiality break.
- **mDNS PeerId is persistent on the local network.** A device's libp2p
  `PeerId` stays the same across restarts, so something else on the same LAN
  segment can correlate "this PeerId showed up again" over time.
- **Kademlia is routing-only.** It never carries message content, only helps
  peers find each other's network addresses — but participating in a public
  DHT inherently makes a node's IP address discoverable to other DHT
  participants, which is true of any DHT-based P2P design.

---

## 6. Local storage

- Chat history, contacts, and ratchet state live in a local SQLite database
  on-device (no cloud sync, no backup server).
- Long-term private keys are generated and stored via the **Android
  Keystore**, StrongBox-first (dedicated secure hardware) with a TEE
  (trusted execution environment) fallback on devices without StrongBox, and
  used through AES/GCM with a fresh IV on every operation. Keys never appear
  in JVM/Rust memory as raw exportable material — the Keystore performs the
  crypto operation and only returns results.
- One known, currently unaddressed gap: the `zeroize` crate is a declared
  dependency (intended to overwrite sensitive key/message material in memory
  once it's no longer needed) but isn't actually used anywhere yet — ratchet
  keys and message keys are today left for Rust's normal drop/deallocation
  rather than being explicitly zeroed. This doesn't expose anything over the
  network; it's a defense-in-depth gap against an attacker who can already
  read process memory (e.g. via a separate device-compromise exploit), and
  is worth closing in a future pass.

---

## 7. Summary of this audit round

| Gap found | Status |
|---|---|
| GroupUpdate sent unencrypted, Ed25519-only | **Fixed** — moved inside ratchet channel, hybrid-signed |
| `verify_hybrid_signature` allowed a missing PQ signature | **Fixed** — both components now mandatory |
| Device revocation flag existed but was never enforced | **Fixed** — real revocation + enforcement added |
| IdentityExchange skipped the TOFU decision tree | **Fixed** — now runs `evaluate_sender_device` |
| Category 3 PQ parameters (ML-KEM-768/ML-DSA-65) | **Upgraded** to Category 5 (ML-KEM-1024/ML-DSA-87) |
| Gossipsub topic-per-fingerprint metadata leakage | Known limitation, not fixed (traffic analysis, not confidentiality) |
| mDNS persistent PeerId on LAN | Known limitation, not fixed |
| `zeroize` dependency unused (in-memory key erasure) | Known gap, not fixed this round |

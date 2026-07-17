# Typoon — Security & Network Architecture

Plain-language summary of how this app protects messages, and how devices find
and talk to each other. Written after a full security audit pass (two rounds);
the fixes each round produced are called out below alongside what was already
correct and what remains a known, accepted limitation.

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

Built on [libp2p](https://libp2p.io/). There is no *company-run* server —
but as of this round, other users' devices can optionally relay traffic for
each other (see "Cross-network connectivity" below), which is a
deliberate, disclosed tradeoff, not a central point of control.

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
- **Cross-network reachability — Circuit Relay v2 + DCUtR.** New this
  round; see its own subsection below.
- **Message delivery — gossipsub.** Encrypted messages are published to a
  gossipsub topic that the recipient is subscribed to. See "Topic
  pseudonymization" below for how that topic name is chosen.
- **Peer metadata — identify.** Standard libp2p peer-info exchange (what
  protocols/addresses a peer supports), feeding discovered addresses into
  Kademlia, and (new this round) into relay-candidate discovery.

### Topic pseudonymization (second audit round fix)

The first audit round found that the gossipsub topic name was computed
**directly from the recipient's device fingerprint** (`p2p_msg_<fingerprint>`).
That fingerprint is exactly the value shown on someone's QR code / shared as
their public identity — so anyone else participating in the swarm could watch
which topics had traffic and directly read off *who* was receiving messages
and *when*, even without being able to decrypt a single byte of content.

**Fix:** once two devices have completed a Double Ratchet handshake (see
section 4), all further traffic between them — every ordinary message, edit,
delete, read receipt, group update, typing indicator, everything — moves to a
topic name derived from that session's `root_key` via HKDF
(`HKDF-SHA256(root_key, "p2pmsg-v0.1-gossip-topic")`). This value is only
computable by the two parties who share that ratchet's secret; an outside
observer sees traffic on a topic that looks like random noise and cannot tie
it back to either party's fingerprint. Because `root_key` changes on every
30-minute hybrid rekey (section 4), **the topic itself rotates automatically
on the same schedule** — even an observer who somehow linked one topic to a
person loses that link at the next rotation.

**Known residual limitation:** the very first contact between two people (the
one-time `IdentityExchange`/`HandshakeInit` pairing exchange) still has to use
the old fingerprint-based "mailbox" topic, because no shared secret exists
yet to derive anything from — there is no way to bootstrap trust with a
total stranger without *some* rendezvous point both sides can compute in
advance. This is an inherent property of any system that supports
introducing two parties who've never spoken before, not a bug specific to
this app. Every subsequent message is protected by the rotating scheme above.

### Cross-network connectivity (Circuit Relay v2 + DCUtR) — third audit round fix

Until this round, two devices on different networks (two different home
Wi-Fi networks, or one on mobile data/CGNAT) generally **could not connect
at all**. Connections were only ever dialed against a literal address — the
QR code's own address, or an mDNS-discovered LAN address — and that address
is only usable if it's actually reachable from the outside. There was no
bootstrap node list and no NAT traversal, despite the original protocol
spec explicitly calling for it.

**What was added:**
- **Circuit Relay v2** — a device with "Node Mode" on now genuinely relays
  encrypted traffic for other users on the network (previously the Node
  Mode description claimed this but it wasn't implemented). A relay only
  ever blind-forwards Noise-encrypted bytes between two addresses — it
  cannot decrypt transport traffic, let alone the separately-encrypted
  (ratchet + hybrid-signed) application payload. Relay service is **open to
  anyone**, not just the relay operator's own contacts — a contacts-only
  policy can't solve the actual scenario that matters (two strangers on
  different networks pairing for the first time have no established
  relay-contact yet). libp2p's Circuit Relay v2 has built-in abuse limits
  (reservation count, circuit count/duration, data caps) so this is safe to
  leave open.
- **DCUtR** — automatically attempts to upgrade a relayed connection into a
  direct one via hole-punching. Succeeds for most common NAT combinations;
  falls back to continuing over the relay when it can't (e.g.
  symmetric-NAT-to-symmetric-NAT).
- **Relay discovery** — no fixed relay list exists. Devices remember
  relay-capable peers they've directly connected to (`known_relay_peers`,
  capped at 10), and QR pairing packets now carry a small list of the
  sharer's currently-known relays (`QrPacket.known_relays`, version bumped
  1→2, backward-compatible with old QR codes) so a new contact can be
  reached through one even if their own direct address isn't. Settings also
  has a manual "known relay address" field for pasting a trusted/
  self-hosted relay's address directly.

**Privacy tradeoff (the honest accounting):** the only new exposure is
metadata — a relay operator can observe *that* two peers are connected
through it, and roughly how much/when, the same class of exposure as the
gossipsub-topic issue above, not a new category of risk. Being someone's
relay costs that operator bandwidth and reveals to them (not to anyone
else) which peers are actively talking through their device.

**What this does *not* solve:** a fully zero-config guarantee that any two
strangers can always connect is not achievable without *some* reachable
point existing in the network — this is a structural property of any
decentralized P2P system with no company server (true of Tox, Briar, raw
IPFS, etc.), not a shortcoming specific to this app. Hole-punching fails for
some NAT combinations, and a brand-new user with zero contacts and no
organically-discovered relay has nothing to route through. The manual
relay-address field in Settings is the honest fix for that gap: a technical
user (or someone they trust) running the app in Node Mode on a reachable
box (e.g. a cheap VPS) becomes a bootstrap point the rest of their contacts
can plug in, rather than the app silently failing or overpromising
"always works, zero setup."

### Full traceability resistance (Tor/onion services) — considered, not implemented

A natural follow-up question after the fixes above: can this app be made
**completely** untraceable? Honest answer: no — and not because of a gap
specific to this app. Every low-latency anonymity network in existence,
including Tor itself, explicitly does not defend against a **global
passive adversary**: an entity able to observe traffic where it enters
*and* where it exits at the same time can correlate the two by timing and
volume, without breaking any encryption. This is a documented limitation
in Tor's own threat model, not an unsolved bug someone forgot to fix — it's
considered an open problem in anonymity-network research generally.

What *would* meaningfully raise the bar beyond the current design (hybrid
PQ encryption, rotating gossipsub topics, open relay/hole-punching above)
is routing this app's libp2p traffic through Tor. This is concretely
buildable — `libp2p-community-tor` is a real, existing crate providing a
libp2p `Transport` built on `arti` (the Tor Project's own Rust
implementation of Tor). Two independent settings would keep this fully
interoperable with users who don't enable it:
- **Hide outbound connections via Tor** — every dial goes through a Tor
  circuit instead of directly, so whoever you connect to (and any relay in
  between) sees a Tor exit address, not your real one. Works completely
  independently of whether the other side uses Tor — a fully classic peer
  notices nothing different.
- **Also reachable as a Tor onion service** — adds an onion address
  *alongside* the existing IP-based listening address (mDNS/relay/direct),
  rather than replacing it, so classic peers keep finding the device the
  same way they do today. Onion services are inherently reachable through
  NAT with no relay/hole-punching needed, so this could even simplify
  reachability for Tor-enabled devices. A stricter "onion-only, drop my
  real address entirely" mode is possible but would break inbound
  reachability from fully-classic peers (they cannot dial a `.onion`
  address without Tor) — that would need to be a clearly-labeled,
  non-default, advanced choice.

**Why this isn't implemented now:** it's a substantial engineering
investment for real, ongoing costs — per-connection latency from Tor
circuit setup (typically seconds, not milliseconds), meaningful mobile
battery/memory overhead from Arti maintaining live circuits, and circuit-
continuity complications when Android backgrounds or kills the app. This
was evaluated and deliberately deferred rather than rushed in; the design
above is left here so it can be revisited if the threat model for this
app's users changes.

### Other known network-level limitations (not addressed)

Being end-to-end encrypted is not the same as being untraceable. These
remain deliberately out of scope — closing them would require a
substantially different transport/anonymity layer (e.g. onion routing over
Tor/I2P, see above), which is a separate, much larger undertaking than
hardening the existing protocol:

- **mDNS PeerId is persistent on the local network.** A device's libp2p
  `PeerId` stays the same across restarts (this is itself a deliberate,
  previously-fixed tradeoff — an earlier bug caused a *new random* PeerId
  every launch, which broke reconnection entirely). The tradeoff: something
  else on the same LAN segment can correlate "this PeerId showed up again"
  over time. Rotating it would reintroduce the reconnection problem it was
  built to fix, so this was reviewed and deliberately left as-is.
- **Kademlia is routing-only.** It never carries message content, only helps
  peers find each other's network addresses — but participating in a public
  DHT inherently makes a node's IP address discoverable to other DHT
  participants, which is true of any DHT-based P2P design (IPFS, BitTorrent's
  DHT, etc. all share this property).

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
- **In-memory key hygiene (second audit round fix).** The `zeroize` crate was
  a declared dependency but wasn't actually wired up anywhere — sensitive key
  material was left for Rust's normal drop/deallocation, which does not
  overwrite memory, only frees it. This is now closed on two levels:
  - The underlying crypto crates (`ml-kem`, `ml-dsa`, `x25519-dalek`,
    `ed25519-dalek`) now build with their `zeroize` feature enabled, so every
    long-term identity secret key and every per-session ratchet keypair is
    automatically overwritten the moment it's dropped — handled by the
    libraries themselves, not custom code.
  - The values those libraries can't see — the Double Ratchet's `root_key`,
    send/receive chain keys, cached skipped-message keys, each individual
    message's derived symmetric key, and the raw secret-key bundle that
    crosses the JNI boundary at startup — are explicitly zeroized on drop or
    immediately after use.
  - The struct carrying raw secret-key bytes across the JNI boundary
    (`SecretKeyBundle`) also had its `Debug` derive removed, so a future
    stray `error!("{:?}", ...)` can't accidentally print a private key to
    the Android system log.

  This doesn't expose anything over the network — it's defense-in-depth
  against an attacker who can already read process memory (e.g. a separate
  device-compromise exploit). Residual limitation: this covers Rust-owned
  memory only; it can't reach OS-level copies (swap, core dumps) or
  anything the JVM/Kotlin side temporarily holds while decrypting the
  Keystore-wrapped bundle before handing it to Rust.

---

## 7. Summary of all three audit rounds

| Gap found | Status |
|---|---|
| GroupUpdate sent unencrypted, Ed25519-only | **Fixed** — moved inside ratchet channel, hybrid-signed |
| `verify_hybrid_signature` allowed a missing PQ signature | **Fixed** — both components now mandatory |
| Device revocation flag existed but was never enforced | **Fixed** — real revocation + enforcement added |
| IdentityExchange skipped the TOFU decision tree | **Fixed** — now runs `evaluate_sender_device` |
| Category 3 PQ parameters (ML-KEM-768/ML-DSA-65) | **Upgraded** to Category 5 (ML-KEM-1024/ML-DSA-87) |
| Gossipsub topic-per-fingerprint metadata leakage | **Fixed** — topic now derived from ratchet `root_key`, rotates every 30 min; first-contact pairing still uses fingerprint (unavoidable bootstrap) |
| `zeroize` dependency unused (in-memory key erasure) | **Fixed** — upstream crate features + explicit zeroize-on-drop for ratchet/session/message keys and the JNI secret-key bundle |
| No cross-network (NAT) connectivity — spec called for it, never implemented | **Fixed** — Circuit Relay v2 (open, Node-mode devices) + DCUtR hole-punching + organic/QR/manual relay discovery |
| mDNS persistent PeerId on LAN | Known limitation, deliberately not changed (would reintroduce a previously-fixed reconnection bug) |
| Kademlia DHT participation reveals IP to other DHT peers | Known limitation, structural to any DHT-based P2P design; relaying mitigates it for message traffic but not DHT participation itself |
| Zero-config guarantee that any two strangers can always connect | Not fully achievable without *some* reachable point in the network (structural to decentralized P2P, not fixable by protocol changes alone) — mitigated, not eliminated, by the manual relay-address field |
| Complete/absolute untraceability (IP-level, against a global adversary) | Not achievable by design — same limitation Tor itself has. Tor/onion-service integration (`libp2p-community-tor`) was designed and evaluated but deliberately **not implemented**: real latency/battery cost, and even then only raises the bar, doesn't reach "complete" |

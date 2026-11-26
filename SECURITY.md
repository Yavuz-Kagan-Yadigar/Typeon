# Typeon — Security & Network Architecture

> **Current state: 2026-11-22, HEAD `09ad037` (released 8.0.0: client, server, Linux, Windows; later commits on `master`).**
> Sections 1–9 are the audit trail and may describe gossipsub, mDNS, UPnP,
> DCUtR and 64-device caps that are no longer in the code. Section 10 lists
> what is true now and overrides older text. Where code and this file differ, the code wins.

Plain-language summary of how this app protects messages, and how devices find
and talk to each other. Written after a full security audit pass (two rounds);
the fixes each round produced are called out below alongside what was already
correct and what remains a known, accepted limitation.

---

## 0. Limits you should know first

These are deliberate trade-offs, each explained further down:

- **Tor hides who can reach you, not who you are to a peer.** The libp2p
  `identify` exchange shows a connected peer your device's addresses, and a
  peer on the same LAN is dialled directly. Use Tor for reachability across
  NAT, not for anonymity from your contacts.
- **A store-and-forward server sees which enrolled device reads which
  mailbox, and when mail arrives.** Deposits are anonymous, so it does not see
  who writes to whom, but timing can hint at it (see "What it can see"). It
  never sees content.
- **The server history archive is not forward-secret.** A leaked archive key
  decrypts every record uploaded with it, and a server can serve an older
  revision of a record to a freshly linked device without it noticing.
- **Session mailbox reader proofs are X25519-only.** A future quantum attacker
  holding both public keys could register as a mailbox reader and see
  deposits arrive; the deposits themselves stay hybrid-sealed.
- **Updates trust one offline key.** Every app installs an update only when
  the release's `SHA256SUMS` carries the owner's Ed25519 signature
  (`SHA256SUMS.sig`, made with `tools/sign-update.sh` on the owner's machine,
  public key pinned in `update.rs`). Signing checks that the GitHub tag matches the
  local tag, that the assets match `SHA256SUMS` and `dist/`, and that the APKs
  carry the release certificate. A build that CI poisoned from a clean commit
  is still not caught; theft of the signing key is not caught either. Android additionally requires the
  APK signing key.

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
- There is **no central server**. Devices find each other over Tor onion
  services (a Kademlia DHT in client mode), and exchange envelopes
  directly, peer-to-peer. There is no gossipsub (removed, see §10).
- Trust in a contact is established once, on first contact ("Trust On First
  Use" / TOFU) — normally by scanning their QR code in person — and then
  cryptographically enforced on every message after that.

---

## 2. Identity and keys

Each **device** (not each person) generates its own key material the first
time the app runs:

| Purpose | Algorithm | Notes |
|---|---|---|
| Signing (keys, devices, handshakes, group changes) | Ed25519 **+** ML-DSA-87 | Both signatures are produced and checked on every signed packet. Chat messages are not signed (see section 4) |
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

### Linking a second device

A new device shows a QR code; a device that already belongs to the identity
scans it and answers with a signed `DeviceLinkGrant`, which hands the new
device the identity, the contacts, the groups and the archive key.

The grant is only worth as much as the proof that it answers *that* QR code,
because any device with a session to the new one can send a grant signed by
itself. Three checks tie it down (2026-10-07):

- The QR code carries **16 random bytes** (`DeviceLinkRequest.nonce`, format
  v3). The grant has to repeat them. They are shown on the screen and travel
  nowhere else, so only the device that scanned the code can produce them.
- The new device accepts a grant only while it is **showing the code**. The
  window closes when a grant is adopted or the QR screen is left, and the
  nonce is deleted with it.
- A device that already has contacts of another identity is **never** moved
  to a new identity by a grant.

Before the nonce, the only tie was the time window (now 30 minutes): a device that
showed its code and backed out could be claimed by any paired device until
the window ran out.

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
  encryption) using the ratchet-derived key. The raw message header is the
  associated data, so the tag covers every header field.
- **Messages carry no signature (deniability).** The AEAD tag is the only
  sender authentication of a message packet. It proves to the receiver that
  the packet came from the other end of the session, but it proves nothing to
  a third party: the receiver holds the same keys and could have made the
  packet itself. The header's identity must match the identity stored for the
  sending device, and a revoked device is refused. Until a packet decrypts its
  header is only a claim, so a packet that arrives before the session exists
  is buffered only when its carrier is the claimed device (the libp2p peer id
  known for it, or the server mailbox only that device fills), and a packet
  that fails to decrypt starts a session reset only under the same condition.
  This also removed one ML-DSA signature and verification per packet.

Every signed packet (handshakes, prekeys, group changes, device-add and
revoke authorizations, founder hand-overs)
is checked with `verify_hybrid_signature`, which — as of this audit —
**requires both** the Ed25519 and ML-DSA components to be present and valid;
previously either signature could be empty and verification would still
pass, silently downgrading a message to classical-only security if the PQ
signature was ever missing.

### Starting a session: signed prekeys

The ratchet protects a session once both sides have spoken. The gap was the
start: everything the initiator sent **before the first reply** was encrypted
to the recipient's *long-term* KEM keys. Those never change, so someone who
recorded that traffic and took the recipient's device keys later, at any time,
could open it. With the recipient online the gap is seconds; with the
recipient off for a week it is every message waiting in the server mailbox.

Since 2026-10-07 a handshake goes to a **signed prekey** instead:

- Each device makes a short-lived KEM key pair (X25519 + ML-KEM-1024), signs
  it with its long-term Ed25519 + ML-DSA-87 keys, and hands the public half
  out in every `HandshakeInit` and `IdentityExchange` it sends.
- The initiator encapsulates to that prekey and names it
  (`recipient_prekey_id`). Both prekey ids are inside the handshake
  signature, so a relay can neither swap the key nor strip the field.
- A new prekey is made every **7 days**. The secret half of an old one is
  deleted **21 days** after it was made: 7 days of being handed out, 7 days
  that a handshake can wait in a mailbox, 7 days of slack. On disk the
  secrets are sealed with the local storage key.
- If a handshake names a prekey the recipient no longer has, the recipient
  starts the handshake from its own side, which also delivers its current
  prekey. That costs one extra round.

What this does **not** give:

- **It is not a one-time prekey.** The exposure went from "forever" to 21
  days, not to zero: a device taken today still holds the prekeys of the last
  three weeks. Per-session forward secrecy for the opening messages needs
  one-time prekeys and a server that hands each out once. Not implemented.
- **The very first handshake can still fall back** to the long-term keys
  (`recipient_prekey_id = 0`) when the initiator has not yet received any
  packet from that device. In a QR pairing the `IdentityExchange` normally
  arrives first, so the fallback is the exception.
- A device whose local storage key cannot be loaded (Keystore failure) hands
  out no prekey, because it could not keep the secret across a restart.

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

**Who wrote a message, when it comes from someone else's copy.** A group
message reaches each member over that member's own 1:1 session with the
author, so a live message is authenticated by the session. Group *history* is
different: a device that joins late, or was offline, asks another member for
the rows it lacks, and that member could attribute any text to any name.

Group messages carry no author signature (deniability, the same reason as
for 1:1 messages above). A history row that the answering member wrote itself
arrived over its own session and is trusted. Any other row is stored with a
"relayed by <member> · unverified" marker shown on the bubble. A relayed row
never replaces a row the device already holds, and a member cannot relay a
row under the asking user's own name. When the author's own copy arrives
later (live, an edit or delete, the author's own history answer, or a sibling
device's copy) the marker goes, and the author's text wins if it differs.

Limits:

- A relayed row is only as true as the member who relayed it. The marker
  says so; nothing else checks it.
- The send time of a relayed row is the relaying member's word.

---

## 5. Network architecture (how devices find each other)

Built on [libp2p](https://libp2p.io/). There is no *company-run* server. Two
things soften that statement, both opt-in and both disclosed: other users'
devices can relay traffic for each other (see "Cross-network connectivity"
below), and **you can now point the app at a store-and-forward server that you
or someone you trust operates** (see "Optional store-and-forward server"
below). Neither is operated by this project, and both are off until a user
turns them on.

- **Local network discovery — removed.** mDNS was removed (M-201): it
  beaconed the PeerId on the LAN, and the transport is onion-only.
- **Wide-area discovery — Kademlia (client only).** The DHT runs in
  `Client` mode only: it looks things up but never joins anyone's routing
  table and publishes no records (no `put_record`). "Node Mode" in settings
  only enables the blind Circuit Relay v2 service; it does not contribute to
  DHT routing.
- **Transport security — Noise protocol.** The underlying TCP connection
  between two peers is wrapped in a Noise handshake (via `libp2p-noise`),
  giving every connection transport-layer encryption and authentication
  independent of the application-layer message encryption described above.
  This is defense in depth: even if something were wrong at the
  application layer, the transport itself isn't sending plaintext over the
  wire.
- **Cross-network reachability — Circuit Relay v2 + DCUtR.** New this
  round; see its own subsection below.
- **Message delivery — direct envelope protocol (gossipsub removed).** Encrypted
  envelopes go point to point over `/p2pmessenger/envelope/1.0.0`, then to the
  server if the direct path fails, then to a retry queue (§10). The "Topic
  pseudonymization" section below describes the old gossipsub design.
- **Peer metadata — identify.** Standard libp2p peer-info exchange (what
  protocols/addresses a peer supports), feeding discovered addresses into
  Kademlia, and (new this round) into relay-candidate discovery.

### Topic pseudonymization (second audit round fix; historical, gossipsub removed — §10)

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
  (ratchet-encrypted) application payload. Relay service is **open to
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

### UPnP port mapping — removed

An earlier round added automatic UPnP port mapping. It was **removed** (M-201): mDNS and UPnP are off in the swarm, so the router is never asked to open a port and no LAN or mapped external address is advertised. Cross-network reachability is Tor onion services only (next section); there is no TCP transport at all (see §10).

### Self-healing reconnection (fourth audit round fix)

All the machinery above establishes connections, but until this round
nothing *re-established* them. A dropped connection — from a network-type
change (Wi-Fi ↔ mobile data), the app being backgrounded and killed, or the
peer going briefly offline — was only recovered by mDNS, which works only on
the same LAN. `ConnectionClosed` and dial-failure events were merely logged;
nothing re-dialed, and a paired contact on a different network could get
stuck disconnected until the user manually re-scanned a QR code. This made
the app feel fragile across real-world usage (different networks, moving
between Wi-Fi and cellular, phones sleeping).

Now the app is self-healing:
- **Persistent per-device address hints.** The last address that worked for
  each contact device is remembered (in a `device_addrs` table), set both at
  pairing time (the QR/manual rendezvous address) and refreshed to the real
  connected address every time a packet actually arrives from that peer. This
  survives app restarts, so reconnection works even after the process is
  killed and even across networks (unlike the previous in-memory-only,
  session-scoped state).
- **A periodic reconnect sweep** (every ≤15 s, piggybacked on the existing
  1 s poll loop) re-dials every known, active contact device that has an
  address hint but no live connection — going through the same
  direct + relay + hole-punch paths as a first connection. Any disconnect
  now heals automatically within seconds.
- **Immediate reconnect on intent.** Opening a chat or sending a message
  triggers an instant reconnect attempt for that peer rather than waiting for
  the next sweep, so the common case feels immediate.

Structural limitation (unchanged, and honestly noted): if a peer's address
changes completely (new public IP, no shared relay), direct
reconnection still can't find them until the address is refreshed some other
way (a new QR or relay discovery) — this is inherent
to P2P without a central rendezvous server. The sweep keeps trying, so
recovery is automatic the moment any working path reappears.

### Tor onion services — reachability across CGNAT (fifth round, v1: reachability only)

The relay work above still fails for the hardest case: **both peers
behind carrier-grade NAT (CGNAT)** — common on mobile data and, increasingly,
home ISPs. When the ISP itself NATs you (WAN IP in `100.64.0.0/10`), no port
forwarding, DMZ, or static IP can make you reachable, because your
whole router is behind the carrier's NAT. This isn't fixable at the app or
router level.

Tor onion services solve exactly this: both the host and the dialer make
only *outbound* connections to Tor rendezvous points, so two peers **both
behind CGNAT can connect** — and unlike a private overlay (Tailscale), a
`.onion` address is public, so it works between strangers with no account or
pre-authorization. This is now implemented, in a **reachability-only v1**:

**What's implemented:**
- **Hosting.** When Tor is enabled (a Settings toggle, **on by default** since
  every device should be reachable across CGNAT out of the box without the
  user having to find and flip a setting — a first install with the toggle
  left untouched stays on; explicitly turning it off is remembered), the
  app launches an `arti` onion service (`arti-client`, built on the Tor
  Project's own Rust Tor). Its `.onion` address is stable across restarts
  (arti's keystore, the Tor analogue of the persistent libp2p PeerId).
  Incoming Tor streams reach the swarm in-process through `tor::OnionListen`,
  a listen-only libp2p transport fed by a channel. No TCP port or socket is
  opened. A stopped onion service is relaunched automatically; inbound
  upgrades must finish within 30 s.
- **Dialing.** A small custom libp2p transport routes `/dns/<hash>.onion/…`
  dials through `arti`'s `TorClient::connect`, composed alongside the normal
  TCP/relay transports (it only claims `.onion` addresses, so everything
  else still uses the fast direct path). Built directly on `arti-client`
  with **rustls (ring)**, deliberately avoiding `libp2p-community-tor` which
  forces OpenSSL — this keeps the Android cross-compile clean (verified for
  all three ABIs).
- **Advertising.** When the onion service is up, `get_node_address()`
  advertises the `.onion` address (in the QR / "copy my address"), so a
  Tor-enabled peer can reach you across any network.

**v1 limitations (honest, and by design for this round):**
- **Reachability, not anonymity.** Your real IP is still observable via the
  libp2p `identify` exchange to a peer you connect to. Full IP anonymity
  (suppressing identify's address advertisement and routing *all* outbound
  dials through Tor) is a deliberately scoped-out **v2**.
- **Tor is mandatory (fix pass 2026-10-20).** With Tor off the core refuses to start the network (`start_network` returns an error); there is no clearnet libp2p transport, and `get_node_address` is onion-only (empty until the onion service is up).
- **Both peers need Tor enabled** to use a `.onion` — a non-Tor device
  cannot reach it (the connectivity layer must be on both ends, same rule as
  any overlay).
- **Real costs, accepted knowingly:** Tor bootstrap on first launch (seconds
  to a minute, fetching the network consensus), seconds of circuit setup per
  new connection, background battery use, and ~5 MB larger native library.
- The toggle takes effect on the next network-layer start (a transport can't
  be added to a live swarm), so enabling it prompts an app restart.

**Snowflake and obfs4 bridges are a fallback, with a privacy cost.** When a
bridge mode is picked, the app still starts with a direct Tor connection and
switches the running Tor client to the bridge only after Direct has had 60 s
of online, awake time without becoming ready (no network at all does not
count). On a censoring network that first Direct attempt shows the network
observer that this device tried to reach Tor. To limit how often that
happens, a block is remembered for 24 h (file `direct-blocked` in arti's
state directory): starts within that time go straight to the bridge. Once a
process is on the bridge it never goes back to Direct. A user who must never
be seen connecting to Tor directly should not rely on this fallback on a new
network. A bridge that is not ready for 5 min of online time, at the start or
after it has died, is parked for growing pauses (10 min doubling to 2 h,
with 5 min tries in between), so a dead Snowflake does not churn the radio
and battery all day. arti uses one bridge as its primary guard; the other
bridge line is only the fallback when the first is down.

**Still true regardless of Tor:** complete/absolute untraceability against a
**global passive adversary** (one observing traffic entering *and* exiting
the network simultaneously) is not achievable — this is a documented
limitation of Tor itself and an open problem in anonymity research, not a gap
specific to this app.

### Other known network-level limitations (not addressed)

Being end-to-end encrypted is not the same as being untraceable. These
remain deliberately out of scope — closing them would require a
substantially different transport/anonymity layer (e.g. onion routing over
Tor/I2P, see above), which is a separate, much larger undertaking than
hardening the existing protocol:

- **PeerId is persistent** (mDNS, which broadcast it on the LAN, is
  removed; the point below now applies to peers that connect). A device's libp2p
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

### Optional store-and-forward server (this round)

Until now the app had **no store-and-forward anywhere**, and that gap was
structural rather than accidental. A libp2p Circuit Relay v2 only builds a
*live* circuit between two peers who are both online at the same moment; it
stores nothing. The old `p2p_msg_<fingerprint>` gossipsub topic (now removed) was a naming
convention, not a mailbox — if the recipient is not subscribed at that
instant, the packet is gone. All durability therefore lived on the **sender**:
retry with exponential backoff, re-encrypt under a fresh ratchet step every
~25 minutes, give up after seven days.

That works when both people open the app regularly. It does not work when a
phone is off for a week, when a device is brand new, or when the sender
uninstalls. A server closes that gap. It is entirely optional, it is not run
by this project, and the app works exactly as before without one.

**What the server is.** Another libp2p peer speaking one extra protocol
(`/typeon/server/1.0.0`). It accepts sealed envelopes addressed to opaque
mailbox ids, stores them on disk, hands them to the recipient when they next
connect, and deletes them once the recipient confirms. Because it is an
ordinary libp2p peer, it inherits Noise transport authentication and the Arti
onion transport for free — which is what makes it possible to run one on a
spare phone behind carrier NAT, with no port forwarding, no domain and no TLS
certificate.

**What it cannot see.**

- *Message content.* Envelopes arrive already end-to-end encrypted, and are
  then sealed a **second** time under `HKDF(root_key, "…server-seal")` (the key comes from the ratchet root; the mailbox id does not, see below) before
  being deposited. Without that second layer the server's database would hold
  `MessagePacketHeader.sender_device_fingerprint` in cleartext — that field is
  openly readable, which is acceptable on a pseudonymous mailbox id but
  not in a log that persists for weeks.
- *Who is talking to whom, by name.* Mailbox ids are `HKDF` of the topic
  string, so a fingerprint cannot be read out of a bucket name. Archive bucket
  ids derive from a per-conversation key and rotate monthly.
- *History and attachments.* Archive records are encrypted under a key derived
  from the identity's archive root key; attachment chunks are stored exactly
  as they arrive, still encrypted under a per-file key that only ever travels
  inside a sealed envelope.
- *Who its users are.* Enrolment uses a **fresh keypair generated for that
  server alone**, never the device's identity keys. The server gets an
  anti-Sybil gate (the invite token) and a revocation handle, and nothing that
  identifies a person. That keypair is hybrid — Ed25519 **and** ML-DSA-87,
  both verified — like every other signature in this app: a classical-only
  signature would let a harvest-now-break-later adversary forge enrolments
  once a quantum computer exists. It would not let them *read* anything, since
  no content encryption depends on it, but there is no reason to leave one
  signature weaker than the rest.

**What it can see, and can do.** The honest accounting:

- Sizes, timing and volume of everything that passes through.
- Which `PeerId` registers and polls which mailbox ids. Each device registers
  only its own **inbound** boxes: one per contact device and direction (HKDF of
  the session's `mailbox_seed` over recipient and sender fingerprint). The
  sender never registers the box it writes to, and it deposits **anonymously**:
  a fresh throwaway libp2p identity per connection, its own Tor circuit, no
  enrollment, authorised only by a per-box deposit secret whose hash the reader
  registered. So the server sees "box X (read by enrollment B) got mail", not
  who sent it. What still leaks:
  - **Timing.** A deposit into B's box followed soon after by a deposit from B
    into another box, or A's enrollment connection being active just before,
    can link A and B statistically, more so on a server with few users.
  - **One burst, one sender.** Deposits that share an anonymous connection
    (everything queued for that server while it is open, up to 30 s idle) share
    its PeerId and circuit, so the server knows they came from one device. The
    next burst has a new identity. A group message fans out in one burst, so
    the server learns the set of boxes one sender writes to: the group's
    member devices, as box ids. One connection per box, or random delays, would
    cost a Tor circuit (and radio time) each; we do not pay that.
  - **Fetch-then-ack timing.** B fetches over its enrollment connection, then
    deposits Acks/receipts into A's box over an anonymous one moments later.
    Non-urgent packets (Ack, Seen, read state) wait for an open anonymous
    connection or the next radio window, which blurs this a little, not much.
  - **Boxes per reader.** The number of inbound boxes an enrollment reads is
    about its number of contact devices; their activity profiles stay visible.
  - **Call relay and attachments are not covered.** Call media relay frames go
    over the caller's enrollment connection to the callee's relay box, and a
    server-held attachment is uploaded by the sender's enrollment and fetched
    over the recipient's main connection. Both link the two ends.
  The deposit secret is no secret from the server (it sees it on each
  deposit); it only keeps others who learn a box id from writing to it.
- **Who made first contact with whom, by device fingerprint.** `Handshake` and
  `IdentityExchange` are stored unsealed and name their sender. The id of a
  first-contact mailbox is keyed with the nonce of the pairing code, so the
  operator cannot compute it from a fingerprint, and `Register` needs a
  signature by the mailbox key, so nobody else can read or occupy it. The
  operator sees the reader, not the depositor (previous point).
- It can **serve an old revision of an archived message** to a device that
  restores its history from nothing: an edited or deleted message comes back
  in its earlier form. The seal proves which revision a record is, not that
  it is the newest. A device that already holds the message is not affected.
- It can **drop, delay, reorder or withhold** messages. This is the
  irreducible power of any store-and-forward operator. It is contained, not
  eliminated: an ordinary message goes direct when the peer is connected, and
  gets a server copy only when no Ack arrives within 1.5 seconds. Pairing
  handshakes and ratchet-rotation announcements always take both paths from the start. A
  censoring server therefore degrades delivery to "slower, over peer-to-peer",
  never to "lost".
- It **cannot forge or modify** anything: the recipient verifies both Ed25519
  and ML-DSA-87 over header and ciphertext, and a modified byte just makes the
  envelope undecryptable — a denial, not a forgery. Replaying an old envelope
  fails too, because the ratchet message key was consumed and deleted, and
  duplicates are dropped by `message_id`.
- Its operator learns your device's `PeerId`, which is stable across
  contacts. A colluding contact and server operator could therefore link an
  enrolment to a real identity. Fixing that would need a separate swarm
  identity per server, which a single libp2p swarm cannot provide.

**Is everything on the server post-quantum encrypted?** Content, yes; two
things, no, and both are worth naming.

- *Pending messages* carry two layers, and both derive from the ratchet
  `root_key`, which comes out of the hybrid X25519 + ML-KEM-1024 handshake. So
  they are protected at the same level as live messaging.
- *The archive and attachment bytes* are sealed with 256-bit symmetric keys
  (ChaCha20-Poly1305). There is no public-key operation there to break —
  Grover costs an attacker a square-root speedup at best, leaving the intended
  128-bit margin — and the keys themselves travel only over the hybrid
  channels described above, or inside the Argon2id-protected recovery file.
- *First-contact envelopes* are the exception, and not because of
  cryptographic strength: `Handshake` and `IdentityExchange` reach the server
  readable, as described above. They carry public keys and a signature, not
  secrets, so a future quantum adversary learns nothing new from them — but
  the server operator sees the sender today.
- *The transport* between client and server is libp2p Noise, which is X25519
  and therefore classical. That is true of every connection this app makes, not
  something the server introduced, and it sits *over* content that is already
  hybrid-protected.
- *Metadata is not encrypted at all.* Mailbox and bucket ids are one-way HKDF
  outputs, but sizes, timings and PeerIds are plainly visible. That is the
  disclosure in "What it can see" above, and no amount of post-quantum
  anything changes it.

**Server-side history is a different bargain, so it is a different switch.**
A stored *delivery* envelope cannot double as history: the ratchet message key
is destroyed on decryption, so last week's envelope is undecryptable by
everyone, including its intended recipient, and a newly linked device never
held those keys at all. History therefore has to be re-encrypted by the client
under a long-lived **archive root key** — one per identity, kept in the
platform keystore, passed to sibling devices over the already-encrypted device
sync channel, and included in the recovery file.

That key is **not forward-secret**. If it ever leaks, every message archived
to a server up to that point is readable, retroactively. Live messaging keeps
full hybrid post-quantum forward secrecy; only the archive gives it up. This
is the same trade Signal's secure backups and WhatsApp's encrypted backups
make, and it is unavoidable: "let a new device load my old messages" and
"old messages become permanently unreadable" are mathematically opposed. So
"Store history on this server" is a separate switch, off by default, sitting
next to a plain-language warning. Removing a server asks it to purge that
archive first — though of course no client can *prove* a server deleted
anything, so the honest reading is "we asked", not "it is gone".

---

## 6. Local storage

- Chat history, contacts, and ratchet state live in a local SQLite database
  on-device. There is no cloud sync and no backup by default — but a user who
  configures a server *and* separately enables "Store history on this server"
  is opting into an encrypted off-device archive. That switch is off by
  default and is deliberately separate from message routing, because it makes
  a real tradeoff; see "Optional store-and-forward server" below.
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
- **No device backup (fourth audit round fix).** `android:allowBackup` was
  `true`, which made the app's private data eligible for Google auto-backup
  and `adb backup`. While the secret-key blobs are Keystore-wrapped (and
  Keystore keys are device-bound, so useless off-device), other on-disk data
  is more exposed: the plaintext decrypted attachment cache
  (`attachments/plain_cache/`), the plaintext `libp2p_identity.key`, and
  plaintext metadata columns in SQLite (contact identities, group
  membership, file names). Backup is now fully disabled (`allowBackup=false`,
  `fullBackupContent=false`, and a `data_extraction_rules.xml` that excludes
  everything from both cloud-backup and device-transfer on API 31+).
- **Screenshot and screen-recording prevention: owner rule.** The *client*
  app deliberately sets **no** `FLAG_SECURE` on ordinary chat, list and settings
  screens (screenshots, recording and recents thumbnails are allowed there).
  It sets the flag, in release builds only (`P2PApplication.setSecure`), on the
  link-device QR, QR scan, camera and lock screens; on every screen below
  Android 13 (no recents opt-out there); on the chat screen and the media viewer
  while a **disappearing message** is on screen; and on the image editor dialog.
  Android 13+ also hides the recents thumbnail. The *server app* (`ServerActivity`)
  sets it in non-debug builds because its join code is a bearer token. The code
  lasts 3 days and is renewed (§10).
- **Recovery file uses Argon2id (fourth audit round fix).** The recovery
  export (which contains *all* long-term secret keys — Ed25519, ML-DSA,
  X25519, ML-KEM) previously derived its file-encryption key with
  HKDF-SHA256(passphrase). HKDF is a single HMAC — essentially free to
  guess — so if that file ever leaked, a user-chosen passphrase could be
  brute-forced offline at enormous speed, undoing all the post-quantum work
  for the one artifact holding the raw keys. It now uses **Argon2id**
  (memory-hard, OWASP baseline parameters: 64 MiB / 2 iterations / 1 lane),
  with the algorithm and parameters stored in the file so a future import
  path can reproduce the key. (Import isn't wired up yet — export is
  currently the only recovery path.)

---

## 7. Summary of all four audit rounds

| Gap found | Status |
|---|---|
| GroupUpdate sent unencrypted, Ed25519-only | **Fixed** — moved inside ratchet channel, hybrid-signed |
| `verify_hybrid_signature` allowed a missing PQ signature | **Fixed** — both components now mandatory |
| Device revocation flag existed but was never enforced | **Fixed** — real revocation + enforcement added |
| IdentityExchange skipped the TOFU decision tree | **Fixed** — now runs `evaluate_sender_device` |
| Category 3 PQ parameters (ML-KEM-768/ML-DSA-65) | **Upgraded** to Category 5 (ML-KEM-1024/ML-DSA-87) |
| Gossipsub topic-per-fingerprint metadata leakage | **Fixed** — topic now derived from ratchet `root_key`, rotates every 30 min (the server mailbox id is separate and stable per device pair, see §5); first-contact pairing still uses fingerprint (unavoidable bootstrap) |
| `zeroize` dependency unused (in-memory key erasure) | **Fixed** — upstream crate features + explicit zeroize-on-drop for ratchet/session/message keys and the JNI secret-key bundle |
| No cross-network (NAT) connectivity — spec called for it, never implemented | **Fixed** — Circuit Relay v2 (open, Node-mode devices) + DCUtR hole-punching + organic/QR/manual relay discovery |
| Cross-network pairing required someone to operate a relay/VPS | **Superseded** — UPnP was tried and removed (M-201); reachability is Tor onion services only |
| Message header `sender_identity_id` was never bound to the authenticated device — a paired contact could spoof another identity's group messages / overwrite another contact's avatar | **Fixed** — `receive_message`/`process_handshake_init` now reject any packet whose header identity doesn't match the device's TOFU-recorded identity |
| Handshake had no replay protection; a replayed `HandshakeInit` could reset a live ratchet (conversation-DoS) | **Fixed** — freshness window (±10 min) + content-based dedup of exact replays; genuine re-pairing (fresh keys) still accepted regardless of clock skew |
| `allowBackup=true` exposed private data to cloud/adb backup | **Fixed** — backup fully disabled |
| Recovery file protected only by fast HKDF | **Fixed** — Argon2id (memory-hard) |
| No reconnection after a drop (network-type change / app restart / peer briefly offline) — only mDNS (same-LAN) recovered; `ConnectionClosed`/dial errors were only logged | **Fixed** — persistent per-device address hints + a self-healing reconnect sweep (≤15 s) + immediate reconnect on chat-open/send; see §5 |
| mDNS persistent PeerId on LAN | Superseded — mDNS removed (M-201); PeerId stays persistent by design |
| Kademlia DHT participation reveals IP to other DHT peers | Known limitation, structural to any DHT-based P2P design; relaying mitigates it for message traffic but not DHT participation itself |
| Zero-config guarantee that any two strangers can always connect | Not fully achievable without *some* reachable point in the network (structural to decentralized P2P, not fixable by protocol changes alone) — mitigated, not eliminated, by the manual relay-address field |
| No connectivity when both peers are behind CGNAT | **Fixed (v1)** — Tor onion-service hosting + `.onion` dialing (arti/rustls), reachable across CGNAT; both peers must enable Tor. IP still visible via `identify` (anonymity is a scoped v2) |
| Complete/absolute untraceability (IP-level, against a global adversary) | Not achievable by design — same limitation Tor itself has; even full Tor routing only raises the bar, doesn't reach "complete" |

---

## 8. 2026-10-20/21 fix pass: changed facts and standing decisions

- **Pairing window:** QR/manual code nonces are bearer secrets valid for **30 minutes** (was 24 h), unlimited scans within it, at most 6 live nonces (5-minute reuse step). Anyone who sees the code in that time can start a pairing; tell the user.
- **Metadata scrub fails closed, but only covers JPEG and PNG.** If the metadata of a JPEG/PNG cannot be parsed the file is refused. HEIC/WebP/GIF/video are not scrubbed by the Rust core (Android re-encodes/remuxes in `OutgoingMedia.kt`; the Linux client has no scrub layer), so GPS can remain in those formats.
- **Notification content is hidden by default.** The client's message notification says only "new message" — neither the sender's name nor the message text — unless the user turns message text on in Settings. The Android client also no longer requests `SYSTEM_ALERT_WINDOW` (that overlay permission is gone).
- **Tor is mandatory** (see above). No Tor, no network.
- **Server revoke = block.** Revoking an enrolled device puts its enroll key on the server's block list; it cannot re-enroll with that key. A reinstall (new PeerId + new enroll key) with a still-valid join code gets past it, so a real ban means **rotating the join code**.
- **Uninstalling the server app wipes** its onion identity and every enrolled device's token; all devices must re-enroll against the new address.
- **Server history off** purges the server archive.
- **Protocol breaks** (server protocol v3, tagged/framed packet and device-auth signatures, keyed archive record ids): all devices must be re-linked and contacts re-paired. Details in `TECHNICAL_HANDOFF.md` section 19.
- **Server rate limits:** mail from the server 600/10 s, unknown peers 300/10 s total, global Enroll/Rebind verify budget, `ArchivePut` <= 256 records.
- **Open by decision:** server `sent_at_ms` stays in clear.
- **Server metadata at rest:** the Android server app now keeps its SQLite database in SQLCipher (random key wrapped by an Android Keystore AES key; a plain DB from an older install is migrated once). The Linux `typeon-server` stays plain unless `TYPEON_SERVER_DB_KEY` (64 hex) is set; there, protect the disk. Sizes/timestamps are still not padded. Archive rows expire 13 months after their last write. One process per data dir (`server.lock`, flock). The Android server app has a PIN lock (join code, device list, settings).
- **Accepted server items (2026-10-21):**
  - SQLite runs inline on the server's single event loop (#16): a slow disk delays all peers; accepted until a load test shows stalls.
  - Node mode relays circuits for strangers (#17): by design, it is the relay/DHT mode and is opt-in.
  - A revoke/block bans only the enroll key (#18): a reinstall with a valid join code gets back in; rotate the join code for a real ban.
  - The server stores each client's global libp2p `PeerId` (#20): servers can link the same device across servers; no per-server identity.
  - The join token is stored in plaintext (#22): the join code must stay re-showable; it is behind the DB encryption and the app PIN.
  - The server app holds a wake lock and Wi-Fi lock while running (#23): without them Doze drops the Tor circuits; costs battery.
  - Blob ids and archive bucket ids are capabilities (#72): anyone enrolled who learns one can fetch it. Since server protocol 8 a bucket id is a hash of a per-bucket purge secret derived from the archive key, so only the account's own devices can purge a bucket; the operator, who sees every id, cannot hand out deletion.
- **2nd round protocol breaks (2026-10-21):** stable session mailbox id, `ServerErrorCode::BadHash`, `FileChunkResponse::Busy`, length-prefixed pairing nonce proof, mandatory `signature_pq` on `DeviceAdd`/`DeviceRevoke`. Bump the version; every device must update.
- **3rd round protocol breaks (2026-10-21):** the message header now travels as the sender's **raw CBOR bytes** — the hybrid signature covers exactly those bytes (`p2pmsg-v0.6-packet`) and the same bytes are the ratchet AEAD's **associated data**, so a receiver can only act on the header the sender actually encrypted under. `IdentityExchange` is signed **for the recipient device** and carries a **timestamp** (`p2pmsg-v0.5-identity-exchange`): a captured pairing packet replays to no other device and only inside the receiver's freshness window. Group first-contact secrets are **per group** (`FirstContactSecret.group_id`), a group update now carries only the **changed** member devices (a `GroupSyncRequest` asks the founder for the full state), a group call invite names its **participants**, and the whiteboard digest is a **per-stroke content hash**. Bump the version; every device must be re-linked and every contact re-paired.
- **Release APKs are signed only by `sign-release.sh`.** Gradle leaves the release build **unsigned** (the debug key tracked in the repo would let anyone with the source sign an update); the script signs with the private key of the v3 rotation lineage, for the client and the server app alike.
- **Unopenable server mail is not acked:** the mailbox cursor stays before it for 5 minutes, then it is passed over (details in `TECHNICAL_HANDOFF.md` section 13.4).

## 9. Remaining metadata and lifetime notes (2026-10-28)

- **Clipboard self-clear only covers the running process.** `SensitiveClip` clears the primary clip 60 s after a copy, but that timer lives in the app process: if the process is killed first (force stop, OOM, reboot) the copied text stays on the clipboard until something else overwrites it. Other apps can also read the clipboard before the timer fires.
- **Server archive buckets reveal record counts.** Archive records are grouped into per-conversation, per-period buckets, so a server can count how many records a conversation produced in each period even though record bodies stay sealed (end-to-end encrypted, keyed ids). Traffic analysis of volume/timing is not hidden. Item sizes are padded since 2026-11-21 (Padmé, §10), so the server sees size classes, not exact lengths; record counts and timing remain visible.

---

## 10. Current state (2026-11-22, HEAD `09ad037`) — overrides earlier sections

**Network**
- **No gossipsub.** Removed in c798a6f. Envelopes go over `/p2pmessenger/envelope/1.0.0`
  to the peer's connected PeerId; if that fails, the server copy; if neither works, the
  pending-envelope retry queue. Replies to pairing (IdentityExchange, Handshake) go back on
  the connection they arrived on.
- Server copy timing: critical packets (handshake, IdentityExchange, ratchet rotation, call
  signal) go to both paths at once. Ordinary messages get a server copy only when there is no
  Ack after 1.5 s, or when the direct path is down.
- **mDNS, UPnP and DCUtR are not in the build.** Circuit Relay v2 (client and service) and
  identify remain. Kademlia runs in client mode. The sections on DCUtR, UPnP and mDNS above
  are history.
- Transport is onion-only. There is no TCP listener and no TCP dial: inbound onion streams reach
  the swarm in-process (`tor::OnionListen`). The `DialReject` wrapper of earlier rounds is gone because
  the TCP transport it blocked is gone.

**Server (optional store-and-forward)**
- Protocol version **8**. Archive bucket ids are hashes of per-bucket purge secrets, so only
  the account's own devices can purge a bucket (see §8).
- Enrolment cap: **16 active devices** per server (`DEFAULT_MAX_ENROLLMENTS`; the Android server
  app uses the same 16). Idle enrolments (30 days) are put to sleep. At most 60 public
  enrolments per hour. Quotas are split per device (`budget / max_devices`).
- Public join code: **valid 3 days**, then renewed by the server (`PUBLIC_CODE_TTL_MS`). It is a
  bearer token, so anyone holding it can enrol until the operator rotates it. Rotating the code
  does not affect enrolled devices. A revoke only blocks the enrol key, so a real ban means
  rotating the code.
- Server DB schema version **6**. Archive rows expire 13 months after their last write.
- **Size padding (2026-11-21, c8ca950).** Mailbox envelopes, first-contact items and archive
  records are padded inside the AEAD with Padmé rounding (minimum 512 bytes, overhead up to
  about 12 %). Acks, receipts and short texts all look alike to the server. Not padded: blob
  chunks, timestamps, and the number and timing of items.
- Server app PIN lock: PBKDF2-HMAC-SHA256, 600,000 iterations, at least 6 characters (older PINs
  with 300,000 iterations are still read).

**Client**
- App lock: PBKDF2-HMAC-SHA256, 600,000 iterations (120,000 is still read). App password minimum
  8 characters.
- `FLAG_SECURE`: only in the places listed in §6 (owner rule: not on ordinary chat, list or
  settings screens). The server app sets it in non-debug builds.
- `allowBackup` off. `targetSdk` 35.
- Notification text hidden by default. No `SYSTEM_ALERT_WINDOW`. A disappearing message never
  shows its content in a notification.
- Desktop (Linux, Windows) clients are link-only secondary devices. They never create an
  account or hold device authority; only the root (first) device adds or revokes devices.
- On Quit a desktop sends a keepalive `bye`, so peers stop dialling it until it connects again.

**Disappearing messages (2026-11-21/22) — what they are and are not**
- A per-chat mode (30 s to 4 weeks) set from the chat's clock button. Each message carries its
  own timer (`expire_secs`). A received message counts down from when it is on this device's
  screen; an unopened one goes after 1 day (or its own timer when longer). The sender's copy
  counts from sending.
- Disappearing rows never go to the server archive, history answers, recovery files or chat
  previews. Expired rows stay as tombstones, so late copies cannot bring them back. A sent file's
  encrypted copy is kept until the cap so an offline receiver can still download it.
- The client blocks copy, forward, quote, save and selection, and sets `FLAG_SECURE` while one is
  on screen. Desktops show only a placeholder.
- **This is a convenience feature, not a guarantee.** A receiver can still photograph the
  screen, use a rooted or modified client, or run an unmodified old copy of the database; the
  server may still hold the sealed delivery envelope until the receiver acks it or it expires
  (14 days). The timer is enforced by each client's own clock and software.

**Calls**
- Group call offers are re-sent to absent members for as long as the call runs, so members see
  **Attend**; `Ended` and `Joined` signals stop the ring on other devices. All signals are
  ratchet messages; the server sees them as ordinary sealed items (call signals go to the server
  and the direct path at once).

**Updates**
- Self-update checks GitHub release tags over Tor about every 20 hours. An update is installed
  only when `SHA256SUMS` carries the owner's offline Ed25519 signature (`SHA256SUMS.sig`). The
  public key is pinned in `update.rs`. A release without the signature counts as unpublished.
  The server installer checks signature, hash and version before the root step replaces the binary.
  A rollback floor stops a downgrade below the newest verified stable version.
- Release APKs are signed only by `sign-release.sh`. Gradle leaves the release build unsigned.
  Every tag, pre-release or not, builds release artifacts in CI.

**Open, not changed by this pass**
- Server `sent_at_ms` still in clear. Blob and bucket ids are still capabilities for anyone enrolled.
- Clipboard self-clear and archive record counts (§9) remain as stated.
- Session mailbox reader proofs are X25519-only (§0).

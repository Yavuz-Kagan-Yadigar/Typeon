# Typeon Server

A **blind store-and-forward server** for Typeon. It holds encrypted mail for
recipients who are offline, keeps an encrypted history archive devices can
page through on demand, and stores attachment blobs — and it can read none of
it.

## Why this exists

Typeon has never had store-and-forward anywhere. libp2p Circuit Relay v2 only
builds a *live* circuit between two peers who are both online at the same
moment, and the `p2p_msg_<fp>` gossipsub topic is a naming convention, not
storage — if the recipient is not subscribed at that instant, the packet is
gone. All durability today lives on the *sender*: retry with backoff for up to
two days, then give up.

That works when both people open the app often. It does not work when a phone
is off for a week, when a device is brand new, or when the sender uninstalls.
This server closes that gap without giving up end-to-end encryption.

## What the server can and cannot see

**Cannot see**

- Message content — envelopes are already end-to-end encrypted, *and* sealed a
  second time under a key derived from the pair's ratchet `root_key`. Without
  that second seal the sender's fingerprint would sit in cleartext in the
  server's database, because `MessagePacketHeader` carries it openly.
- History — archive records are encrypted under a key derived from the
  identity's archive root key, which never leaves the client's keystore.
- Attachment content — chunks are stored exactly as they arrive, still
  encrypted under the per-file key that travels inside a sealed envelope.
- Who is who — mailbox and archive-bucket ids are HKDF-blinded, and enrollment
  uses a **fresh keypair generated for this server alone** (hybrid Ed25519 +
  ML-DSA-87, like every other signature in this app), never the device's
  identity keys.

**Can see**

- Sizes, timing and volume.
- Which `PeerId` registered and polls which mailbox ids. Because a ratchet
  mailbox is shared by exactly two devices, that joins into a pairwise social
  graph **of its own enrolled users**. Connecting over the server's `.onion`
  hides network location, not this linkage. Hiding it properly needs anonymous
  per-mailbox credentials and a separate circuit per mailbox — out of scope,
  and not pretended otherwise.
- It can also **drop, delay, reorder or withhold** messages. It cannot forge
  or modify them (the recipient verifies Ed25519 + ML-DSA-87 signatures), and
  withholding is contained: the client keeps sending over gossipsub/Tor/relay
  in parallel after a short grace period, so a censoring server degrades
  delivery to "slower over P2P", not "lost".

## Two stores, deliberately not one

| Store | Holds | Lifetime |
|---|---|---|
| `mail` | sealed delivery envelopes | deleted on the recipient's `Ack`, else 14 days |
| `archive` | re-encrypted history records | until the owner purges them or hits quota |

They cannot be merged. A ratchet message key is consumed and destroyed on
decryption, so a stored delivery envelope from last week is undecryptable by
*everyone*, including its intended recipient. History therefore has to be a
separate artifact the client re-encrypts under a long-lived key. That trade —
recoverable history is not forward-secret — is why server-side history is a
**separate switch, off by default**.

## Build and run

    cargo build --release

Needs the same toolchain as the desktop client; the first build is slow
because it compiles the protocol core, including Arti (Tor) and a bundled
SQLite.

    ./target/release/typeon-server run

Configuration is environment variables — systemd already does this well, so
there is no bespoke config file format:

| Variable | Default | Meaning |
|---|---|---|
| `TYPEON_SERVER_DIR` | `~/.local/share/typeon-server` | data directory |
| `TYPEON_SERVER_BUDGET_BYTES` | 16 GiB | total disk the server may use (mail + archive + blobs) |
| `TYPEON_SERVER_MAX_DEVICES` | `64` | most enrolled devices |
| `TYPEON_SERVER_NODE` | `0` | also act as a Kademlia server + Circuit Relay v2 |
| `TYPEON_SERVER_NAME` | `Typeon Server` | shown to clients on connect |

Tor is always on: the server listens on 127.0.0.1 only and is reached through
its own onion service. There is no clearnet mode.

`data/typeon-server.service` is a ready systemd unit.

## Letting people join

    typeon-server join-code                    # the permanent code — publish once
    typeon-server join-code rotate             # invalidate it and print a new one
    typeon-server devices list
    typeon-server devices revoke <enrollment_id>   # revoke = block the device's key
    typeon-server devices unblock <enrollment_id>
    typeon-server address

`join-code` prints a single line like

    typeon-server:/dns/abc…onion/tcp/42612/p2p/12D3Koo…#a1b2c3…

Paste it into **Settings → Servers → Add server** on Android or Linux, tap it
as a link on Android, or show it as a QR from the Android server app. The same
code works for **any number of people**: publish it once and nobody has to ask
you for anything.

The Sybil gate is not the token being single-use, then, but two other things:
at most 60 new enrollments per hour are accepted through a public code, and
`join-code rotate` shuts the door instantly if the code leaks (already-enrolled
devices keep working — enrollment does not depend on the token).

`devices revoke` blocks the device's enrollment key and PeerId until
`devices unblock`. The key is made by the device, so a reinstall (new key, new
PeerId) can enroll again with any live code: rotate the join code as well when
you want someone out. The Android server app's *Block* does that rotation.

Because the code has to stay printable, the public token is stored in the
clear. Hashing only ever protected *unused* invites against someone who stole
the database; a code published on a poster has no such secret to protect.

### One-off invites

    typeon-server invite new my-phone 1 7      # label, uses (0 = unlimited), days
    typeon-server invite list

Still there for the narrower case: a code you want to burn after a fixed number
of uses or a fixed number of days. These tokens are stored hashed.

These commands open only the database, so they work while the server runs:
the address in a code is the one the running server last advertised.

## The address takes a minute

The onion address only appears after Arti finishes bootstrapping — usually
30–60 seconds on first run. Until the server has advertised one, `join-code`,
`invite new` and `address` say so and print nothing; run them again.

## Android

The same crate builds for Android via cargo-ndk and backs the dedicated server
app. That is meant for an always-on spare phone: Android will still kill a
foreground service under memory pressure, so a small VPS is the recommended
deployment. The `.onion` transport is what makes a phone reachable at all,
with no port forwarding and no domain.

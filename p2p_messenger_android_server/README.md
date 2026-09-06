# Typeon Server for Android

A dedicated, minimal APK that turns a phone into a **store-and-forward
server** for Typeon. Separate project from the messenger on purpose: the
client's build never has to compile this, and the two APKs install side by
side.

## What it is for

Typeon has no store-and-forward without a server. A libp2p relay only builds a
*live* circuit between two peers who are both online at the same instant; the
gossipsub mailbox topic is a naming convention, not storage. Durability
otherwise lives entirely on the sender, which stops working once a phone has
been off for longer than the sender's retry window.

This app closes that gap for a small group of people who know each other. It
holds encrypted mail for recipients who are offline, optionally keeps an
encrypted history archive, and serves attachment chunks — and it can read none
of it.

## Honest limitation, read this first

**Android will still kill a foreground service under memory pressure.** This
app is meant for a spare phone left plugged in, not for a server that must
never miss anything. For that, run the `typeon-server` daemon on a small VPS —
same crate, same protocol, no OS fighting you. See `../typeon-server/README.md`.

Do tap **"Exempt from battery optimisation"** on first run; without it Android
throttles the process hard once the screen has been off for a while.

## Tor is always on, and is not a setting

The app always hosts an onion service. That is the only way a phone behind
carrier-grade NAT is reachable at all — no port forwarding, no domain, no TLS
certificate. Making it switchable would just be a way to silently produce a
server nobody can connect to, which the operator would only discover when
someone complained that messages stopped arriving.

The onion address takes 30–60 seconds to appear on first launch while Arti
bootstraps. The join code cannot exist before then, because a code with no
address in it is useless.

## Letting people join

The screen shows one **permanent** join code — a QR and a copyable line:

    typeon-server:/dns/abc…onion/tcp/42612/p2p/12D3Koo…#a1b2c3…

It appears by itself once the onion address is up. Publish it once: any number
of people can scan it, paste it under **Settings → Servers → Add server**, or
just tap it as a link on Android. Nobody has to ask you for a code, and you do
not have to come back to this screen for each new person.

**Rotate code** invalidates it and prints a new one — the answer if the code
leaks or ends up somewhere you did not intend. Devices that already enrolled
are unaffected, because enrolment does not depend on the token.

The remaining Sybil defence is a ceiling of 60 new enrolments per hour, plus
that rotate button. The token itself is stored in the clear, because a code
printed on a poster has no secret left to protect; one-off invites (still
available through the `typeon-server` daemon's `invite new`) are the ones
stored hashed.

Enrolled devices appear in the list with a short id and how much space they
use. That id comes from a keypair generated for this server alone — it tells
you nothing about who the person is, only which enrolment to revoke if you
need to. Revoking is immediate and non-destructive: that person's messenger
keeps working, it just falls back to peer-to-peer delivery.

## Building

Needs the same toolchain as the client — Rust with the Android targets, the
NDK, and `cargo-ndk`. Gradle runs the cross-compile itself:

    ./gradlew :app:assembleDebug

The first build is slow: it compiles the whole protocol core, including Arti
(Tor) and a bundled SQLite, for three ABIs.

## What the operator can and cannot see

Cannot: message content, history, attachment content, or who any enrolled
device belongs to.

Can: sizes, timing, volume, and which peer polls which mailbox. Because a
mailbox is shared by exactly two devices, that does join into a pairwise
social graph *of this server's own users*. It can also drop or delay messages
— though clients keep a peer-to-peer path open in parallel, so that degrades
delivery rather than blocking it. The full accounting is in the repository's
`SECURITY.md`.

# Typeon for Linux

A native GTK4 desktop client that joins an existing Typeon account **as a
secondary device**.

It is not a reimplementation of the protocol. The whole core — hybrid
post-quantum handshake (ML-KEM-1024 + X25519, ML-DSA-87 + Ed25519), the double
ratchet, the encrypted SQLite archive, libp2p and the Tor onion transport,
multi-device linking — is the *exact crate the Android app ships*, linked into
this binary as an rlib. What lives in `src/` is the user interface, the local
key vault, and the desktop plumbing that Android gets from system services.

No Electron, no webview, no container: one statically-linked Rust binary
against the system GTK4.

## Secondary device only

The desktop is a secondary device only. It cannot create or restore an account.
First launch offers one choice, **Link to my phone**: the app generates its own
keypair, shows a device-link QR, and waits to be adopted. The phone signs a
`DeviceAdd`, ships a full sync (contacts, groups, sibling devices) and announces
this one to every contact. Its secret key never moves. Afterwards the two are
independent: contacts fan every message out to all your active devices, so
neither has to be online for the other to receive anything.

A half-finished link resumes on the next launch rather than dropping you into an
empty window. The phone scans the QR this app displays; the desktop never scans.

## Building

    sudo zypper install gtk4-devel libadwaita-devel   # openSUSE
    # sudo dnf install gtk4-devel libadwaita-devel    # Fedora
    # sudo apt install libgtk-4-dev libadwaita-1-dev  # Debian/Ubuntu

At runtime you also need a secret store — `kwalletd6` **or** `gnome-keyring`.
Typeon refuses to start without one; see below.

Voice messages need `ffmpeg` (it captures through PipeWire's PulseAudio
interface and encodes Opus). Without it the microphone button is disabled and
says so; everything else works.

    cd Linux
    cargo build --release
    ./target/release/typeon

The first build is slow — it compiles the whole core, including `arti` (Tor) and
a bundled SQLite.

Desktop integration — **the `.desktop` file is required for notifications**, not
just for the app menu. GLib's `GNotification` silently does nothing when no
desktop file matches the application id, so without this step messages arrive
with no alert at all:

    install -Dm755 target/release/typeon ~/.local/bin/typeon
    install -Dm644 data/com.p2p.messenger.Typeon.desktop \
        ~/.local/share/applications/com.p2p.messenger.Typeon.desktop
    install -Dm644 data/com.p2p.messenger.Typeon.svg \
        ~/.local/share/icons/hicolor/scalable/apps/com.p2p.messenger.Typeon.svg
    update-desktop-database ~/.local/share/applications

You also need a notification daemon running (mako, dunst, swaync, or your
desktop's built-in one).

### Running a second profile

Typeon is single-instance: launching it again raises the window you already
have. To run a second identity in parallel, give it its own data directory and
opt out:

    XDG_DATA_HOME=~/.typeon-alt TYPEON_ALLOW_MULTIPLE=1 typeon

## Linking this computer to your account

1. Launch `typeon`. Give the device a name (it is what your phone will list
   under "Linked devices") and optionally set a vault passphrase.
2. Press **Generate link code**. The QR appears once the network has a listening
   address — a few seconds, longer with Tor.
3. On the phone: **Settings → Linked devices → Link a device**, and scan.
4. The desktop switches to the main window on its own once the phone has adopted
   it. If you quit halfway through, relaunching returns you to the same QR.

## Where things are stored

Everything is under `$XDG_DATA_HOME/typeon` (usually `~/.local/share/typeon`):
the SQLite database, encrypted attachment blobs, Tor state, `settings.json`, and
`vault.bin`.

### About `vault.bin` and the system keyring

`vault.bin` holds this device's secret key bundle and the two symmetric keys the
core needs on each launch. Android keeps the equivalent under a hardware-backed
Keystore key; the desktop equivalent is your session's own secret store.

**Typeon requires KDE Wallet or GNOME Keyring and will not start without one.**
There is no plaintext fallback — if neither is available it shows what is
missing and quits.

The file is sealed with ChaCha20-Poly1305 under

    SHA-256("typeon-vault-v2" ‖ wallet_key ‖ argon2id(passphrase, salt)?)

where `wallet_key` is 32 random bytes that exist only inside the wallet (which
is itself encrypted at rest and unlocked by your login credentials). Copying
`vault.bin` off the machine therefore gets an attacker nothing on its own.

An **extra passphrase** is optional and is a *second factor*, not an
alternative: with one set, opening the vault needs both the unlocked wallet and
something you know, and Argon2id (64 MiB, 3 passes) stretches it. Both halves
are required — forgetting it means re-linking this computer from your phone.
Set or remove it in Settings → Security.

Both wallets are reached through the same freedesktop Secret Service D-Bus API.
GNOME Keyring implements `org.freedesktop.secrets` directly; KDE Wallet does it
through `ksecretd` (shipped with `kwalletd6`), which is often *not* activatable
under that name — so Typeon activates `org.kde.secretservicecompat` explicitly
before connecting, rather than failing on a machine that has a perfectly good
wallet installed.

## What it does

Chats and contacts in a sidebar, the conversation beside it (it collapses to
single-pane on a narrow window). 1:1 and group chats share one implementation.

- Text messages with replies, edit, delete-for-everyone, and delivery ticks
  (one = handed to the network, two = the peer's app displayed it)
- Attachments: send any file, inline previews for photos, download with
  progress, open with the system default application
- Infinite scroll upward — local archive first, then requested from the peer
- Typing indicators, read receipts, and read-state sync across your devices
- Groups: create, invite, remove, leave, delete, group picture
- Pairing by QR or pasted manual code, pin/unpin, search, per-chat clear/delete
- Desktop notifications (suppressed for the chat you are looking at)
- Node mode, Tor toggle, storage limit, manual relay addresses
- The device-change security alert, shown modally, one at a time
- Linked-device management and revocation; recovery-file export
- Voice messages: record (with a discard button), send, and play back
- In-app viewer for photos, video and voice messages, with save-a-copy
- Search within a conversation
- Chat wallpaper, font choice, and log out / erase this device
- Light/dark/system, plus accent / background / text colour pickers and text /
  interface size sliders, matching the Android Settings screen

## Look and feel

The layout is GTK4/libadwaita; the design language is Material 3 (`src/theme.rs`).
A full M3 tonal palette is generated from one seed colour — every surface,
container and accent is derived from it — alongside M3's shape scale and
pill geometry for anything interactive.

One thing worth knowing if you touch the theme: **libadwaita 1.6+ owns its own
colours and an application cannot take them back.** Neither redefining its named
colours (`@define-color accent_bg_color`) nor the 1.7 CSS custom properties
(`--accent-bg-color`) reaches its widgets, even at `PRIORITY_USER`; the result
is a window that follows your palette while switches, sliders and surfaces stay
on the desktop's system colours. `AdwStyleManager::set_accent_color` only accepts
nine presets, not arbitrary RGB. So the accented and surface widgets are painted
explicitly, each with `background-image: none` — libadwaita draws them with a
gradient that otherwise sits on top of any `background-color`.

## Development aids

Set `TYPEON_UI_TEST` to render one screen without a linked device — useful
because most of the UI is otherwise only reachable after pairing with a phone:

    TYPEON_ALLOW_MULTIPLE=1 TYPEON_UI_TEST=bubbles typeon             # chat bubble layout
    TYPEON_ALLOW_MULTIPLE=1 TYPEON_UI_TEST=settings typeon            # settings
    TYPEON_ALLOW_MULTIPLE=1 TYPEON_UI_TEST=settings-appearance typeon # theming
    TYPEON_ALLOW_MULTIPLE=1 TYPEON_UI_TEST=prompt typeon              # dialog spacing
    TYPEON_DUMP_CSS=1 typeon                                          # print the generated stylesheet

The harness must mirror the real widget tree — a divergence there once made a
wallpaper look broken when only the harness was wrong.

## Harmless warnings on startup

    Gtk-WARNING: GtkGizmo (slider) reported min width -2, but sizes must be >= 0
    Adwaita-WARNING: Using GtkSettings:gtk-application-prefer-dark-theme …

Neither comes from this code. The first reproduces with a bare `AdwStatusPage`
containing nothing at all (libadwaita 1.9.2 / GTK 4.22) — it is that widget's
own internal scrolled window. The second comes from the system's GTK settings.
Rendering is unaffected.

## Known gaps versus the Android app

- **No camera QR scanning.** Adding a contact uses the pasted manual code, which
  carries an identical payload. Showing *your* QR works.
- **No video thumbnails** — that would need a decoder this does not pull in.
  Videos still send and play; they just have no preview image.
- **No camera QR scanning**, so contacts are added by pasted code and this
  machine cannot adopt other devices as a primary (see above).
- **No language switcher.** The Android app ships English and Turkish strings;
  every string here is English and inline. Adding a picker means externalising
  them all first — a separate piece of work, not a setting.
- Audio and video playback needs a GTK media backend module. If it is missing
  the viewer says so and offers to hand the file to your usual player; images
  always work.
- **Day separators only appear on load**, not on messages that arrive live.
- **Older pages of history are text-only**; attachments are merged onto the
  first page, because the core does not paginate them.
- **Attachment rows refresh by reloading the conversation** when a new offer
  arrives, rather than being patched in place.

## Relationship to the Android tree

Three additive changes were made to `p2p_messenger_android/.../rust`, none of
which alter Android behaviour:

- `Cargo.toml`: `rlib` added to `crate-type` (a Rust crate cannot `use` a
  cdylib). cargo-ndk still produces the same `.so`.
- `src/api.rs` (new): a JNI-free façade mirroring each `Java_..._P2PLib_*`
  export one-to-one — same locking order, same return shapes. The JNI exports
  are untouched and do not call it.
- `Deserialize` added to the six public summary structs, so this client reads
  back the core's own types instead of keeping hand-written copies that could
  drift.

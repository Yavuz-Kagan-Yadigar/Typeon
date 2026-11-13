# Packaging

## Linux — Flatpak

```sh
# One-time: runtime + SDK + Rust extension + builder
flatpak --user install -y flathub org.gnome.Platform//49 org.gnome.Sdk//49 \
        org.freedesktop.Sdk.Extension.rust-stable//25.08 org.flatpak.Builder

# Build and write to a local ostree repo
cd Linux/packaging
flatpak run org.flatpak.Builder --user --force-clean --disable-rofiles-fuse \
        --repo=repo build-dir com.p2p.messenger.Typeon.yml

# Single-file distributable bundle
flatpak build-bundle repo typeon.flatpak com.p2p.messenger.Typeon

# Install (on the target machine)
flatpak install --user typeon.flatpak
flatpak run com.p2p.messenger.Typeon
```

`flatpak-builder` is NOT on PATH on this machine. It is installed as a flatpak app
(`org.flatpak.Builder`), so it is called through `flatpak run`.

`--disable-rofiles-fuse` looks unnecessary, but it is required when the build runs
OUTSIDE the graphical session (for example over ssh or from automation). Otherwise the
build dies with `Failed to execute child process "fusermount3" (Permission denied)` →
`Failure spawning rofiles-fuse`. The flag only disables a write-protection optimisation;
it does not change the output.

**Trap:** `flatpak build-bundle` returns 0 even when the build before it failed. It
packages whatever is in `repo`, so you get a freshly timestamped copy of OLD content.
Check the builder's own exit code, and verify the commit date before packaging:

```sh
ostree --repo=repo log app/com.p2p.messenger.Typeon/x86_64/master | head -4
```

### Why Flatpak (not AppImage or RPM)

- The app is built on **GTK4 + libadwaita**. Packaging these by hand into an AppImage
  also means bundling the gdk-pixbuf loader cache, the compiled GSettings schemas and the
  icon theme. That is fragile and does not carry across distributions. The GNOME runtime
  already provides all of them at the right versions.
- An RPM would be the easiest, but it is **not self-contained**: it would depend on the
  gtk4 and libadwaita versions installed on the system.
- The build runs **inside the sandbox**, not on the host. The host has openSUSE with
  GTK 4.22, and the runtime has 4.20. Building on the host and running in the runtime
  would risk symbol mismatches.

### Permissions (`finish-args`) and why

| Permission | Reason |
|---|---|
| `--share=network` | libp2p/gossipsub + Tor. The app has no function without a network. |
| `--talk-name=org.freedesktop.secrets` | **Required.** The vault key lives in the system keyring, and the app does not start without a keyring (see `src/keyring.rs`). KDE Wallet and GNOME Keyring both provide this name. |
| `--socket=wayland` / `--socket=fallback-x11` / `--device=dri` | GTK4 window. |
| `--socket=pulseaudio` | Voice message recording and playback. |

Broad filesystem access is **deliberately absent**. File open and save go through the
portal via `gtk::FileDialog`, so nothing outside the sandbox needs to be reachable.

## Android — release APK

```sh
export JAVA_HOME=/usr/lib64/jvm/java-21-openjdk
cd p2p_messenger_android        && ./gradlew :app:assembleRelease   # client
cd p2p_messenger_android_server && ./gradlew :app:assembleRelease   # server
```

Output: `app/build/outputs/apk/release/app-release.apk`

Do NOT use `--offline`. The `lintVitalRelease` task wants to download the `lint-gradle`
artifact, and an offline build fails at that step.

### Signing — read this

The release is signed with **the keystore committed to the repo** (`app/debug.keystore`,
`CN=Typeon Debug`). This is a deliberate choice. If the signing key changed, Android would
treat the app as a different application, refuse to install over it, and the user would
have to uninstall first. That deletes the identity, ratchet sessions, the message archive,
and on the server app the **onion identity**. Once the onion address changes, every client
registered with that server by its address can no longer reach it.

If the app is ever published to the Play Store, a separate release keystore will be needed.
That switch requires the existing installs to be removed once.

## Two traps found on a real device

**1. The keyring permission alone is not enough.** With only
`--talk-name=org.freedesktop.secrets` granted, the app did not start and showed:
*"No system keyring found — Neither KDE Wallet nor GNOME Keyring is installed."*

The reason is written in the file header note of `src/keyring.rs`. On KDE,
`org.freedesktop.secrets` often cannot be started over D-Bus by itself, so
`ensure_available()` first activates the wallet under its real name. The Flatpak D-Bus
proxy also hides the names it does not allow from the `ListActivatableNames` result, so the
app could not see any candidate and concluded that nothing was installed. That is why all
four backend names need `--talk-name` (the `BACKEND_NAMES` list).

**2. Editing the manifest invalidated the build cache.** The source is `../..`, so the
manifest was inside the copied tree. `Linux/packaging` is now on the `skip` list.

## Known limits

- **The Flatpak is a SEPARATE device.** The native build uses `~/.local/share/typeon`,
  and the Flatpak uses `~/.var/app/com.p2p.messenger.Typeon/data/typeon`. Also, the vault
  key in the system keyring is stored **per data directory path** (the `profile` field in
  `attributes()` in `keyring.rs`). Copying the profile makes the vault impossible to open.
  The right way: link the Flatpak to your account as a new secondary device by QR.
- Theme: libadwaita does not follow the system GTK theme. Inside the sandbox it falls back
  to Adwaita instead of Breeze-Dark. Cosmetic.
- Voice messages call `ffmpeg`. The GNOME 49 Platform runtime provides `/usr/bin/ffmpeg`
  (7.1.3), so no extra module is needed.

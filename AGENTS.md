# Typeon — notes for coding agents

Read this before you change anything. It holds the owner's standing rules and
the build recipes. Claude Code's private memory lives only on the owner's Linux
install, so this file is the shared copy for opencode, and for Claude on Windows.

## Layout
- `p2p_messenger_android/app/src/main/cpp/rust/` — **the protocol core** (`p2p_messenger_core`): crypto, ratchet, SQLCipher DB, libp2p + Tor (arti). Android, Linux and Windows all use this one crate.
- `p2p_messenger_android/` — Android client (Kotlin + JNI to the core).
- `p2p_messenger_android_server/`, `typeon-server/` — store-and-forward server (Android app + Rust crate).
- `typeon-crypto/` — shared crypto primitives.
- `Linux/` — GTK4 + libadwaita desktop client (`typeon-linux`). **The same crate builds the Windows client**: platform code sits behind `#[cfg(windows)]` / `#[cfg(unix)]`, plus `src/*_win.rs` and `src/win.rs`.
- `dist/` — release artifacts + `SHA256SUMS` (ignored by git).

## Owner rules
- Desktop clients (Linux, Windows) are **secondary devices only**: they link to the phone by QR. Never add account creation, pairing authority or device-authority roles to them. Unreachable desktops would break the other devices.
- Compatibility with older Typeon versions never matters. Protocol breaks are fine; write no compat code.
- **Do not build** (cargo, gradle, flatpak) unless the owner explicitly says so ("derle").
- Never use `git checkout`/`git restore` to undo work. Back the files up first, then edit them back.
- Code review: judge the code, not its comments. Comments are not evidence.
- On a release: bump the version, copy every artifact into `dist/` and refresh `dist/SHA256SUMS`.
- Never write passwords, keys or device secrets into the repo or this file.

## Windows client (cross-compiled on Linux)
Toolchain (no sudo):
- `rustup target add x86_64-pc-windows-gnullvm`
- llvm-mingw (UCRT) unpacked as `~/tools/llvm-mingw-<date>-ucrt-ubuntu-22.04-x86_64`
- MSYS2 **CLANG64** sysroot: `python3 -I Linux/packaging/windows/fetch-sysroot.py` → `~/tools/msys2-clang64` (MSYS2 no longer ships gtk4 for MINGW64). It installs the pinned set from `Linux/packaging/windows/sysroot.lock`; refresh it with `TYPEON_MSYS2_KEYRING=<msys2.kbx> python3 -I Linux/packaging/windows/fetch-sysroot.py --update-lock`, then commit the lock.

Build: `Linux/packaging/windows/build.sh [--release]`. Portable zip: `Linux/packaging/windows/package.sh` → `Linux/target/typeon-windows-<ver>.zip` (exe + DLLs, GStreamer plugins, schemas, icons, ffmpeg.exe).

Windows specifics:
- Vault key: DPAPI (`src/keyring_win.rs`), file `vault-key.dpapi` in `%LOCALAPPDATA%\typeon`.
- Voice messages: GStreamer `wasapi2src` (`src/audio_win.rs`). Calls: wasapi2, mfvideosrc, Media Foundation / OpenH264 encoders, D3D11 decoders (`src/call_media.rs`).
- Tray icon: our own `Shell_NotifyIconW` icon (`src/win.rs`, exe icon resource 1 embedded by `Linux/build.rs`): left click opens, right click → Open / Quit. Notifications are balloons on that icon (`app::post_notification`). Never call gio `send_notification`/`withdraw_notification` directly: on Windows that creates GLib's second, menu-less tray icon. Closing the window hides it to the tray; main menu → Quit also exits.
- Autostart: Settings → Network → "Start with Windows" (HKCU Run, `--background`).
- Custom fonts: `pango_font_map_add_font_file` (`src/win.rs`).
- Debug log: the package ships `bin\typeon-debug.exe` (a release build with `--features console`: a console window, no debug assertions or debug hooks) and `gdbus.exe`. From `cmd` in `Typeon\bin`: `set RUST_LOG=info` then `typeon-debug.exe 2> log.txt`. The release `typeon.exe` has no console.

Testing on Windows: write findings to `Linux/packaging/windows/TEST-NOTES.md` (what you did, what broke, exact error text). The Linux side reads it after reboot.

## Linux client
Build inside the GNOME SDK (the host has no GStreamer -devel):
`flatpak run --user --filesystem=home --share=network --command=sh org.gnome.Sdk//49 -c 'export PATH=/usr/lib/sdk/rust-stable/bin:$PATH CARGO_TARGET_DIR=target-sdk; cargo build'`
Release packaging is a Flatpak: see `Linux/packaging/README.md`.

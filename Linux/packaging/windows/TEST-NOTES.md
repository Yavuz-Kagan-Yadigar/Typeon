# Windows test notes

## 2026-11-08 first run on Windows 11 (owner screenshot of the link page)
1. No window decoration on onboarding pages (welcome / "Starting the network" / link QR / fatal).
   Cause: those pages are set straight into the ToastOverlay with no HeaderBar; libadwaita draws its
   own frame, so no title, no close/minimise, no drag. FIXED in `src/ui/onboarding.rs` (`framed()` wraps
   them in ToolbarView + HeaderBar). Not compiled (no-build rule).
   → 6.1.1: lock page got the same header bar (`ui/window.rs`). Compiled on Linux.
2. Tray right-click only offers exit. That menu belongs to GLib's win32 notification backend; GApplication
   gives no way to add items. A real menu (Open / Quit) needs our own Shell_NotifyIcon.
   → Done on Windows side in `src/win.rs`; reviewed on Linux for 6.1.1: hidden WS_POPUP window instead of
     HWND_MESSAGE (message-only windows miss TaskbarCreated), icon removed at shutdown, handler run from
     the GLib loop, and all notifications go as balloons on this icon (`app::post_notification`) so GLib's
     own icon never appears next to it.
3. Scan QR + approve on phone: nothing happens. NOT diagnosed. Nothing in the Windows-specific code blocks
   the adoption poll (`link_page` polls `core::is_secondary_device` every 2 s; poll loop is shared).
   Data dir after the attempt: arti_state/state touched, p2p_messenger.db-wal 1 MB, awaiting_link=true.
   Next step: debug build, `RUST_LOG=info typeon.exe` with TYPEON_DEBUG_LINK=1 from a terminal; check the
   Tor bootstrap/onion publish and whether the phone's IdentityExchange reaches this device (Windows
   Firewall prompt for typeon.exe, UCRT/arti network errors).
   → 6.1.1 ships `bin\typeon-debug.exe` with a console for exactly this. Run it, try linking, bring back log.txt.

## Tray menu (written, not compiled)
`win::install_tray` (src/win.rs) adds our own Shell_NotifyIcon: left click = Open, right click = Open Typeon / Quit.
Replaces the `withdraw_notification("typeon-tray")` trick in main.rs. UNVERIFIED: GLib's notification backend may
still add a second icon when the first notification is shown. Check; if so, suppress or send balloons via our icon.
Compile errors in the windows-sys 0.61 signatures (pointer vs isize HWND, LoadIconW arg) are possible.
→ 6.1.1 (Linux): compiled. The second-icon risk is real (GLib creates its icon on any send OR withdraw), so
  notifications now go as balloons on our icon and gio notifications are never touched on Windows.

## 2026-11-08 Linux side: same build under wine 11.20 (Xvfb)
- Window + header bar fine, DPAPI vault OK, Tor bootstraps, onion service published, link QR shown.
- **Linking WORKS under wine**: owner scanned + approved on the phone → "Bu cihaz 0c58fd8c kimliğine ikincil
  cihaz olarak bağlandı", root archive key received, contacts + chats synced. Phone reached this device
  through its onion (inbound from 127.0.0.1 = arti's local hand-off).
- So nothing in the Windows code path blocks linking; the failure on real Windows is environmental.
  Suspects: Tor not yet bootstrapped when the QR was scanned (QR appears before "onion service yayında";
  the phone's dial then fails), something blocking arti's outbound Tor connections (AV / firewall / proxy),
  or the loopback hand-off. Need the `typeon-debug.exe` log from real Windows to tell which.
- 6.1.2: desktop is secondary-only — welcome page has only "Link to my phone"; "Create a new account" and
  "Restore from a recovery file" are gone (owner decision).

## 2026-11-08 typeon-debug.exe: stack overflow at start
log.txt: `Identity DB'den yüklendi ... load_secret_bundle bekleniyor` then `thread 'main' (10312) has overflowed its stack`.
Cause (by reading, not verified): `core::load_secret_bundle` runs on the GTK main thread (onboarding.rs `start`), and
ML-DSA-87 / ML-KEM-1024 key construction needs more than Windows' default 1 MB main-thread stack (Linux: 8 MB).
Fix: `build.rs` links with `-Wl,--stack,16777216` on Windows. Not compiled. If the flag is rejected by the linker,
use `-C link-arg=-Wl,--stack=16777216` via RUSTFLAGS in build.sh, or move the unlock/init path into a big-stack thread.

## Native Windows build (MSYS2 CLANG64): jpegxl-src
`jpegxl-src` 0.12.0 keys its MSVC/ClangCL CMake settings on `cfg!(windows)` (build host), which breaks a native gnullvm build.
Patched copy in `Linux/patched/jpegxl-src` (checks CARGO_CFG_TARGET_ENV == msvc), wired via `[patch.crates-io]` in Linux/Cargo.toml.
Same patched crate also links `static=c++` + `static=c++abi` on a Windows host (undefined `std::__1::*`, `__gxx_personality_seh0` otherwise).

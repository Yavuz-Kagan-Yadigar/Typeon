//! Windows-only helpers: start with Windows, custom font registration.

use std::ffi::{c_char, c_void, CString, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows_sys::Win32::System::Registry::{
    RegDeleteKeyValueW, RegGetValueW, RegSetKeyValueW, HKEY_CURRENT_USER, REG_SZ, RRF_RT_REG_SZ,
};

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const RUN_VALUE: &str = "Typeon";
/// Argument the autostart entry passes: start straight into the tray.
pub const BACKGROUND_ARG: &str = "--background";

fn wide(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(Some(0)).collect()
}

/// Whether the per-user Run entry exists.
pub fn autostart_enabled() -> bool {
    let (key, value) = (wide(RUN_KEY), wide(RUN_VALUE));
    let mut size = 0u32;
    // SAFETY: valid NUL-terminated strings; a null buffer only queries the size.
    let status = unsafe {
        RegGetValueW(HKEY_CURRENT_USER, key.as_ptr(), value.as_ptr(), RRF_RT_REG_SZ, std::ptr::null_mut(), std::ptr::null_mut(), &mut size)
    };
    status == 0
}

/// Adds or removes the per-user Run entry (no admin rights needed).
pub fn set_autostart(enabled: bool) -> Result<(), String> {
    let (key, value) = (wide(RUN_KEY), wide(RUN_VALUE));
    // SAFETY: all buffers are valid NUL-terminated UTF-16 for the call.
    let status = if enabled {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let command = wide(format!("\"{}\" {BACKGROUND_ARG}", exe.display()));
        unsafe {
            RegSetKeyValueW(
                HKEY_CURRENT_USER,
                key.as_ptr(),
                value.as_ptr(),
                REG_SZ,
                command.as_ptr() as *const c_void,
                (command.len() * 2) as u32,
            )
        }
    } else {
        match unsafe { RegDeleteKeyValueW(HKEY_CURRENT_USER, key.as_ptr(), value.as_ptr()) } {
            2 => 0, // ERROR_FILE_NOT_FOUND: already off
            status => status,
        }
    };
    if status == 0 { Ok(()) } else { Err(std::io::Error::from_raw_os_error(status as i32).to_string()) }
}

#[link(name = "pango-1.0")]
extern "C" {
    fn pango_font_map_add_font_file(map: *mut c_void, filename: *const c_char, error: *mut *mut c_void) -> i32;
}
#[link(name = "pangocairo-1.0")]
extern "C" {
    fn pango_cairo_font_map_get_default() -> *mut c_void;
}

/// Makes a .ttf/.otf visible to GTK's font map for this process only. Pango
/// on Windows uses DirectWrite, not fontconfig, so the Linux trick of copying
/// into a fonts directory does nothing here. Main thread only.
pub fn register_font(path: &Path) -> bool {
    // register_active runs on every theme change: add each file once.
    static DONE: std::sync::Mutex<Vec<std::path::PathBuf>> = std::sync::Mutex::new(Vec::new());
    let mut done = DONE.lock().unwrap_or_else(|e| e.into_inner());
    if done.iter().any(|p| p == path) {
        return true;
    }
    let Ok(file) = CString::new(path.to_string_lossy().as_bytes()) else { return false };
    // SAFETY: the default map is owned by Pango (not ours to free); the file
    // name is a valid C string; a null error pointer is allowed.
    unsafe {
        let map = pango_cairo_font_map_get_default();
        let ok = !map.is_null() && pango_font_map_add_font_file(map, file.as_ptr(), std::ptr::null_mut()) != 0;
        if ok {
            done.push(path.to_path_buf());
        }
        ok
    }
}

// --- tray icon with an Open / Quit menu, and notifications as its balloons ---
//
// GLib's own win32 notification backend would add a second tray icon (with
// only an Exit item) the moment any gio notification is sent or withdrawn, so
// on Windows notifications go through `notify` below instead.

use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::Shell::NOTIFYICONDATAW;

/// What the user asked for from the tray icon.
#[derive(Clone, Copy)]
pub enum TrayAction {
    Open,
    Quit,
    /// Windows logoff or shutdown (`WM_ENDSESSION`). Delivered synchronously:
    /// the process may be killed as soon as the window procedure returns.
    EndSession,
}

const TRAY_CALLBACK: u32 = windows_sys::Win32::UI::WindowsAndMessaging::WM_APP + 1;
const TRAY_ID: u32 = 1;
const MENU_OPEN: usize = 1;
const MENU_QUIT: usize = 2;

thread_local! {
    // The window procedure runs on the GTK thread (GDK pumps this thread's
    // messages), so thread-locals are enough to reach the handler.
    static TRAY_HANDLER: std::cell::RefCell<Option<std::rc::Rc<dyn Fn(TrayAction)>>> = std::cell::RefCell::new(None);
    static TASKBAR_CREATED: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    static TRAY_HWND: std::cell::Cell<HWND> = const { std::cell::Cell::new(std::ptr::null_mut()) };
}

fn copy_wide(dst: &mut [u16], text: &str) {
    // Leave room for the terminating NUL (the struct starts zeroed).
    let room = dst.len() - 1;
    for (slot, unit) in dst.iter_mut().take(room).zip(text.encode_utf16()) {
        *slot = unit;
    }
}

fn tray_data(hwnd: HWND) -> NOTIFYICONDATAW {
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::UI::Shell::{NIF_ICON, NIF_MESSAGE, NIF_TIP};
    use windows_sys::Win32::UI::WindowsAndMessaging::LoadIconW;
    // SAFETY: plain-old-data struct, all-zero is a valid empty value.
    let mut data: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
    data.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    data.hWnd = hwnd;
    data.uID = TRAY_ID;
    data.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    data.uCallbackMessage = TRAY_CALLBACK;
    // Resource 1 is the exe icon embedded by build.rs.
    data.hIcon = unsafe { LoadIconW(GetModuleHandleW(std::ptr::null()), 1 as *const u16) };
    copy_wide(&mut data.szTip, "Typeon");
    data
}

fn tray_add(hwnd: HWND) {
    use windows_sys::Win32::UI::Shell::{Shell_NotifyIconW, NIM_ADD};
    let data = tray_data(hwnd);
    // SAFETY: `data` is fully initialised and outlives the call.
    unsafe { Shell_NotifyIconW(NIM_ADD, &data) };
}

/// Removes the icon; call before quitting, or a dead icon stays in the tray
/// until the mouse passes over it.
pub fn remove_tray() {
    use windows_sys::Win32::UI::Shell::{Shell_NotifyIconW, NIM_DELETE};
    let hwnd = TRAY_HWND.with(|h| h.replace(std::ptr::null_mut()));
    if !hwnd.is_null() {
        let data = tray_data(hwnd);
        // SAFETY: as in `tray_add`.
        unsafe { Shell_NotifyIconW(NIM_DELETE, &data) };
    }
}

/// Shows a notification as a balloon/toast on Typeon's tray icon. Plain text.
pub fn notify(title: &str, body: &str) {
    use windows_sys::Win32::UI::Shell::{Shell_NotifyIconW, NIF_INFO, NIIF_INFO, NIM_MODIFY};
    let hwnd = TRAY_HWND.with(|h| h.get());
    if hwnd.is_null() {
        return;
    }
    let mut data = tray_data(hwnd);
    data.uFlags = NIF_INFO;
    data.dwInfoFlags = NIIF_INFO;
    copy_wide(&mut data.szInfoTitle, title);
    // An empty szInfo would hide the balloon instead of showing it.
    copy_wide(&mut data.szInfo, if body.is_empty() { " " } else { body });
    // SAFETY: as in `tray_add`.
    unsafe { Shell_NotifyIconW(NIM_MODIFY, &data) };
}

fn tray_dispatch(action: TrayAction) {
    // Run the handler from the GLib loop, not inside this window procedure
    // (GTK calls from a nested Win32 dispatch are asking for re-entrancy trouble).
    let handler = TRAY_HANDLER.with(|h| h.borrow().clone());
    if let Some(handler) = handler {
        gtk::glib::idle_add_local_once(move || handler(action));
    }
}

unsafe extern "system" fn tray_proc(hwnd: HWND, message: u32, wparam: usize, lparam: isize) -> isize {
    use windows_sys::Win32::Foundation::POINT;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        AppendMenuW, CreatePopupMenu, DefWindowProcW, DestroyMenu, GetCursorPos, PostMessageW,
        SetForegroundWindow, TrackPopupMenu, MF_STRING, TPM_RETURNCMD, TPM_RIGHTBUTTON, WM_ENDSESSION,
        WM_LBUTTONUP, WM_NULL, WM_RBUTTONUP,
    };
    if message == TRAY_CALLBACK {
        // Legacy (pre-NOTIFYICON_VERSION_4) mode: lparam is the mouse message.
        match (lparam & 0xffff) as u32 {
            WM_LBUTTONUP => tray_dispatch(TrayAction::Open),
            WM_RBUTTONUP => {
                let menu = CreatePopupMenu();
                let (open, quit) = (wide(crate::i18n::t("Open Typeon")), wide(crate::i18n::t("Quit")));
                AppendMenuW(menu, MF_STRING, MENU_OPEN, open.as_ptr());
                AppendMenuW(menu, MF_STRING, MENU_QUIT, quit.as_ptr());
                let mut at = POINT { x: 0, y: 0 };
                GetCursorPos(&mut at);
                // Without these two the menu does not close when clicking elsewhere.
                SetForegroundWindow(hwnd);
                let chosen = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, at.x, at.y, 0, hwnd, std::ptr::null());
                PostMessageW(hwnd, WM_NULL, 0, 0);
                DestroyMenu(menu);
                match chosen as usize {
                    MENU_OPEN => tray_dispatch(TrayAction::Open),
                    MENU_QUIT => tray_dispatch(TrayAction::Quit),
                    _ => {}
                }
            }
            _ => {}
        }
        return 0;
    }
    if message == WM_ENDSESSION {
        if wparam != 0 {
            let handler = TRAY_HANDLER.with(|h| h.borrow().clone());
            if let Some(handler) = handler {
                handler(TrayAction::EndSession);
            }
        }
        return 0;
    }
    if message != 0 && message == TASKBAR_CREATED.with(|m| m.get()) {
        // Explorer restarted: its tray is empty again.
        tray_add(hwnd);
        return 0;
    }
    DefWindowProcW(hwnd, message, wparam, lparam)
}

/// Puts Typeon's own icon in the notification area: Open on left click, an
/// Open / Quit menu on right click. Main thread only; call once.
pub fn install_tray(handler: impl Fn(TrayAction) + 'static) {
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, RegisterClassW, RegisterWindowMessageW, WNDCLASSW, WS_POPUP,
    };
    TRAY_HANDLER.with(|slot| *slot.borrow_mut() = Some(std::rc::Rc::new(handler)));
    let class = wide("TypeonTrayWindow");
    // SAFETY: valid NUL-terminated strings and a window procedure with the
    // right signature; the hidden window lives for the whole process.
    unsafe {
        let instance = GetModuleHandleW(std::ptr::null());
        let mut wc: WNDCLASSW = std::mem::zeroed();
        wc.lpfnWndProc = Some(tray_proc);
        wc.hInstance = instance;
        wc.lpszClassName = class.as_ptr();
        RegisterClassW(&wc);
        TASKBAR_CREATED.with(|m| m.set(RegisterWindowMessageW(wide("TaskbarCreated").as_ptr())));
        // A hidden top-level window, not HWND_MESSAGE: message-only windows
        // never get the TaskbarCreated broadcast.
        let hwnd = CreateWindowExW(
            0, class.as_ptr(), class.as_ptr(), WS_POPUP, 0, 0, 0, 0,
            std::ptr::null_mut(), std::ptr::null_mut(), instance, std::ptr::null(),
        );
        if !hwnd.is_null() {
            TRAY_HWND.with(|h| h.set(hwnd));
            tray_add(hwnd);
        }
    }
}

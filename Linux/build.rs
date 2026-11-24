// Windows only: embed the app icon as resource 1. Explorer shows it on the
// exe, and the tray icon (win.rs) loads resource 1.
fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    println!("cargo:rerun-if-changed=packaging/windows/typeon.ico");
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let rc = out.join("typeon.rc");
    let ico = std::fs::canonicalize("packaging/windows/typeon.ico").unwrap();
    // Forward slashes and no `\\?\` prefix: backslashes are escapes inside an
    // .rc string, and a Windows host's canonicalize returns the verbatim form.
    let ico = ico.display().to_string();
    let ico = ico.trim_start_matches(r"\\?\").replace('\\', "/");
    std::fs::write(&rc, format!("1 ICON \"{}\"\n", ico)).unwrap();
    let obj = out.join("typeon-res.o");
    // windres: llvm-mingw's name when cross-compiling on Linux, plain or llvm-
    // prefixed under MSYS2 CLANG64 on Windows. First one that succeeds wins.
    let ok = ["x86_64-w64-mingw32-windres", "windres", "llvm-windres"].iter().any(|tool| {
        std::process::Command::new(tool)
            .arg(&rc)
            .args(["-O", "coff", "-o"])
            .arg(&obj)
            .status()
            .map_or(false, |s| s.success())
    });
    assert!(ok, "windres failed or not found (x86_64-w64-mingw32-windres, windres, llvm-windres)");
    println!("cargo:rustc-link-arg-bins={}", obj.display());
    // The main thread gets 1 MB on Windows (8 MB on Linux). ML-DSA-87 / ML-KEM-1024
    // key loading on the GTK thread overflows that ("thread 'main' has overflowed
    // its stack" right after the identity loads), so ask for 16 MB.
    println!("cargo:rustc-link-arg-bins=-Wl,--stack,16777216");
}

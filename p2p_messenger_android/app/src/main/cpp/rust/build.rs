// libjxl (jpegxl-rs "vendored") is C++ built against the NDK's libc++, but
// its build script links "stdc++" for every non-Apple target. On Android that
// is the system's tiny libstdc++.so without libc++'s symbols: link the NDK's
// static libc++ into our .so.
fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("android") {
        println!("cargo:rustc-link-arg-cdylib=-lc++_static");
        println!("cargo:rustc-link-arg-cdylib=-lc++abi");
    }
}

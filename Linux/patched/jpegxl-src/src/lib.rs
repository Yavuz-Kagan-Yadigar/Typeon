/*
 * This file is part of jpegxl-rs.
 *
 * jpegxl-rs is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * jpegxl-rs is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with jpegxl-rs.  If not, see <https://www.gnu.org/licenses/>.
 */

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use core::panic;
use std::{
    env,
    path::{Path, PathBuf},
};

fn source_dir() -> PathBuf {
    env::var("DEP_JXL_PATH").map_or_else(
        |_| Path::new(env!("CARGO_MANIFEST_DIR")).join("libjxl"),
        PathBuf::from,
    )
}

#[cfg_attr(coverage_nightly, coverage(off))]
/// Builds the JPEG XL library.
///
/// # Panics
///
/// This function will panic if the source directory does not exist or is not a directory.
pub fn build() {
    let source = source_dir();
    assert!(
        source.exists() && source.is_dir(),
        "Source directory {} does not exist",
        source.display()
    );

    let mut config = cmake::Config::new(source);
    config
        .define("BUILD_TESTING", "OFF")
        .define("BUILD_SHARED_LIBS", "OFF")
        .define("JPEGXL_ENABLE_TOOLS", "OFF")
        .define("JPEGXL_ENABLE_DOXYGEN", "OFF")
        .define("JPEGXL_ENABLE_MANPAGES", "OFF")
        .define("JPEGXL_ENABLE_BENCHMARK", "OFF")
        .define("JPEGXL_ENABLE_EXAMPLES", "OFF")
        .define("JPEGXL_ENABLE_JNI", "OFF")
        .define("JPEGXL_ENABLE_SJPEG", "OFF")
        .define("JPEGXL_ENABLE_OPENEXR", "OFF")
        .define("JPEGXL_BUNDLE_LIBPNG", "OFF");

    if let Ok(p) = std::thread::available_parallelism() {
        config.env("CMAKE_BUILD_PARALLEL_LEVEL", format!("{p}"));
    }

    if cfg!(asan) {
        config
            .env("SANITIZER", "asan")
            .cflag("-g -DADDRESS_SANITIZER -fsanitize=address")
            .cxxflag("-g -DADDRESS_SANITIZER -fsanitize=address")
            .define("JPEGXL_ENABLE_TCMALLOC", "OFF");
    } else if cfg!(tsan) {
        config
            .env("SANITIZER", "tsan")
            .cflag("-g -DTHREAD_SANITIZER -fsanitize=thread")
            .cxxflag("-g -DTHREAD_SANITIZER -fsanitize=thread")
            .define("JPEGXL_ENABLE_TCMALLOC", "OFF");
    }

    #[cfg(windows)]
    const {
        assert!(!cfg!(tsan), "Thread sanitizer is not supported on Windows");
    }
    // Host-based `cfg!(windows)` is wrong when a Windows host builds a gnullvm
    // (MSYS2 clang64) target: the ClangCL/MSVC settings only apply to msvc.
    if env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        // For CMake pre-checking
        let mut exeflags = "MSVCRTD.lib".to_string();
        if cfg!(asan) {
            exeflags.push_str(
                " clang_rt.asan_dynamic-x86_64.lib clang_rt.asan_dynamic_runtime_thunk-x86_64.lib",
            );
        }

        config
            .generator_toolset("ClangCL")
            .define(
                "CMAKE_VS_GLOBALS",
                "UseMultiToolTask=true;EnforceProcessCountAcrossBuilds=true",
            ) // Enable parallel builds
            .define("CMAKE_MSVC_RUNTIME_LIBRARY", "MultiThreaded")
            .define("CMAKE_EXE_LINKER_FLAGS", exeflags)
            .cflag("/Zl");
    }

    let prefix = config.build();

    let lib_dir = {
        let mut lib_dir = prefix.join("lib");
        if lib_dir.exists() {
            lib_dir
        } else {
            lib_dir.pop();
            lib_dir.push("lib64");
            if lib_dir.exists() {
                lib_dir
            } else {
                panic!(
                    "Could not find the library directory, please check the files in {prefix:?}"
                );
            }
        }
    };
    println!("cargo:rustc-link-search=native={}", lib_dir.display());

    println!("cargo:rustc-link-lib=static=jxl");
    println!("cargo:rustc-link-lib=static=jxl_cms");
    println!("cargo:rustc-link-lib=static=jxl_threads");

    println!("cargo:rustc-link-lib=static=hwy");
    println!("cargo:rustc-link-lib=static=brotlidec");
    println!("cargo:rustc-link-lib=static=brotlienc");
    println!("cargo:rustc-link-lib=static=brotlicommon");

    if cfg!(any(target_vendor = "apple", target_os = "freebsd")) {
        println!("cargo:rustc-link-lib=c++");
    } else if cfg!(target_os = "linux") {
        println!("cargo:rustc-link-lib=stdc++");
    } else if cfg!(windows) {
        // Windows host, MSYS2 CLANG64 target: libjxl is C++ built against
        // clang's libc++. Static, so typeon.exe needs no extra DLL.
        // The library search path is not passed to this crate's rustc, so ask
        // clang where libc++.a lives.
        if let Ok(out) = std::process::Command::new("clang").arg("--print-file-name=libc++.a").output() {
            let found = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if let Some(dir) = Path::new(&found).parent().filter(|d| d.is_dir()) {
                println!("cargo:rustc-link-search=native={}", dir.display());
            }
        }
        println!("cargo:rustc-link-lib=static=c++");
        println!("cargo:rustc-link-lib=static=c++abi");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_source_dir() {
        let mut path = source_dir();
        assert!(path.is_dir());

        path.push("lib/include/jxl/codestream_header.h");
        assert!(path.exists());
    }
}

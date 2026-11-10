#!/bin/sh
# Cross-compile typeon.exe on Linux. Needs:
#   rustup target add x86_64-pc-windows-gnullvm
#   llvm-mingw (ucrt) unpacked under ~/tools/llvm-mingw-*
#   the MSYS2 CLANG64 sysroot from fetch-sysroot.py (~/tools/msys2-clang64)
# Extra arguments go to cargo (e.g. --release).
set -eu
T=x86_64-pc-windows-gnullvm
TV=x86_64_pc_windows_gnullvm
LLVM=$(ls -d "$HOME"/tools/llvm-mingw-* | tail -n1)
SYS=${TYPEON_WIN_SYSROOT:-$HOME/tools/msys2-clang64}
export PATH="$LLVM/bin:$PATH"
export CC_$TV=x86_64-w64-mingw32-clang CXX_$TV=x86_64-w64-mingw32-clang++ AR_$TV=llvm-ar
export CARGO_TARGET_X86_64_PC_WINDOWS_GNULLVM_LINKER=x86_64-w64-mingw32-clang
# Rust links against the sysroot's import libraries (gtk, glib, gstreamer).
export CARGO_TARGET_X86_64_PC_WINDOWS_GNULLVM_RUSTFLAGS="-L $SYS/clang64/lib"
export PKG_CONFIG_ALLOW_CROSS=1
export PKG_CONFIG_SYSROOT_DIR_$TV="$SYS"
export PKG_CONFIG_LIBDIR_$TV="$SYS/clang64/lib/pkgconfig:$SYS/clang64/share/pkgconfig"
cd "$(dirname "$0")/../.."
exec cargo build --target $T "$@"

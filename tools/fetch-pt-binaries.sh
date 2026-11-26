#!/bin/sh
# Fetches the Tor pluggable-transport client lyrebird (obfs4 + snowflake; the bundle ships no separate
# snowflake-client, its transports.json maps snowflake -> lyrebird) for every Typeon build,
# from the Tor Project's pinned "tor-expert-bundle" release (the same binaries Tor Browser ships).
#
#   tools/fetch-pt-binaries.sh               download, check pins, unpack
#   tools/fetch-pt-binaries.sh --print-sums  download and print the sha256 of each bundle (to fill the pins)
#
# Fill the pins once per TB_VERSION: run --print-sums, compare each sum with the signed list
#   https://dist.torproject.org/torbrowser/$TB_VERSION/sha256sums-signed-build.txt (+ .asc, Tor Browser
#   signing key), then paste them below. A TODO pin makes the normal run stop.
#
# Output (all gitignored):
#   p2p_messenger_android/app/src/main/jniLibs/<abi>/liblyrebird.so  (abi: arm64-v8a, armeabi-v7a)
#   pt-bin/linux-x86_64/lyrebird                                     (Flatpak manifest installs it)
#   pt-bin/windows-x86_64/lyrebird.exe                               (Linux/packaging/windows/package.sh)
set -eu

TB_VERSION="16.0.3"   # verified against sha256sums-signed-build.txt.asc (Tor Browser key EF6E286DDA85EA2A4BA7DE684E2C6E8793298290)
BASE="https://dist.torproject.org/torbrowser/$TB_VERSION"

# platform  sha256-pin  output-dir  lyrebird-name
TARGETS="
android-aarch64 9d052898c39e8aeaa2035df4db205ef7f6afadfd26e606ca42107d1f1f08f5a5 p2p_messenger_android/app/src/main/jniLibs/arm64-v8a liblyrebird.so
android-armv7 07146c3c874e609591832465979d2347e4b9b80542ef720af99241e5acd74783 p2p_messenger_android/app/src/main/jniLibs/armeabi-v7a liblyrebird.so
linux-x86_64 a3fae0d3c263b81ba09e3446bd2af92bc9f8f6edf5bd8f16ab666c6140dc29f7 pt-bin/linux-x86_64 lyrebird
windows-x86_64 b70cabe2b93b5b1fd144466e42afaabe7a1a470228912657b3b5776e9cb7a9f1 pt-bin/windows-x86_64 lyrebird.exe
"

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PRINT=0
[ "${1:-}" = "--print-sums" ] && PRINT=1
if [ "$TB_VERSION" = TODO ]; then
    echo "Set TB_VERSION in $0 first." >&2
    exit 1
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

echo "$TARGETS" | while read -r platform pin outdir lyre; do
    [ -n "$platform" ] || continue
    tarball="tor-expert-bundle-$platform-$TB_VERSION.tar.gz"
    curl -fsSL --proto '=https' --tlsv1.2 -o "$WORK/$tarball" "$BASE/$tarball"
    sum=$(sha256sum "$WORK/$tarball" | cut -d' ' -f1)
    if [ "$PRINT" = 1 ]; then
        echo "$platform $sum"
        continue
    fi
    if [ "$pin" = TODO ] || [ "$pin" != "$sum" ]; then
        echo "$tarball: sha256 $sum does not match pin '$pin' (see the header of $0)" >&2
        exit 1
    fi
    mkdir -p "$WORK/$platform"
    tar -xzf "$WORK/$tarball" -C "$WORK/$platform"
    mkdir -p "$ROOT/$outdir"
    src_name=lyrebird
    dst_name=$lyre
    case "$platform" in windows-*) src_name="$src_name.exe" ;; esac
    src=$(find "$WORK/$platform" -type f -name "$src_name" | head -n1)
    if [ -z "$src" ]; then
        echo "$tarball: $src_name not found in the bundle" >&2
        exit 1
    fi
    install -m755 "$src" "$ROOT/$outdir/$dst_name"
    case "$platform" in windows-*)
        # Console -> GUI subsystem (what Go's -H=windowsgui does): arti starts the PT with no creation
        # flags, and a console exe would pop a window from the console-less typeon.exe. Pipes still work.
        python3 -I -c 'import struct,sys
f=open(sys.argv[1],"r+b"); d=f.read(4096); pe=struct.unpack_from("<I",d,0x3C)[0]
assert d[pe:pe+4]==b"PE\0\0"; f.seek(pe+0x5C); f.write(struct.pack("<H",2))' "$ROOT/$outdir/$dst_name"
        ;;
    esac
    echo "$outdir/$dst_name"
done

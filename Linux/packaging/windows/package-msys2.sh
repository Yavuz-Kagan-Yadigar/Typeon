#!/bin/sh
# Portable Windows package built NATIVELY under MSYS2 CLANG64 (the Linux
# cross-build uses package.sh). Run from an "MSYS2 CLANG64" shell after
#   cargo build --release      (and optionally  cargo build --release --features console
#   --target-dir target/console  for typeon-debug.exe)
# Output: Linux/target/windows-package/Typeon and Linux/target/typeon-windows-<ver>.zip
# Layout follows the MSYS2 prefix (bin/, lib/, share/) so GLib, GTK and
# GStreamer find their data relative to their DLLs with no env variables.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
SYS=${MSYSTEM_PREFIX:-/clang64}
VER=$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -n1)
OUT="$ROOT/target/windows-package/Typeon"

[ -f "$ROOT/target/release/typeon.exe" ] || { echo "missing target/release/typeon.exe: run cargo build --release"; exit 1; }

rm -rf "$OUT"
mkdir -p "$OUT/bin" "$OUT/lib/gstreamer-1.0" "$OUT/share/glib-2.0/schemas" "$OUT/share/icons"
cp "$ROOT/target/release/typeon.exe" "$OUT/bin/"
# Release build with a console window (feature `console`), for RUST_LOG=info
# diagnostics on Windows. Never a debug build: releases ship release code only.
if [ -f "$ROOT/target/console/release/typeon.exe" ]; then
    cp "$ROOT/target/console/release/typeon.exe" "$OUT/bin/typeon-debug.exe"
fi
cp "$SYS/bin/ffmpeg.exe" "$OUT/bin/"   # video metadata strip (util.rs)

# GStreamer plugins the app uses: calls (call_media.rs), voice messages
# (audio_win.rs) and GtkMediaFile playback (GstPlay inside GTK).
PLUGINS="coreelements app audioconvert audioresample audiomixer audiotestsrc audiorate
volume opus ogg videoconvertscale videorate videofilter videotestsrc wasapi wasapi2
mediafoundation d3d11 d3d12 libav openh264 webrtcdsp videoparsersbad audioparsers isomp4
matroska playback typefindfunctions autodetect pbtypes gio id3demux"
for p in $PLUGINS; do
    if [ -f "$SYS/lib/gstreamer-1.0/libgst$p.dll" ]; then
        cp "$SYS/lib/gstreamer-1.0/libgst$p.dll" "$OUT/lib/gstreamer-1.0/"
    else
        echo "warning: gstreamer plugin $p not found"
    fi
done
mkdir -p "$OUT/lib/gdk-pixbuf-2.0/2.10.0/loaders"
cp "$SYS/lib/gdk-pixbuf-2.0/2.10.0/loaders/pixbufloader_svg.dll" "$OUT/lib/gdk-pixbuf-2.0/2.10.0/loaders/"

# Every DLL any of the above imports that lives in the sysroot (system DLLs
# are skipped: they are not in $SYS/bin). Repeat until nothing new appears.
deps() { llvm-objdump -p "$1" | sed -n 's/^ *DLL Name: //p'; }
todo=$(find "$OUT" -name '*.exe' -o -name '*.dll')
while [ -n "$todo" ]; do
    next=""
    for f in $todo; do
        for d in $(deps "$f"); do
            src=$(find "$SYS/bin" -maxdepth 1 -iname "$d" | head -n1)
            if [ -n "$src" ] && [ ! -e "$OUT/bin/$(basename "$src")" ]; then
                cp "$src" "$OUT/bin/"
                next="$next $OUT/bin/$(basename "$src")"
            fi
        done
    done
    todo=$next
done
# gspawn helpers are started by name, never imported.
cp "$SYS"/bin/gspawn-win64-*.exe "$OUT/bin/" 2>/dev/null || true
# GLib autolaunches gdbus.exe for the session bus; without it GApplication
# silently loses single-instance mode.
cp "$SYS/bin/gdbus.exe" "$OUT/bin/"

cp "$SYS"/share/glib-2.0/schemas/*.xml "$OUT/share/glib-2.0/schemas/"
glib-compile-schemas "$OUT/share/glib-2.0/schemas"
cp -r "$SYS/share/icons/Adwaita" "$SYS/share/icons/hicolor" "$OUT/share/icons/"

# MSYS2 builds the loaders cache in a post-install hook, so the package has
# none. PNG/JPEG/TIFF are built into gdk-pixbuf; only SVG needs a loader.
cat > "$OUT/lib/gdk-pixbuf-2.0/2.10.0/loaders.cache" <<'CACHE'
"lib\\gdk-pixbuf-2.0\\2.10.0\\loaders\\pixbufloader_svg.dll"
"svg" 6 "gdk-pixbuf" "Scalable Vector Graphics" "LGPL"
"image/svg+xml" "image/svg" "image/svg-xml" "image/vnd.adobe.svg+xml" "text/xml-svg" "image/svg+xml-compressed" ""
"svg" "svgz" "svg.gz" ""
" <svg" "*    " 100
" <!DOCTYPE svg" "*             " 100

CACHE

ZIP="$ROOT/target/typeon-windows-$VER.zip"
rm -f "$ZIP"
powershell.exe -NoProfile -Command "Compress-Archive -Path '$(cygpath -w "$OUT")' -DestinationPath '$(cygpath -w "$ZIP")' -CompressionLevel Optimal"
du -sh "$OUT" "$ZIP"

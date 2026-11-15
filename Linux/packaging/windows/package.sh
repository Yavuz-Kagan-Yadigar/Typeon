#!/bin/sh
# Release build (debug with TYPEON_WIN_DEBUG=1) + portable zip: typeon-windows-<version>.zip in Linux/target/.
# Layout follows the MSYS2 prefix (bin/, lib/, share/) so GLib, GTK and
# GStreamer find their data relative to their DLLs with no env variables.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
SYS=${TYPEON_WIN_SYSROOT:-$HOME/tools/msys2-clang64}/clang64
LLVM=$(ls -d "$HOME"/tools/llvm-mingw-* | tail -n1)
OBJDUMP="$LLVM/bin/llvm-objdump"
VER=$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -n1)
OUT="$ROOT/target/windows-package/Typeon"

rm -rf "$OUT"
mkdir -p "$OUT/bin" "$OUT/lib/gstreamer-1.0" "$OUT/share/glib-2.0/schemas" "$OUT/share/icons"
# Debug build with a console window, for RUST_LOG=info diagnostics on Windows.
"$HERE/build.sh"
cp "$ROOT/target/x86_64-pc-windows-gnullvm/debug/typeon.exe" "$OUT/bin/typeon-debug.exe"
# Debug assertions + console stay; the 700 MB of DWARF does not.
"$LLVM/bin/llvm-strip" --strip-debug "$OUT/bin/typeon-debug.exe"
# TYPEON_WIN_DEBUG=1 (local test builds only, CI never sets it): typeon.exe is that debug build too.
if [ "${TYPEON_WIN_DEBUG:-}" = 1 ]; then
    cp "$OUT/bin/typeon-debug.exe" "$OUT/bin/typeon.exe"
else
    "$HERE/build.sh" --release
    cp "$ROOT/target/x86_64-pc-windows-gnullvm/release/typeon.exe" "$OUT/bin/"
fi
cp "$SYS/bin/ffmpeg.exe" "$OUT/bin/"   # video metadata strip (util.rs)

# GStreamer plugins the app uses: calls (call_media.rs), voice messages
# (audio_win.rs) and GtkMediaFile playback (GstPlay inside GTK).
PLUGINS="coreelements app audioconvert audioresample audiomixer audiotestsrc audiorate
volume opus ogg videoconvertscale videorate videofilter videotestsrc wasapi wasapi2
mediafoundation d3d11 d3d12 libav openh264 webrtcdsp videoparsersbad audioparsers isomp4
matroska playback typefindfunctions autodetect pbtypes gio id3demux"
for p in $PLUGINS; do
    cp "$SYS/lib/gstreamer-1.0/libgst$p.dll" "$OUT/lib/gstreamer-1.0/"
done
mkdir -p "$OUT/lib/gdk-pixbuf-2.0/2.10.0/loaders"
cp "$SYS/lib/gdk-pixbuf-2.0/2.10.0/loaders/pixbufloader_svg.dll" "$OUT/lib/gdk-pixbuf-2.0/2.10.0/loaders/"

# Every DLL any of the above imports that lives in the sysroot (system DLLs
# are skipped: they are not in $SYS/bin). Repeat until nothing new appears.
deps() { "$OBJDUMP" -p "$1" | sed -n 's/^ *DLL Name: //p'; }
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
( cd "$OUT/.." && 7z a -tzip -mx=9 "$ZIP" Typeon >/dev/null )
du -sh "$OUT" "$ZIP"

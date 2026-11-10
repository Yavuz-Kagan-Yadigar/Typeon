#!/usr/bin/env python3
"""Download the MSYS2 CLANG64 packages the Windows build links against and
unpack them into one sysroot directory (default ~/tools/msys2-clang64).

Run on Linux. Runtime dependencies are resolved from the repo database, so the
sysroot also holds every DLL the packaged app needs.

    python3 -I fetch-sysroot.py [sysroot-dir]
"""
import io, os, re, sys, tarfile, urllib.request, subprocess

REPO = "https://repo.msys2.org/mingw/clang64/"
PREFIX = "mingw-w64-clang-x86_64-"
ROOTS = ["gtk4", "libadwaita", "gstreamer", "gst-plugins-base", "gst-plugins-good",
         "gst-plugins-bad", "gst-libav", "adwaita-icon-theme", "ffmpeg"]

def fetch(url):
    with urllib.request.urlopen(url, timeout=120) as r:
        return r.read()

def parse_db(raw):
    # The repo DB is a zstd tar; Python's tarfile has no zstd before 3.14.
    raw = subprocess.run(["zstd", "-dc"], input=raw, capture_output=True, check=True).stdout
    pkgs, provides = {}, {}
    with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
        for m in tar.getmembers():
            f = tar.extractfile(m) if m.name.endswith("/desc") else None
            if f is None:
                continue
            fields, key = {}, None
            for line in f.read().decode().splitlines():
                if line.startswith("%") and line.endswith("%"):
                    key = line.strip("%"); fields[key] = []
                elif line and key:
                    fields[key].append(line)
            name = fields["NAME"][0]
            pkgs[name] = fields
            for p in fields.get("PROVIDES", []):
                provides[re.split(r"[<>=]", p)[0]] = name
    return pkgs, provides

def resolve(pkgs, provides):
    want, todo = set(), [PREFIX + r for r in ROOTS]
    while todo:
        name = re.split(r"[<>=]", todo.pop())[0]
        name = name if name in pkgs else provides.get(name)
        if not name or name in want:
            continue
        want.add(name)
        todo += pkgs[name].get("DEPENDS", [])
    return sorted(want)

def main():
    root = os.path.expanduser(sys.argv[1] if len(sys.argv) > 1 else "~/tools/msys2-clang64")
    cache = os.path.join(root, ".pkgcache")
    os.makedirs(cache, exist_ok=True)
    pkgs, provides = parse_db(fetch(REPO + "clang64.db"))
    names = resolve(pkgs, provides)
    print(f"{len(names)} packages")
    for name in names:
        fn = pkgs[name]["FILENAME"][0]
        path = os.path.join(cache, fn)
        if not os.path.exists(path):
            print("get", fn)
            data = fetch(REPO + fn)
            with open(path + ".part", "wb") as f:
                f.write(data)
            os.rename(path + ".part", path)
        # Packages hold mingw64/... plus .PKGINFO/.MTREE; only the tree is wanted.
        subprocess.run(["tar", "--zstd", "-xf", path, "-C", root, "--exclude=.[A-Z]*"], check=True)
    # pkg-config files carry prefix=/clang64; the build sets PKG_CONFIG_SYSROOT_DIR=root.
    print("sysroot:", os.path.join(root, "clang64"))

if __name__ == "__main__":
    main()

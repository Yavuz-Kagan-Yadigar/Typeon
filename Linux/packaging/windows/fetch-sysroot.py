#!/usr/bin/env python3
"""Download the MSYS2 CLANG64 packages the Windows build links against and
unpack them into one sysroot directory (default ~/tools/msys2-clang64).

Run on Linux. The package set is pinned in `sysroot.lock` (sha256sum format:
"<sha256>  <file name>"), next to this script. Every file is checked against
that hash before it is unpacked, cached files included, so a changed mirror
file stops the build instead of shipping in the release zip.

    python3 -I fetch-sysroot.py [sysroot-dir]

To move to newer packages (or after changing ROOTS):

    TYPEON_MSYS2_KEYRING=msys2.kbx python3 -I fetch-sysroot.py --update-lock

This resolves the dependencies from the current repo database, takes each
package's hash from the database and rewrites the lock. The database
signature is checked with gpgv when TYPEON_MSYS2_KEYRING names a binary
keyring (`gpg --dearmor` of msys2.gpg from the msys2-keyring package).
Review and commit the new lock.
"""
import hashlib, io, os, re, sys, tarfile, urllib.request, subprocess, tempfile

REPO = "https://repo.msys2.org/mingw/clang64/"
PREFIX = "mingw-w64-clang-x86_64-"
ROOTS = ["gtk4", "libadwaita", "gstreamer", "gst-plugins-base", "gst-plugins-good",
         "gst-plugins-bad", "gst-libav", "adwaita-icon-theme", "ffmpeg"]
LOCK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sysroot.lock")

def fetch(url):
    with urllib.request.urlopen(url, timeout=120) as r:
        return r.read()

def sha256(data):
    return hashlib.sha256(data).hexdigest()

def check_db_signature(raw):
    keyring = os.environ.get("TYPEON_MSYS2_KEYRING")
    if not keyring:
        print("warning: TYPEON_MSYS2_KEYRING not set, repo database signature NOT checked")
        return
    sig = fetch(REPO + "clang64.db.sig")
    with tempfile.TemporaryDirectory() as tmp:
        db, sf = os.path.join(tmp, "clang64.db"), os.path.join(tmp, "clang64.db.sig")
        with open(db, "wb") as f:
            f.write(raw)
        with open(sf, "wb") as f:
            f.write(sig)
        subprocess.run(["gpgv", "--keyring", os.path.abspath(keyring), sf, db], check=True)

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

def update_lock():
    raw = fetch(REPO + "clang64.db")
    check_db_signature(raw)
    pkgs, provides = parse_db(raw)
    lines = [f'{pkgs[n]["SHA256SUM"][0]}  {pkgs[n]["FILENAME"][0]}' for n in resolve(pkgs, provides)]
    with open(LOCK, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"wrote {LOCK} ({len(lines)} packages)")

def read_lock():
    if not os.path.exists(LOCK):
        sys.exit(f"missing {LOCK}: run with --update-lock first")
    pinned = []
    for line in open(LOCK):
        line = line.strip()
        if line:
            digest, fn = line.split(None, 1)
            # Names only, never paths: the lock decides where files land.
            if "/" in fn or fn.startswith("."):
                sys.exit(f"bad file name in lock: {fn}")
            pinned.append((digest.lower(), fn))
    return pinned

def main():
    args = sys.argv[1:]
    if "--update-lock" in args:
        args.remove("--update-lock")
        update_lock()
    root = os.path.expanduser(args[0] if args else "~/tools/msys2-clang64")
    cache = os.path.join(root, ".pkgcache")
    os.makedirs(cache, exist_ok=True)
    pinned = read_lock()
    print(f"{len(pinned)} packages")
    for digest, fn in pinned:
        path = os.path.join(cache, fn)
        data = open(path, "rb").read() if os.path.exists(path) else None
        if data is None or sha256(data) != digest:
            print("get", fn)
            data = fetch(REPO + fn)
            if sha256(data) != digest:
                sys.exit(f"sha256 mismatch for {fn}: the mirror file is not the pinned one")
            with open(path + ".part", "wb") as f:
                f.write(data)
            os.rename(path + ".part", path)
        # Packages hold clang64/... plus .PKGINFO/.MTREE; only the tree is wanted.
        subprocess.run(["tar", "--zstd", "-xf", path, "-C", root, "--exclude=.[A-Z]*"], check=True)
    # pkg-config files carry prefix=/clang64; the build sets PKG_CONFIG_SYSROOT_DIR=root.
    print("sysroot:", os.path.join(root, "clang64"))

if __name__ == "__main__":
    main()

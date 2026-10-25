#!/usr/bin/env python3
"""
toolchain.py — fetch an official Solana/Anza platform-tools release.

  python3 toolchain.py 1.41                 # -> ~/.cache/solopen/platform-tools-v1.41
  python3 toolchain.py 1.41 --dest DIR
  python3 toolchain.py auto --original capture/<ID>/program.so
                                            # work out WHICH release built it, then install
                                            # that one (see pick_toolchain.py)

The compiler version is part of what has to match, so reconstructions pin an
exact platform-tools release. Downloads only from the official
anza-xyz/platform-tools GitHub releases, records the archive's SHA-256 in
toolchain.lock.json next to it, and refuses to reuse a cached copy whose
archive hash changed. Linux x86-64 is the reference host. stdlib only.
"""
import argparse, hashlib, json, os, platform, re, sys, tarfile, tempfile, urllib.error, urllib.request
from pathlib import Path

BASE = "https://github.com/anza-xyz/platform-tools/releases/download/v{v}/{asset}"
KNOWN_ARCHIVE_SHA256 = {
    # Verified against daosfun-source's 47 v1.41 component hashes on 2026-10-24.
    "1.41": "d464229ce31fa36aaf1184505701a2da5c7bb48e29d34004f5b2055dfd9fb0b8",
}


def file_sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def component_hashes(root):
    """Hash EVERY file in the toolchain. `rust/bin/rustc` is only a launcher: the
    compiler is rust/lib/librustc_driver-*.so, and the SBF target's core/alloc/std
    rlibs are compiled into every program, so checking a few executables would
    not catch a change that alters output bytes. (~1.2 GB, a few seconds.)"""
    out = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            path = Path(dirpath) / name
            rel = path.relative_to(root).as_posix()
            out[rel] = ("symlink:" + os.readlink(path)) if path.is_symlink() else file_sha(path)
    return out


def asset_name():
    sysname, mach = platform.system().lower(), platform.machine().lower()
    if sysname == "linux":
        return "platform-tools-linux-x86_64.tar.bz2" if mach in ("x86_64", "amd64") \
            else "platform-tools-linux-aarch64.tar.bz2"
    if sysname == "darwin":
        return "platform-tools-osx-aarch64.tar.bz2" if mach in ("arm64", "aarch64") \
            else "platform-tools-osx-x86_64.tar.bz2"
    raise SystemExit("unsupported host; use Linux x86-64 (the reference host)")


CACHE = Path.home() / ".cache/solopen"


class NoRelease(Exception):
    """The release (or this host's asset of it) is not published."""


def default_dest(version):
    return CACHE / f"platform-tools-v{version.lstrip('v')}"


def install(version, dest=None, log=print):
    """Install (or verify the cached copy of) one platform-tools release.
    Returns the toolchain directory."""
    v = version.lstrip("v")
    dest = Path(dest or default_dest(v)).expanduser().resolve()
    lock = dest.parent / f"{dest.name}.lock.json"
    if (dest / "rust/bin/rustc").exists():
        if not lock.exists():
            raise SystemExit(f"cached toolchain has no verification lock: {lock}; remove it or use a fresh --dest")
        recorded = json.loads(lock.read_text())
        if not recorded.get("components"):
            raise SystemExit(f"{lock} was written by an older solopen and has no per-file hashes. Delete "
                             f"{dest} and {lock} and run this again to re-download and record them.")
        current = component_hashes(dest)
        if current != recorded["components"]:
            changed = sorted(k for k in set(current) | set(recorded["components"])
                             if current.get(k) != recorded["components"].get(k))
            raise SystemExit(f"cached toolchain differs from its verification lock in {len(changed)} file(s), "
                             f"e.g. {', '.join(changed[:3])} — refusing to reuse")
        log(f"already present and verified: {dest}\n  archive sha256 {recorded['archive_sha256']}")
        return dest
    asset = asset_name()
    if asset != "platform-tools-linux-x86_64.tar.bz2":
        log(f"note: using {asset}; byte-identical results are only established on Linux x86-64")
    url = BASE.format(v=v, asset=asset)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=dest.parent) as tmp:
        tmp = Path(tmp)
        arc = tmp / asset
        log(f"downloading {url}")
        req = urllib.request.Request(url, headers={"User-Agent": "solopen"})
        h = hashlib.sha256()
        try:
            with urllib.request.urlopen(req, timeout=300) as r, arc.open("wb") as f:
                for chunk in iter(lambda: r.read(8 * 1024 * 1024), b""):
                    h.update(chunk)
                    f.write(chunk)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise NoRelease(f"v{v} has no {asset} release asset") from exc
            raise
        h = h.hexdigest()
        if v in KNOWN_ARCHIVE_SHA256 and h != KNOWN_ARCHIVE_SHA256[v]:
            raise SystemExit(f"archive sha256 does not match the known-good v{v} release hash")
        if lock.exists() and json.loads(lock.read_text())["archive_sha256"] != h:
            raise SystemExit("archive hash differs from the one recorded earlier — refusing")
        ex = tmp / "x"
        ex.mkdir()
        with tarfile.open(arc, "r:bz2") as t:
            t.extractall(ex, filter="data")
        arc.unlink()
        root = next((p for p in [ex] + [d for d in ex.iterdir() if d.is_dir()]
                     if (p / "rust/bin/rustc").exists()), None)
        if root is None:
            raise SystemExit("unexpected archive layout (no rust/bin/rustc)")
        root.rename(dest)
    lock.write_text(json.dumps(dict(version=v, url=url, archive_sha256=h,
                                    components=component_hashes(dest)), indent=2) + "\n")
    log(f"ok: {dest}\n  archive sha256 {h}")
    return dest


def resolve(spec, log=print):
    """--toolchain value -> toolchain directory: an unpacked platform-tools
    directory, or a release version ("1.44", "v1.46.1") to install."""
    p = Path(str(spec)).expanduser()
    if p.is_dir():
        return p.resolve()
    if re.fullmatch(r"v?\d+\.\d+(?:\.\d+)?", str(spec)):
        try:
            return install(str(spec), log=log)
        except NoRelease as exc:
            raise SystemExit(str(exc))
    raise SystemExit(f"--toolchain {spec}: neither a platform-tools directory nor a release version like 1.44")


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "auto":
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import pick_toolchain
        return pick_toolchain.main(sys.argv[2:])
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("version", help="platform-tools version, e.g. 1.41 — or `auto --original <program.so>`")
    ap.add_argument("--dest", type=Path, default=None)
    a = ap.parse_args()
    try:
        install(a.version, a.dest)
    except NoRelease as exc:
        raise SystemExit(str(exc))


if __name__ == "__main__":
    main()

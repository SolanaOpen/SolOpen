#!/usr/bin/env python3
"""vendor.py — fetch every crates.io package pinned in a Cargo.lock into a
vendor directory, checking each archive against the lockfile's SHA-256.

  python3 tools/vendor.py --lock WORKSPACE/Cargo.lock --out WORKSPACE/vendor

Nothing is built or executed: archives are downloaded from static.crates.io,
hash-checked, unpacked (rejecting links and paths that escape), and given the
.cargo-checksum.json Cargo needs for `[source.vendored-sources]`. Directory
names are <name>-<version>, so several versions of one crate can coexist.
stdlib only (Python 3.11+ for tomllib).
"""
import argparse, hashlib, json, os, shutil, tarfile, tempfile, time, tomllib, urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path, PurePosixPath

URL = "https://static.crates.io/crates/{name}/{name}-{version}.crate"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download(url, dest, tries=4):
    for attempt in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "solopen-vendor"})
            with urllib.request.urlopen(req, timeout=120) as r, open(dest, "wb") as f:
                shutil.copyfileobj(r, f)
            return
        except Exception:
            if attempt == tries - 1:
                raise
            time.sleep(2 ** attempt)


def registry_packages(lock_path):
    lock = tomllib.loads(Path(lock_path).read_text())
    pkgs = [p for p in lock.get("package", []) if p.get("source", "").startswith("registry+")]
    missing = [f"{p['name']} {p['version']}" for p in pkgs if not p.get("checksum")]
    if missing:
        raise SystemExit("lockfile entries without checksum (old lockfile format?): " + ", ".join(missing[:5]))
    return pkgs


def verify_existing(target, checksum):
    manifest = json.loads((target / ".cargo-checksum.json").read_text())
    if manifest.get("package") != checksum:
        raise SystemExit(f"existing vendored package has a different checksum: {target}")
    for rel, digest in manifest["files"].items():
        if sha256_file(target / rel) != digest:
            raise SystemExit(f"existing vendored file was modified: {target / rel}")


def install(pkg, out):
    name, version, checksum = pkg["name"], pkg["version"], pkg["checksum"]
    target = out / f"{name}-{version}"
    if target.exists():
        verify_existing(target, checksum)
        return "kept"
    with tempfile.TemporaryDirectory(dir=out) as tmp:
        tmp = Path(tmp)
        arc = tmp / "crate.tar.gz"
        download(URL.format(name=name, version=version), arc)
        got = sha256_file(arc)
        if got != checksum:
            raise SystemExit(f"{name} {version}: archive sha256 {got} does not match Cargo.lock {checksum}")
        prefix = f"{name}-{version}"
        with tarfile.open(arc, "r:gz") as t:
            for m in t.getmembers():
                parts = PurePosixPath(m.name).parts
                if not parts or parts[0] != prefix or ".." in parts or m.issym() or m.islnk():
                    raise SystemExit(f"{name} {version}: unexpected archive member {m.name!r}")
            try:
                t.extractall(tmp / "x", filter="data")
            except TypeError:            # Python 3.11.0-3.11.3: no filter=; members were vetted above
                t.extractall(tmp / "x")
        crate = tmp / "x" / prefix
        files = {f.relative_to(crate).as_posix(): sha256_file(f)
                 for f in sorted(crate.rglob("*")) if f.is_file() and f.name != ".cargo-checksum.json"}
        (crate / ".cargo-checksum.json").write_text(json.dumps({"files": files, "package": checksum}, sort_keys=True))
        # Copy next to the target, then rename: an interrupted run never leaves a
        # half-copied crate that a later run would treat as already vendored.
        staging = target.with_name(f".{target.name}.partial-{os.getpid()}")
        shutil.copytree(crate, staging)
        os.replace(staging, target)
    return "fetched"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--lock", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--jobs", type=int, default=6)
    a = ap.parse_args()
    pkgs = registry_packages(a.lock)
    a.out.mkdir(parents=True, exist_ok=True)
    out = a.out.resolve()
    with ThreadPoolExecutor(max_workers=a.jobs) as pool:
        results = list(pool.map(lambda p: install(p, out), pkgs))
    print(f"vendored {len(pkgs)} packages into {out} "
          f"({results.count('fetched')} fetched, {results.count('kept')} already present and verified)")


if __name__ == "__main__":
    main()

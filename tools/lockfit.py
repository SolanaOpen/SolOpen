#!/usr/bin/env python3
"""
lockfit.py — which dependency versions built the original? Check Cargo.lock
against the binary, and fix it.

  python3 solopen.py lockfit --id <ID> --workspace W            # report
  python3 solopen.py lockfit --id <ID> --workspace W --apply    # + cargo update --precise
  python3 solopen.py lockfit --id <ID> --workspace W --try-lock a.lock --try-lock b.lock
                                                                # build with each, compare coverage

A wrong dependency version changes code everywhere that crate is used, and
it is invisible in your source. The binary carries evidence for it:

  exact      a few releases leave a crate's registry path in panic messages
             (`…/registry/src/…/borsh-1.5.7/src/ser/mod.rs`): that is the
             crate and version, verbatim. The standard library has crates.io
             dependencies of its own (hashbrown is std's HashMap), compiled
             into the toolchain's sysroot; a path the sysroot carries is
             std's copy and says nothing about Cargo.lock.
  coordinates  every other dependency panic location is `src/<file>.rs` with a
             line and column (Cargo builds registry crates from their own
             directory, and the remapped prefix is gone). For each crate in
             Cargo.lock its published source is checked: does the locked
             version have that file, with code at that line and column? A
             crate whose file exists but whose coordinates don't fit is
             probably the wrong version; the other published versions are
             checked the same way and the best fit is proposed.
  builds     --try-lock builds your workspace once per candidate lockfile (an
             official release's Cargo.lock, say) and ranks them by how much of
             the original's code they reproduce.

Crate sources come from static.crates.io, checked against the checksum in
Cargo.lock or the crates.io index, and are cached (or read from --vendor).
Nothing from a crate is built or run for the report. stdlib only.
"""
import argparse, collections, json, os, re, shutil, subprocess, sys, tempfile, time, tomllib
import urllib.error, urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import calibrate as C
import vendor

CACHE = Path.home() / ".cache/solopen"
INDEX = "https://index.crates.io/{path}"
REGISTRY_PATH = re.compile(r"/registry/src/[^/]+/([A-Za-z0-9_-]+?)-(\d+\.\d+\.\d+[^/]*)/(.+)$")
GIT_PATH = re.compile(r"/git/checkouts/([^/]+?)-[0-9a-f]{16}/([0-9a-f]{7,})/(.+)$")
DISTINCT = 2                 # a file shipped by more crates than this says nothing about any one
# crates.io crates the standard library itself is built with. Used only when no
# platform-tools sysroot is cached to check against.
STD_DEPS = {"hashbrown", "compiler_builtins", "rustc-demangle", "cfg-if", "libc", "adler", "adler2",
            "miniz_oxide", "addr2line", "gimli", "object", "memchr", "dlmalloc", "unwinding", "r-efi",
            "rustc-std-workspace-core", "rustc-std-workspace-alloc", "rustc-std-workspace-std"}


def sysroot_has(name, version, roots=None):
    """Does a platform-tools sysroot carry `name-version`? True or False when a
    cached sysroot has that crate at all; None when none can tell."""
    roots = sorted(CACHE.glob("platform-tools-v*/rust/lib/rustlib")) if roots is None else roots
    needle, seen = f"/{name}-{version}/".encode(), False
    for root in roots:
        for rlib in Path(root).glob(f"*/lib/lib{name.replace('-', '_')}-*.rlib"):
            seen = True
            if needle in rlib.read_bytes():
                return True
    return False if seen else None


# ---------------------------------------------------------------- crates
def index_path(name):
    n = name.lower()
    if len(n) <= 2:
        return f"{len(n)}/{n}"
    if len(n) == 3:
        return f"3/{n[0]}/{n}"
    return f"{n[:2]}/{n[2:4]}/{n}"


def semver_key(v):
    core, _, pre = v.partition("-")
    nums = [int(x) if x.isdigit() else 0 for x in core.split("+")[0].split(".")]
    return tuple(nums + [0] * (3 - len(nums))) + ((1,) if not pre else (0, pre))


class CrateStore:
    """Published crate sources: a --vendor dir first, else a verified cache."""

    def __init__(self, vendors=(), cache=CACHE / "crates"):
        self.vendors = [Path(v) for v in vendors]
        self.cache = Path(cache)
        self.cache.mkdir(parents=True, exist_ok=True)
        self._index = {}

    def versions(self, name):
        """[{vers, cksum, yanked}] from the crates.io sparse index (cached a day)."""
        if name not in self._index:
            f = self.cache.parent / "crates-index" / f"{name.lower()}.json"
            if f.exists() and time.time() - f.stat().st_mtime < 86400:
                self._index[name] = json.loads(f.read_text())
            else:
                req = urllib.request.Request(INDEX.format(path=index_path(name)), headers={"User-Agent": "solopen"})
                with urllib.request.urlopen(req, timeout=60) as r:
                    rows = [json.loads(line) for line in r.read().decode().splitlines() if line.strip()]
                self._index[name] = [dict(vers=x["vers"], cksum=x["cksum"], yanked=x.get("yanked", False))
                                     for x in rows]
                f.parent.mkdir(parents=True, exist_ok=True)
                f.write_text(json.dumps(self._index[name]))
        return self._index[name]

    def get(self, name, version, checksum=None):
        for v in self.vendors:
            d = v / f"{name}-{version}"
            if d.is_dir():
                return d
            if v.joinpath(name, "Cargo.toml").exists() and f'version = "{version}"' in v.joinpath(name, "Cargo.toml").read_text(errors="replace"):
                return v / name                          # cargo vendor's unversioned layout
        if checksum is None:
            checksum = next((x["cksum"] for x in self.versions(name) if x["vers"] == version), None)
            if checksum is None:
                return None
        vendor.install(dict(name=name, version=version, checksum=checksum), self.cache)
        return self.cache / f"{name}-{version}"


def plausible(text, line, col):
    lines = text.split("\n")
    if line > len(lines):
        return False
    s = lines[line - 1]
    return col <= len(s) and not s[col - 1].isspace() and not s.lstrip().startswith("//")


def read(root, rel, memo):
    key = (str(root), rel)
    if key not in memo:
        p = Path(root) / rel
        memo[key] = p.read_text(errors="replace") if p.is_file() else None
    return memo[key]


# --------------------------------------------------------------- analysis
def lock_packages(lock_path):
    lock = tomllib.loads(Path(lock_path).read_text())
    return [p for p in lock.get("package", []) if p.get("source", "").startswith("registry+")]


def classify(locs, workspace):
    """Split panic locations into std / workspace / exact registry / git / dependency-relative."""
    out = collections.defaultdict(list)
    for f, n, line, col in sorted(locs):
        m = REGISTRY_PATH.search(f)
        g = GIT_PATH.search(f)
        if C.is_std(f):
            out["std"].append((f, line, col))
        elif m:
            out["exact"].append((m.group(1), m.group(2), m.group(3), line, col))
        elif g:
            out["git"].append((g.group(1), g.group(2), g.group(3), line, col))
        elif workspace and (Path(workspace) / f).is_file():
            out["workspace"].append((f, line, col))
        elif f.startswith("src/"):
            # Cargo compiles a registry crate from its own directory, so after
            # the cwd prefix is remapped its paths start at `src/`.
            out["dependency"].append((f, line, col))
        elif not f.startswith("/"):
            out["workspace_missing"].append((f, line, col))     # e.g. programs/<name>/src/…
        else:
            out["other"].append((f, line, col))
    return out


def fit_version(store, name, version, checksum, locs, memo):
    root = store.get(name, version, checksum)
    if root is None:
        return None
    return sum(1 for f, line, col in locs if (t := read(root, f, memo)) is not None and plausible(t, line, col))


def analyze(original, workspace, lock_path, store, max_versions=12, log=print, sysroots=None):
    locs = C.panic_locations(Path(original).read_bytes())
    parts = classify(locs, workspace)
    pkgs = lock_packages(lock_path)
    by_name = collections.defaultdict(list)
    for p in pkgs:
        by_name[p["name"]].append(p)
    report = dict(locations=len(locs), std=len(parts["std"]), workspace=len(parts["workspace"]),
                  dependency=len(parts["dependency"]), crates=[], proposals=[], unexplained=[], exact=[], git=[],
                  workspace_missing=sorted({f for f, _l, _c in parts["workspace_missing"]}))

    # 1. exact name-version evidence
    for name, version, rel, line, col in parts["exact"]:
        locked = sorted(p["version"] for p in by_name.get(name, []))
        row = dict(crate=name, binary_version=version, locked=locked, file=rel, line=line, col=col)
        report["exact"].append(row)
        in_std = sysroot_has(name, version, sysroots)
        if in_std or (in_std is None and name in STD_DEPS):
            row["std"] = "sysroot" if in_std else "probably (no sysroot cached to check)"
            continue
        if version not in locked:
            report["proposals"].append(dict(crate=name, locked=locked[0] if len(locked) == 1 else None,
                                            proposed=version, evidence="exact registry path in the binary"))
    report["git"] = [dict(repo=r, commit=c, file=f, line=line, col=col) for r, c, f, line, col in parts["git"]]

    # 2. coordinates of dependency-relative locations
    deps = parts["dependency"]
    if not deps:
        return report
    log(f"  {len(deps)} dependency panic locations; reading {len(pkgs)} locked crates' sources…")
    memo, roots = {}, {}
    for p in pkgs:
        try:
            roots[(p["name"], p["version"])] = store.get(p["name"], p["version"], p.get("checksum"))
        except (SystemExit, OSError, urllib.error.URLError) as exc:
            log(f"  can't read {p['name']} {p['version']}: {exc}")
    files = {f for f, _l, _c in deps}
    owners = {f: [k for k, r in roots.items() if r and read(r, f, memo) is not None] for f in files}
    explained = collections.Counter()
    suspect = collections.defaultdict(list)
    confirmed = collections.defaultdict(list)
    for f, line, col in deps:
        fits = [k for k in owners[f] if plausible(read(roots[k], f, memo), line, col)]
        if fits:
            for k in fits:
                explained[k] += 1
                if len(owners[f]) <= DISTINCT:
                    confirmed[k].append((f, line, col))
        elif owners[f]:
            if len(owners[f]) <= DISTINCT:
                for k in owners[f]:
                    suspect[k].append((f, line, col))
            else:
                report["unexplained"].append(dict(file=f, line=line, col=col, note=f"{len(owners[f])} crates have it"))
        else:
            report["unexplained"].append(dict(file=f, line=line, col=col, note="no locked crate has this file"))

    # 3. a crate whose own distinctive files don't fit: try its other versions
    for (name, version) in sorted(set(confirmed) | set(suspect)):
        row = dict(crate=name, locked=version, confirmed=len(confirmed[(name, version)]),
                   suspect=len(suspect[(name, version)]))
        report["crates"].append(row)
        if not row["suspect"]:
            continue
        probe = confirmed[(name, version)] + suspect[(name, version)]
        try:
            avail = [x for x in store.versions(name) if not x["yanked"]]
        except Exception as exc:          # offline / unknown crate
            row["note"] = f"could not list versions: {exc}"
            continue
        base = semver_key(version)
        avail.sort(key=lambda x: (semver_key(x["vers"])[0] != base[0], abs(semver_key(x["vers"])[1] - base[1]),
                                  abs(semver_key(x["vers"])[2] - base[2])))
        tried = {}
        for x in avail[:max_versions]:          # nearest versions first
            if x["vers"] == version:
                continue
            try:
                score = fit_version(store, name, x["vers"], x["cksum"], probe, memo)
            except (SystemExit, OSError) as exc:
                log(f"  {name} {x['vers']}: {exc}")
                continue
            if score is not None:
                tried[x["vers"]] = score
        row["versions_tried"] = tried
        row["fit"] = f"{row['confirmed']}/{len(probe)} with {version}"
        top = max(tried.values(), default=-1)
        if top <= row["confirmed"]:
            continue
        winners = [v for v in tried if tried[v] == top]      # in nearest-first order
        tie = sorted(winners, key=semver_key)
        row["fit"] += f", {top}/{len(probe)} with " + (f"{tie[0]} … {tie[-1]} ({len(tie)} versions)"
                                                         if len(tie) > 1 else tie[0])
        report["proposals"].append(dict(
            crate=name, locked=version, proposed=winners[0], equally_good=tie if len(tie) > 1 else [],
            evidence=f"{top}/{len(probe)} of its panic locations fit {winners[0]}, {row['confirmed']}/{len(probe)} "
                     f"fit {version}" + (f"; {', '.join(tie)} fit equally — the nearest is proposed, "
                                         "--resolve-ties builds each" if len(tie) > 1 else "")))
    return report


def tie_locks(args, proposal, tc, out_dir, log=print):
    """One Cargo.lock per equally good version of a proposal (cargo update --precise)."""
    out = []
    for v in proposal["equally_good"]:
        with tempfile.TemporaryDirectory(prefix="solopen-lockfit-tie-") as tmp:
            ws = Path(tmp) / "ws"
            shutil.copytree(args.workspace, ws, ignore=shutil.ignore_patterns("target", ".git", "vendor"))
            done = apply([dict(proposal, proposed=v)], ws, tc, log=lambda m: None)
            if done and done[0]["applied"]:
                dest = Path(out_dir) / f"Cargo.{proposal['crate']}-{v}.lock"
                shutil.copy2(ws / "Cargo.lock", dest)
                out.append(dest)
            else:
                log(f"  {proposal['crate']} {v}: cargo could not pin it (incompatible requirement?)")
    return out


# ------------------------------------------------------------------ apply
def cargo_env(tc):
    home = Path(tempfile.mkdtemp(prefix="solopen-lockfit-home-"))
    cargo_home = CACHE / "cargo-home"
    cargo_home.mkdir(parents=True, exist_ok=True)
    keep = ("PATH", "TMPDIR", "LANG", "SSL_CERT_FILE", "SSL_CERT_DIR", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY",
            "https_proxy", "http_proxy", "no_proxy", "CARGO_HTTP_CAINFO", "CARGO_HTTP_PROXY")
    env = {k: os.environ[k] for k in keep if k in os.environ}
    env.update(HOME=str(home), CARGO_HOME=str(cargo_home), RUSTC=str(tc / "rust/bin/rustc"))
    return env


def apply(proposals, workspace, tc, log=print):
    cargo = tc / "rust/bin/cargo"
    done = []
    for p in proposals:
        if not p.get("locked"):
            log(f"  {p['crate']}: several or no locked versions — pin {p['proposed']} by hand")
            continue
        now = sorted(x["version"] for x in lock_packages(Path(workspace) / "Cargo.lock") if x["name"] == p["crate"])
        if p["locked"] not in now:
            ok = p["proposed"] in now or bool(set(now) & set(p.get("equally_good") or []))
            log(f"  {'✓' if ok else '•'} {p['crate']}: already {', '.join(now) or 'gone'} "
                "(re-resolved by an earlier update)")
            done.append(dict(p, applied=ok, now=now))
            continue
        cmd = [str(cargo), "update", "--manifest-path", str(Path(workspace) / "Cargo.toml"),
               "-p", f"{p['crate']}@{p['locked']}", "--precise", p["proposed"]]
        r = subprocess.run(cmd, capture_output=True, text=True, env=cargo_env(tc))
        ok = r.returncode == 0
        log(f"  {'✓' if ok else '✗'} {p['crate']} {p['locked']} -> {p['proposed']}"
            + ("" if ok else ": " + " ".join(x.strip() for x in r.stderr.strip().splitlines()[-3:])))
        done.append(dict(p, applied=ok))
    return done


def try_locks(args, locks, log=print):
    """Build the workspace once per candidate Cargo.lock; rank by coverage."""
    results = []
    cache = Path(tempfile.mkdtemp(prefix="solopen-lockfit-cache-"))
    for lock in [None] + list(locks):
        with tempfile.TemporaryDirectory(prefix="solopen-lockfit-") as tmp:
            ws = Path(tmp) / "workspace"
            shutil.copytree(args.workspace, ws, ignore=shutil.ignore_patterns("target", ".git"))
            if lock:
                shutil.copy2(lock, ws / "Cargo.lock")
            run = Path(tmp) / "run"
            argv = ["--id", args.id, "--capture-root", str(args.capture_root), "--workspace", str(ws),
                    "--program", args.program, "--run-dir", str(run), "--quiet", "--no-difftest",
                    "--target-cache", str(cache)]
            if args.toolchain:
                argv += ["--toolchain", str(args.toolchain)]
            if args.package:
                argv += ["--package", args.package]
            rc = solopen_try(argv)
            cov = None
            om = run / "order/order-mapping.json"
            if om.exists():
                cov = json.loads(om.read_text())["summary"]["coverage_pct"]
            label = str(lock) if lock else "current Cargo.lock"
            log(f"  {label}: " + (f"{cov}% coverage" + (" — byte-identical" if rc == 0 else "")
                                  if cov is not None else "build failed"))
            results.append(dict(lock=label, coverage_pct=cov, identical=rc == 0))
    shutil.rmtree(cache, ignore_errors=True)
    return sorted(results, key=lambda r: (r["identical"], r["coverage_pct"] or -1), reverse=True)


def solopen_try(argv):
    sys.path.insert(0, str(HERE.parent))
    import solopen
    return solopen.try_round(argv)


def print_report(rep):
    print(f"panic locations: {rep['locations']} ({rep['std']} standard library, {rep['workspace']} your workspace, "
          f"{rep['dependency']} dependencies)")
    for e in rep["exact"]:
        if e.get("std"):
            print(f"  std    {e['crate']} {e['binary_version']}: the standard library's own copy, not a Cargo.lock "
                  f"dependency ({e['std']}); the program uses it through std")
            continue
        mark = "ok" if e["binary_version"] in e["locked"] else "MISMATCH"
        print(f"  exact  {e['crate']} {e['binary_version']} (lock: {', '.join(e['locked']) or 'absent'})  {mark}")
    for g in rep["git"][:5]:
        print(f"  git    {g['repo']} at {g['commit']} ({g['file']})")
    for c in rep["crates"]:
        if c["suspect"]:
            print(f"  ?      {c['crate']} {c['locked']}: {c.get('fit', '')}")
        else:
            print(f"  ok     {c['crate']} {c['locked']}: {c['confirmed']} distinctive location(s) fit")
    if rep["workspace_missing"]:
        print(f"  {len(rep['workspace_missing'])} source file(s) the original was built from are not in your "
              "workspace (or sit at another path), e.g. " + ", ".join(rep["workspace_missing"][:3]))
    if rep["unexplained"]:
        print(f"  {len(rep['unexplained'])} dependency location(s) no locked crate explains, e.g. "
              + ", ".join(f"{u['file']}:{u['line']}" for u in rep["unexplained"][:4]))
    if rep["proposals"]:
        print("proposed changes:")
        for p in rep["proposals"]:
            print(f"  cargo update -p {p['crate']}{'@' + p['locked'] if p.get('locked') else ''} --precise {p['proposed']}")
            print(f"      {p['evidence']}")
    else:
        print("no changes proposed: every dependency location that names one crate fits the locked version")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--id", required=True)
    ap.add_argument("--capture-root", type=Path, default=Path("capture"))
    ap.add_argument("--workspace", required=True, type=Path)
    ap.add_argument("--lock", type=Path, default=None, help="default: <workspace>/Cargo.lock")
    ap.add_argument("--vendor", type=Path, action="append", default=[], help="vendored crates to read first")
    ap.add_argument("--max-versions", type=int, default=12, help="other versions to try per suspect crate")
    ap.add_argument("--apply", action="store_true", help="run `cargo update --precise` for each proposal")
    ap.add_argument("--try-lock", type=Path, action="append", default=[],
                    help="candidate Cargo.lock to build with and rank by coverage (repeatable)")
    ap.add_argument("--resolve-ties", action="store_true",
                    help="when several versions fit equally, build with each and keep the best coverage")
    ap.add_argument("--program", default=None, help="program lib name (needed with --try-lock/--resolve-ties)")
    ap.add_argument("--package", default=None)
    ap.add_argument("--toolchain", default=None, help="default: capture/<ID>/toolchain.json or detect it")
    ap.add_argument("--out", type=Path, default=None, help="default: capture/<ID>/lockfit.json")
    a = ap.parse_args(argv)
    original = a.capture_root / a.id / "program.so"
    lock = a.lock or a.workspace / "Cargo.lock"
    if not original.exists():
        raise SystemExit(f"{original} missing — run: solopen.py fetch {a.id}")
    if not lock.exists():
        raise SystemExit(f"{lock} missing — generate it with the program's toolchain first")
    print(f"checking {lock} against {original}")
    rep = analyze(original, a.workspace.resolve(), lock, CrateStore(a.vendor), a.max_versions)
    print_report(rep)
    if (a.try_lock or a.resolve_ties) and not a.program:
        raise SystemExit("--try-lock / --resolve-ties need --program (the program crate's lib name)")
    tc = None
    if a.apply or a.resolve_ties:
        import pick_toolchain
        tc, _target = pick_toolchain.resolve_for(a.toolchain, original)
    if a.resolve_ties:
        work = Path(tempfile.mkdtemp(prefix="solopen-lockfit-ties-"))
        for p in [p for p in rep["proposals"] if p.get("equally_good")]:
            print(f"building {p['crate']} {', '.join(p['equally_good'])}:")
            trials = try_locks(a, tie_locks(a, p, tc, work))
            ranked = [t for t in trials if t["lock"] != "current Cargo.lock" and t["coverage_pct"] is not None]
            if ranked:
                p["proposed"] = re.search(rf"{re.escape(p['crate'])}-(.+)\.lock$", ranked[0]["lock"]).group(1)
                p["evidence"] += f"; builds: {ranked[0]['coverage_pct']}% coverage with {p['proposed']}"
                p["builds"] = trials
    if a.apply and rep["proposals"]:
        print("applying:")
        rep["applied"] = apply(rep["proposals"], a.workspace, tc)
    if a.try_lock:
        print("building with each lockfile:")
        rep["lock_trials"] = try_locks(a, a.try_lock)
        best = rep["lock_trials"][0]
        print(f"best: {best['lock']} ({best['coverage_pct']}% coverage)")
    out = a.out or a.capture_root / a.id / "lockfit.json"
    out.write_text(json.dumps(rep, indent=1) + "\n")
    print(f"details: {out}")


if __name__ == "__main__":
    main()

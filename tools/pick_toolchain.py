#!/usr/bin/env python3
"""
pick_toolchain.py — work out which platform-tools release built a program, and
install that one.

  python3 solopen.py toolchain auto --original capture/<ID>/program.so
      -> capture/<ID>/toolchain.json, and the release installed in ~/.cache/solopen

`try`, `rebuild` and `build` do this by themselves when --toolchain is left
out, and reuse capture/<ID>/toolchain.json afterwards.

Cheapest evidence first, so only a few toolchains are ever downloaded:

 1. Releases. Every published platform-tools release (GitHub API, or the git
    tags when the API can't be reached), minus releases published after the
    program was last deployed (capture/<ID>/report.json): it can't have been
    built with those.
 2. Standard-library source. Each release's build.sh names the anza-xyz/rust
    tag it compiled. The original's panic locations inside core/alloc/std
    (file, line, column) are checked against that tag's source: with the wrong
    release they point at files that don't exist, past the end of a file, or
    at blank and comment lines. This fetches a handful of source files per
    release with git — no toolchains.
 3. Canary. Only the releases that fit best (at most --max-downloads) are
    downloaded and fingerprinted with calibrate.py's canary (ELF header,
    std coordinates in the precompiled sysroot, helper-function bodies); the
    best one wins. Releases downloaded only for this are deleted again unless
    --keep; their fingerprints stay cached, so later programs don't need them.

It assumes a stock platform-tools build. A program built with a custom
toolchain, or one that embeds almost no standard-library code, can come out
ambiguous; the result says so, and --toolchain always overrides it. stdlib +
git only; read-only toward the chain.
"""
import argparse, calendar, hashlib, json, os, re, shutil, subprocess, sys, time, urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import calibrate as C
import toolchain as T

PT_REPO = "https://github.com/anza-xyz/platform-tools"
API = "https://api.github.com/repos/anza-xyz/platform-tools/releases?per_page=100&page={page}"
GIT_CACHE = T.CACHE / "git"
CLOSE = 3                   # helper-count margin below which the canary can't separate two releases
SLOT_SECONDS = 0.4          # a low estimate, so a slot-derived deploy date errs late
DATE_SLACK = 14 * 86400


def vkey(v):
    return tuple(int(x) for x in v.split("."))


def git(repo, *args, timeout=180):
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    try:
        return subprocess.run(["git", "-C", str(repo)] + list(args), capture_output=True,
                              timeout=timeout, env=env)
    except (OSError, subprocess.TimeoutExpired):
        return None


def bare_repo(name, url):
    d = GIT_CACHE / name
    if not (d / "HEAD").exists():
        d.mkdir(parents=True, exist_ok=True)
        git(d, "init", "-q", "--bare")
        git(d, "remote", "add", "origin", url)
    return d


# ------------------------------------------------------------------ releases
def api_releases():
    out, page = [], 1
    headers = {"User-Agent": "solopen", "Accept": "application/vnd.github+json"}
    if os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = "Bearer " + os.environ["GITHUB_TOKEN"]
    asset = T.asset_name()
    while page < 20:
        req = urllib.request.Request(API.format(page=page), headers=headers)
        with urllib.request.urlopen(req, timeout=20) as r:
            batch = json.load(r)
        if not batch:
            break
        for rel in batch:
            m = re.fullmatch(r"v(\d+\.\d+(?:\.\d+)?)", rel.get("tag_name", ""))
            if not m or rel.get("draft") or rel.get("prerelease"):
                continue
            when = rel.get("published_at")
            out.append(dict(version=m.group(1), source="github api",
                            published=calendar.timegm(time.strptime(when, "%Y-%m-%dT%H:%M:%SZ")) if when else None,
                            has_asset=any(a.get("name") == asset for a in rel.get("assets", []))))
        page += 1
    return out


def git_releases(repo):
    r = git(repo, "for-each-ref", "refs/tags", "--format=%(refname:strip=2) %(creatordate:unix)")
    out = []
    for line in (r.stdout.decode().splitlines() if r and r.returncode == 0 else []):
        tag, _, when = line.partition(" ")
        m = re.fullmatch(r"v(\d+\.\d+(?:\.\d+)?)", tag)
        if m:
            out.append(dict(version=m.group(1), source="git tag", published=int(when) if when else None,
                            has_asset=None))
    return out


def list_releases(log):
    """Every platform-tools release, oldest first, with its publication time."""
    cache = T.CACHE / "platform-tools-releases.json"
    repo = None
    if shutil.which("git"):
        repo = bare_repo("platform-tools.git", PT_REPO)
        r = git(repo, "fetch", "-q", "--filter=tree:0", "--tags", "--force", "origin")
        if r is None or r.returncode:
            log("  (could not refresh platform-tools tags; using what is cached)")
    try:
        rels = api_releases()
    except Exception as exc:          # offline, rate-limited, proxied …
        rels = git_releases(repo) if repo else []
        if rels:
            log(f"  GitHub API unavailable ({exc.__class__.__name__}); using git tag dates")
    if rels:
        T.CACHE.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps(rels, indent=1) + "\n")
    elif cache.exists():
        rels = json.loads(cache.read_text())
        log("  offline: using the release list saved by an earlier run")
    seen = {}
    for rel in rels:
        seen.setdefault(rel["version"], rel)
    return sorted(seen.values(), key=lambda r: vkey(r["version"])), repo


def deploy_bound(original):
    """Latest time the program could have been built, from fetch's report."""
    rep = Path(original).parent / "report.json"
    try:
        r = json.loads(rep.read_text())
    except (OSError, ValueError):
        return None, "no capture report next to the original: release dates not used"
    if r.get("last_deploy_utc"):
        t = calendar.timegm(time.strptime(r["last_deploy_utc"], "%Y-%m-%dT%H:%M:%SZ"))
        return t, f"last deployed {r['last_deploy_utc'][:10]}"
    if r.get("last_deploy_slot") and r.get("slot") and r.get("fetched_utc"):
        now = calendar.timegm(time.strptime(r["fetched_utc"], "%Y-%m-%dT%H:%M:%SZ"))
        t = now - (r["slot"] - r["last_deploy_slot"]) * SLOT_SECONDS + DATE_SLACK
        return t, f"deployed by about {time.strftime('%Y-%m-%d', time.gmtime(t))} (estimated from its slot)"
    return None, "deploy time unknown: release dates not used"


# --------------------------------------------------------- std-source check
class RustSource:
    """Lazily fetched anza-xyz/rust tags (depth 1, trees and blobs on demand)."""

    def __init__(self, url):
        name = "rust-" + re.sub(r"[^A-Za-z0-9]+", "-", url.split("github.com/")[-1]).strip("-") + ".git"
        self.repo = bare_repo(name, url)
        self.memo = {}

    def show(self, tag, path):
        key = (tag, path)
        if key not in self.memo:
            have = git(self.repo, "rev-parse", "-q", "--verify", f"refs/tags/{tag}^{{commit}}")
            if have is None or have.returncode:
                for ref in (f"refs/tags/{tag}", f"refs/heads/{tag}"):
                    r = git(self.repo, "fetch", "-q", "--depth=1", "--filter=tree:0", "origin", f"{ref}:refs/tags/{tag}")
                    if r is not None and r.returncode == 0:
                        break
            r = git(self.repo, "show", f"{tag}:{path}")
            self.memo[key] = r.stdout if r is not None and r.returncode == 0 else None
        return self.memo[key]


def rust_tag(pt_repo, version):
    """(rust repository URL, tag) that release's build.sh compiled, or None."""
    r = git(pt_repo, "show", f"v{version}:build.sh")
    if r is None or r.returncode:
        return None
    m = re.search(r"(?m)^\s*git clone\b[^\n]*?--branch\s+([^\s$]+)[^\n]*?\s(https://github\.com/[\w.-]+/rust)(?:\.git)?\s*$",
                  r.stdout.decode("utf-8", "replace"))
    return (m.group(2), m.group(1)) if m else None


def coordinate_fit(src, tag, std_locs):
    """(files found, plausible coordinates) for the original's std locations."""
    files = ok = 0
    for f, _n, line, col in std_locs:
        text = src.show(tag, re.sub(r"^.*?(?=library/)", "", f))
        if text is None:
            continue
        files += 1
        lines = text.decode("utf-8", "replace").split("\n")
        if line <= len(lines):
            s = lines[line - 1]
            if col <= len(s) and not s[col - 1].isspace() and not s.lstrip().startswith("//"):
                ok += 1
    return files, ok


def shortlist(cands, total):
    """Releases worth downloading, best first, and how strong the evidence is.
    Within 10% of the best coordinate fit (with every file present) counts as
    a fit: releases sharing one Rust version fit equally, and the canary
    decides between them."""
    scored = [r for r in cands if "plausible" in r]
    if not (scored and total):
        return sorted(cands, key=lambda r: vkey(r["version"]), reverse=True), "none"
    best = max((r["files"], r["plausible"]) for r in scored)
    tol = int(0.1 * total)
    short = [r for r in scored if r["files"] == best[0] and r["plausible"] >= best[1] - tol]
    short.sort(key=lambda r: (r["plausible"], vkey(r["version"])), reverse=True)
    return short, ("strong" if total >= 3 and best[1] >= 0.8 * total else "weak")


# --------------------------------------------------------------------- pick
def pick(original, max_downloads=6, keep=False, out=None, log=print):
    original = Path(original).resolve()
    raw = original.read_bytes()
    orig = C.analyze_original(raw)
    std_locs = orig["std_locs"]
    log(f"identifying the platform-tools release that built {original}")
    rels, pt_repo = list_releases(log)
    if not rels:
        raise SystemExit("could not list platform-tools releases (no network, no git and no cached list); "
                         "pass --toolchain <version> explicitly")
    bound, why = deploy_bound(original)
    cands = [r for r in rels if bound is None or r["published"] is None or r["published"] <= bound]
    cands = [r for r in cands if r.get("has_asset") is not False]
    log(f"  {len(rels)} releases; {len(cands)} could have built it ({why})")

    # 2. standard-library source coordinates
    strength = "none"
    if len(std_locs) and pt_repo is not None:
        log(f"  checking {len(std_locs)} standard-library panic locations against each release's Rust source…")
        sources = {}
        for r in cands:
            rt = rust_tag(pt_repo, r["version"])
            if not rt:
                continue
            src = sources.setdefault(rt[0], RustSource(rt[0]))
            r["rust_tag"] = rt[1]
            r["files"], r["plausible"] = coordinate_fit(src, rt[1], std_locs)
    total = len(std_locs)
    short, strength = shortlist(cands, total)
    if strength == "none":
        log("  no standard-library locations to check; falling back to the newest candidates")
    else:
        log(f"  source fit: {short[0]['plausible']}/{total} at best; {len(short)} release(s) fit: "
            + ", ".join("v" + r["version"] for r in sorted(short, key=lambda r: vkey(r["version"]))))

    # 3. canary fingerprints, starting from what is cached and climbing from
    # the leader to its neighbouring releases until both neighbours score lower.
    cached = C.cached_fingerprints()
    fps, downloaded, skipped, removed, done = [], [], [], [], set()
    by_version = {r["version"]: r for r in short}
    order = sorted(by_version, key=vkey)

    def add(version):
        """Fingerprint one release (from cache, or install it). False if it can't be."""
        done.add(version)
        name = T.default_dest(version).name
        have = [fp for (n, _t), fp in cached.items() if n == name and fp_still_valid(fp)]
        if have:
            fps.extend(have)
            return True
        was_installed = (T.default_dest(version) / "rust/bin/rustc").exists()
        if not was_installed and len(downloaded) >= max_downloads:
            skipped.append(version)
            return False
        try:
            tc = T.install(version, log=lambda m: log("  " + m))
        except T.NoRelease as exc:
            log(f"  {exc}; skipping")
            by_version[version]["has_asset"] = False
            return False
        except SystemExit as exc:       # e.g. a cached copy that fails verification
            log(f"  v{version}: {exc}; skipping")
            return False
        for triple in C.targets_of(tc, orig["version"]):
            log(f"  fingerprinting {tc.name}/{triple}")
            fps.append(C.fingerprint(tc, triple))
        if not was_installed:
            downloaded.append(tc)
            if not keep:
                # Only the fingerprint is needed from here on: keep at most the
                # current leader on disk, not every release tried.
                lead = leaders()
                for d in [d for d in downloaded if d.exists() and C.release_of(d.name) not in lead[:1]]:
                    shutil.rmtree(d, ignore_errors=True)
                    removed.append(d.name)
        return True

    def leaders():
        rows = C.rank(orig, fps)[0]
        if not rows:
            return []
        top = C.score(rows[0])[:3]
        return list(dict.fromkeys(r["release"] for r in rows if C.score(r)[:3] == top))

    for version in order:                 # free: releases fingerprinted before
        name = T.default_dest(version).name
        if any(n == name and fp_still_valid(fp) for (n, _t), fp in cached.items()):
            add(version)
    if not fps and short:
        add(short[0]["version"])          # best source fit, newest first
    while True:
        lead = [v for v in leaders() if v in by_version]
        frontier = []
        for v in lead:
            i = order.index(v)
            frontier += [order[j] for j in (i - 1, i + 1) if 0 <= j < len(order) and order[j] not in done]
        if not lead and short:            # nothing fingerprinted yet could be used
            frontier = [r["version"] for r in short if r["version"] not in done][:1]
        if not frontier:
            break
        # newer neighbour first: later releases are the more common default
        frontier.sort(key=vkey, reverse=True)
        progressed = False
        for v in frontier:
            progressed |= add(v)
        if not progressed and all(v in done for v in frontier) and len(downloaded) >= max_downloads:
            break
    if skipped:
        log(f"  not downloaded (--max-downloads {max_downloads}): " + ", ".join("v" + v for v in skipped))
    rows, verdict = C.rank(orig, fps)
    if not rows:
        raise SystemExit("no candidate release could be fingerprinted; pass --toolchain <version> explicitly")
    best = rows[0]
    tied = sorted({r["release"] for r in rows if C.score(r)[:3] == C.score(best)[:3]}, key=vkey)
    # Releases within CLOSE helpers of the winner (same header and paths) are
    # too close to call on the canary alone.
    df = lambda r: r.get("helpers", {}).get("discriminating_found", 0)
    close = sorted({r["release"] for r in rows if r["release"] != best["release"]
                    and C.score(r)[:2] == C.score(best)[:2] and df(best) - df(r) < CLOSE}, key=vkey)
    edge = sorted(set(best.get("helpers", {}).get("found_names", [])) -
                  set().union(*[set(r.get("helpers", {}).get("found_names", [])) for r in rows
                                if r["release"] in close])) if close else []
    confident = (best.get("header_matches") and not best["stdlib"]["missing_paths"] and len(tied) == 1
                 and not close and strength != "none")
    tc = T.install(best["release"], log=lambda m: log("  " + m))
    for d in downloaded:
        if d != tc and d.exists() and not keep:
            shutil.rmtree(d, ignore_errors=True)
            removed.append(d.name)
    removed = [n for n in dict.fromkeys(removed) if n != tc.name]
    result = dict(
        release=best["release"], toolchain=str(tc), target=best["target"],
        confidence="high" if confident else "low",
        note=(None if confident else
              ("ambiguous: " + ", ".join("v" + v for v in tied) + " fit equally" if len(tied) > 1 else
               "close: " + ", ".join("v" + v for v in close) + f" within {CLOSE - 1} helper(s) of "
               f"v{best['release']}" + (" (it alone matches " + ", ".join(short_name(n) for n in edge[:3]) + ")"
                                        if edge else "") if close else
               "weak evidence") + " — pass --toolchain to override, or compare clean builds"),
        close_releases=close,
        verdict=verdict, original=str(original), original_sha256=hashlib.sha256(raw).hexdigest(),
        deploy_bound=why, source_check_strength=strength,
        source_check=[{k: r.get(k) for k in ("version", "published", "rust_tag", "files", "plausible")}
                      for r in cands if "plausible" in r],
        std_locations=total, shortlist=[r["version"] for r in short],
        ranking=rows, downloaded=[d.name for d in downloaded], removed=removed,
        not_downloaded=skipped, decided_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    out = Path(out) if out else original.parent / "toolchain.json"
    out.write_text(json.dumps(result, indent=2) + "\n")
    C.print_table(orig, rows, verdict)
    log(f"\n→ platform-tools v{result['release']} (--target {result['target']}), confidence {result['confidence']}"
        + (f"\n  {result['note']}" if result["note"] else "") + f"\n  saved {out}")
    if removed:
        log("  removed the other downloaded releases (fingerprints kept): " + ", ".join(removed))
    return result


def short_name(sym):
    """`_ZN17compiler_builtins3int19specialized_div_rem12u128_div_remE` -> `u128_div_rem`."""
    if not sym.startswith("_ZN"):
        return sym
    parts, i = [], 3
    while i < len(sym) and sym[i].isdigit():
        j = i
        while j < len(sym) and sym[j].isdigit():
            j += 1
        n = int(sym[i:j])
        parts.append(sym[j:j + n])
        i = j + n
    return parts[-1] if parts else sym


def fp_still_valid(fp):
    """A cached fingerprint is reusable while its release's lock is unchanged."""
    lock = Path(fp["toolchain"]).parent / f"{fp['name']}.lock.json"
    try:
        return fp["key"] == "archive:" + json.loads(lock.read_text())["archive_sha256"]
    except (OSError, ValueError, KeyError):
        return Path(fp["toolchain"]).is_dir()


def ensure(original, log=print, **kw):
    """(toolchain dir, target) for a capture: reuse toolchain.json when it was
    made for these exact bytes, else pick() now."""
    original = Path(original).resolve()
    saved = original.parent / "toolchain.json"
    sha = hashlib.sha256(original.read_bytes()).hexdigest()
    try:
        prev = json.loads(saved.read_text())
    except (OSError, ValueError):
        prev = None
    if prev and prev.get("original_sha256") == sha and prev.get("release"):
        log(f"toolchain: platform-tools v{prev['release']} (from {saved}, confidence {prev.get('confidence')})")
        try:
            return T.install(prev["release"], log=lambda m: None), prev.get("target")
        except T.NoRelease as exc:
            raise SystemExit(str(exc))
    res = pick(original, log=log, **kw)
    return Path(res["toolchain"]), res["target"]


def resolve_for(spec, original, log=print):
    """A --toolchain value for one capture -> (toolchain dir, target or None).
    Left out or "auto": detect it (or reuse toolchain.json). A release version
    ("1.44") is installed if needed; a directory is used as is."""
    if spec in (None, "", "auto"):
        if not Path(original).exists():
            raise SystemExit(f"{original} missing — fetch the program first, or pass --toolchain <version>")
        return ensure(original, log=log)
    return T.resolve(spec, log=log), None


def main(argv=None):
    ap = argparse.ArgumentParser(prog="toolchain.py auto", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--original", required=True, type=Path, help="capture/<ID>/program.so")
    ap.add_argument("--max-downloads", type=int, default=6,
                    help="most toolchains to download for the final comparison (default 6)")
    ap.add_argument("--keep", action="store_true", help="keep every release downloaded for the comparison")
    ap.add_argument("--out", type=Path, default=None, help="default: toolchain.json next to the original")
    a = ap.parse_args(argv)
    pick(a.original, max_downloads=a.max_downloads, keep=a.keep, out=a.out)


if __name__ == "__main__":
    main()

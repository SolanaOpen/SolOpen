#!/usr/bin/env python3
"""
calibrate.py — find the compiler that built a deployed program BEFORE writing
source for it.

  python3 calibrate.py --original capture/<ID>/program.so \\
      --toolchain ~/.cache/solopen/platform-tools-v1.43 \\
      --toolchain ~/.cache/solopen/platform-tools-v1.44 ... --out calib/<ID>

Rebuilding byte-for-byte only works with the same platform-tools release, and
a wrong guess is expensive: every function differs a little and the source
gets "fixed" towards the wrong compiler. Three independent checks, run for
every toolchain and every SBPF v0 target it ships:

  header   A tiny canary program bundled with this script (no dependencies)
           is compiled, and its ELF e_machine / e_flags are compared with the
           original's (EM_BPF 247 vs EM_SBF 263 rules out whole families).
  stdlib   Every `library/<crate>/src/….rs` path embedded in the original must
           exist in the toolchain's precompiled core/alloc/std, and each
           standard-library panic location (file, line, column) is looked up
           in them. Standard-library source moves between Rust releases, so
           the coordinates pin the release family.
  helpers  The canary links the precompiled helpers every program gets
           (core::fmt::write, integer formatting, __multi3, Vec growth, …).
           Each body is searched in the original .text, raw and with
           call/lddw immediates masked. Only helpers whose bodies DIFFER
           between the toolchains tested are counted as evidence; helpers
           every toolchain compiles identically are reported as controls.

The original is only read and searched; nothing from it is written into a
build. Matches assume stock platform-tools sysroots: a custom std, LTO or
unusual opt-level changes helper bodies, so treat the result as a ranking
to start from, not a proof. stdlib only.
"""
import argparse, json, os, re, shutil, struct, subprocess, sys, tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import linkorder as LO
import sbf

V0_TARGETS = ("sbf-solana-solana", "sbpf-solana-solana")


def version_targets(version):
    """Rust targets that emit a given SBPF version (ELF e_flags)."""
    return V0_TARGETS if version == 0 else (f"sbpfv{version}-solana-solana",)

# Uses what Anchor/solana-program code pulls in from the precompiled sysroot:
# core::fmt machinery, integer/char/str formatting, 128-bit arithmetic,
# alloc::fmt::format, Vec growth and slice-index panics. Never executed.
CANARY = r'''
#![no_std]
extern crate alloc;
use alloc::{format, string::String, vec::Vec};
use core::alloc::{GlobalAlloc, Layout};
use core::fmt::Write;

struct Dummy;
unsafe impl GlobalAlloc for Dummy {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 { (0x3_0000_0000usize + l.size()) as *mut u8 }
    unsafe fn dealloc(&self, _: *mut u8, _: Layout) {}
}
#[global_allocator]
static ALLOC: Dummy = Dummy;

#[derive(Debug)]
struct Pair { a: u64, b: [u8; 4] }

#[no_mangle]
pub unsafe extern "C" fn entrypoint(input: *mut u8) -> u64 {
    let rd = |o: usize| core::ptr::read_volatile(input.add(o) as *const u64);
    let x = rd(0);
    let y = ((rd(8) as u128) << 64) | rd(16) as u128;
    let i = rd(24) as i64;
    let c = char::from_u32(rd(32) as u32).unwrap_or('?');
    let mut v: Vec<u8> = Vec::new();
    for k in 0..(x as usize & 63) { v.push(k as u8); }
    v.extend_from_slice(&x.to_le_bytes());
    let mut s = String::new();
    let _ = write!(s, "{} {} {} {} {:?} {:x} {:?} {:?} {:?} {:>8}",
                   x, y.wrapping_mul(x as u128), y / (x as u128 | 1),
                   (y as i128) % ((i as i128) | 1), c, x,
                   core::str::from_utf8(&v), &v[..], Pair { a: x, b: [1, 2, 3, 4] }, i);
    let t = format!("{s}{i}{}", y as u64 as f64 as u64);
    let idx = rd(40) as usize;
    (t.as_bytes()[idx] as u64) + v[idx..].len() as u64 + s.len() as u64
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }
'''


def header(b):
    return struct.unpack_from("<H", b, 18)[0], struct.unpack_from("<I", b, 0x30)[0]


def strip_hash(name):
    return re.sub(r"17h[0-9a-f]{16}E$", "E", name)


def panic_locations(b):
    """{(file, line, col)} for every Rust panic Location record in data."""
    img = LO.image_of(b)
    out = set()
    for nm, a, sz, raw in img["data"]:
        for o in range(0, sz - 23, 8):
            is_ptr, p = LO.ptr_value(struct.unpack_from("<Q", raw, o)[0], a + o, img)
            n, line, col = struct.unpack_from("<QII", raw, o + 8)
            if not is_ptr or not 4 <= n < 256 or not 0 < line < 1 << 20 or not 0 < col < 1 << 12:
                continue
            for nm2, a2, sz2, raw2 in img["data"]:
                if a2 <= p and p + n <= a2 + sz2:
                    s = raw2[p - a2:p - a2 + n]
                    name = s[:-1] if s.endswith(b"\0") else s
                    if name.endswith(b".rs") and all(32 < ch < 127 for ch in name):
                        out.add((name.decode(), n, line, col))
                    break
    return out


def is_std(path):
    """core/alloc/std sources: `library/core/src/…`, or the absolute build path
    some releases leave in (`/home/runner/work/platform-tools/…/library/core/src/…`)."""
    return re.search(r"(?:^|/)library/[a-z_]+/src/", path) is not None


FP_ROOT = Path.home() / ".cache/solopen/fingerprints"
FP_FORMAT = 1
# A standard-library source path, relative or under an absolute build directory.
STD_PATH = re.compile(rb"(?:/[A-Za-z0-9_.+-]+)*/?library/[a-z_]+/src/[A-Za-z0-9_/]+\.rs")
REL_STD = re.compile(rb"library/[a-z_]+/src/[A-Za-z0-9_/]+\.rs")


def sysroot_blob(tc, triple):
    """All precompiled standard-library bytes for one target, concatenated."""
    d = tc / "rust/lib/rustlib" / triple / "lib"
    return b"".join(p.read_bytes() for p in sorted(d.glob("*.rlib")))


def rustc_version(tc):
    return subprocess.run([str(tc / "rust/bin/rustc"), "--version"], capture_output=True,
                          text=True).stdout.strip()


def release_of(name):
    m = re.search(r"v(\d+\.\d+(?:\.\d+)?)$", name)
    return m.group(1) if m else name


def toolchain_key(tc):
    """Identity of an installed toolchain: its verified archive hash if solopen
    installed it, else the compiler's version string."""
    lock = tc.parent / f"{tc.name}.lock.json"
    try:
        return "archive:" + json.loads(lock.read_text())["archive_sha256"]
    except (OSError, ValueError, KeyError):
        return "rustc:" + rustc_version(tc)


def targets_of(tc, version=0):
    return [t for t in version_targets(version) if (tc / "rust/lib/rustlib" / t / "lib").is_dir()]


def fingerprint(tc, triple, root=FP_ROOT):
    """Everything calibration needs from one toolchain + target, cached under
    ~/.cache/solopen/fingerprints so the toolchain itself can be deleted: the
    canary build (helper bodies, ELF header), the standard-library source
    paths its sysroot knows and every (len, line, col) Location tail in it."""
    tc = Path(tc).expanduser().resolve()
    d = root / tc.name / triple
    key = toolchain_key(tc)
    try:
        meta = json.loads((d / "meta.json").read_text())
        if meta.get("key") == key and meta.get("format") == FP_FORMAT:
            return load_fingerprint(d)
    except (OSError, ValueError):
        pass
    d.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="solopen-canary-") as tmp:
        canary, err = build_canary(tc, triple, Path(tmp))
        shutil.copy2(Path(tmp) / "build.log", d / "build.log")
    blob = sysroot_blob(tc, triple)
    full = set(STD_PATH.findall(blob))
    paths = sorted({REL_STD.search(x).group(0).decode() for x in full})
    # In an object file a Location is {file ptr (relocated, so 0), len, line, col}.
    lens = {len(x) for x in full} | {len(x) + 1 for x in full}
    locs = set()
    for n in lens:
        pat = struct.pack("<Q", n)
        at = blob.find(pat)
        while at >= 0:
            if at + 16 <= len(blob):
                line, col = struct.unpack_from("<II", blob, at + 8)
                if 0 < line < 1 << 16 and 0 < col < 1 << 10:
                    locs.add((n, line, col))
            at = blob.find(pat, at + 1)
    if canary:
        (d / "canary.so").write_bytes(canary)
    meta = dict(format=FP_FORMAT, key=key, name=tc.name, release=release_of(tc.name), toolchain=str(tc),
                target=triple, rustc=rustc_version(tc),
                header=dict(zip(("machine", "flags"), header(canary))) if canary else None,
                canary_error=err, std_paths=paths, std_locations=sorted(locs))
    (d / "meta.json").write_text(json.dumps(meta) + "\n")
    return load_fingerprint(d)


def load_fingerprint(d):
    meta = json.loads((Path(d) / "meta.json").read_text())
    so = Path(d) / "canary.so"
    meta["_canary"] = so.read_bytes() if so.exists() else None
    meta["_paths"] = set(meta["std_paths"])
    meta["_locs"] = {tuple(x) for x in meta["std_locations"]}
    return meta


def cached_fingerprints(root=FP_ROOT):
    """{(toolchain dir name, target): fingerprint} for everything cached."""
    out = {}
    for meta in sorted(Path(root).glob("*/*/meta.json")):
        try:
            fp = load_fingerprint(meta.parent)
        except (OSError, ValueError, KeyError):
            continue
        if fp.get("format") == FP_FORMAT:
            out[(fp["name"], fp["target"])] = fp
    return out


def build_canary(tc, triple, out):
    out.mkdir(parents=True, exist_ok=True)
    src = out / "canary.rs"
    src.write_text(CANARY)
    rustc = tc / "rust/bin/rustc"
    lld = next(iter(sorted(tc.glob("rust/lib/rustlib/*/bin/rust-lld"))), None) or tc / "llvm/bin/ld.lld"
    home = out / "home"
    home.mkdir(exist_ok=True)
    env = {"PATH": f"{tc / 'rust/bin'}:{tc / 'llvm/bin'}:{os.environ.get('PATH', '/usr/bin:/bin')}",
           "HOME": str(home), "LANG": "C"}
    so = out / "canary.so"
    cmd = [str(rustc), "--edition", "2021", "--crate-type", "cdylib", "--crate-name", "solopen_canary",
           "--target", triple, "-C", "opt-level=3", "-C", "codegen-units=1", "-C", "overflow-checks=on",
           f"--remap-path-prefix={out}=/canary", "-C", f"linker={lld}", "-o", str(so), str(src)]
    r = subprocess.run(cmd, cwd=out, env=env, capture_output=True, text=True)
    (out / "build.log").write_text(" ".join(cmd) + "\n\n" + r.stdout + r.stderr)
    if r.returncode or not so.exists():
        return None, (r.stderr.strip().splitlines() or ["build failed"])[-1]
    return so.read_bytes(), None


def helper_bodies(canary):
    version = sbf.elf_version(canary)
    try:
        funcs, text_sec = LO.functions_of(canary)
    except (SystemExit, StopIteration):
        return {}      # e.g. v1.44's early sbpfv3 target links without a symbol table
    _, text = LO.text_of(canary)
    out = {}
    for name, off, size, _aliases in funcs:
        if "solopen_canary" in name or name in ("entrypoint",) or size < 48:
            continue
        body = text[off:off + size]
        out[strip_hash(name)] = (body, LO.mask(body, version))
    return out


def find_body(orig_text, orig_masked, body, masked):
    """(masked_found, raw_found) at an instruction-aligned offset."""
    at, masked_hit = 0, False
    while True:
        at = orig_masked.find(masked, at)
        if at < 0:
            return masked_hit, False
        if at % 8 == 0:
            masked_hit = True
            if orig_text[at:at + len(body)] == body:
                return True, True
        at += 1


def analyze_original(raw):
    _, text = LO.text_of(raw)
    locs = panic_locations(raw)
    version = sbf.elf_version(raw)
    return dict(raw=raw, header=header(raw), version=version, text=text, masked=LO.mask(text, version), locs=locs,
                std_locs=sorted(l for l in locs if is_std(l[0])),
                paths=sorted(set(m.decode() for m in REL_STD.findall(raw))))


def stdlib_check(orig, fp):
    missing = [p for p in orig["paths"] if p not in fp["_paths"]]
    hits = [l for l in orig["std_locs"] if (l[1], l[2], l[3]) in fp["_locs"]]
    return dict(paths=len(orig["paths"]), missing_paths=missing,
                std_locations=len(orig["std_locs"]), location_hits=len(hits),
                location_misses=[f"{l[0]}:{l[2]}:{l[3]}" for l in orig["std_locs"] if l not in hits][:20])


def score(row):
    s = row["stdlib"]
    h = row.get("helpers", {})
    return (row.get("header_matches", False), -len(s["missing_paths"]),
            h.get("discriminating_found", 0), s["location_hits"], h.get("raw_exact", 0))


def rank(orig, fps):
    """Score fingerprints against the original. Returns (rows best first, verdict)."""
    rows = []
    for fp in fps:
        row = {k: fp[k] for k in ("name", "release", "toolchain", "target", "rustc", "header", "canary_error")}
        row["stdlib"] = stdlib_check(orig, fp)
        if fp["_canary"]:
            row["_bodies"] = helper_bodies(fp["_canary"])
            row["header_matches"] = (fp["header"]["machine"], fp["header"]["flags"]) == orig["header"]
        rows.append(row)
    # A helper discriminates when the tested toolchains compile it differently.
    by_name = {}
    for row in rows:
        for name, (_body, masked) in row.get("_bodies", {}).items():
            by_name.setdefault(name, set()).add(masked)
    built = [r for r in rows if "_bodies" in r]
    for row in built:
        found, raw, controls, discr = [], [], [], []
        for name, (body, masked) in sorted(row["_bodies"].items()):
            hit, exact = find_body(orig["text"], orig["masked"], body, masked)
            spread = len(by_name[name]) > 1 or sum(name in r["_bodies"] for r in built) < len(built)
            (discr if spread else controls).append(name)
            if hit:
                found.append(name)
                if exact:
                    raw.append(name)
        row["helpers"] = dict(
            tested=len(row["_bodies"]), found=len(found), raw_exact=len(raw),
            discriminating=len(discr), discriminating_found=sum(n in found for n in discr),
            found_names=[n for n in found if n in discr][:40], control_names=controls[:20])
    for row in rows:
        row.pop("_bodies", None)
    rows.sort(key=score, reverse=True)
    best = rows[0] if rows else None
    tied = [r for r in rows if score(r)[:3] == score(best)[:3]] if best else []
    if not best:
        verdict = None
    elif len({r["name"] for r in tied}) > 1:
        verdict = ("inconclusive: " + ", ".join(r["name"] for r in tied) + " tie — add the "
                   "releases between them, or compare clean builds of your source with each")
    else:
        verdict = f"start with {best['name']} --target {best['target']}"
        if len(tied) > 1:
            verdict += (" (its " + " and ".join(r["target"] for r in tied) + " targets fit equally; "
                        "use the one your build recipe used)")
    return rows, verdict


def print_table(orig, rows, verdict, out=None):
    om, of = orig["header"]
    print(f"\noriginal: machine {om} flags {of}; {len(orig['locs'])} panic locations "
          f"({len(orig['std_locs'])} in the standard library)")
    print(f"{'toolchain / target':44} {'header':>7} {'paths':>9} {'std locs':>9} {'helpers*':>9} {'raw':>5}")
    for r in rows:
        s, h = r["stdlib"], r.get("helpers")
        hdr = ("ok" if r["header_matches"] else f"{r['header']['machine']}/{r['header']['flags']}") \
            if r.get("header") else "error"
        print(f"{r['name'] + '/' + r['target']:44} {hdr:>7} "
              f"{s['paths'] - len(s['missing_paths']):>4}/{s['paths']:<4} "
              f"{s['location_hits']:>4}/{s['std_locations']:<4} "
              + (f"{h['discriminating_found']:>4}/{h['discriminating']:<4} {h['raw_exact']:>5}" if h else
                 f"  canary failed: {(r.get('canary_error') or '')[:60]}"))
    print("* helpers whose bodies differ between the toolchains tested, found in the original")
    print(f"\n{verdict or 'no toolchain could be tested'}" + (f"  (details: {out})" if out else ""))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--original", required=True, type=Path, help="capture/<ID>/program.so")
    ap.add_argument("--toolchain", action="append", default=[],
                    help="platform-tools directory or release version to install (repeat for each release)")
    ap.add_argument("--cached", action="store_true",
                    help="also score every release fingerprinted earlier (no toolchain needed)")
    ap.add_argument("--target", action="append", default=None,
                    help="limit to these target triples (default: every SBPF v0 target each toolchain ships)")
    ap.add_argument("--out", type=Path, default=None, help="write calibration.json here")
    a = ap.parse_args()
    if not a.toolchain and not a.cached:
        ap.error("give --toolchain (repeatable) and/or --cached — or let `solopen.py toolchain auto` choose")
    import toolchain as T
    orig = analyze_original(a.original.read_bytes())
    fps = {}
    for spec in a.toolchain:
        tc = T.resolve(spec)
        for triple in a.target or targets_of(tc, orig["version"]):
            if triple in targets_of(tc, orig["version"]):
                print(f"… {tc.name}/{triple}", flush=True)
                fps[(tc.name, triple)] = fingerprint(tc, triple)
    if a.cached:
        for k, fp in cached_fingerprints().items():
            if a.target is None or k[1] in a.target:
                fps.setdefault(k, fp)
    rows, verdict = rank(orig, list(fps.values()))
    report = dict(original=str(a.original), original_header=dict(zip(("machine", "flags"), orig["header"])),
                  panic_locations=len(orig["locs"]), ranking=rows, verdict=verdict)
    out = None
    if a.out:
        a.out.mkdir(parents=True, exist_ok=True)
        out = a.out / "calibration.json"
        out.write_text(json.dumps(report, indent=2) + "\n")
    print_table(orig, rows, verdict, out)


if __name__ == "__main__":
    main()

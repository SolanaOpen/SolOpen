"""End-to-end check for every SBPF version (v0-v3), on a program written here.

For each version it builds a small no-dependency program with platform-tools,
relinks that build with its functions shuffled (what a different build
machine or source order does to a real deployment), strips it, and treats
the result as "the original". Then `solopen.py try` must rebuild it
byte-for-byte from source alone: the link order is recovered from bytes. It also decompiles each original and checks the
syscalls are named (v3 calls them by hash).

  python3 _test/e2e_versions.py [--toolchain 1.54]      (needs that release; ~2 min)
"""
import argparse, json, random, shutil, subprocess, sys, tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / "tools"))
import linkorder as LO
import sbf
import toolchain as T

PROGRAM = r'''
#![no_std]
#[cfg(not(target_feature = "static-syscalls"))]
extern "C" {
    fn sol_log_(msg: *const u8, len: u64);
    fn sol_log_64_(a: u64, b: u64, c: u64, d: u64, e: u64);
}
#[cfg(target_feature = "static-syscalls")]
unsafe fn sol_log_(msg: *const u8, len: u64) {
    #[repr(usize)] enum S { C = 0x207559bd }
    let f: extern "C" fn(*const u8, u64) = core::mem::transmute(S::C); f(msg, len)
}
#[cfg(target_feature = "static-syscalls")]
unsafe fn sol_log_64_(a: u64, b: u64, c: u64, d: u64, e: u64) {
    #[repr(usize)] enum S { C = 0x5c2a3178 }
    let f: extern "C" fn(u64, u64, u64, u64, u64) = core::mem::transmute(S::C); f(a, b, c, d, e)
}
trait Shape { fn area(&self) -> u64; fn name(&self) -> &'static str; fn scale(&self, k: u64) -> u64 { self.area() * k } }
struct Sq(u64); struct Rect(u64, u64); struct Tri(u64, u64);
impl Shape for Sq { fn area(&self) -> u64 { self.0 * self.0 } fn name(&self) -> &'static str { "square" } }
impl Shape for Rect { fn area(&self) -> u64 { self.0 * self.1 } fn name(&self) -> &'static str { "rectangle" } }
impl Shape for Tri { fn area(&self) -> u64 { self.0 * self.1 / 2 } fn name(&self) -> &'static str { "triangle" }
                     fn scale(&self, k: u64) -> u64 { self.area() * k + 1 } }
static TABLE: [u64; 8] = [3, 1, 4, 1, 5, 9, 2, 6];
static NAMES: [&str; 4] = ["alpha", "beta", "gamma", "delta"];
#[inline(never)] fn log(s: &str) { unsafe { sol_log_(s.as_ptr(), s.len() as u64) } }
#[inline(never)] fn pick(k: u64) -> &'static dyn Shape {
    static A: Sq = Sq(7); static B: Rect = Rect(3, 5); static C: Tri = Tri(4, 9);
    match k % 3 { 0 => &A, 1 => &B, _ => &C }
}
#[inline(never)] fn mix(a: u64, b: u64) -> u64 { a.wrapping_mul(31) ^ (b / (a | 1)) ^ (b % 7) ^ ((a as i64 >> 3) as u64) }
#[inline(never)] fn sum(v: &[u64]) -> u64 { v.iter().fold(0u64, |t, x| t.wrapping_add(*x)) }
#[inline(never)] fn checked(a: u64, b: u64) -> u64 { a.checked_sub(b).unwrap_or(0) + (a as u32).wrapping_sub(b as u32) as u64 }
#[inline(never)] fn fib(n: u64) -> u64 { if n < 2 { n } else { fib(n - 1).wrapping_add(fib(n - 2)) } }
#[inline(never)] fn gcd(a: u64, b: u64) -> u64 { if b == 0 { a } else { gcd(b, a % b) } }
#[inline(never)] fn name_of(i: u64) -> &'static str { NAMES[(i & 3) as usize] }
#[inline(never)] fn generic<T: Copy + Into<u64>>(x: T, y: T) -> u64 { x.into().wrapping_mul(3) ^ y.into() }
#[inline(never)] fn dispatch(op: u8, a: u64, b: u64) -> u64 {
    match op { 0 => a + b, 1 => a.wrapping_sub(b), 2 => mix(a, b), 3 => gcd(a, b), 4 => fib(a & 15),
               5 => generic(a as u32, b as u32), 6 => generic(a as u8, b as u8), _ => checked(a, b) }
}
#[inline(never)] fn report(k: u64, s: &dyn Shape) {
    log(s.name()); log(name_of(k));
    unsafe { sol_log_64_(s.area(), s.scale(k), sum(&TABLE), TABLE[(k & 7) as usize], k) }
}
#[no_mangle]
pub unsafe extern "C" fn entrypoint(input: *mut u8) -> u64 {
    let k = core::ptr::read_volatile(input as *const u64);
    let s = pick(k);
    log("hello from solopen");
    report(k, s);
    let mut acc = 0u64;
    for op in 0..8u8 { acc ^= dispatch(op, k, acc | 1); }
    if acc == 0x1234_5678_9abc { return 1; }
    acc & 1
}
#[panic_handler] fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }
'''


def run(cmd, **kw):
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if r.returncode:
        raise SystemExit(f"{' '.join(map(str, cmd))} failed:\n{r.stdout[-2000:]}\n{r.stderr[-2000:]}")
    return r.stdout


def scramble(capture, out, seed):
    """Relink a build with its functions shuffled. Code addresses then differ
    everywhere — calls, function-pointer loads, vtables (.data.rel.ro up to
    v2, inside .rodata in v3) — and all of it must be recovered from bytes."""
    base = (capture / "baseline.unstripped.so").read_bytes()
    funcs, _ = LO.functions_of(base)
    order = list(range(len(funcs)))
    rnd = random.Random(seed)
    rnd.shuffle(order)
    rows = [dict(original=8 * order[i], candidate=f[1], size=f[2], symbol=f[0]) for i, f in enumerate(funcs)]
    mapping = out.parent / f"{out.name}-mapping.json"
    mapping.write_text(json.dumps(dict(rows=rows, constants=[])))
    run([sys.executable, "-I", str(ROOT / "tools/relink.py"), "--capture", str(capture),
         "--order", str(mapping), "--out", str(out)])
    return (out / "program.so").read_bytes()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--toolchain", default="1.54")
    ap.add_argument("--keep", type=Path, default=None, help="keep the work directory here")
    a = ap.parse_args()
    tc = T.resolve(a.toolchain, log=lambda m: None)
    work = a.keep or Path(tempfile.mkdtemp(prefix="solopen-e2e-versions-"))
    ws = work / "workspace"
    (ws / "vtest/src").mkdir(parents=True, exist_ok=True)
    (ws / "Cargo.toml").write_text('[workspace]\nmembers = ["vtest"]\nresolver = "2"\n\n'
                                   '[profile.release]\nopt-level = 3\ncodegen-units = 1\n')
    (ws / "vtest/Cargo.toml").write_text('[package]\nname = "vtest"\nversion = "0.1.0"\nedition = "2021"\n\n'
                                         '[lib]\ncrate-type = ["cdylib"]\n')
    (ws / "vtest/src/lib.rs").write_text(PROGRAM)
    run([str(tc / "rust/bin/cargo"), "generate-lockfile", "--offline"], cwd=ws,
        env={"HOME": str(work), "PATH": f"{tc / 'rust/bin'}:/usr/bin:/bin", "RUSTC": str(tc / "rust/bin/rustc")})
    targets = [("sbpf-solana-solana", 0), ("sbpfv1-solana-solana", 1), ("sbpfv2-solana-solana", 2),
               ("sbpfv3-solana-solana", 3)]
    results = []
    for triple, version in targets:
        if not (tc / "rust/lib/rustlib" / triple / "lib").is_dir():
            print(f"skip v{version}: {tc.name} has no {triple}")
            continue
        first = work / f"first-{version}"
        shutil.rmtree(first, ignore_errors=True)
        run([sys.executable, "-I", str(ROOT / "tools/build.py"), "--workspace", str(ws), "--toolchain", str(tc),
             "--program", "vtest", "--out", str(first), "--target", triple])
        pid = f"vtest{version}"
        cap = work / "capture" / pid
        shutil.rmtree(cap, ignore_errors=True)
        cap.mkdir(parents=True)
        original = scramble(first / "capture", work / f"scrambled-{version}", seed=version + 1)
        assert sbf.elf_version(original) == version, (triple, sbf.elf_version(original))
        fresh = (first / "capture" / "baseline.unstripped.so").read_bytes()
        (cap / "program.so").write_bytes(original)
        # a fresh build must NOT already match, or the test proves nothing
        assert LO.text_of(original)[1] != LO.text_of(fresh)[1], "scramble left .text unchanged"
        run_dir = work / f"try-{version}"
        shutil.rmtree(run_dir, ignore_errors=True)
        out = subprocess.run([sys.executable, "-I", str(ROOT / "solopen.py"), "try", "--id", pid,
                              "--capture-root", str(work / "capture"), "--workspace", str(ws), "--program", "vtest",
                              "--toolchain", str(tc), "--run-dir", str(run_dir), "--no-difftest"],
                             capture_output=True, text=True)
        ok = out.returncode == 0 and "byte-identical" in out.stdout
        dec = work / f"decompile-{version}"
        shutil.rmtree(dec, ignore_errors=True)
        run([sys.executable, "-I", str(ROOT / "tools/decompile.py"), str(cap / "program.so"), "--out", str(dec)])
        analysis = json.loads((dec / "analysis.json").read_text())
        syscalls = sorted({s for f in analysis["functions"] for s in f["syscalls"]})
        named = {"sol_log_", "sol_log_64_"} <= set(syscalls)
        results.append((version, ok, named))
        print(f"v{version} ({triple}): rebuild {'MATCH' if ok else 'FAILED'}; decompile names {syscalls}")
        if not ok:
            print(out.stdout[-3000:], out.stderr[-2000:])
    if not a.keep:
        shutil.rmtree(work, ignore_errors=True)
    if not results or not all(ok and named for _, ok, named in results):
        raise SystemExit("FAILED")
    print(f"ALL {len(results)} SBPF VERSIONS REBUILT BYTE-FOR-BYTE")


if __name__ == "__main__":
    main()

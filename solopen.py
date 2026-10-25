#!/usr/bin/env python3
"""
solopen — open-source a deployed Solana program by rebuilding it byte-for-byte.

  solopen.py fetch   <PROGRAM_ID> [--rpc URL]       capture the live executable + who can upgrade it
  solopen.py inspect capture/<ID>                   what it does: instructions, modules, CPIs, errors
  solopen.py decompile capture/<ID> --out reverse/<ID> [--workspace W]
                     SBPF disassembly + CFG + an unimplemented Anchor source scaffold
  solopen.py toolchain <VERSION>                    fetch an official platform-tools release
  solopen.py toolchain auto --original capture/<ID>/program.so
                     detect which release built it and install that one (try/rebuild do this
                     by themselves when --toolchain is left out)
  solopen.py calibrate --original capture/<ID>/program.so --toolchain T1 --toolchain T2 ...
                     which platform-tools release built it (header, stdlib coordinates, helper bodies)
  solopen.py try     --id <ID> --workspace W --program NAME [--toolchain T|VERSION] [--vendor V]
                     one round of the loop: build -> recover order -> relink -> byte-compare
  solopen.py cases   --id <ID> [--limit 200]          recent real transactions + account snapshot, for difftest
  solopen.py difftest --id <ID> --run runs/<attempt>  replay them on the original and your build; compare
                     behaviour (needs `pip install solders==0.29.0`; `try` runs it when cases exist)
  solopen.py lockfit --id <ID> --workspace W         dependency versions the binary proves vs Cargo.lock
  solopen.py target  --run runs/<attempt> --original capture/<ID>/program.so
                     per-function to-do list: where each broken function belongs, asm diff, panic lines
  solopen.py rebuild --id <ID> --workspace W --program NAME --out runs/ai-01 --model MODEL
                     AI loop, one function at a time; keep improvements, roll back regressions
  solopen.py vendor  --lock W/Cargo.lock --out vendor    hash-checked crates for offline builds
  solopen.py finalize --id <ID> --workspace W --run runs/ai-01/attempt-008 --out release/<ID>
                     exact-match gate -> source + binaries + proof + security review package

Lower-level steps (each is also a standalone script in tools/):
  solopen.py build   ...   (tools/build.py)      solopen.py order   ...   (tools/linkorder.py)
  solopen.py relink  ...   (tools/relink.py)     solopen.py compare ...   (tools/compare.py)

Read-only toward the chain: no wallet, no keys, no transactions.
"""
import os, subprocess, sys, json, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
T = HERE / "tools"
SIMPLE = {"fetch": "fetch.py", "toolchain": "toolchain.py", "build": "build.py",
          "order": "linkorder.py", "relink": "relink.py", "compare": "compare.py",
          "decompile": "decompile.py", "rebuild": "rebuild.py", "finalize": "finalize.py",
          "target": "target.py", "vendor": "vendor.py", "calibrate": "calibrate.py",
          "cases": "cases.py", "difftest": "difftest.py", "lockfit": "lockfit.py"}


def run(script, args, log=None):
    sys.stdout.flush()          # keep our progress lines ahead of the child's output
    if log is None:
        return subprocess.call([sys.executable, str(T / script)] + list(args))
    with open(log, "a") as f:
        return subprocess.call([sys.executable, str(T / script)] + list(args), stdout=f, stderr=subprocess.STDOUT)


def inspect(args):
    if not args:
        raise SystemExit("usage: solopen.py inspect capture/<ID> | program.so")
    p = Path(args[0])
    so = p / "program.so" if p.is_dir() else p
    extra = args[1:]
    if p.is_dir() and "--json" not in extra:
        extra += ["--json", str(p / "inspect.json")]
    return run("inspect_program.py", [str(so)] + extra)


def try_round(argv):
    import argparse
    ap = argparse.ArgumentParser(prog="solopen.py try")
    ap.add_argument("--id", required=True, help="program id (uses capture/<id>/program.so)")
    ap.add_argument("--capture-root", type=Path, default=Path("capture"))
    ap.add_argument("--workspace", required=True, type=Path)
    ap.add_argument("--toolchain", default=None,
                    help="platform-tools directory or release version (e.g. 1.44); default: detect "
                         "which release built the original and install it (see `toolchain auto`)")
    ap.add_argument("--program", required=True, help="lib name of the program crate, e.g. dao_v1")
    ap.add_argument("--vendor", type=Path, default=None)
    ap.add_argument("--package", default=None)
    ap.add_argument("--target", default=None, help="Rust target triple (default: what the toolchain ships)")
    ap.add_argument("--features", default=None)
    ap.add_argument("--rustflags", default=None)
    ap.add_argument("--runs", type=Path, default=Path("runs"))
    ap.add_argument("--run-dir", type=Path, default=None,
                    help="explicit fresh output directory (used by the AI rebuild loop)")
    ap.add_argument("--target-cache", type=Path, default=None,
                    help="reuse dependencies for fast search loops; not for finalization")
    ap.add_argument("--quiet", action="store_true", help="only print the score line")
    ap.add_argument("--no-difftest", action="store_true",
                    help="skip the behaviour comparison even when capture/<id>/cases exists")
    a = ap.parse_args(argv)
    orig = a.capture_root / a.id / "program.so"
    if not orig.exists():
        raise SystemExit(f"{orig} missing — run: solopen.py fetch {a.id}")
    sys.path.insert(0, str(T))
    import integrity, pick_toolchain
    integrity.require_clean(a.workspace, orig)
    say = (lambda *x: None) if a.quiet else print
    toolchain, auto_target = pick_toolchain.resolve_for(a.toolchain, orig, log=say)
    import sbf
    version = sbf.elf_version(orig.read_bytes())
    a.target = a.target or auto_target or (f"sbpfv{version}-solana-solana" if version else None)
    run_dir = a.run_dir or a.runs / time.strftime("%Y%m%d-%H%M%S")
    b = ["--workspace", str(a.workspace), "--toolchain", str(toolchain), "--program", a.program,
         "--out", str(run_dir)]
    if a.vendor:
        b += ["--vendor", str(a.vendor)]
    if a.package:
        b += ["--package", a.package]
    if a.target:
        b += ["--target", a.target]
    if a.features:
        b += ["--features", a.features]
    if a.target_cache:
        b += ["--target-cache", str(a.target_cache)]
    if a.rustflags is not None:
        b += ["--rustflags=" + a.rustflags]
    log = None
    if a.quiet:
        run_dir.parent.mkdir(parents=True, exist_ok=True)
        log = run_dir.parent / f"{run_dir.name}.try.log"
    say(f"== 1/3 build  -> {run_dir}")
    if run("build.py", b, log):
        return 1
    say("== 2/3 recover link order")
    cand = run_dir / "capture" / "baseline.unstripped.so"
    if run("linkorder.py", ["--original", str(orig), "--candidate", str(cand), "--out", str(run_dir / "order")], log):
        return 1
    say("== 3/3 relink in recovered order + byte-compare")
    rc = run("relink.py", ["--capture", str(run_dir / "capture"), "--order", str(run_dir / "order/order-mapping.json"),
                           "--out", str(run_dir / "relinked"), "--original", str(orig)], log)
    s = json.loads((run_dir / "order/order-mapping.json").read_text())["summary"]
    print(f"\nscore: {s['coverage_pct']}% of the original's code reproduced by your functions "
          f"({s['unmatched']} of yours don't match yet, {s['uncovered_ranges']} unexplained ranges)")
    cases = a.capture_root / a.id / "cases"
    if rc != 0 and not a.no_difftest and (cases / "index.json").exists():
        import importlib.util
        if importlib.util.find_spec("solders") is None:
            print("behaviour: not compared — `python3 -m pip install solders==0.29.0` to replay "
                  f"{cases} on the original and this build")
        else:
            say("== behaviour: replaying recorded transactions on the original and this build")
            run("difftest.py", ["--id", a.id, "--capture-root", str(a.capture_root), "--run", str(run_dir)], log)
            if a.quiet and (run_dir / "difftest.json").exists():
                d = json.loads((run_dir / "difftest.json").read_text())
                print(f"behaviour: {d['identical']}/{d['cases']} cases identical")
    if rc == 0:
        print("DONE — byte-identical. Publish the workspace + toolchain version + this run directory.")
        print(f"package: solopen.py finalize --id {a.id} --workspace {a.workspace} "
              f"--run {run_dir} --out release/{a.id}")
    else:
        print("next: fix the functions listed under 'don't match the original yet' (biggest first);\n"
              "      if coverage is far below ~95%, the toolchain or dependency versions are wrong, not your code.")
    return rc


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
        print(__doc__)
        return 0
    cmd, args = sys.argv[1], sys.argv[2:]
    if cmd in SIMPLE:
        return run(SIMPLE[cmd], args)
    if cmd == "inspect":
        return inspect(args)
    if cmd == "try":
        return try_round(args)
    raise SystemExit(f"unknown command {cmd!r}; see solopen.py --help")


if __name__ == "__main__":
    sys.exit(main())

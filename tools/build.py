#!/usr/bin/env python3
"""
build.py — compile your reconstruction with a pinned Solana toolchain and
capture the final link.

  python3 build.py --workspace ../workspace --toolchain 1.41 \\
                   --program dao_v1 --out ../build/try-01 [--vendor ../workspace/vendor]

It runs plain `cargo build --release --target <sbf target>` (what
cargo-build-sbf does under the hood) with:
  - the toolchain's own rustc/cargo/clang, nothing from your PATH,
  - ambient RUSTFLAGS / wrappers cleared so nothing on your machine leaks in,
  - an empty target dir (a fresh build every time — no stale objects),
  - capture_link.py as the linker, so the link can be replayed in a new order.

Output: <out>/capture/ (link inputs, link.map, baseline.unstripped.so) and
<out>/build.log. Then run linkorder.py and relink.py. stdlib only.
"""
import argparse, json, os, shlex, shutil, subprocess, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import evidence


def find(toolchain, rel):
    p = toolchain / rel
    if not p.exists():
        raise SystemExit(f"toolchain is missing {rel} — is {toolchain} an unpacked platform-tools release?")
    return p


def default_target(tc):
    """The SBPF v0 target this toolchain ships a std for (old name first)."""
    for triple in ("sbf-solana-solana", "sbpf-solana-solana"):
        if (tc / "rust/lib/rustlib" / triple / "lib").is_dir():
            return triple
    raise SystemExit(f"{tc} has no sbf-solana-solana or sbpf-solana-solana standard library — is it platform-tools?")


def program_packages(ws, lib):
    """Package names whose lib target is `lib` (plus obvious spellings)."""
    import re
    names = {lib, lib.replace("_", "-")}
    for dirpath, dirnames, filenames in os.walk(ws, followlinks=False):
        dirnames[:] = [name for name in dirnames if name not in ("target", "vendor", ".git")]
        for filename in filenames:
            if filename != "Cargo.toml":
                continue
            toml = Path(dirpath) / filename
            text = toml.read_text(errors="replace")
            pkg = re.search(r'(?ms)^\[package\][^\[]*?^name\s*=\s*"([^"]+)"', text)
            lib_name = re.search(r'(?ms)^\[lib\][^\[]*?^name\s*=\s*"([^"]+)"', text)
            if pkg and (lib_name.group(1) if lib_name else pkg.group(1).replace("-", "_")) == lib:
                names.add(pkg.group(1))
    return sorted(names)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", required=True, type=Path, help="Cargo workspace with your reconstructed source")
    ap.add_argument("--toolchain", required=True,
                    help="unpacked platform-tools directory, or a release version (e.g. 1.44) to install")
    ap.add_argument("--program", required=True, help="the program crate's lib name (the <name>.so cargo produces)")
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--vendor", type=Path, default=None, help="vendored crates dir → build offline")
    ap.add_argument("--package", default=None, help="cargo -p <package> (default: whole workspace)")
    ap.add_argument("--rustflags", default="-Zremap-cwd-prefix=",
                    help="extra rustc flags for the SBF target (default strips your local path from panic "
                         "locations; this IS part of what must match — see README)")
    ap.add_argument("--features", default=None)
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--keep-target", action="store_true",
                    help="keep <out>/target after a clean build (captured link inputs are already copied)")
    ap.add_argument("--target-cache", type=Path, default=None,
                    help="reuse Cargo dependencies for search loops; the program crate is always recompiled. "
                         "Finalization refuses these runs and requires a clean build")
    ap.add_argument("--target", default=None,
                    help="Rust target triple. Default: sbf-solana-solana while the toolchain still ships "
                         "it, else sbpf-solana-solana (added in v1.44, the only SBPF v0 name in later releases; "
                         "where both exist they compile the same code). Use sbpfv1/v2/v3-solana-solana only "
                         "for SBPF v1+ programs (ELF e_flags 1-3)")
    ap.add_argument("--cargo-home", type=Path, default=Path.home() / ".cache/solopen/cargo-home",
                    help="Cargo download cache shared across builds. It must hold no Cargo config or "
                         "credentials (checked); downloaded crates are verified against Cargo.lock, so "
                         "sharing them cannot change a build. Default ~/.cache/solopen/cargo-home")
    a = ap.parse_args()

    import toolchain as toolchains
    ws, tc, out = a.workspace.resolve(), toolchains.resolve(a.toolchain), a.out.resolve()
    if out.exists():
        raise SystemExit(f"{out} exists — use a fresh --out per attempt so every result is a clean build")
    out.mkdir(parents=True)
    source = evidence.source_manifest(ws)
    (out / "source-manifest.json").write_text(json.dumps(source, indent=2) + "\n")
    target = a.target_cache.resolve() if a.target_cache else out / "target"
    target.mkdir(parents=True, exist_ok=True)
    if a.target_cache:
        # Keep dependencies cached but always redo the program crate and link.
        fp = target / (a.target or default_target(tc)) / "release" / ".fingerprint"
        for pkg in program_packages(ws, a.program):
            for stale in fp.glob(f"{pkg}-*"):
                shutil.rmtree(stale, ignore_errors=True)
    triple = a.target or default_target(tc)
    if not (tc / "rust/lib/rustlib" / triple / "lib").is_dir():
        have = sorted(d.name for d in (tc / "rust/lib/rustlib").iterdir() if (d / "lib").is_dir() and "solana" in d.name)
        raise SystemExit(f"{tc.name} ships no standard library for {triple}; it has: {', '.join(have)}")
    var = "CARGO_TARGET_" + triple.upper().replace("-", "_")
    rustc = find(tc, "rust/bin/rustc")
    cargo = find(tc, "rust/bin/cargo")
    lld = find(tc, "rust/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld") \
        if (tc / "rust/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld").exists() \
        else next(tc.glob("rust/lib/rustlib/*/bin/rust-lld"), None) or find(tc, "llvm/bin/ld.lld")
    objcopy = find(tc, "llvm/bin/llvm-objcopy")

    # Cargo executes the linker directly. Zip downloads do not preserve +x, so
    # write an executable launcher with a stable path inside the target/cache.
    launcher = (target if a.target_cache else out) / "capture-link.sh"
    tmp = launcher.with_name(f".{launcher.name}.{os.getpid()}")
    tmp.write_text(f'#!/bin/sh\nexec {shlex.quote(sys.executable)} -I '
                   f'{shlex.quote(str(HERE / "capture_link.py"))} "$@"\n')
    tmp.chmod(0o755)
    os.replace(tmp, launcher)

    # Start from a minimal environment: CARGO_PROFILE_* and user Cargo config
    # must not silently change a measured build. Workspace .cargo/config.toml
    # remains allowed because it is hashed as a source/configuration input.
    # Network settings (proxies, CA bundles) can't change what gets compiled, but
    # without them crate downloads fail on networks that need an explicit proxy.
    keep = ("PATH", "TMPDIR", "LANG", "LC_ALL", "LD_LIBRARY_PATH", "LIBRARY_PATH",
            "PKG_CONFIG_PATH", "PKG_CONFIG_SYSROOT_DIR", "SSL_CERT_FILE", "SSL_CERT_DIR",
            "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "all_proxy",
            "no_proxy", "CARGO_HTTP_PROXY", "CARGO_HTTP_CAINFO", "CARGO_HTTP_TIMEOUT", "CARGO_NET_RETRY")
    env = {k: os.environ[k] for k in keep if k in os.environ}
    (out / "home").mkdir()
    # One download cache for every build instead of a fresh, never-cleaned one
    # per run (without --vendor that re-downloaded every crate, ~300 MB, each try).
    cargo_home = a.cargo_home.expanduser().resolve()
    cargo_home.mkdir(parents=True, exist_ok=True)
    stray = [n for n in ("config", "config.toml", "credentials", "credentials.toml") if (cargo_home / n).exists()]
    if stray:
        raise SystemExit(f"{cargo_home} contains {', '.join(stray)}; solopen's Cargo home must hold no "
                         "configuration that could change a build — remove it or pass another --cargo-home")
    env.update({
        "HOME": str(out / "home"),
        "CARGO_HOME": str(cargo_home),
        "RUSTC": str(rustc),
        "RUSTDOC": str(tc / "rust/bin/rustdoc"),
        "PATH": str(tc / "rust/bin") + os.pathsep + str(tc / "llvm/bin") + os.pathsep + env.get("PATH", ""),
        "CC": str(tc / "llvm/bin/clang"),
        "AR": str(tc / "llvm/bin/llvm-ar"),
        "CARGO_INCREMENTAL": "0",
        "CARGO_TARGET_DIR": str(target),
        "CARGO_BUILD_JOBS": str(a.jobs),
        var + "_RUSTFLAGS": a.rustflags,
        var + "_LINKER": str(launcher),
        "SOLOPEN_REAL_LINKER": str(lld),
        "SOLOPEN_OBJCOPY": str(objcopy),
        "SOLOPEN_CAPTURE_DIR": str(out / "capture"),
        "SOLOPEN_PROGRAM": a.program,
    })
    cmd = [str(cargo), "build", "--release", "--target", triple, "--locked"]
    if a.vendor:
        cmd += ["--offline", "--config", "source.vendored-sources.directory=" + json.dumps(str(a.vendor.resolve())),
                "--config", 'source.crates-io.replace-with="vendored-sources"']
    if a.package:
        cmd += ["-p", a.package]
    if a.features:
        cmd += ["--features", a.features]
    (out / "command.json").write_text(json.dumps(dict(
        cwd=str(ws), command=cmd, rustflags=a.rustflags, toolchain=str(tc), target=triple,
        program=a.program, vendor=str(a.vendor.resolve()) if a.vendor else None,
        package=a.package, features=a.features, source_tree_sha256=source["tree_sha256"],
        target_cache=str(target) if a.target_cache else None, cargo_home=str(cargo_home)), indent=2) + "\n")
    print("building…", " ".join(cmd))
    with (out / "build.log").open("w") as log:
        rc = subprocess.run(cmd, cwd=ws, env=env, stdout=log, stderr=subprocess.STDOUT).returncode
    if not evidence.same_source(source, ws):
        raise SystemExit("source workspace changed during the build; refusing to bind evidence to an unstable tree")
    if not a.target_cache and not a.keep_target and (rc or not (out / "capture" / "baseline.unstripped.so").exists()):
        shutil.rmtree(target, ignore_errors=True)
    if rc:
        print((out / "build.log").read_text()[-4000:])
        raise SystemExit(f"build failed (exit {rc}); full log in {out/'build.log'}")
    base = out / "capture" / "baseline.unstripped.so"
    if not base.exists():
        raise SystemExit(f"build succeeded but no link of {a.program}.so was captured — check --program "
                         "(it must be the lib name, e.g. dao_v1 for crate dao-v1)")
    if not a.target_cache and not a.keep_target:
        shutil.rmtree(target, ignore_errors=True)
    print(f"ok — captured link in {out/'capture'}; unstripped program {base}")


if __name__ == "__main__":
    main()

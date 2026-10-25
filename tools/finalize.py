#!/usr/bin/env python3
"""Package a measured exact reconstruction as source, proof and review artifacts.

Refuses mismatched binaries, a missing source manifest, or a workspace that has
changed since the measured build. The original binary is copied only as release
comparison evidence, never into compilation or linking.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import zipfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
import compare as CMP
import evidence
import integrity
import security_review
import solopen

VERIFY = r'''#!/usr/bin/env python3
"""Independent receipt verifier: stdlib only; does not rebuild the program."""
import hashlib, json, sys, zipfile
from pathlib import Path
ROOT = Path(__file__).resolve().parent

def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def main():
    proof = json.loads((ROOT / "repro/final-proof.json").read_text())
    manifest = json.loads((ROOT / "repro/source-manifest.json").read_text())
    original = ROOT / "evidence/original.so"
    rebuilt = ROOT / "binaries/rebuilt.so"
    assert original.read_bytes() == rebuilt.read_bytes(), "binary files differ"
    assert sha(original) == proof["original_sha256"], "original hash differs"
    assert sha(rebuilt) == proof["rebuilt_sha256"], "rebuilt hash differs"
    assert sha(ROOT / "binaries/rebuilt.elf.so") == proof["elf_sha256"], "ELF hash differs"
    for row in manifest["files"]:
        path = ROOT / "source" / row["path"]
        assert path.stat().st_size == row["bytes"], f"source size differs: {row['path']}"
        assert sha(path) == row["sha256"], f"source hash differs: {row['path']}"
    assert sha(ROOT / "source-reconstruction.zip") == proof["source_zip_sha256"], "source zip differs"
    with zipfile.ZipFile(ROOT / "source-reconstruction.zip") as z:
        assert sorted(z.namelist()) == sorted("source/" + x["path"] for x in manifest["files"]), "zip file list differs"
    print(f"VERIFIED — {proof['bytes']} identical bytes; sha256 {proof['rebuilt_sha256']}")
    print(f"VERIFIED — {len(manifest['files'])} source files and deterministic source archive")
    print("Security status:", proof["security_review_status"])

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("VERIFICATION FAILED:", exc, file=sys.stderr)
        sys.exit(1)
'''


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + "\n")


def copy_source(workspace, manifest, out):
    for row in manifest["files"]:
        src = workspace / row["path"]
        dst = out / "source" / row["path"]
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(src.read_bytes())
    with zipfile.ZipFile(out / "source-reconstruction.zip", "w", zipfile.ZIP_STORED) as z:
        for row in sorted(manifest["files"], key=lambda x: x["path"]):
            info = zipfile.ZipInfo("source/" + row["path"], (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = 0o100644 << 16
            z.writestr(info, (workspace / row["path"]).read_bytes())


def independent_rebuild(args, command, out, original_path, measured_manifest):
    """Rebuild from the packaged source, never merely trust the supplied run."""
    packaged = out / "source"
    integrity.require_clean(packaged, original_path)
    with tempfile.TemporaryDirectory(prefix="solopen-finalize-") as tmp:
        attempt = Path(tmp) / "attempt"
        argv = ["--id", args.id, "--capture-root", str(args.capture_root),
                "--workspace", str(packaged), "--toolchain", str(command["toolchain"]),
                "--program", command["program"], "--run-dir", str(attempt), "--quiet"]
        if command.get("vendor"):
            argv += ["--vendor", str(command["vendor"])]
        if command.get("rustflags") is not None:
            argv += ["--rustflags=" + command["rustflags"]]
        if command.get("package"):
            argv += ["--package", command["package"]]
        if command.get("target"):
            argv += ["--target", command["target"]]
        if command.get("features"):
            argv += ["--features", command["features"]]
        rc = solopen.try_round(argv)
        rebuilt = attempt / "relinked" / "program.so"
        if rc != 0 or not rebuilt.exists():
            raise SystemExit("independent rebuild from packaged source failed or was not byte-identical")
        rebuilt_raw = rebuilt.read_bytes()
        original_raw = original_path.read_bytes()
        end = CMP.elf_end(rebuilt_raw) or len(rebuilt_raw)
        rebuilt_padded = rebuilt_raw[:end] + bytes(max(0, len(original_raw) - end))
        if len(rebuilt_padded) != len(original_raw) or rebuilt_padded != original_raw:
            raise SystemExit("packaged source did not reproduce the original during finalization")
        manifest = json.loads((attempt / "source-manifest.json").read_text())
        if manifest != measured_manifest:
            raise SystemExit("packaged source manifest changed during independent rebuild")
        receipt = out / "repro" / "reverification"
        receipt.mkdir(parents=True, exist_ok=True)
        for relative in ("source-manifest.json", "command.json", "build.log",
                         "order/order-mapping.json", "relinked/relink-report.json"):
            source = attempt / relative
            if source.exists():
                target = receipt / Path(relative).name
                shutil.copy2(source, target)
        return {"identical": True, "workspace": "source/",
                "source_tree_sha256": manifest["tree_sha256"],
                "receipt": "repro/reverification/"}


def finalize(args):
    workspace = args.workspace.resolve()
    run = args.run.resolve()
    out = args.out.resolve()
    original_path = args.capture_root / args.id / "program.so"
    capture_report_path = args.capture_root / args.id / "report.json"
    source_manifest_path = run / "source-manifest.json"
    command_path = run / "command.json"
    rebuilt_path = run / "relinked" / "program.so"
    for path in (original_path, source_manifest_path, command_path, rebuilt_path):
        if not path.exists():
            raise SystemExit(f"missing required evidence: {path}; rerun `solopen.py try` with this version")
    capture_report = json.loads(capture_report_path.read_text()) if capture_report_path.exists() else {}
    expected_sha = capture_report.get("program_so_sha256")
    if not expected_sha or sha256(original_path) != expected_sha:
        raise SystemExit("capture/program.so does not match program_so_sha256 in report.json")
    integrity.require_clean(workspace, original_path)
    if out.exists():
        raise SystemExit(f"output exists: {out}; use a fresh release directory")
    if out == workspace or workspace in out.parents:
        raise SystemExit("release output cannot be inside the measured source workspace")

    manifest = json.loads(source_manifest_path.read_text())
    paths = {row.get("path") for row in manifest.get("files", [])}
    if not any(x and x.endswith(".rs") for x in paths):
        raise SystemExit("source manifest contains no Rust source; refusing an empty recovery package")
    if "Cargo.lock" not in paths and not any(x and x.endswith("/Cargo.lock") for x in paths):
        raise SystemExit("Cargo.lock is missing from the measured source manifest; reproducibility requires pinned dependencies")
    command = json.loads(command_path.read_text())
    if command.get("target_cache"):
        raise SystemExit("this run reused a cached target dir (a search-loop build); rerun `solopen.py try` "
                         "without --target-cache and finalize that clean build")
    if Path(command.get("cwd", ".")).resolve() != workspace:
        raise SystemExit("the measured build used a different source workspace")
    if not evidence.same_source(manifest, workspace):
        raise SystemExit("workspace differs from the measured build; rerun `try` before finalizing")

    original = original_path.read_bytes()
    built = rebuilt_path.read_bytes()
    elf_end = CMP.elf_end(built) or len(built)
    elf = built[:elf_end]
    padded = elf + bytes(max(0, len(original) - len(elf)))
    if len(padded) != len(original) or padded != original:
        raise SystemExit("not byte-identical; finalization is blocked")

    inspection = {}
    if args.decompile and (args.decompile / "analysis.json").exists():
        inspection = json.loads((args.decompile / "analysis.json").read_text()).get("inspection", {})
    review = security_review.review(workspace, capture_report, inspection)
    security_status = "SUPPLIED_AUDIT_UNVALIDATED_BY_FINALIZER" if args.audit else review["status"]

    # Build the release in a staging folder and move it into place only once
    # everything (including the independent rebuild) has passed, so a failure
    # never leaves a half-written release that blocks the next attempt.
    final_out = out
    out = final_out.with_name(f".{final_out.name}.partial-{os.getpid()}")
    out.mkdir(parents=True)
    try:
        proof = _package(args, out, final_out, workspace, run, command, manifest, original, original_path,
                         elf, padded, capture_report, review, security_status)
    except BaseException:
        shutil.rmtree(out, ignore_errors=True)
        raise
    os.rename(out, final_out)
    print(f"MATCH verified and release packaged at {final_out}")
    print(f"  source: {len(manifest['files'])} files, tree {manifest['tree_sha256']}")
    print(f"  binary: {len(original):,} bytes, sha256 {proof['original_sha256']}")
    print(f"  security: {security_status}")
    print("  check: python3 verify_release.py")
    return proof


def _package(args, out, final_out, workspace, run, command, manifest, original, original_path,
             elf, padded, capture_report, review, security_status):
    paths = {row.get("path") for row in manifest.get("files", [])}
    for directory in ("source", "binaries", "evidence", "repro", "audit", "docs"):
        (out / directory).mkdir(exist_ok=True)
    copy_source(workspace, manifest, out)
    (out / "evidence/original.so").write_bytes(original)
    (out / "binaries/rebuilt.elf.so").write_bytes(elf)
    (out / "binaries/rebuilt.so").write_bytes(padded)
    save_json(out / "repro/source-manifest.json", manifest)
    save_json(out / "repro/build-command.json", command)
    shutil.copy2(run / "build.log", out / "repro/build.log") if (run / "build.log").exists() else None
    for source, name in ((run / "order/order-mapping.json", "order-mapping.json"),
                         (run / "relinked/relink-report.json", "relink-report.json")):
        if source.exists():
            shutil.copy2(source, out / "repro" / name)
    toolchain = Path(command.get("toolchain", ""))
    lock = toolchain.parent / f"{toolchain.name}.lock.json"
    if lock.exists():
        shutil.copy2(lock, out / "repro/toolchain-lock.json")
    vendor = command.get("vendor")
    if vendor and Path(vendor).is_dir():
        save_json(out / "repro/vendor-manifest.json", evidence.source_manifest(vendor))
    reverification = independent_rebuild(args, command, out, original_path, manifest)

    original_sha = hashlib.sha256(original).hexdigest()
    elf_sha = hashlib.sha256(elf).hexdigest()
    cargo_text = "\n".join((workspace / p).read_text(errors="replace") for p in paths
                           if p and p.endswith("Cargo.toml"))
    proof = {
        "schema_version": 1, "program_id": args.id,
        "source_framework": "Anchor/Rust" if "anchor-lang" in cargo_text else "Rust (Anchor not detected)",
        "cmp_exit_code": 0, "clean_rebuild_identical": True,
        "independent_finalize_comparison": True,
        "packaged_source_rebuild_identical": True,
        "reverification": reverification,
        "source_tree_matches_measured_build": True,
        "source_tree_sha256": manifest["tree_sha256"],
        "source_zip_sha256": sha256(out / "source-reconstruction.zip"),
        "original_sha256": original_sha, "rebuilt_sha256": hashlib.sha256(padded).hexdigest(),
        "elf_sha256": elf_sha, "bytes": len(original), "elf_bytes": len(elf),
        "generated_zero_padding_bytes": len(original) - len(elf),
        "capture_slot": capture_report.get("slot"),
        "last_deploy_slot": capture_report.get("last_deploy_slot"),
        "upgrade_authority_at_capture": capture_report.get("upgrade_authority"),
        "security_review_status": security_status,
        "original_historical_configuration_uniquely_established": False,
        "note": "This source builds these bytes. Historical identifiers, comments and build configuration are not uniquely established.",
    }
    save_json(out / "repro/final-proof.json", proof)
    save_json(out / "audit/automated-security-review.json", review)
    if args.audit:
        shutil.copy2(args.audit, out / "audit/AUDIT.md")
    else:
        (out / "audit/AUDIT.md").write_text(security_review.audit_markdown(review, args.id, original_sha))
    if args.scope:
        shutil.copy2(args.scope, out / "docs/SECURITY_SCOPE.md")
    else:
        (out / "docs/SECURITY_SCOPE.md").write_text(security_review.scope_markdown(review, args.id))
    (out / "verify_release.py").write_text(VERIFY)

    program = command.get("program") or "<PROGRAM_LIB_NAME>"
    toolchain_text = str(toolchain) or "<PLATFORM_TOOLS_DIR>"
    vendor_line = f" --vendor {vendor}" if vendor else ""
    build_doc = f"""# Reproduce the exact binary

The `source/` tree is the measured Anchor/Rust reconstruction. Dependencies are pinned by its lockfile.
A normal `anchor build` does not apply recovered linker ordering. Use solopen's complete loop:

```sh
mkdir -p capture/{args.id}
cp evidence/original.so capture/{args.id}/program.so
python3 solopen.py try --id {args.id} --workspace source \\
  --toolchain {toolchain_text} --program {program}{vendor_line}
```

Use Linux x86-64, the same official platform-tools release, and the locked dependency set. If
`repro/toolchain-lock.json` or `repro/vendor-manifest.json` is present, check those inputs before
building. Start with no target cache and never format span-sensitive Rust source.

`repro/final-proof.json` binds the source manifest to the measured run. `repro/build-command.json`,
`build.log`, `order-mapping.json` and `relink-report.json` retain the recipe and layout evidence.

## Check this published package

```sh
python3 verify_release.py
```

That checks whole-file binary equality, all hashes, every published source file and the deterministic
source archive. It does not replace a fresh rebuild. Original bytes are comparison evidence only.
"""
    (out / "docs/BUILD.md").write_text(build_doc)
    delivery = f"""# Reconstruction delivery record

Target: `{args.id}`

- Anchor/Rust source: `source/` and `source-reconstruction.zip`
- Rebuilt ELF: `binaries/rebuilt.elf.so` ({len(elf):,} bytes, sha256 `{elf_sha}`)
- Rebuilt account-padded binary: `binaries/rebuilt.so` ({len(padded):,} bytes)
- Original comparison capture: `evidence/original.so`
- Full SHA-256: `{original_sha}`
- Generated zero allocation padding: {len(original) - len(elf):,} bytes
- Source tree: `{manifest['tree_sha256']}` across {len(manifest['files'])} files
- Security status: **{security_status}**

The finalizer independently compared the complete original and rebuilt payloads and verified that
the published source tree is unchanged from the measured build. This proves this source builds these
bytes, not the author's unique historical source. A supplied audit is packaged but not independently
validated by the finalizer. An automated pre-review is not a completed security audit.
"""
    (out / "docs/DELIVERY.md").write_text(delivery)
    return proof


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--id", required=True)
    ap.add_argument("--capture-root", type=Path, default=Path("capture"))
    ap.add_argument("--workspace", required=True, type=Path)
    ap.add_argument("--run", required=True, type=Path, help="successful try/attempt directory")
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--decompile", type=Path, default=None)
    ap.add_argument("--audit", type=Path, default=None, help="optional completed audit Markdown to package")
    ap.add_argument("--scope", type=Path, default=None, help="optional completed security scope Markdown")
    args = ap.parse_args()
    finalize(args)


if __name__ == "__main__":
    main()

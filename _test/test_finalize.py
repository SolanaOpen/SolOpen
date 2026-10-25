"""Offline tests for source binding, release proof and security scope."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "tools"))
import evidence
import finalize
import integrity
import security_review


class EvidenceTests(unittest.TestCase):
    def test_manifest_is_deterministic_and_detects_changes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "src").mkdir()
            (root / "src/lib.rs").write_text("pub fn x() {}\n")
            first = evidence.source_manifest(root)
            second = evidence.source_manifest(root)
            self.assertEqual(first, second)
            self.assertTrue(evidence.same_source(first, root))
            (root / "src/lib.rs").write_text("pub fn y() {}\n")
            self.assertFalse(evidence.same_source(first, root))


def successful_rebuild(_args, _command, out, _original, manifest):
    """Unit-test the packaging contract without invoking a real compiler."""
    assert (out / "source/Cargo.lock").exists()
    return {"identical": True, "workspace": "source/",
            "source_tree_sha256": manifest["tree_sha256"], "receipt": "repro/reverification/"}


class FinalizeTests(unittest.TestCase):
    def make_case(self, root):
        workspace = root / "workspace"
        source = workspace / "programs/demo/src"
        source.mkdir(parents=True)
        (source / "lib.rs").write_text(
            "use anchor_lang::prelude::*;\n"
            "pub struct X<'info> { pool: UncheckedAccount<'info> }\n"
            "pub fn x() { invoke_signed(&todo!(), &[], &[]).unwrap(); }\n")
        (workspace / "Cargo.toml").write_text('[workspace]\nmembers = ["programs/demo"]\n')
        (workspace / "Cargo.lock").write_text('# test lockfile\n')
        (workspace / "programs/demo/Cargo.toml").write_text('[package]\nname = "demo"\n')
        original = root / "capture/test-id"
        original.mkdir(parents=True)
        payload = b"test deployed binary\x00\x00"
        (original / "program.so").write_bytes(payload)
        (original / "report.json").write_text(json.dumps({
            "program_id": "test-id", "slot": 123,
            "program_so_sha256": __import__("hashlib").sha256(payload).hexdigest(),
            "upgrade_authority": {"kind": "none", "address": None}}))
        run = root / "run"
        (run / "relinked").mkdir(parents=True)
        (run / "relinked/program.so").write_bytes(payload)
        (run / "relinked/relink-report.json").write_text('{"identical":true}')
        (run / "build.log").write_text("clean build\n")
        manifest = evidence.source_manifest(workspace)
        (run / "source-manifest.json").write_text(json.dumps(manifest))
        (run / "command.json").write_text(json.dumps({
            "cwd": str(workspace), "command": ["cargo", "build"],
            "toolchain": str(root / "platform-tools-v1"), "program": "demo",
            "vendor": None, "rustflags": ""}))
        return workspace, run, original

    def args(self, root, workspace, run, out):
        return SimpleNamespace(id="test-id", capture_root=root / "capture",
                               workspace=workspace, run=run, out=out,
                               decompile=None, audit=None, scope=None)

    def test_exact_release_is_self_checking(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workspace, run, _ = self.make_case(root)
            out = root / "release"
            with mock.patch("finalize.independent_rebuild", side_effect=successful_rebuild) as rebuild:
                proof = finalize.finalize(self.args(root, workspace, run, out))
            rebuild.assert_called_once()
            self.assertTrue(proof["clean_rebuild_identical"])
            self.assertEqual(proof["security_review_status"], "MANUAL_SECURITY_REVIEW_REQUIRED")
            audit = (out / "audit/AUDIT.md").read_text()
            self.assertIn("UNCONFIRMED", audit)
            self.assertNotIn("program is secure", audit)
            result = subprocess.run([sys.executable, str(out / "verify_release.py")],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("VERIFIED", result.stdout)

    def test_changed_source_and_mismatch_are_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workspace, run, _ = self.make_case(root)
            (workspace / "programs/demo/src/lib.rs").write_text("// changed after build\n")
            with self.assertRaises(SystemExit):
                finalize.finalize(self.args(root, workspace, run, root / "bad-release"))

    def test_cached_run_is_not_finalizable(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workspace, run, _ = self.make_case(root)
            command = json.loads((run / "command.json").read_text())
            command["target_cache"] = str(root / "cache")
            (run / "command.json").write_text(json.dumps(command))
            with self.assertRaisesRegex(SystemExit, "cached target"):
                finalize.finalize(self.args(root, workspace, run, root / "release"))

    def test_failed_packaged_source_rebuild_is_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workspace, run, _ = self.make_case(root)
            with mock.patch("finalize.independent_rebuild", side_effect=SystemExit("rebuild mismatch")):
                with self.assertRaisesRegex(SystemExit, "rebuild mismatch"):
                    finalize.finalize(self.args(root, workspace, run, root / "release"))
            # nothing half-written is left behind to block the next attempt
            self.assertFalse((root / "release").exists())
            self.assertEqual([p.name for p in root.iterdir() if "partial" in p.name], [])

    def test_manifest_and_integrity_cover_smuggling_channels(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "src/build").mkdir(parents=True)
            (root / "src/build/mod.rs").write_text("pub fn nested() {}\n")
            (root / "payload.custom").write_bytes(b"build input")
            manifest = evidence.source_manifest(root)
            paths = {x["path"] for x in manifest["files"]}
            self.assertIn("src/build/mod.rs", paths)
            self.assertIn("payload.custom", paths)
            (root / "src/build/mod.rs").write_text('include_bytes!("../../capture/x/program.so");')
            original = root / "original.so"
            original.write_bytes(b"A" * 96)
            with self.assertRaises(SystemExit):
                integrity.require_clean(root, original)

    def test_integrity_rejects_alias_and_arch_smuggling(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            original = root / "original.so"
            original.write_bytes(b"B" * 96)
            for code in (
                'use core::arch::global_asm as g; g!(".incbin \\"p.so\\"");',
                'use core::include_bytes as ib; ib!("p.so");',
                'core::arch::asm!("mov r0, r0");',
            ):
                (root / "lib.rs").write_text(code)
                with self.assertRaises(SystemExit):
                    integrity.require_clean(root, original)

    def test_integrity_allows_ordinary_cfg_feature_gates(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "src").mkdir()
            (root / "src/entrypoint.rs").write_text(
                '#![cfg(all(target_os = "solana", not(feature = "no-entrypoint")))]\nuse solana_program::entrypoint;\n')
            self.assertEqual(integrity.violations(root), [])
            (root / "src/lib.rs").write_text("#![feature(asm_experimental_arch)]\n")
            self.assertTrue(integrity.violations(root))

    def test_fetch_recognizes_real_loader_ids(self):
        import fetch
        for loader in fetch.LOADERS:
            self.assertEqual(len(fetch.base58_decode(loader)), 32, loader)
        self.assertIn("BPFLoaderUpgradeab1e11111111111111111111111", fetch.LOADERS)

    def test_fetch_keeps_the_program_when_block_time_is_pruned(self):
        import base64, struct
        from unittest import mock
        import fetch
        pid = "4FqThZWv3QKWkSyXCDmATpWkpEiCHq5yhkdGWpSEDAZM"
        pd_key = bytes(range(1, 33))
        elf = b"\x7fELF" + bytes(60)
        program = {"owner": fetch.UPGRADEABLE_LOADER, "executable": True,
                   "data": [base64.b64encode(struct.pack("<I", 2) + pd_key).decode(), "base64"]}
        # No authority: option byte 0, but the 32 authority bytes are still
        # reserved — the ELF starts at byte 45 either way.
        programdata = {"owner": fetch.UPGRADEABLE_LOADER, "executable": False,
                       "data": [base64.b64encode(struct.pack("<IQB", 3, 370107442, 0) + bytes(32) + elf).decode(), "base64"]}
        calls = []
        def fake_rpc(url, method, params, tries=5):
            calls.append(method)
            if method == "getAccountInfo":
                key = params[0]
                value = program if key == pid else programdata if key == fetch.base58_encode(pd_key) else None
                return {"context": {"slot": 460000000}, "value": value}
            if method == "getMultipleAccounts":
                return {"context": {"slot": 460000001},
                        "value": [program if k == pid else programdata for k in params[0]]}
            if method == "getBlockTime":
                raise fetch.RPCError("Block 370107442 cleaned up, does not exist on node")
            raise AssertionError(method)
        with tempfile.TemporaryDirectory() as td, \
                mock.patch.object(fetch, "rpc", fake_rpc), mock.patch.object(fetch, "fetch_idl", lambda *a: {}), \
                mock.patch.object(fetch, "ottersec_status", lambda *a: {}):
            rep = fetch.fetch_program("http://rpc", pid, td)
            self.assertEqual(Path(td, "program.so").read_bytes(), elf)
        self.assertIsNone(rep["last_deploy_utc"])
        self.assertIn("cleaned up", rep["block_time_error"])
        self.assertEqual(rep["upgrade_authority"]["address"], None)
        self.assertEqual(calls.count("getBlockTime"), 1)
        self.assertEqual(rep["slot"], 460000001)   # both accounts from one snapshot

    def test_static_review_never_confirms_pattern_findings(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "lib.rs").write_text("fn x(a: UncheckedAccount) { invoke(&a).unwrap(); }\n")
            report = security_review.review(root)
            self.assertEqual(report["confirmed_findings"], [])
            self.assertGreaterEqual(len(report["review_leads"]), 2)
            self.assertTrue(all(x["status"] == "UNCONFIRMED_REVIEW_LEAD" for x in report["review_leads"]))


if __name__ == "__main__":
    unittest.main()

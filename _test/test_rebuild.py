"""Offline tests for AI response validation, rollback and scoring."""
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest import mock
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "tools"))
import rebuild


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers["Content-Length"])
        request = json.loads(self.rfile.read(length))
        assert request["model"] == "test-model"
        body = json.dumps({"choices": [{"message": {"content": '{"summary":"ok","edits":[]}'}}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class RebuildTests(unittest.TestCase):
    def test_response_parser(self):
        value = rebuild.parse_response('```json\n{"summary":"x","edits":[]}\n```')
        self.assertEqual(value["summary"], "x")
        with self.assertRaises(ValueError):
            rebuild.parse_response('{"summary":"missing edits"}')

    def test_edits_are_confined_and_atomic(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            original = root / "lib.rs"
            original.write_text("old\n")
            with self.assertRaises(ValueError):
                rebuild.apply_edits(root, [{"path": "../outside.rs", "content": "bad"}])
            self.assertEqual(original.read_text(), "old\n")
            with self.assertRaises(ValueError):
                rebuild.apply_edits(root, [
                    {"path": "lib.rs", "content": "temporarily changed"},
                    {"path": "bad.exe", "content": "not allowed"},
                ])
            self.assertEqual(original.read_text(), "old\n")
            backup = rebuild.apply_edits(root, [{"path": "src/new.rs", "content": "new\n"}])
            self.assertEqual((root / "src" / "new.rs").read_text(), "new\n")
            rebuild.rollback(backup)
            self.assertFalse((root / "src" / "new.rs").exists())

    def test_regressions_never_outrank_improvements(self):
        failed = {"built": False, "identical": False}
        built = {"built": True, "identical": False, "coverage_pct": 20,
                 "unmatched": 10, "uncovered_ranges": 5, "differing_bytes": 100}
        better = dict(built, coverage_pct=21)
        exact = dict(built, identical=True, coverage_pct=1)
        self.assertGreater(rebuild.rank(built), rebuild.rank(failed))
        self.assertGreater(rebuild.rank(better), rebuild.rank(built))
        self.assertGreater(rebuild.rank(exact), rebuild.rank(better))

    def test_build_status_and_key_routing(self):
        with tempfile.TemporaryDirectory() as td:
            run = Path(td)
            (run / "capture").mkdir()
            (run / "capture/baseline.unstripped.so").write_bytes(b"built")
            result = rebuild.trial_result(run)
            self.assertTrue(result["built"])
            self.assertFalse(result["ordered"])
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "openai", "MOONSHOT_API_KEY": "moon"}):
            os.environ.pop("SOLOPEN_AI_API_KEY", None)      # restored by patch.dict on exit
            self.assertEqual(rebuild.api_key_for("https://api.openai.com/v1"), "openai")
            self.assertEqual(rebuild.api_key_for("https://api.moonshot.ai/v1"), "moon")
            self.assertIsNone(rebuild.api_key_for("http://localhost:8000/v1"))

    def test_prompt_has_rejections_and_overall_budget(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "lib.rs").write_text("pub fn current() {}\n")
            args = SimpleNamespace(id="id", workspace=root)
            target = {
                "name": "current", "your_size": 32, "original_size": 40,
                "distance": 2, "evidence": [{"kind": "called-by", "detail": "main"}],
                "panic_sites_original": [], "panic_sites_yours": [],
                "source_file": "lib.rs", "kind": "code", "missing_callees": [],
                "unmatched_callees": [],
            }
            history = [{"attempt": 1, "summary": "bad proposal", "outcome": "rejected",
                        "error": "rejected compiler error"}]
            prompt = rebuild.make_prompt(args, target, "- old\n+ new", history, 8000)
            self.assertIn("bad proposal", prompt)
            self.assertIn("rejected compiler error", prompt)
            self.assertIn("=== lib.rs ===", prompt)
            self.assertIn("pub fn current", prompt)

    def test_replace_edits_are_exact_and_all_or_nothing(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "a.rs").write_text("fn a() { 1 + 1 }\n")
            (root / "b.rs").write_text("fn b() {}\nfn b() {}\n")
            backup = rebuild.apply_edits(root, [{"path": "a.rs", "replace": [{"old": "1 + 1", "new": "2"}]}])
            self.assertEqual((root / "a.rs").read_text(), "fn a() { 2 }\n")
            rebuild.rollback(backup)
            self.assertEqual((root / "a.rs").read_text(), "fn a() { 1 + 1 }\n")
            with self.assertRaises(ValueError):    # ambiguous old text in b.rs: nothing is applied
                rebuild.apply_edits(root, [{"path": "a.rs", "replace": [{"old": "1 + 1", "new": "2"}]},
                                           {"path": "b.rs", "replace": [{"old": "fn b() {}", "new": "x"}]}])
            self.assertEqual((root / "a.rs").read_text(), "fn a() { 1 + 1 }\n")

    def test_edits_cannot_smuggle_bytes_or_leave_source(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "lib.rs").write_text("fn x() {}\n")
            bad = ['static B: &[u8] = include_bytes!("../capture/x/program.so");',
                   'core::arch::global_asm!(".byte 0x95");', "#![feature(asm_experimental_arch)]",
                   'include_bytes !("p.so")', 'use core::include_bytes as ib; const B: &[u8] = ib!("p.so");',
                   'use core::arch::global_asm as g; g!(".incbin \\"p.so\\"");',
                   "#![cfg_attr(all(), feature(x))]", "# ! [feature(x)]",
                   '#[link_section = ".text"] static X: [u8; 4] = [0; 4];']
            for text in bad:
                with self.assertRaises(ValueError):
                    rebuild.apply_edits(root, [{"path": "lib.rs", "content": text}])
            for path in ("build.rs", "Cargo.toml", ".cargo/config.toml", "vendor/x/src/lib.rs", "Cargo.lock",
                         "docs/x.rs", "evidence/x.rs", "build/x.rs"):   # not covered by the source manifest
                with self.assertRaises(ValueError):
                    rebuild.apply_edits(root, [{"path": path, "content": "x"}])
            self.assertEqual((root / "lib.rs").read_text(), "fn x() {}\n")

    def test_existing_forbidden_construct_does_not_license_more(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "lib.rs").write_text('#![doc = include_str!("README.md")]\nfn x() {}\n')
            with self.assertRaises(ValueError):
                rebuild.apply_edits(root, [{"path": "lib.rs", "replace": [
                    {"old": "fn x() {}", "new": 'const B: &[u8] = include_bytes!("p.so");'}]}])
            rebuild.apply_edits(root, [{"path": "lib.rs", "replace": [{"old": "fn x() {}", "new": "fn y() {}"}]}])

    def test_regressions_see_constants_and_full_symbols(self):
        import json
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            def run(name, symbols):
                d = root / name / "order"; d.mkdir(parents=True)
                (d / "order-mapping.json").write_text(json.dumps({"rows": [{"symbol": s} for s in symbols]}))
                return root / name
            a1 = "_ZN3foo3bar17h0000000000000001E"; a2 = "_ZN3foo3bar17h0000000000000002E"
            before, after = run("b", [a1, a2]), run("a", [a2, "_ZN3foo3baz17h0000000000000003E"])
            # one generic instance of foo::bar lost while an unrelated function started matching
            self.assertEqual(rebuild.regressions(before, after), ["foo::bar"])
            # a function whose code still matches but now loads different constants
            old_t = {"targets": [{"original_offset": 8, "kind": "code", "name": "t"}]}
            new_t = {"targets": [{"original_offset": 8, "kind": "code", "name": "t"},
                                 {"original_offset": 64, "kind": "data", "name": "foo::later"}]}
            lost = rebuild.regressions(before, before, old_t, new_t, current_offset=8)
            self.assertEqual(lost, ["foo::later (now loads different constants)"])

    def test_target_status_is_about_this_function(self):
        mapping = {"rows": [{"original": 0x100, "symbol": "_ZN3foo1g17h0000000000000001E"}]}
        self.assertEqual(rebuild.target_status({"targets": []}, mapping, "foo::f", 0x100), (False, None))
        self.assertEqual(rebuild.target_status({"targets": []}, mapping, "foo::g", 0x100), (True, 0))
        other = {"targets": [{"name": "foo::g", "original_offset": 0x200, "distance": 5}]}
        self.assertEqual(rebuild.target_status(other, {}, "foo::f", 0x200), (False, None))

    def test_bad_paths_are_rejections_not_crashes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "lib.rs").write_text("x\n")
            (root / "d.rs").mkdir()
            for path in ("lib.rs/x.rs", "d.rs", "a" * 300 + ".rs"):
                with self.assertRaises((ValueError, OSError)):
                    rebuild.apply_edits(root, [{"path": path, "content": "fn x() {}"}])

    def test_cfg_feature_predicate_is_not_an_unstable_feature(self):
        gate = '#![cfg(all(target_os = "solana", not(feature = "no-entrypoint")))]\n'
        self.assertEqual(rebuild.provenance_problems("entrypoint.rs", gate), [])
        self.assertTrue(rebuild.provenance_problems("lib.rs", "#![feature(asm_experimental_arch)]\n"))

    def test_only_targets_with_source_here_are_workable(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / "src").mkdir()
            (ws / "src/lib.rs").write_text("fn f() {}\n")
            generic = {"source_file": None, "panic_sites_original": []}
            mine = {"source_file": None, "panic_sites_original": ["src/lib.rs:3:9", "library/core/src/fmt/mod.rs:1:1"]}
            self.assertEqual(rebuild.editable_files(ws, generic), [])
            self.assertEqual(rebuild.editable_files(ws, mine), ["src/lib.rs"])

    def test_drops_temperature_when_the_model_refuses_it(self):
        seen = []

        class NoTemperature(Handler):
            def do_POST(self):
                request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                seen.append("temperature" in request)
                if "temperature" in request:
                    status, body = 400, b'{"error":{"message":"`temperature` is deprecated for this model."}}'
                else:
                    status, body = 200, json.dumps({"choices": [{"message": {"content": '{"edits":[]}'}}]}).encode()
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        server = HTTPServer(("127.0.0.1", 0), NoTemperature)
        thread = threading.Thread(target=lambda: [server.handle_request() for _ in range(3)], daemon=True)
        thread.start()
        try:
            client = rebuild.AIClient(f"http://127.0.0.1:{server.server_port}/v1", "test-model")
            self.assertIn('"edits":[]', client.complete("prompt"))
            self.assertIn('"edits":[]', client.complete("again"))   # remembered: no second refusal
            self.assertEqual(seen, [True, False, False])
        finally:
            thread.join(timeout=2)
            server.server_close()

    def test_openai_compatible_client(self):
        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()
        try:
            client = rebuild.AIClient(f"http://127.0.0.1:{server.server_port}/v1", "test-model")
            self.assertIn('"edits":[]', client.complete("prompt"))
        finally:
            thread.join(timeout=2)
            server.server_close()


if __name__ == "__main__":
    unittest.main()

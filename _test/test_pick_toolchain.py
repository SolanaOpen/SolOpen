"""Offline tests for automatic platform-tools selection (no network, no toolchains)."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "tools"))
import pick_toolchain as P
import toolchain as T
import shutil
REAL_RMTREE = shutil.rmtree


class FakeSource:
    def __init__(self, files):
        self.files = files

    def show(self, tag, path):
        return self.files.get((tag, path))


class PickTests(unittest.TestCase):
    def test_build_script_names_the_rust_tag(self):
        script = (b"#!/bin/bash\nset -ex\n"
                  b"git clone --single-branch --branch solana-tools-v1.44 --recurse-submodules "
                  b"--shallow-submodules https://github.com/anza-xyz/rust.git\n"
                  b"git clone --single-branch --branch solana-tools-v1.44 https://github.com/anza-xyz/cargo.git\n")
        with mock.patch.object(P, "git", lambda *a, **k: SimpleNamespace(returncode=0, stdout=script)):
            self.assertEqual(P.rust_tag(Path("."), "1.44"),
                             ("https://github.com/anza-xyz/rust", "solana-tools-v1.44"))

    def test_coordinates_must_land_on_code(self):
        src = FakeSource({("t", "library/core/src/a.rs"): b"fn x() {\n    // note\n    foo.unwrap();\n"})
        locs = [("library/core/src/a.rs", 22, 3, 5),       # `foo` — plausible
                ("/build/rust/library/core/src/a.rs", 34, 2, 5),   # a comment line
                ("library/core/src/a.rs", 22, 9, 1),       # past the end of the file
                ("library/alloc/src/gone.rs", 26, 1, 1)]   # file not in this release
        self.assertEqual(P.coordinate_fit(src, "t", locs), (3, 1))

    def test_shortlist_keeps_releases_that_fit_equally(self):
        cands = [dict(version="1.42", files=27, plausible=21), dict(version="1.43", files=27, plausible=27),
                 dict(version="1.44", files=27, plausible=27), dict(version="1.47", files=17, plausible=7),
                 dict(version="1.46.1", files=27, plausible=26)]
        short, strength = P.shortlist(cands, 27)
        self.assertEqual([r["version"] for r in short], ["1.44", "1.43", "1.46.1"])
        self.assertEqual(strength, "strong")
        short, strength = P.shortlist([dict(version="1.9"), dict(version="1.10")], 0)
        self.assertEqual(([r["version"] for r in short], strength), (["1.10", "1.9"], "none"))

    def test_releases_after_the_deploy_cannot_have_built_it(self):
        with tempfile.TemporaryDirectory() as td:
            rep = Path(td) / "report.json"
            rep.write_text(json.dumps({"last_deploy_utc": "2026-05-13T12:39:34Z"}))
            t, why = P.deploy_bound(Path(td) / "program.so")
            self.assertEqual(time_str(t), "2026-05-13")
            self.assertIn("2026-05-13", why)
            rep.write_text(json.dumps({"last_deploy_utc": None, "last_deploy_slot": 1000,
                                       "slot": 1000 + 86400 * 10 * 10 // 4, "fetched_utc": "2026-10-25T00:00:00Z"}))
            t, why = P.deploy_bound(Path(td) / "program.so")
            # ten days of slots at 0.4 s, plus two weeks of slack
            self.assertEqual(time_str(t), "2026-10-29")
            self.assertIn("estimated", why)

    def test_saved_choice_is_reused_only_for_the_same_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            so = Path(td) / "program.so"
            so.write_bytes(b"one")
            import hashlib
            (Path(td) / "toolchain.json").write_text(json.dumps(dict(
                release="1.44", target="sbpf-solana-solana", confidence="high",
                original_sha256=hashlib.sha256(b"one").hexdigest())))
            with mock.patch.object(T, "install", lambda v, log=None: Path("/tc/platform-tools-v" + v)), \
                    mock.patch.object(P, "pick", side_effect=AssertionError("should not re-detect")):
                self.assertEqual(P.ensure(so, log=lambda m: None),
                                 (Path("/tc/platform-tools-v1.44"), "sbpf-solana-solana"))
            so.write_bytes(b"two")
            with mock.patch.object(P, "pick", return_value=dict(toolchain="/tc/x", target=None)) as picked:
                P.ensure(so, log=lambda m: None)
            picked.assert_called_once()

    def test_explicit_toolchain_wins(self):
        with mock.patch.object(T, "install", lambda v, log=None: Path("/tc/v" + v)):
            self.assertEqual(P.resolve_for("1.46.1", Path("/nope")), (Path("/tc/v1.46.1"), None))
        with self.assertRaises(SystemExit):
            P.resolve_for(None, Path("/definitely/missing/program.so"))


class ClimbTests(unittest.TestCase):
    """The canary stage downloads only the leader's neighbours."""

    def run_pick(self, versions, plausible, helpers, cached=()):
        installs, removed = [], []
        rels = [dict(version=v, published=None, has_asset=None) for v in versions]

        def fake_fp(tc, triple):
            return dict(release=tc.name.split("-v")[-1], name=tc.name, target=triple)

        def fake_rank(orig, fps):
            rows = [dict(release=fp["release"], name=fp["name"], target=fp["target"], header_matches=True,
                         stdlib=dict(missing_paths=[], location_hits=1),
                         helpers=dict(discriminating_found=helpers[fp["release"]], raw_exact=0)) for fp in fps]
            rows.sort(key=P.C.score, reverse=True)
            return rows, "verdict"

        def fake_install(v, log=None):
            installs.append(v)
            d = Path(self.td) / f"platform-tools-v{v}"
            d.mkdir(exist_ok=True)
            return d

        cache = {(f"platform-tools-v{v}", "sbpf-solana-solana"):
                 dict(release=v, name=f"platform-tools-v{v}", target="sbpf-solana-solana") for v in cached}
        with mock.patch.object(P, "list_releases", lambda log: (rels, Path("."))), \
                mock.patch.object(P, "deploy_bound", lambda o: (None, "no report")), \
                mock.patch.object(P, "rust_tag", lambda repo, v: ("https://github.com/x/rust", "t" + v)), \
                mock.patch.object(P, "RustSource", lambda url: None), \
                mock.patch.object(P, "coordinate_fit", lambda src, tag, locs: (3, plausible[tag[1:]])), \
                mock.patch.object(P.C, "analyze_original", lambda raw: dict(version=0, std_locs=[("library/x.rs", 1, 1, 1)] * 3)), \
                mock.patch.object(P.C, "cached_fingerprints", lambda: cache), \
                mock.patch.object(P, "fp_still_valid", lambda fp: True), \
                mock.patch.object(P.C, "targets_of", lambda tc, version=0: ["sbpf-solana-solana"]), \
                mock.patch.object(P.C, "fingerprint", fake_fp), \
                mock.patch.object(P.C, "rank", fake_rank), \
                mock.patch.object(P.C, "print_table", lambda *a: None), \
                mock.patch.object(P.T, "install", fake_install), \
                mock.patch.object(P.T, "default_dest", lambda v: Path(self.td) / f"platform-tools-v{v}"), \
                mock.patch.object(P.shutil, "rmtree",
                                  lambda d, ignore_errors=False: (removed.append(Path(d).name), REAL_RMTREE(d))):
            so = Path(self.td) / "program.so"
            so.write_bytes(b"x")
            res = P.pick(so, log=lambda m: None)
        return res, installs, removed

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.td = self._td.name

    def tearDown(self):
        self._td.cleanup()

    def test_climbs_through_a_rust_version_block(self):
        versions = ["1.42", "1.43", "1.44", "1.45", "1.46", "1.46.1", "1.47"]
        plausible = {"1.42": 1, "1.43": 3, "1.44": 3, "1.45": 3, "1.46": 3, "1.46.1": 3, "1.47": 0}
        helpers = {"1.43": 5, "1.44": 47, "1.45": 16, "1.46": 15, "1.46.1": 15}
        res, installs, removed = self.run_pick(versions, plausible, helpers)
        self.assertEqual(res["release"], "1.44")
        self.assertEqual(installs[:5], ["1.46.1", "1.46", "1.45", "1.44", "1.43"])
        self.assertNotIn("1.42", installs)
        self.assertNotIn("platform-tools-v1.44", removed)

    def test_cached_leader_needs_only_its_neighbours(self):
        versions = ["1.50", "1.51", "1.52", "1.53", "1.54"]
        plausible = dict.fromkeys(versions, 3)
        helpers = {"1.50": 5, "1.51": 5, "1.52": 6, "1.53": 6, "1.54": 17}
        res, installs, removed = self.run_pick(versions, plausible, helpers, cached=["1.54"])
        self.assertEqual(res["release"], "1.54")
        self.assertEqual(installs, ["1.53", "1.54"])     # one neighbour, then the winner itself
        self.assertEqual(removed, ["platform-tools-v1.53"])


def time_str(t):
    import time
    return time.strftime("%Y-%m-%d", time.gmtime(t))


if __name__ == "__main__":
    unittest.main()

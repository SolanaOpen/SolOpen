"""Offline tests for compiler calibration (no toolchain needed)."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "tools"))
import calibrate


def image(rodata_addr, rodata, rel_addr, rel, relative):
    return dict(text_addr=0x120, text_size=0, relative=relative,
                data=[(".rodata", rodata_addr, len(rodata), rodata),
                      (".data.rel.ro", rel_addr, len(rel), rel)])


class CalibrateTests(unittest.TestCase):
    def test_hash_suffix_is_ignored_between_builds(self):
        self.assertEqual(calibrate.strip_hash("_ZN4core3fmt5write17h0123456789abcdefE"),
                         calibrate.strip_hash("_ZN4core3fmt5write17hfedcba9876543210E"))

    def test_body_must_start_on_an_instruction(self):
        text = bytes(4) + bytes(range(1, 17)) + bytes(4)
        body = bytes(range(1, 17))
        self.assertEqual(calibrate.find_body(text, text, body, body), (False, False))
        text = bytes(8) + body
        self.assertEqual(calibrate.find_body(text, text, body, body), (True, True))

    def test_panic_locations_with_and_without_trailing_nul(self):
        path = b"library/alloc/src/raw_vec.rs"
        rodata = path + b"\0" + bytes(3) + b"programs/x/src/lib.rs"
        loc = lambda p, n, line, col: struct.pack("<QQII", p << 32, n, line, col)
        rel = loc(0x1000, len(path) + 1, 25, 5) + loc(0x1000 + 32, 21, 7, 9)
        img = image(0x1000, rodata, 0x2000, rel, {0x2000, 0x2018})
        with mock.patch.object(calibrate.LO, "image_of", lambda b: img):
            got = calibrate.panic_locations(b"")
        self.assertEqual(got, {("library/alloc/src/raw_vec.rs", len(path) + 1, 25, 5),
                               ("programs/x/src/lib.rs", 21, 7, 9)})

    def test_stdlib_check_needs_paths_and_coordinates(self):
        orig = dict(paths=["library/alloc/src/raw_vec.rs", "library/alloc/src/raw_vec/mod.rs"],
                    std_locs=sorted([("library/alloc/src/raw_vec.rs", 28, 25, 5),
                                     ("library/alloc/src/raw_vec.rs", 28, 26, 5)]))
        fp = {"_paths": {"library/alloc/src/raw_vec.rs"}, "_locs": {(28, 25, 5)}}
        got = calibrate.stdlib_check(orig, fp)
        self.assertEqual(got["missing_paths"], ["library/alloc/src/raw_vec/mod.rs"])
        self.assertEqual((got["std_locations"], got["location_hits"]), (2, 1))

    def test_fingerprint_reads_locations_from_the_sysroot(self):
        with tempfile.TemporaryDirectory() as td:
            tc = Path(td) / "platform-tools-v9.9"
            lib = tc / "rust/lib/rustlib/sbpf-solana-solana/lib"
            lib.mkdir(parents=True)
            path = b"/build/out/rust/library/core/src/str/pattern.rs"
            (lib / "libcore-x.rlib").write_bytes(path + bytes(8) + struct.pack("<QII", len(path) + 1, 462, 55))
            (tc / "rust/bin").mkdir(parents=True)
            with mock.patch.object(calibrate, "build_canary", lambda tc, t, out: (
                    (out / "build.log").write_text("") and None, "no compiler in this test")), \
                    mock.patch.object(calibrate, "rustc_version", lambda tc: "rustc 9.9.0-dev"):
                fp = calibrate.fingerprint(tc, "sbpf-solana-solana", root=Path(td) / "fp")
                again = calibrate.fingerprint(tc, "sbpf-solana-solana", root=Path(td) / "fp")
        self.assertIn("library/core/src/str/pattern.rs", fp["_paths"])
        self.assertIn((len(path) + 1, 462, 55), fp["_locs"])
        self.assertEqual(fp["release"], "9.9")
        self.assertEqual(again["key"], fp["key"])


if __name__ == "__main__":
    unittest.main()

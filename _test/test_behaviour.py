"""Offline tests for cases / difftest / lockfit (no network; LiteSVM tests skip without solders)."""
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "tools"))
import cases
import difftest
import fetch
import lockfit


def cu16(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def tx_bytes(keys, v0=False, tables=()):
    msg = bytearray()
    if v0:
        msg.append(0x80)
    msg += bytes([1, 0, 1]) + cu16(len(keys)) + b"".join(keys) + bytes(32)
    msg += cu16(1) + bytes([len(keys) - 1]) + cu16(2) + bytes([0, 1]) + cu16(3) + b"abc"
    if v0:
        msg += cu16(len(tables))
        for t in tables:
            msg += t + cu16(1) + bytes([4]) + cu16(0)
    return cu16(1) + bytes(64) + bytes(msg)


class CasesTests(unittest.TestCase):
    def test_parses_legacy_and_v0_messages(self):
        keys = [bytes([i]) * 32 for i in (1, 2, 3)]
        legacy = cases.parse_transaction(tx_bytes(keys))
        self.assertEqual(legacy["keys"], [fetch.base58_encode(k) for k in keys])
        self.assertEqual(legacy["instructions"][0]["data"], b"abc")
        self.assertIsNone(legacy["version"])
        table = bytes([9]) * 32
        v0 = cases.parse_transaction(tx_bytes(keys, v0=True, tables=[table]))
        self.assertEqual((v0["version"], v0["tables"]), (0, [fetch.base58_encode(table)]))


class DifftestTests(unittest.TestCase):
    def outcome(self, **kw):
        base = dict(status="ok", logs=["Program P invoke [1]", "Program log: Instruction: Buy",
                                       "Program P consumed 100 of 200000 compute units", "Program P success"],
                    return_data=None, post={"A": [1, "o", "h"]})
        base.update(kw)
        base["logs"] = [difftest.mask_cu(x) for x in base["logs"]]
        return base

    def test_compute_units_are_masked_but_everything_else_counts(self):
        a = self.outcome()
        b = self.outcome(logs=["Program P invoke [1]", "Program log: Instruction: Buy",
                               "Program P consumed 999 of 200000 compute units", "Program P success"])
        self.assertIsNone(difftest.compare(a, b))
        self.assertEqual(difftest.compare(a, self.outcome(status="Custom(6000)"))["kind"], "status")
        d = difftest.compare(a, self.outcome(post={"A": [2, "o", "h"]}))
        self.assertEqual((d["kind"], d["account"]), ("account", "A"))
        d = difftest.compare(a, self.outcome(logs=a["logs"][:2]))
        self.assertEqual((d["kind"], d["line"], d["candidate"]), ("log", 2, "<end>"))

    def test_names_the_instruction_from_the_target_logs(self):
        logs = ["Program X invoke [1]", "Program log: Instruction: Other", "Program X success",
                "Program P invoke [1]", "Program log: Instruction: Buy"]
        self.assertEqual(difftest.instruction_name(logs, "P"), "Buy")

    @unittest.skipUnless(__import__("importlib").util.find_spec("solders"), "solders not installed")
    def test_programdata_snapshot_never_replaces_the_candidate(self):
        pid = "4FqThZWv3QKWkSyXCDmATpWkpEiCHq5yhkdGWpSEDAZM"
        pd = str(difftest.program_data_address(pid))
        with mock.patch("solders.litesvm.LiteSVM"):
            rt = difftest.Runtime(pid, b"\x7fELF", fetch.UPGRADEABLE_LOADER, ".", {"programs": {}},
                                  {pd: dict(executable=False)})
        self.assertIn(pd, rt.skip)


class FakeStore:
    def __init__(self, files):
        self.files = files            # {(name, version): {rel: text}}

    def get(self, name, version, checksum=None):
        if (name, version) not in self.files:
            return None
        d = Path(self.td) / f"{name}-{version}"
        for rel, text in self.files[(name, version)].items():
            (d / rel).parent.mkdir(parents=True, exist_ok=True)
            (d / rel).write_text(text)
        return d

    def versions(self, name):
        return [dict(vers=v, cksum="x", yanked=False) for (n, v) in self.files if n == name]


class LockfitTests(unittest.TestCase):
    def test_classifies_where_each_location_comes_from(self):
        locs = {("library/core/src/fmt/mod.rs", 28, 1, 1),
                ("/home/runner/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/hashbrown-0.15.4/src/raw/mod.rs",
                 99, 2, 3),
                ("src/ops/div.rs", 15, 4, 5), ("programs/x/src/lib.rs", 22, 6, 7)}
        parts = lockfit.classify(locs, None)
        self.assertEqual(parts["exact"], [("hashbrown", "0.15.4", "src/raw/mod.rs", 2, 3)])
        self.assertEqual(parts["dependency"], [("src/ops/div.rs", 4, 5)])
        self.assertEqual(parts["workspace_missing"], [("programs/x/src/lib.rs", 6, 7)])
        self.assertEqual(len(parts["std"]), 1)

    def test_proposes_the_version_whose_source_fits(self):
        good = "fn a() {}\nfn div() {\n    x / y\n}\n"
        bad = "// moved\n\n\n\n\nfn div() {\n    x / y\n}\n"
        store = FakeStore({("num", "0.4.3"): {"src/ops/div.rs": bad}, ("num", "0.4.6"): {"src/ops/div.rs": good},
                           ("num", "0.4.7"): {"src/ops/div.rs": good}})
        with tempfile.TemporaryDirectory() as td:
            store.td = td
            lock = Path(td) / "Cargo.lock"
            lock.write_text('version = 3\n[[package]]\nname = "num"\nversion = "0.4.3"\n'
                            'source = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "x"\n')
            so = Path(td) / "program.so"
            so.write_bytes(b"")
            with mock.patch.object(lockfit.C, "panic_locations", lambda raw: {("src/ops/div.rs", 15, 3, 5)}):
                rep = lockfit.analyze(so, None, lock, store, log=lambda m: None)
        (p,) = rep["proposals"]
        self.assertEqual((p["crate"], p["locked"], p["proposed"]), ("num", "0.4.3", "0.4.6"))
        self.assertEqual(p["equally_good"], ["0.4.6", "0.4.7"])


if __name__ == "__main__":
    unittest.main()

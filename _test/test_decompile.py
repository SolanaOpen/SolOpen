"""Synthetic SBPF/ELF tests for the decompiler; no chain or toolchain needed."""
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "tools"))
import decompile
import sbf


def ins(op, dst=0, src=0, off=0, imm=0):
    return struct.pack("<BBhi", op, (src << 4) | dst, off, imm)


def elf_with_text(text, rodata=b"hello\x00"):
    names = b"\x00.text\x00.rodata\x00.shstrtab\x00"
    text_off = 64
    ro_off = text_off + len(text)
    str_off = ro_off + len(rodata)
    shoff = (str_off + len(names) + 7) & ~7
    shnum, shstrndx = 4, 3
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    hdr = struct.pack("<16sHHIQQQIHHHHHH", ident, 1, 247, 1, 0, 0, shoff, 0,
                      64, 0, 0, 64, shnum, shstrndx)
    blob = bytearray(hdr + text + rodata + names)
    blob += bytes(shoff - len(blob))
    def sh(name=0, typ=0, addr=0, off=0, size=0):
        return struct.pack("<IIQQQQIIQQ", name, typ, 0, addr, off, size, 0, 0, 0, 0)
    blob += sh()
    blob += sh(1, 1, 0x1000, text_off, len(text))
    blob += sh(7, 1, 0x2000, ro_off, len(rodata))
    blob += sh(15, 3, 0, str_off, len(names))
    return bytes(blob)


def sample_code():
    return b"".join([
        ins(0x18, dst=1, imm=0x2000) + bytes(8),  # lddw r1, rodata
        ins(0xB7, dst=2, imm=5),                  # mov64 r2, 5
        ins(0x85, src=1, imm=1),                  # call .text+0x28
        ins(0x95),                                # exit
        ins(0xB7, dst=0, imm=0),                  # callee
        ins(0x95),
    ])


class SBFTests(unittest.TestCase):
    def test_anchor_discriminators_use_rust_handler_names(self):
        mapping = decompile.anchor_discriminators(["StartRaise", "redeem_sol"])
        self.assertIn("start_raise", mapping.values())
        self.assertIn("redeem_sol", mapping.values())
        initialize = int.from_bytes(decompile.IP.anchor_discriminator("global", "initialize"), "little")
        self.assertEqual(decompile.anchor_discriminators(["Initialize"])[initialize], "initialize")

    def test_decoder_and_cfg(self):
        code = sample_code()
        decoded = sbf.decode(code)
        self.assertEqual(decoded[0].imm64, 0x2000)
        self.assertEqual(decoded[0].size, 16)
        self.assertEqual(decoded[2].target, 40)
        starts = sbf.discover_starts(decoded, len(code))
        self.assertEqual(starts, [0, 40])
        blocks = sbf.basic_blocks(decoded, 0, 40)
        self.assertTrue(blocks)
        self.assertEqual(blocks[0]["start"], 0)

    def test_elf_analysis_and_artifacts(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            so = root / "program.so"
            so.write_bytes(elf_with_text(sample_code()))
            analysis = decompile.analyze(so)
            self.assertEqual(analysis["format"], "ELF64 SBPF v0")
            self.assertEqual(analysis["boundary_method"], "heuristic")
            self.assertEqual(len(analysis["functions"]), 2)
            self.assertEqual(analysis["functions"][0]["calls"], [40])
            self.assertEqual(analysis["functions"][0]["data_references"][0]["preview"], "hello")
            out = root / "reverse"
            decompile.write_artifacts(analysis, out)
            rendered = (out / "functions" / "fn_00000000.s").read_text()
            self.assertIn("fn_00000028", rendered)
            self.assertIn(".rodata+0x0", rendered)
            self.assertTrue((out / "cfg" / "fn_00000000.json").exists())

    def test_anchor_scaffold_is_explicitly_unimplemented(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            capture = root / "capture" / "11111111111111111111111111111111"
            capture.mkdir(parents=True)
            so = capture / "program.so"
            so.write_bytes(elf_with_text(sample_code()))
            (capture / "report.json").write_text(json.dumps({"program_id": capture.name}))
            analysis = decompile.analyze(so)
            analysis["inspection"]["instruction_log_strings"] = ["StartRaise", "RedeemSol"]
            analysis["inspection"]["project_source_paths"] = ["programs/demo/src/lib.rs"]
            ws = root / "rebuild"
            result = decompile.scaffold(analysis, so, ws, HERE.parent / "workspace_template")
            self.assertEqual(result["program"], "demo")
            lib = (ws / "programs" / "demo" / "src" / "lib.rs").read_text()
            self.assertIn("pub fn start_raise", lib)
            self.assertIn("NotImplemented", lib)
            cargo = (ws / "programs" / "demo" / "Cargo.toml").read_text()
            self.assertIn('name = "demo"', cargo)
            self.assertNotIn('name = "my_program"', cargo)


if __name__ == "__main__":
    unittest.main()

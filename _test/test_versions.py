"""Offline tests for SBPF v1-v3 decoding, masking and loader-v4 capture.

The encodings were checked against platform-tools v1.54 builds and its
llvm-objdump (0 mnemonic, callx-register or call-target differences over
~22,000 instructions); these tests pin the rules with hand-made bytes."""
import base64
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "tools"))
import linkorder as LO
import sbf


def ins(op, dst=0, src=0, off=0, imm=0):
    return struct.pack("<BBhi", op, dst | (src << 4), off, imm)


class DecodeTests(unittest.TestCase):
    def text(self, code, version):
        return [x.text for x in sbf.decode(code, None, version)]

    def test_v2_memory_pqr_and_address_pairs(self):
        code = (ins(0x9C, dst=0, src=1, off=8) +       # ldxdw r0, [r1+8] (moved class)
                ins(0x9F, dst=10, src=2, off=-8) +     # stxdw [r10-8], r2
                ins(0x97, dst=1, imm=7) +              # stdw [r1], 7
                ins(0x5E, dst=3, src=1) +              # udiv64 r3, r1 (PQR)
                ins(0x96, dst=0, imm=31) +             # lmul64 r0, 31
                ins(0xB4, dst=2, imm=0x470) +          # mov32 r2, 0x470
                ins(0x55, dst=4, imm=0, off=1) +       # jne (unrelated, between the pair)
                ins(0xF7, dst=2, imm=0) +              # hor64 r2, 0
                ins(0x8D, src=2) +                     # callx r2 (v2: src)
                ins(0x95))
        t = self.text(code, 2)
        self.assertEqual(t[:5], ["ldxdw r0, [r1+8]", "stxdw [r10-8], r2", "stdw [r1], 7",
                                 "udiv64 r3, r1", "lmul64 r0, 31"])
        self.assertEqual(t[7:9], ["hor64 r2, 0x0", "callx r2"])
        self.assertEqual(LO.address_pairs(code), [(40, 56)])
        self.assertEqual(LO.decode_lddw(code, 2), {40: 0x470})
        masked = LO.mask(code, 2)
        self.assertEqual(masked[44:48] + masked[60:64], bytes(8))
        self.assertEqual(masked[36:40], struct.pack("<i", 31))          # ordinary constants stay
        # under v0 rules the same bytes would be mul/div/neg — the version matters
        self.assertTrue(self.text(code, 0)[0].startswith("mod32"))

    def test_v2_pair_is_not_formed_across_another_write(self):
        code = ins(0xB4, dst=2, imm=0x470) + ins(0xBC, dst=2, src=5) + ins(0xF7, dst=2, imm=1)
        self.assertEqual(LO.address_pairs(code), [])

    def test_v3_static_syscalls_jmp32_and_callx(self):
        h = sbf.murmur3_32(b"sol_log_")
        self.assertEqual(h, 0x207559BD)
        code = (ins(0x85, src=0, imm=h if h < 1 << 31 else h - (1 << 32)) +    # call sol_log_ (static)
                ins(0x85, src=1, imm=1) +                # call +1 (internal, pc-relative)
                ins(0x16, dst=1, imm=3, off=1) +         # jeq32 r1, 3 (class 0x06 from v3)
                ins(0x8D, dst=4) +                       # callx r4 (v3: dst)
                ins(0x95))
        decoded = sbf.decode(code, None, 3)
        self.assertEqual(decoded[0].text, "call sol_log_")
        self.assertEqual(decoded[1].target, 24)
        self.assertTrue(decoded[2].jump and decoded[2].text.startswith("jeq32 r1, 3"))
        self.assertEqual(decoded[3].text, "callx r4")
        self.assertEqual(LO.decode_calls(code, 3), {8: 24})
        masked = LO.mask(code, 3)
        self.assertEqual(masked[4:8], code[4:8])          # a syscall hash is not layout
        self.assertEqual(masked[12:16], bytes(4))         # an internal call target is
        # before v3, `call -1` is a relocated syscall, not a call to itself
        self.assertEqual(LO.decode_calls(ins(0x85, src=1, imm=-1), 0), {})

    def test_v3_pointer_words_without_relocations(self):
        rodata = bytearray(64)
        rodata[8:16] = b"src/a.rs"
        struct.pack_into("<QQII", rodata, 16, 8, 8, 40, 7)           # Location {ptr 8, len 8, line, col}
        struct.pack_into("<Q", rodata, 40, (1 << 32) + 0x18)         # a code pointer (vtable slot)
        struct.pack_into("<QQ", rodata, 48, 9, 1)                    # numbers, not a pointer
        img = dict(text_addr=1 << 32, text_size=0x100, version=3, data=[(".rodata", 0, 64, bytes(rodata))])
        self.assertEqual(LO.v3_pointer_words(img), {16, 40})

    def test_unknown_versions_are_refused(self):
        elf = bytearray(64)
        struct.pack_into("<I", elf, 0x30, 4)
        with self.assertRaises(SystemExit):
            sbf.elf_version(bytes(elf))


class LoaderV4Tests(unittest.TestCase):
    def test_fetch_reads_the_executable_after_the_48_byte_state(self):
        import fetch
        pid = "4FqThZWv3QKWkSyXCDmATpWkpEiCHq5yhkdGWpSEDAZM"
        elf = b"\x7fELF" + bytes(60)
        state = struct.pack("<Q", 370107442) + bytes(range(1, 33)) + struct.pack("<Q", 2)    # finalized
        acct = {"owner": fetch.LOADER_V4, "executable": True,
                "data": [base64.b64encode(state + elf).decode(), "base64"]}

        def fake_rpc(url, method, params, tries=5):
            if method == "getAccountInfo":
                return {"context": {"slot": 460000000}, "value": acct}
            if method == "getBlockTime":
                return 1700000000
            raise AssertionError(method)
        with tempfile.TemporaryDirectory() as td, mock.patch.object(fetch, "rpc", fake_rpc), \
                mock.patch.object(fetch, "fetch_idl", lambda *a: {}), \
                mock.patch.object(fetch, "ottersec_status", lambda *a: {}):
            rep = fetch.fetch_program("http://rpc", pid, td)
            self.assertEqual(Path(td, "program.so").read_bytes(), elf)
        self.assertEqual((rep["loader"], rep["loader_v4_status"], rep["last_deploy_slot"]),
                         ("loader-v4", "finalized", 370107442))
        self.assertIsNone(rep["upgrade_authority"]["address"])


if __name__ == "__main__":
    unittest.main()

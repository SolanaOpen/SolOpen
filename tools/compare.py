#!/usr/bin/env python3
"""
compare.py — the byte-identical check at the heart of the reconstruction loop.

Given the captured original (.so) and a freshly built candidate (.so), it:
  - strips the candidate ELF to its real end (section-header table),
  - appends N zero bytes to match the original's account-padding length,
  - compares, and on a mismatch points at the FIRST diverging byte and the
    section it falls in (via the ELF section headers), so you know what to fix.

This mirrors the daosfun recipe's final step. It NEVER copies bytes from the
original into the candidate — the original is only the answer key. stdlib only.

  python3 compare.py --original capture/<id>/program.so --candidate build/dao.so
  python3 compare.py --original capture/<id>/program.so --candidate build/dao.elf.so --pad-to 1120784
"""
import sys, os, struct, hashlib, argparse, json


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def elf_sections(b):
    """Return [(name, start, size)] from the ELF section header table, best effort."""
    if len(b) < 64 or b[:4] != b"\x7fELF":
        return []
    is64 = b[4] == 2
    if not is64:
        return []
    e_shoff = struct.unpack_from("<Q", b, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", b, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", b, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", b, 0x3E)[0]
    if e_shoff == 0 or e_shoff + e_shentsize * e_shnum > len(b):
        return []
    secs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name = struct.unpack_from("<I", b, off)[0]
        sh_offset = struct.unpack_from("<Q", b, off + 0x18)[0]
        sh_size = struct.unpack_from("<Q", b, off + 0x20)[0]
        secs.append([sh_name, sh_offset, sh_size])
    # resolve names from .shstrtab
    try:
        stroff = secs[e_shstrndx][1]
        def name(n):
            end = b.index(b"\x00", stroff + n)
            return b[stroff + n:end].decode("latin1")
        return [(name(n), o, s) for (n, o, s) in secs]
    except Exception:
        return [("?", o, s) for (n, o, s) in secs]


def elf_end(b):
    if len(b) < 64 or b[:4] != b"\x7fELF" or b[4] != 2:
        return None
    e_shoff = struct.unpack_from("<Q", b, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", b, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", b, 0x3C)[0]
    end = e_shoff + e_shentsize * e_shnum
    return end if 0 < end <= len(b) else None


def section_of(secs, off):
    hit = None
    for (nm, o, s) in secs:
        if s and o <= off < o + s:
            hit = nm
    return hit


def main():
    ap = argparse.ArgumentParser(description="Byte-compare a rebuilt program against the captured original.")
    ap.add_argument("--original", required=True)
    ap.add_argument("--candidate", required=True)
    ap.add_argument("--pad-to", type=int, default=None,
                    help="target total length; default = original length (zero-pad candidate to match)")
    ap.add_argument("--json", default=None)
    a = ap.parse_args()

    orig = open(a.original, "rb").read()
    cand = open(a.candidate, "rb").read()

    target = a.pad_to or len(orig)
    # Trim candidate to its ELF end, then zero-pad to the target length.
    ce = elf_end(cand)
    cand_elf = cand[:ce] if ce else cand
    if len(cand_elf) > target:
        padded = cand_elf  # too long already; compare as-is to reveal the overflow
    else:
        padded = cand_elf + bytes(target - len(cand_elf))

    res = {
        "original": a.original, "candidate": a.candidate,
        "original_bytes": len(orig), "candidate_elf_bytes": len(cand_elf),
        "target_bytes": target,
        "original_sha256": sha256(orig),
        "candidate_padded_sha256": sha256(padded),
        "identical": orig == padded,
    }

    if orig == padded:
        print("MATCH — byte-identical.")
        print(f"  sha256 {res['original_sha256']}")
        print(f"  {len(orig):,} bytes (ELF {len(cand_elf):,} + {len(orig)-len(cand_elf):,} zero padding)")
    else:
        # first divergence
        n = min(len(orig), len(padded))
        first = next((i for i in range(n) if orig[i] != padded[i]), n)
        secs = elf_sections(orig)
        res["first_diff_offset"] = first
        res["first_diff_section"] = section_of(secs, first)
        res["original_len_vs_candidate"] = [len(orig), len(padded)]
        print("MISMATCH — not yet byte-identical.")
        print(f"  original  sha256 {res['original_sha256']}")
        print(f"  candidate sha256 {res['candidate_padded_sha256']}")
        print(f"  lengths: original {len(orig):,}  candidate(padded) {len(padded):,}")
        print(f"  first differing byte at offset {first} (0x{first:x})"
              + (f", in section {res['first_diff_section']}" if res['first_diff_section'] else ""))
        lo = max(0, first - 8)
        print(f"  original  …{orig[lo:first+8].hex()}")
        print(f"  candidate …{padded[lo:first+8].hex()}")
        print("\n  Fix hints by section:")
        print("   .text  → code differs: wrong source logic, inlining, or compiler/flags.")
        print("            A tiny shift often means a panic line/column moved — check blank")
        print("            lines and #[inline(never)] placement, do not reformat source.")
        print("   .rodata→ constants/strings differ: a literal, error message, or embedded")
        print("            pubkey is wrong, or rodata ordering differs (recover link order).")
        print("   section-table / later → linker section ORDER differs, not the code: apply")
        print("            the recovered order-mapping; a plain `anchor build` won't match.")

    if a.json:
        json.dump(res, open(a.json, "w"), indent=2)
    sys.exit(0 if res["identical"] else 1)


if __name__ == "__main__":
    main()

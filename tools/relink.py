#!/usr/bin/env python3
"""
relink.py — replay your captured link in the recovered order, strip, compare.

  python3 relink.py --capture build/try-01/capture --order order/order-mapping.json \\
                    --out build/try-01/relinked [--original capture/<id>/program.so]

It never recompiles and never copies a byte from the original: it rewrites the
linker script so that the SAME objects your compiler produced are laid out in
the order linkorder.py recovered, links with the same linker and arguments,
strips with llvm-objcopy, and (with --original) byte-compares the result.

  .text          ordered by the recovered function order (every input section
                 named by object + section, so identical names can't collide)
  .rodata,       reordered only where the recovered constant map says your
  .data.rel.ro   layout differs from the original (the repo's constant-order)
"""
import argparse, json, re, struct, subprocess, sys, hashlib, bisect
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import compare as CMP  # noqa: E402

LINE = re.compile(r"^\s*([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+(\d+) (\s*)(\S.*)$")
INPUT = re.compile(r"^(.*):\(([^()]*)\)$")


def parse_map(path):
    """lld -Map: rows of output sections and the input sections inside them.
    The column after Align is indented 0 (output section), 8 (input section)
    or 16 (symbol)."""
    outs, cur = [], None
    for line in Path(path).read_text(errors="replace").splitlines():
        m = LINE.match(line)
        if not m:
            continue
        vma, _, size, align, indent, rest = m.groups()
        vma, size = int(vma, 16), int(size, 16)
        depth = len(indent)
        if depth == 0:
            cur = dict(name=rest.strip(), vma=vma, size=size, inputs=[])
            outs.append(cur)
        elif depth <= 8 and cur is not None:
            mi = INPUT.match(rest.strip())
            if mi:
                cur["inputs"].append(dict(vma=vma, size=size, align=int(align),
                                          owner=mi.group(1), section=mi.group(2)))
    return {o["name"]: o for o in outs}


def script_ref(row, rename):
    """Linker-script input-section selector for one map row."""
    owner, sec = row["owner"], row["section"]
    if owner == "<internal>":
        return f"*({json.dumps(sec)})"
    if owner.endswith(")") and "(" in owner:                 # archive(member)
        archive, member = owner.rsplit("(", 1)
        owner = rename.get(archive, archive) + ":" + member[:-1]
    else:
        owner = rename.get(owner, owner)
    return f"{json.dumps(owner)}({json.dumps(sec)})"


SELECTOR = re.compile(r'(?:\*|"[^"]*")[^\s;()]*\([^()]*\)')


def replace_rule(script, out_name, body_lines, fallback):
    """Put `body_lines` first in output section `out_name` of a linker script.

    Only the input-section selectors are replaced; anything else in the rule
    stays where it was — SBPF v3's `.rodata 0x0 : SUBALIGN(8) { BYTE(0);
    *(.rodata*) *(.data.rel.ro*) . = ALIGN(8); }` keeps its leading byte,
    trailing alignment and both selectors (as fallbacks after the explicit
    list). The rule may carry an address (`.text 0x100000000 : {`)."""
    pat = re.compile(r"(^|\n)(\s*" + re.escape(out_name) + r"(?=[\s:])[^:{\n]*:[^{\n]*\{)([^}]*)(\})")
    m = pat.search(script)
    if not m:
        raise SystemExit(f"couldn't find the {out_name} rule in the linker script")
    body = m.group(3)
    sel = list(SELECTOR.finditer(body))
    if not sel:
        return script[:m.start(3)] + "\n" + "".join(f"    {l}\n" for l in body_lines) + f"    {fallback}\n  " \
            + body + script[m.end(3):]
    head, tail = body[:sel[0].start()], body[sel[-1].end():]
    fallbacks = [x.group(0) for x in sel] or [fallback]
    middle = "".join(f"{l}\n    " for l in body_lines) + "\n    ".join(fallbacks)
    return script[:m.start(3)] + head + middle + tail + script[m.end(3):]


def text_order(outs, rows, cand_text_vma):
    """Input sections of .text in recovered order. A row names a function by
    its offset in YOUR .text; the input section starting there moves with it."""
    ins = sorted(outs[".text"]["inputs"], key=lambda r: r["vma"])
    starts = [r["vma"] for r in ins]
    seen, ordered, inside = set(), [], 0
    for r in sorted(rows, key=lambda r: r["original"]):
        v = cand_text_vma + r["candidate"]
        i = bisect.bisect_right(starts, v) - 1
        if i < 0 or not (ins[i]["vma"] <= v < ins[i]["vma"] + max(1, ins[i]["size"])):
            continue
        if ins[i]["vma"] != v:
            inside += 1          # function shares an input section with another
        if i not in seen:
            seen.add(i)
            ordered.append(ins[i])
    return ordered, len(ins), inside

def const_order(outs, group, consts):
    """New order for the input sections of one data output section, from the
    recovered constant map (section-relative offsets, yours -> original).
    Returns None when your layout already agrees."""
    if group not in outs:
        return None
    base = outs[group]["vma"]
    ins = sorted(outs[group]["inputs"], key=lambda r: r["vma"])
    cs = sorted((c["yours"], c["original"]) for c in consts if c["section"] == group)
    ys = [y for y, _ in cs]
    keys, last = [], -1.0
    for idx, r in enumerate(ins):
        lo, hi = r["vma"] - base, r["vma"] - base + r["size"]
        j = bisect.bisect_left(ys, lo)
        want = cs[j][1] - (cs[j][0] - lo) if j < len(cs) and cs[j][0] < hi else None
        if want is None:
            want = last + 1e-6          # no evidence: stay right after your predecessor
        last = want
        keys.append((want, idx))
    new = [ins[i] for _, i in sorted(keys)]
    return None if new == ins else new


def script_arg(args):
    for i, a in enumerate(args):
        if a in ("--script", "-T") and i + 1 < len(args):
            return i + 1, ""
        for p in ("--script=", "-T"):
            if a.startswith(p) and len(a) > len(p):
                return i, p
    raise SystemExit("the captured link has no --script argument; can't reorder sections")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--capture", required=True, type=Path)
    ap.add_argument("--order", required=True, type=Path, help="order-mapping.json from linkorder.py")
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--original", type=Path, default=None, help="captured program.so to byte-compare against")
    ap.add_argument("--no-constants", action="store_true", help="only reorder .text")
    a = ap.parse_args()

    cap, out = a.capture.resolve(), a.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    link = json.loads((cap / "link-args.json").read_text())
    rename = {r["original"]: r["saved"] for r in json.loads((cap / "link-inputs.json").read_text())}
    for r in json.loads((cap / "link-inputs.json").read_text()):
        if hashlib.sha256(Path(r["saved"]).read_bytes()).hexdigest() != r["sha256"]:
            raise SystemExit("captured link input changed since capture: " + r["saved"])
    outs = parse_map(cap / "link.map")
    mapping = json.loads(a.order.read_text())
    base = (cap / "baseline.unstripped.so").read_bytes()
    sys.path.insert(0, str(HERE))
    import linkorder as LO
    tsec, _ = LO.text_of(base)

    ordered, total, inside = text_order(outs, mapping["rows"], tsec["addr"])
    args = list(link["args"])
    si, prefix = script_arg(args)
    script = Path(args[si][len(prefix):]).read_text()
    script = replace_rule(script, ".text", [script_ref(r, rename) for r in ordered], "*(.text*)")
    report = dict(text_sections_ordered=len(ordered), text_sections_total=total,
                  functions_sharing_a_section=inside, constant_groups_reordered=[])
    if not a.no_constants:
        for group in (".rodata", ".data.rel.ro"):
            new = const_order(outs, group, mapping.get("constants", []))
            if new:
                script = replace_rule(script, group, [script_ref(r, rename) for r in new], f"*({group}*)")
                report["constant_groups_reordered"].append(group)
    (out / "recovered.ld").write_text(script)
    args[si] = prefix + str(out / "recovered.ld")
    args[args.index("@OUTPUT@")] = str(out / "program.unstripped.so")
    args.append("-Map=" + str(out / "link.map"))
    with (out / "link.log").open("w") as log:
        rc = subprocess.run([link["linker"]] + args, stdout=log, stderr=subprocess.STDOUT).returncode
    if rc:
        print((out / "link.log").read_text()[-3000:])
        raise SystemExit(f"relink failed (exit {rc})")
    objcopy = link.get("objcopy") or "llvm-objcopy"
    subprocess.run([objcopy, "--strip-all", str(out / "program.unstripped.so"), str(out / "program.so")], check=True)
    built = (out / "program.so").read_bytes()
    report.update(size=len(built), sha256=hashlib.sha256(built).hexdigest())
    print(f"relinked: {len(ordered)}/{total} .text input sections placed in recovered order"
          + (f", constants reordered in {', '.join(report['constant_groups_reordered'])}"
             if report["constant_groups_reordered"] else ""))
    print(f"  {out/'program.so'}  {len(built):,} bytes  sha256 {report['sha256']}")
    if a.original:
        orig = a.original.read_bytes()
        ce = CMP.elf_end(built) or len(built)
        padded = built[:ce] + bytes(max(0, len(orig) - ce))
        report["identical"] = padded == orig
        if padded == orig:
            print(f"MATCH — byte-identical to {a.original} ({len(orig):,} bytes, "
                  f"{len(orig) - ce:,} of them account zero-padding)")
        else:
            n = min(len(orig), len(padded))
            first = next((i for i in range(n) if orig[i] != padded[i]), n)
            sec = CMP.section_of(CMP.elf_sections(orig), first)
            diff = sum(1 for i in range(n) if orig[i] != padded[i])
            report.update(first_diff=first, first_diff_section=sec, differing_bytes=diff)
            print(f"MISMATCH — {diff:,} bytes differ; first at 0x{first:x}" + (f" in {sec}" if sec else "")
                  + f"  (run compare.py for details)")
    (out / "relink-report.json").write_text(json.dumps(report, indent=2) + "\n")
    sys.exit(0 if report.get("identical", True) else 1)


if __name__ == "__main__":
    main()

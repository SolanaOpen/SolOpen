#!/usr/bin/env python3
"""Recover SBPF disassembly, control flow and an editable Rust starting point.

  python3 tools/decompile.py capture/<ID>/program.so --out reverse/<ID>
  python3 tools/decompile.py capture/<ID> --out reverse/<ID> --workspace rebuild

The output is evidence for reconstruction, not recovered original source.
Stripped function boundaries are heuristic; byte comparison decides correctness.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import linkorder as LO
import inspect_program as IP
import sbf


def snake(name):
    name = re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()
    name = re.sub(r"[^a-zA-Z0-9_]", "_", name)
    if not name or name[0].isdigit():
        name = "ix_" + name
    return name


def pascal(name):
    parts = re.split(r"[^a-zA-Z0-9]+|_+", name)
    out = "".join(p[:1].upper() + p[1:] for p in parts if p)
    if not out:
        out = "Instruction"
    if out[0].isdigit():
        out = "Ix" + out
    return out


def resolve_input(path):
    p = Path(path)
    return p / "program.so" if p.is_dir() else p


def anchor_discriminators(names):
    """Map both log-style CamelCase and Rust snake_case instruction names.

    Anchor's discriminator uses the Rust handler name (start_raise), while its
    default log string uses StartRaise. Real daos.fun evidence exposed this
    distinction; using the log spelling alone misses the deployed constants.
    """
    out = {}
    for name in names:
        for rust_name in {name, snake(name)}:
            value = int.from_bytes(IP.anchor_discriminator("global", rust_name), "little")
            out[value] = rust_name
    return out


def pointer_targets(image):
    """Text offsets of code pointers stored in data (vtables, fn tables)."""
    t0, n = image["text_addr"], image["text_size"]
    return {v - t0 for _, _, v in LO.data_pointers(image) if t0 <= v < t0 + n}


def syscall_names(raw, text_sec):
    """{.text offset: symbol} for every syscall: up to v2 the calls the loader
    resolves by name (R_BPF_64_32 against .dynsym): sol_log_,
    sol_invoke_signed_rust, abort…; from v3 static syscalls, whose imm is the
    murmur3 hash of the name."""
    if sbf.elf_version(raw) == 3:
        text = raw[text_sec["off"]:text_sec["off"] + text_sec["size"]]
        out, i = {}, 0
        while i + 8 <= len(text):
            if text[i] == sbf.OP_CALL and (text[i + 1] >> 4) == 0:
                h = struct.unpack_from("<I", text, i + 4)[0]
                out[i] = sbf.SYSCALL_BY_HASH.get(h, f"syscall_0x{h:08x}")
            i += sbf.insn_size(text, i, 3)
        return out
    secs = {s["name"]: s for s in LO._sections(raw)}
    rel, dynsym, dynstr = secs.get(".rel.dyn"), secs.get(".dynsym"), secs.get(".dynstr")
    if not (rel and dynsym and dynstr):
        return {}
    out = {}
    lo, hi = text_sec["addr"], text_sec["addr"] + text_sec["size"]
    for k in range(rel["size"] // 16):
        off, info = struct.unpack_from("<QQ", raw, rel["off"] + 16 * k)
        typ, sym = info & 0xFFFFFFFF, info >> 32
        if typ != 10 or not sym or not lo <= off < hi:   # R_BPF_64_32
            continue
        name_off = struct.unpack_from("<I", raw, dynsym["off"] + 24 * sym)[0]
        start = dynstr["off"] + name_off
        name = raw[start:raw.index(b"\x00", start)].decode("latin1")
        if name:
            out[off - lo] = name
    return out


def analyze(so_path, idl_path=None):
    raw = Path(so_path).read_bytes()
    if len(raw) < 64 or raw[:4] != b"\x7fELF" or raw[4] != 2:
        raise SystemExit("decompile expects a 64-bit Solana SBPF ELF")
    machine = struct.unpack_from("<H", raw, 18)[0]
    if machine not in (247, 263):  # EM_BPF (v0 before platform-tools v1.44, and v3), EM_SBF
        raise SystemExit(f"ELF machine {machine} is neither EM_BPF (247) nor EM_SBF (263); not a Solana program")
    version = sbf.elf_version(raw)           # e_flags 0-3; refuses anything newer
    text_sec, text = LO.text_of(raw)
    image = LO.image_of(raw)
    names_by_pc = syscall_names(raw, text_sec)
    insns = sbf.decode(text, names_by_pc, version)
    try:
        symbols = LO.functions_of(raw)[0]
    except (SystemExit, StopIteration):
        symbols = None
    ptrs = pointer_targets(image)
    loads = LO.decode_lddw(text, version)        # lddw, or mov32+hor64 in v2
    ptrs.update(v - text_sec["addr"] for v in loads.values()
                if text_sec["addr"] <= v < text_sec["addr"] + len(text))
    starts = sbf.discover_starts(insns, len(text), ptrs)
    functions = sbf.function_ranges(insns, starts, len(text), symbols)
    report = IP.inspect(str(so_path), idl_path)
    discriminators = anchor_discriminators(report.get("instruction_log_strings", []))
    names = {f["offset"]: f["name"] for f in functions}

    for f in functions:
        body = sbf.slice_instructions(insns, f["offset"], f["size"])
        f["instruction_count"] = len(body)
        f["calls"] = sorted({x.target for x in body if sbf.is_internal_call(x)})
        f["call_names"] = [names.get(x, f"text+0x{x:x}") for x in f["calls"]]
        f["syscalls"] = sorted({names_by_pc.get(x.pc, f"0x{x.imm & 0xffffffff:08x}") for x in body
                                if x.opcode == sbf.OP_CALL and x.target is None})
        f["indirect_calls"] = sum(1 for x in body if x.opcode == sbf.OP_CALL | 8)
        refs, ixs = [], []
        for ins in body:
            value = loads.get(ins.pc)
            if value is not None:
                ref = sbf.data_reference(value, image["data"])
                if ref:
                    refs.append(dict(pc=ins.pc, **ref))
                if value in discriminators:
                    ixs.append(dict(pc=ins.pc, name=discriminators[value]))
        f["data_references"] = refs
        f["anchor_instruction_evidence"] = ixs
        f["blocks"] = sbf.basic_blocks(insns, f["offset"], f["size"])
        f["file"] = f"functions/fn_{f['offset']:08x}.s"

    return dict(
        schema_version=1,
        input=str(so_path), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
        format=f"ELF64 SBPF v{version}", sbpf_version=version,
        text=dict(address=text_sec["addr"], offset=text_sec["off"], size=len(text)),
        boundary_method="symtab" if symbols else "heuristic",
        boundary_warning=None if symbols else
            "Stripped function ranges are AI-facing chunks inferred from calls, exits and code pointers; they are not guaranteed original function boundaries.",
        instructions=[x.json() for x in insns], functions=functions,
        inspection=report,
        limitations=[
            "This is disassembly and CFG recovery, not original Rust source.",
            "Types, account constraints, variable names, comments and off-chain behavior are not recovered.",
            "SBPF v0-v3 ELF input is decoded; correctness requires a byte-identical rebuild.",
        ])


def render_function(f, analysis):
    labels = {x["offset"]: x["name"] for x in analysis["functions"]}
    insns = [sbf.Insn(**{k: v for k, v in x.items() if k in sbf.Insn.__dataclass_fields__})
             for b in f["blocks"] for x in b["instructions"]]
    lines = [f"# {f['name']}  .text+0x{f['offset']:x}  {f['size']} bytes",
             f"# boundaries: {f['boundary']}; blocks: {len(f['blocks'])}"]
    refs = {x["pc"]: x for x in f["data_references"]}
    ixs = {x["pc"]: x["name"] for x in f["anchor_instruction_evidence"]}
    block_starts = {b["start"] for b in f["blocks"]}
    for ins in insns:
        if ins.pc in block_starts:
            lines.append(f"\nloc_{ins.pc:08x}:")
        text = ins.text
        if ins.opcode == sbf.OP_CALL and ins.src == 1 and ins.target in labels:
            text += f"  ; {labels[ins.target]}"
        if ins.pc in refs:
            r = refs[ins.pc]
            text += f"  ; {r['section']}+0x{r['offset']:x} \"{r['preview']}\""
        if ins.pc in ixs:
            text += f"  ; Anchor discriminator: {ixs[ins.pc]}"
        lines.append(f"  {ins.pc:08x}:  {text}")
    return "\n".join(lines) + "\n"


def write_artifacts(analysis, out):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=False)
    (out / "functions").mkdir()
    (out / "cfg").mkdir()
    all_text = []
    for f in analysis["functions"]:
        rendered = render_function(f, analysis)
        (out / f["file"]).write_text(rendered)
        (out / "cfg" / f"fn_{f['offset']:08x}.json").write_text(json.dumps(f["blocks"], indent=2) + "\n")
        all_text.append(rendered)
    (out / "disassembly.s").write_text("\n".join(all_text))
    (out / "analysis.json").write_text(json.dumps(analysis, indent=2) + "\n")
    strings = analysis["inspection"]
    context = [
        "# Reconstruction context", "",
        f"- Input SHA-256: `{analysis['sha256']}`",
        f"- .text: {analysis['text']['size']:,} bytes; {len(analysis['functions'])} recovered chunks/functions",
        f"- Function boundaries: **{analysis['boundary_method']}**",
        f"- Anchor instruction names: {', '.join(strings.get('instruction_log_strings', [])) or 'none found'}",
        f"- Source paths in panic metadata: {', '.join(strings.get('project_source_paths', [])) or 'none found'}",
        "", "## Rules for an AI or human rebuilder", "",
        "1. Treat assembly and string references as evidence, not as original source.",
        "2. Reconstruct small pieces, then run the existing build/order/relink/compare loop.",
        "3. Never claim semantic or byte equivalence from decompiler output alone.",
        "4. Preserve file paths and line positions once matching: panic locations affect bytes.",
        "5. A final match proves this source builds these bytes, not the author's historical source.",
    ]
    (out / "context.md").write_text("\n".join(context) + "\n")
    return out


def load_capture(so_path):
    root = Path(so_path).parent
    report = root / "report.json"
    if report.exists():
        return json.loads(report.read_text()), root
    return {}, root


def scaffold(analysis, so_path, workspace, template, program=None):
    """Create a compile-oriented Anchor skeleton; behavior remains unimplemented."""
    inspection = analysis["inspection"]
    ix_names = inspection.get("instruction_log_strings", [])
    if inspection.get("idl", {}).get("instructions"):
        ix_names = inspection["idl"]["instructions"]
    if not ix_names:
        raise SystemExit("no Anchor instruction names or IDL found; disassembly was still written, "
                         "but automatic Rust scaffolding currently requires Anchor evidence")
    workspace = Path(workspace)
    if workspace.exists():
        raise SystemExit(f"workspace already exists: {workspace}; refusing to overwrite source")
    shutil.copytree(template, workspace)
    capture, capture_root = load_capture(so_path)
    program_id = capture.get("program_id") or capture_root.name
    paths = inspection.get("project_source_paths", [])
    crate = program
    if not crate and paths:
        m = re.match(r"programs/([^/]+)/src/", paths[0])
        if m:
            crate = m.group(1)
    crate = crate or inspection.get("idl", {}).get("name") or "my_program"
    crate = re.sub(r"[^a-zA-Z0-9_-]", "_", crate)
    lib = crate.replace("-", "_")
    old = workspace / "programs" / "my_program"
    new = workspace / "programs" / crate
    if old != new:
        new.parent.mkdir(parents=True, exist_ok=True)
        old.rename(new)
    root_cargo = workspace / "Cargo.toml"
    root_cargo.write_text(root_cargo.read_text().replace('members = ["programs/my_program"]',
                                                         f'members = ["programs/{crate}"]'))
    crate_cargo = new / "Cargo.toml"
    cc = crate_cargo.read_text().replace('name = "my_program"', f'name = "{crate}"', 1)
    cc = cc.replace('name = "my_program"', f'name = "{lib}"', 1)
    crate_cargo.write_text(cc)

    seen, handlers, accounts = set(), [], []
    for original in ix_names:
        fn = snake(original)
        base = fn
        n = 2
        while fn in seen:
            fn, n = f"{base}_{n}", n + 1
        seen.add(fn)
        st = pascal(original)
        handlers.append(f"    pub fn {fn}(_ctx: Context<{st}>) -> Result<()> {{\n"
                        f"        err!(ReconstructionError::NotImplemented)\n    }}")
        accounts.append(f"#[derive(Accounts)]\npub struct {st} {{}}")
    lib_rs = f"""// Reconstruction scaffold generated from deployed-program evidence.
// The instruction bodies are deliberately unimplemented. A byte match is the
// only acceptance test; do not mistake these names for recovered source logic.
use anchor_lang::prelude::*;

declare_id!("{program_id}");

#[program]
pub mod {lib} {{
    use super::*;
{chr(10).join(handlers)}
}}

{chr(10).join(accounts)}

#[error_code]
pub enum ReconstructionError {{
    #[msg("Instruction not reconstructed yet")]
    NotImplemented,
}}
"""
    (new / "src" / "lib.rs").write_text(lib_rs)
    notes = ["# Reconstruction workspace", "",
             "Generated instruction names and empty account contexts are hypotheses, not recovered behavior.",
             "Fill argument types, accounts, constraints, state and handler logic from the disassembly/IDL.",
             "The loop will reject the scaffold until those bytes are reproduced.", "",
             "## Evidence", f"- Decompilation: `{analysis['input']}`",
             f"- Program id: `{program_id}`", f"- Crate/lib: `{crate}` / `{lib}`",
             f"- Original source paths: {', '.join(paths) or 'not found'}", "",
             "Generate a lockfile with the pinned dependency versions before using `solopen.py try`.",
             "Do not run rustfmt after functions begin matching: line/column metadata changes bytes."]
    (workspace / "RECONSTRUCTION.md").write_text("\n".join(notes) + "\n")
    return dict(workspace=str(workspace), program=lib, crate=crate, program_id=program_id,
                instruction_stubs=len(ix_names))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("so", help="capture/<ID> directory or ELF program.so")
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--idl", default=None)
    ap.add_argument("--workspace", type=Path, default=None, help="also create an Anchor Rust reconstruction scaffold")
    ap.add_argument("--program", default=None, help="crate name for the scaffold (default: recovered path/IDL)")
    a = ap.parse_args()
    so = resolve_input(a.so)
    if a.idl is None and so.parent.joinpath("idl.json").exists():
        a.idl = str(so.parent / "idl.json")
    analysis = analyze(so, a.idl)
    write_artifacts(analysis, a.out)
    print(f"wrote {a.out}/analysis.json, disassembly.s, functions/ and cfg/")
    print(f"recovered {len(analysis['functions'])} functions/chunks; boundaries: {analysis['boundary_method']}")
    if a.workspace:
        result = scaffold(analysis, so, a.workspace, HERE.parent / "workspace_template", a.program)
        print(f"created Anchor reconstruction scaffold at {result['workspace']} "
              f"({result['instruction_stubs']} unimplemented instruction stubs)")
    print("NOTE: this is evidence for rebuilding, not recovered original source; use `try`/`rebuild` to verify.")


if __name__ == "__main__":
    main()

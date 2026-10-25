#!/usr/bin/env python3
"""Small, dependency-free SBPF decoder (versions 0-3) used by the decompiler.

This is deliberately a disassembler/CFG recoverer, not a claim that machine
code can be turned back into the author's Rust.  The AI rebuild loop consumes
these grounded artifacts and the byte matcher remains the source of truth.

The version is the ELF's e_flags. What changes (anza-xyz/sbpf, SBPFVersion):

  v0  the original encoding; syscalls are `call -1` + a named relocation
  v1  v0 + dynamic stack frames (`add64 r10, imm`); same encoding
  v2  SIMD-0173/0174: no lddw (addresses are `mov32` + `hor64`), memory
      instructions moved into the ALU classes, mul/div/mod moved to a PQR
      class (0x06), callx names its register in `src`
  v3  v0's encoding plus SIMD-0178 static syscalls (`call` src=0, imm =
      murmur3 hash of the name), SIMD-0189 fixed layout (.rodata at 0, .text
      at 1<<32, no relocations), jmp32 in class 0x06, callx register in `dst`
"""
from dataclasses import dataclass, asdict
import struct

OP_LDDW = 0x18
OP_CALL = 0x85
OP_EXIT = 0x95
OP_MOV32_IMM = 0xB4
OP_HOR64 = 0xF7
SUPPORTED_VERSIONS = (0, 1, 2, 3)

# Every syscall the SDK defines (solana-define-syscall 5.3.0, definitions.rs),
# plus older ones still found in deployed programs. v3 programs call them by
# murmur3_32 hash, so the names are recovered from this table.
SYSCALL_NAMES = """abort sol_panic_ sol_log_ sol_log_64_ sol_log_compute_units_ sol_log_pubkey sol_log_data
sol_create_program_address sol_try_find_program_address sol_sha256 sol_keccak256 sol_keccak_p1600 sol_blake3
sol_sha512 sol_secp256k1_recover sol_poseidon sol_get_clock_sysvar sol_get_epoch_schedule_sysvar
sol_get_fees_sysvar sol_get_rent_sysvar sol_get_last_restart_slot sol_get_epoch_rewards_sysvar sol_get_sysvar
sol_memcpy_ sol_memmove_ sol_memcmp_ sol_memset_ sol_invoke_signed_c sol_invoke_signed_rust sol_alloc_free_
sol_set_return_data sol_get_return_data sol_get_stack_height sol_get_processed_sibling_instruction
sol_curve_validate_point sol_curve_group_op sol_curve_multiscalar_mul sol_curve_pairing_map sol_curve_decompress
sol_alt_bn128_group_op sol_alt_bn128_compression sol_big_mod_exp sol_remaining_compute_units sol_get_epoch_stake
sol_get_leader""".split()


def murmur3_32(data, seed=0):
    """The hash SBPF uses for syscall and function keys."""
    def rotl(x, r):
        return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF
    h, n = seed, len(data) // 4
    for i in range(n):
        k = (int.from_bytes(data[4 * i:4 * i + 4], "little") * 0xCC9E2D51) & 0xFFFFFFFF
        h ^= (rotl(k, 15) * 0x1B873593) & 0xFFFFFFFF
        h = (rotl(h, 13) * 5 + 0xE6546B64) & 0xFFFFFFFF
    tail = data[4 * n:]
    if tail:
        k = (int.from_bytes(tail, "little") * 0xCC9E2D51) & 0xFFFFFFFF
        h ^= (rotl(k, 15) * 0x1B873593) & 0xFFFFFFFF
    h ^= len(data)
    h = ((h ^ (h >> 16)) * 0x85EBCA6B) & 0xFFFFFFFF
    h = ((h ^ (h >> 13)) * 0xC2B2AE35) & 0xFFFFFFFF
    return h ^ (h >> 16)


SYSCALL_BY_HASH = {murmur3_32(n.encode()): n for n in SYSCALL_NAMES}


def elf_version(raw):
    """SBPF version of an ELF (its e_flags)."""
    flags = struct.unpack_from("<I", raw, 0x30)[0]
    if flags not in SUPPORTED_VERSIONS:
        raise SystemExit(f"ELF e_flags={flags}: SBPF version {flags} is not supported (0-3 are)")
    return flags


def insn_size(code, i, version=0):
    """lddw is the only 16-byte instruction, and v2 removed it."""
    return 16 if code[i] == OP_LDDW and version != 2 and i + 16 <= len(code) else 8


def is_jump_opcode(op, version=0):
    """Branches (not call/exit): class 0x05, plus jmp32 (0x06) from v3. In v2
    class 0x06 is arithmetic (PQR)."""
    cls = op & 7
    return (cls == 5 or (cls == 6 and version != 2)) and (op & 0xF0) not in (0x80, 0x90)


def internal_call_target(code, i, version=0):
    """Target offset of a pc-relative internal call at i, else None. Before v3
    a syscall is also `call` (src=1, imm=-1, plus a relocation); from v3 a
    syscall is `call` with src=0 and the name's hash."""
    if code[i] != OP_CALL or (code[i + 1] >> 4) != 1:
        return None
    imm = struct.unpack_from("<i", code, i + 4)[0]
    if version < 3 and imm == -1:
        return None
    return i + 8 + 8 * imm

ALU = {
    0x00: "add", 0x10: "sub", 0x20: "mul", 0x30: "div",
    0x40: "or", 0x50: "and", 0x60: "lsh", 0x70: "rsh",
    0x80: "neg", 0x90: "mod", 0xA0: "xor", 0xB0: "mov",
    0xC0: "arsh", 0xD0: "end",
}
JMP = {
    0x00: "ja", 0x10: "jeq", 0x20: "jgt", 0x30: "jge",
    0x40: "jset", 0x50: "jne", 0x60: "jsgt", 0x70: "jsge",
    0x80: "call", 0x90: "exit", 0xA0: "jlt", 0xB0: "jle",
    0xC0: "jslt", 0xD0: "jsle",
}
SIZE = {0x00: "w", 0x08: "h", 0x10: "b", 0x18: "dw"}


@dataclass
class Insn:
    pc: int
    size: int
    opcode: int
    dst: int
    src: int
    off: int
    imm: int
    text: str
    target: int | None = None
    imm64: int | None = None
    jump: bool = False

    def json(self):
        return asdict(self)


def signed32(x):
    return x - (1 << 32) if x & (1 << 31) else x


def reg(n):
    return f"r{n}"


def mem(dst, off):
    return f"[{reg(dst)}{off:+d}]" if off else f"[{reg(dst)}]"


PQR = {0x20: "uhmul", 0x40: "udiv", 0x60: "urem", 0x80: "lmul", 0xA0: "shmul", 0xC0: "sdiv", 0xE0: "srem"}
V2_SIZES = {0x20: "b", 0x30: "h", 0x80: "w", 0x90: "dw"}


def decode_one(code, pc, syscall_names=None, version=0):
    if pc + 8 > len(code):
        raise ValueError("truncated SBPF instruction")
    opcode, regs, off, raw_imm = struct.unpack_from("<BBhi", code, pc)
    dst, src = regs & 15, regs >> 4
    imm = raw_imm
    cls, op = opcode & 7, opcode & 0xF0
    target, imm64 = None, None
    size = 8
    jump = is_jump_opcode(opcode, version)

    if version == 2 and cls == 0x04 and opcode & 8 and op in V2_SIZES:      # moved loads
        text = f"ldx{V2_SIZES[op]} {reg(dst)}, {mem(src, off)}"
    elif version == 2 and cls == 0x07 and op in V2_SIZES:                   # moved stores
        text = (f"stx{V2_SIZES[op]} {mem(dst, off)}, {reg(src)}" if opcode & 8
                else f"st{V2_SIZES[op]} {mem(dst, off)}, {imm}")
    elif version == 2 and cls == 0x06:                                      # PQR arithmetic
        bits = 64 if opcode & 0x10 else 32
        rhs = reg(src) if opcode & 8 else str(imm)
        text = f"{PQR.get(opcode & 0xE0, f'pqr{opcode:#x}')}{bits} {reg(dst)}, {rhs}"
    elif version == 2 and opcode == OP_HOR64:
        text = f"hor64 {reg(dst)}, 0x{imm & 0xFFFFFFFF:x}"
    elif opcode == OP_LDDW and version != 2:
        if pc + 16 > len(code):
            raise ValueError("truncated lddw")
        hi = struct.unpack_from("<I", code, pc + 12)[0]
        imm64 = (raw_imm & 0xFFFFFFFF) | (hi << 32)
        text = f"lddw {reg(dst)}, 0x{imm64:x}"
        size = 16
    elif cls in (0x00, 0x01, 0x02, 0x03):
        width = SIZE.get(opcode & 0x18, f"size{opcode & 0x18:#x}")
        mode = opcode & 0xE0
        if cls == 0x01 and mode == 0x60:       # LDX MEM
            text = f"ldx{width} {reg(dst)}, {mem(src, off)}"
        elif cls == 0x03 and mode == 0x60:     # STX MEM
            text = f"stx{width} {mem(dst, off)}, {reg(src)}"
        elif cls == 0x02 and mode == 0x60:     # ST MEM
            text = f"st{width} {mem(dst, off)}, {imm}"
        elif cls == 0x03 and mode == 0xC0:     # atomic operations
            text = f"atomic{op:#x} {mem(dst, off)}, {reg(src)}"
        else:
            text = f"load/store op=0x{opcode:02x} dst={dst} src={src} off={off} imm={imm}"
    elif cls in (0x04, 0x07):
        name = ALU.get(op, f"alu{op:#x}")
        bits = 32 if cls == 0x04 else 64
        if op == 0x80:
            text = f"neg{bits} {reg(dst)}"
        elif op == 0xD0:                       # 0xd4 = le, 0xdc = be (source bit)
            text = f"{'be' if opcode & 8 else 'le'}{imm} {reg(dst)}"
        else:
            rhs = reg(src) if opcode & 8 else str(imm)
            text = f"{name}{bits} {reg(dst)}, {rhs}"
    elif cls in (0x05, 0x06):
        name = JMP.get(op, f"jmp{op:#x}")
        suffix = "32" if cls == 0x06 else ""
        if name == "exit":
            text = "exit"
        elif name == "call":
            if opcode & 8:                     # callx: the register is in imm (v0/v1), src (v2), dst (v3)
                text = f"callx {reg(src if version == 2 else dst if version == 3 else imm & 15)}"
            elif syscall_names and pc in syscall_names:
                text = f"call {syscall_names[pc]}"
            elif version == 3 and src == 0:    # static syscall: imm is the name's hash
                name_ = SYSCALL_BY_HASH.get(imm & 0xFFFFFFFF)
                text = f"call {name_}" if name_ else f"call syscall_0x{imm & 0xFFFFFFFF:08x}"
            elif src == 1 and (version == 3 or imm != -1):  # imm -1 = relocated syscall, not a self-call
                target = pc + 8 + imm * 8
                text = f"call 0x{target:x}"
            else:
                text = f"call syscall_0x{imm & 0xFFFFFFFF:08x}"
        elif name == "ja":
            target = pc + 8 + off * 8
            text = f"ja 0x{target:x}"
        else:
            rhs = reg(src) if opcode & 8 else str(imm)
            target = pc + 8 + off * 8
            text = f"{name}{suffix} {reg(dst)}, {rhs}, 0x{target:x}"
    else:
        text = f".byte 0x{opcode:02x} ; dst={dst} src={src} off={off} imm={imm}"
    return Insn(pc, size, opcode, dst, src, off, imm, text, target, imm64, jump)


def decode(code, syscall_names=None, version=0):
    """Decode from offset zero; SBPF instructions are fixed-width except lddw.
    syscall_names: optional {text offset: name} from the ELF's relocations."""
    out, pc = [], 0
    while pc + 8 <= len(code):
        ins = decode_one(code, pc, syscall_names, version)
        out.append(ins)
        pc += ins.size
    if pc != len(code):
        out.append(Insn(pc, len(code) - pc, -1, 0, 0, 0, 0,
                        f".byte {code[pc:].hex()} ; trailing bytes"))
    return out


def is_branch(ins):
    return ins.jump


def is_exit(ins):
    return ins.opcode == OP_EXIT


def is_internal_call(ins):
    return ins.opcode == OP_CALL and ins.target is not None


def discover_starts(insns, text_size, pointer_targets=()):
    """Conservative stripped-binary function starts.

    Direct internal calls, entry zero and code pointers are strong evidence.
    The instruction after an exit is only a start if no branch crosses it:
    functions with several exits keep code after an early exit.
    """
    import bisect
    strong = {0} | {x for x in pointer_targets if 0 <= x < text_size}
    strong |= {i.target for i in insns if is_internal_call(i) and 0 <= i.target < text_size}
    strong_sorted = sorted(strong)
    branches = [(i.pc, i.target) for i in insns if is_branch(i) and i.target is not None]
    srcs = [s for s, _ in branches]

    def crossed(s):
        k = bisect.bisect_right(strong_sorted, s) - 1
        lo_pc = strong_sorted[k] if k >= 0 else 0
        hi_pc = strong_sorted[k + 1] if k + 1 < len(strong_sorted) else text_size
        lo, hi = bisect.bisect_left(srcs, lo_pc), bisect.bisect_left(srcs, hi_pc)
        return any(src < s <= t or t < s <= src for src, t in branches[lo:hi])

    starts = set(strong)
    for ins in insns:
        nxt = ins.pc + ins.size
        if is_exit(ins) and nxt < text_size and nxt not in strong and not crossed(nxt):
            starts.add(nxt)
    return sorted(starts)


def function_ranges(insns, starts, text_size, symbols=None):
    """Return function records. Exact ELF symbols win over heuristic starts."""
    if symbols:
        return [dict(name=nm, offset=off, size=size, boundary="symtab")
                for nm, off, size, _aliases in symbols]
    ranges = []
    for i, start in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else text_size
        if end > start:
            ranges.append(dict(name=f"fn_{start:08x}", offset=start,
                               size=end - start, boundary="heuristic"))
    return ranges


def slice_instructions(insns, start, size):
    return [x for x in insns if start <= x.pc < start + size]


def basic_blocks(insns, start, size):
    """Build a CFG without following jumps outside the current function."""
    body = slice_instructions(insns, start, size)
    if not body:
        return []
    by_pc = {x.pc: x for x in body}
    leaders = {body[0].pc}
    for i, ins in enumerate(body):
        if is_branch(ins):
            if ins.target in by_pc:
                leaders.add(ins.target)
            if i + 1 < len(body):
                leaders.add(body[i + 1].pc)
        if is_exit(ins) and i + 1 < len(body):
            leaders.add(body[i + 1].pc)
    ordered = sorted(leaders)
    blocks = []
    for i, leader in enumerate(ordered):
        end = ordered[i + 1] if i + 1 < len(ordered) else start + size
        instructions = [x for x in body if leader <= x.pc < end]
        if not instructions:
            continue
        last = instructions[-1]
        successors = []
        if is_branch(last):
            if last.target in by_pc:
                successors.append(last.target)
            if last.opcode & 0xF0 != 0 and last.pc + last.size < start + size:
                successors.append(last.pc + last.size)
        elif not is_exit(last) and last.pc + last.size < start + size:
            successors.append(last.pc + last.size)
        blocks.append(dict(start=leader, end=end,
                           instructions=[x.json() for x in instructions],
                           successors=sorted(set(successors))))
    return blocks


def printable(raw, limit=72):
    out = ""
    for b in raw[:limit]:
        if 32 <= b < 127 and chr(b) not in ('"', "\\"):
            out += chr(b)
        elif b == 10:
            out += "\\n"
        elif b == 9:
            out += "\\t"
        elif b == 0:
            break
        else:
            out += f"\\x{b:02x}"
    if len(raw) > limit:
        out += "…"
    return out


def data_reference(value, data_sections):
    for name, addr, size, raw in data_sections:
        if addr <= value < addr + size:
            off = value - addr
            return dict(section=name, offset=off, preview=printable(raw[off:off + 96]))
    return None

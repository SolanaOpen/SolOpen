#!/usr/bin/env python3
"""
linkorder.py — recover the original function (link) order automatically.

This is the step the daosfun repo did as a one-off. A normal build places
functions in a different order than the deployed program, so the bytes can't
match even when every function is right. Moving a function only changes two
kinds of instruction bytes in sBPF:

  call imm   (opcode 0x85)  — call targets are relocated
  lddw imm64 (opcode 0x18)  — 64-bit loads of rodata/function addresses

Masking those immediates gives every function a position-independent
fingerprint. We find each of YOUR compiled functions inside the ORIGINAL
.text, which tells us where it sat, and therefore the order to link in.

What you get:
  - order-mapping.json   original offset ↔ your function, like the repo's file
  - symbol-order.txt     for lld:  -C link-arg=--symbol-ordering-file=<this>
  - text-order.ld        a .text { … } fragment listing input sections in order
  - unmatched functions  YOUR version of these doesn't match yet → fix source
  - uncovered ranges     code in the original nothing of yours reproduces yet

It never copies bytes from the original into anything — the original is only
searched. stdlib only.

  python3 linkorder.py --original capture/<id>/program.so \\
                       --candidate target/<sbf target>/release/<name>.so \\
                       --out order/
(--candidate must be the UNSTRIPPED build output so it still has symbols.)
"""
import sys, os, struct, json, argparse
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sbf

OP_CALL, OP_LDDW = 0x85, 0x18
KEY = 24       # bytes (3 instructions) used to index the original
GAP_OPEN = 64  # tiling cost of starting a separate unexplained stretch


# ---------------------------------------------------------------- masking ---
def mask(code, version=0):
    """Zero the relocatable immediates. Walks instruction-by-instruction from
    the start, so it must start on an instruction boundary.

    v0/v1/v3: call targets and lddw values. v3 keeps a syscall's imm (src=0:
    the hash of its name, the same wherever things are laid out). v2 has no
    lddw: an address is `mov32 rX, lo` + `hor64 rX, hi`, so both of those
    immediates are masked."""
    m = bytearray(code)
    i, n = 0, len(m)
    if version == 2:
        for lo, hi in address_pairs(code):
            m[lo + 4:lo + 8] = b"\x00\x00\x00\x00"
            m[hi + 4:hi + 8] = b"\x00\x00\x00\x00"
    while i + 8 <= n:
        op = m[i]
        if op == OP_CALL and not (version == 3 and (m[i + 1] >> 4) == 0):
            m[i + 4:i + 8] = b"\x00\x00\x00\x00"
            i += 8
        elif op == OP_LDDW and version != 2 and i + 16 <= n:
            m[i + 4:i + 8] = b"\x00\x00\x00\x00"
            m[i + 12:i + 16] = b"\x00\x00\x00\x00"
            i += 16
        else:
            i += 8
    return bytes(m)


def address_pairs(code, window=8):
    """v2 address loads: (pc of `mov32 rX, imm`, pc of the `hor64 rX, imm`
    that completes it). LLVM may schedule other instructions in between; the
    mov32 is the nearest earlier write of rX."""
    out = []
    for hi in range(0, len(code) - 7, 8):
        if code[hi] != sbf.OP_HOR64:
            continue
        r = code[hi + 1] & 15
        for lo in range(hi - 8, max(-8, hi - 8 * window), -8):
            if lo < 0:
                break
            op, dst = code[lo], code[lo + 1] & 15
            if dst == r and op == sbf.OP_MOV32_IMM:
                out.append((lo, hi))
                break
            if (dst == r and _writes_dst_v2(op)) or op in (OP_CALL, OP_CALL | 8):
                break                     # rX written by something else first
    return out


_V2_STORES = {0x27, 0x37, 0x87, 0x97, 0x2F, 0x3F, 0x8F, 0x9F}


def _writes_dst_v2(op):
    """Whether a v2 instruction writes its dst register (ALU, loads, PQR — not
    stores, whose dst is the address base, and not jumps)."""
    cls = op & 7
    return cls in (4, 6) or (cls == 7 and op not in _V2_STORES)


# ---------------------------------------------------------------- ELF glue --
def _sections(b):
    if len(b) < 64 or b[:4] != b"\x7fELF" or b[4] != 2:
        raise SystemExit("not a 64-bit ELF")
    shoff = struct.unpack_from("<Q", b, 0x28)[0]
    shentsize = struct.unpack_from("<H", b, 0x3A)[0]
    shnum = struct.unpack_from("<H", b, 0x3C)[0]
    shstrndx = struct.unpack_from("<H", b, 0x3E)[0]
    rows = []
    for i in range(shnum):
        o = shoff + i * shentsize
        name, typ = struct.unpack_from("<II", b, o)
        flags = struct.unpack_from("<Q", b, o + 0x08)[0]
        addr, off, size = struct.unpack_from("<QQQ", b, o + 0x10)
        link, info = struct.unpack_from("<II", b, o + 0x28)
        entsize = struct.unpack_from("<Q", b, o + 0x38)[0]
        rows.append(dict(idx=i, name_off=name, type=typ, flags=flags, addr=addr, off=off, size=size,
                         link=link, entsize=entsize))
    strtab = rows[shstrndx]["off"]
    for r in rows:
        e = b.index(b"\x00", strtab + r["name_off"])
        r["name"] = b[strtab + r["name_off"]:e].decode("latin1")
    return rows


def text_of(b):
    for s in _sections(b):
        if s["name"] == ".text":
            return s, b[s["off"]:s["off"] + s["size"]]
    raise SystemExit("no .text section")


def functions_of(b):
    """FUNC symbols in .text from .symtab: [(name, text_rel_offset, size)]."""
    secs = _sections(b)
    text = next(s for s in secs if s["name"] == ".text")
    symtab = next((s for s in secs if s["type"] == 2), None)  # SHT_SYMTAB
    if symtab is None:
        raise SystemExit("candidate has no .symtab — pass the UNSTRIPPED build output "
                         "(target/<sbf target>/release/<name>.so), not the stripped deploy .so")
    strs = secs[symtab["link"]]
    out = {}
    for k in range(symtab["size"] // 24):
        o = symtab["off"] + k * 24
        st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from("<IBBHQQ", b, o)
        if (st_info & 0xF) != 2 or st_shndx != text["idx"] or st_size == 0:  # STT_FUNC in .text
            continue
        e = b.index(b"\x00", strs["off"] + st_name)
        nm = b[strs["off"] + st_name:e].decode("latin1")
        rel = st_value - text["addr"]
        # aliases share an address; keep the first name, record the others
        out.setdefault(rel, [nm, rel, st_size, []])
        if out[rel][0] != nm:
            out[rel][3].append(nm)
    return sorted(out.values(), key=lambda x: x[1]), text


# ---------------------------------------------------------------- matching --
def decode_calls(text, version=0):
    """pc -> target for every internal (pc-relative, src=1) call in a linked
    .text. Decoded from offset 0 so lddw's 16-byte form keeps us in sync.
    Before v3 a syscall is also `call` with src=1, but imm = -1 and a named
    R_BPF_64_32 relocation; it is not a call to the instruction itself."""
    calls, i, n = {}, 0, len(text)
    while i + 8 <= n:
        t = sbf.internal_call_target(text, i, version)
        if t is not None:
            calls[i] = t
        i += sbf.insn_size(text, i, version)
    return calls


def decode_lddw(text, version=0):
    """pc -> 64-bit value for every address load in a linked .text: lddw, or
    in v2 the mov32 + hor64 pair (keyed by the mov32)."""
    out, i, n = {}, 0, len(text)
    if version == 2:
        for lo, hi in address_pairs(text):
            out[lo] = (struct.unpack_from("<I", text, lo + 4)[0]
                       | (struct.unpack_from("<I", text, hi + 4)[0] << 32))
        return out
    while i + 8 <= n:
        if text[i] == OP_LDDW and i + 16 <= n:
            out[i] = (struct.unpack_from("<I", text, i + 4)[0]
                      | (struct.unpack_from("<I", text, i + 12)[0] << 32))
            i += 16
        else:
            i += 8
    return out


def after_exit_starts(text, strong, version=0):
    """Positions right after an exit that no branch jumps across. A function
    with several exits has code after an early exit that a branch still
    reaches; treating that as a function start lets a small look-alike body
    be tiled into the tail of a broken function."""
    import bisect
    n = len(text)
    br, i = [], 0
    while i + 8 <= n:
        op = text[i]
        if sbf.insn_size(text, i, version) == 16:
            i += 16; continue
        if sbf.is_jump_opcode(op, version):
            br.append((i, i + 8 + 8 * struct.unpack_from("<h", text, i + 2)[0]))
        i += 8
    srcs = [a for a, _ in br]
    st = sorted(strong)
    out = set()
    for e in range(0, n - 8, 8):
        if text[e] != 0x95:
            continue
        s = e + 8
        k = bisect.bisect_right(st, s) - 1
        a = st[k] if k >= 0 else 0
        b = st[k + 1] if k + 1 < len(st) else n
        lo, hi = bisect.bisect_left(srcs, a), bisect.bisect_left(srcs, b)
        if not any(src < s <= t or t < s <= src for src, t in br[lo:hi]):
            out.add(s)
    return out


R_BPF_64_RELATIVE = 8


def relative_words(b, secs=None):
    """Addresses of data words the loader relocates (R_BPF_64_RELATIVE outside
    .text): exactly the words in .data.rel.ro & co. that hold pointers."""
    secs = secs or _sections(b)
    rel = next((s for s in secs if s["name"] == ".rel.dyn"), None)
    text = next((s for s in secs if s["name"] == ".text"), None)
    if rel is None:
        return None
    out = set()
    for k in range(rel["size"] // 16):
        off, info = struct.unpack_from("<QQ", b, rel["off"] + 16 * k)
        if info & 0xFFFFFFFF == R_BPF_64_RELATIVE and not (
                text and text["addr"] <= off < text["addr"] + text["size"]):
            out.add(off)
    return out


def ptr_value(word, addr, img):
    """Decode a 64-bit data word that may be a pointer. Up to v2 a relocated
    pointer's address is stored in the HIGH 32 bits (low half zero) and the
    loader moves it down. v3 has no relocations: pointers are plain absolute
    addresses, found by v3_pointer_words. Returns (is_pointer, value)."""
    rel = img.get("relative")
    if img.get("version") == 3:
        return (rel is not None and addr in rel), word
    if rel is not None and addr not in rel:
        return False, word
    if word & 0xFFFFFFFF == 0 and word >> 32:
        return True, word >> 32
    return rel is not None, word


def encode_ptr(value, like_word):
    """Inverse of ptr_value for a word that used the high-half encoding."""
    return value << 32 if like_word & 0xFFFFFFFF == 0 else value


def image_of(b):
    """Address map of an ELF for resolving lddw targets: .text placement plus
    the data sections a 64-bit load can point into, and which data words are
    relocated pointers."""
    secs = _sections(b)
    version = sbf.elf_version(b)
    text = next(s for s in secs if s["name"] == ".text")
    # v3 puts .rodata at address 0, so "has an address" can't be the filter
    data = [(s["name"], s["addr"], s["size"], b[s["off"]:s["off"] + s["size"]])
            for s in secs if s["size"] and s["type"] == 1 and s["name"] != ".text"
            and (s["addr"] or (version == 3 and s["flags"] & 2))]
    img = dict(text_addr=text["addr"], text_size=text["size"], data=data, version=version,
               relative=relative_words(b, secs))
    if version == 3:
        img["relative"] = v3_pointer_words(img)
    return img


def v3_pointer_words(img):
    """Data words that hold pointers in a v3 program, which has no relocations
    to say so: code pointers (into .text at 1<<32) and the pointer half of a
    (pointer, length) pair whose bytes are text — &str and panic-location file
    names. Other data pointers can't be told from numbers and are left out."""
    t0, tn = img["text_addr"], img["text_size"]
    out = set()
    for nm, a, sz, raw in img["data"]:
        for o in range(0, sz - 7, 8):
            w = struct.unpack_from("<Q", raw, o)[0]
            if t0 <= w < t0 + tn:
                out.add(a + o)
                continue
            # small numbers pair up too (a table of 3, 1, 4, 1…): demand an
            # address past the first few bytes and at least 3 bytes of text
            if not (a + 8 <= w < a + sz) or o + 16 > sz:
                continue
            n = struct.unpack_from("<Q", raw, o + 8)[0]
            s = raw[w - a:w - a + n]
            if 3 <= n < 4096 and len(s) == n and all(32 <= c < 127 or c in (9, 10) for c in s.rstrip(b"\0")):
                out.add(a + o)
    return out


def data_pointers(img):
    """[(section, offset, decoded value)] for every pointer word in data."""
    out = []
    for nm, a, sz, raw in img["data"]:
        for o in range(0, sz - 7, 8):
            is_ptr, v = ptr_value(struct.unpack_from("<Q", raw, o)[0], a + o, img)
            if is_ptr:
                out.append((nm, o, v))
    return out


def _in_text(x, img):
    t0 = img["text_addr"]
    return t0 <= x < t0 + img["text_size"]


def _word_at(img, x):
    """(is_pointer, value) of the 8-byte data word at address x, or None."""
    for nm, a, sz, raw in img["data"]:
        if a <= x and x + 8 <= a + sz:
            return ptr_value(struct.unpack_from("<Q", raw, x - a)[0], x, img)
    return None


def _pointee(x, img):
    """Position-independent description of the data a pointer x points at:
    content for plain data, 'fn' for a code pointer, and one level of
    indirection for a pointer to a pointer (e.g. a panic Location's file)."""
    for nm, a, sz, raw in img["data"]:
        if a <= x < a + sz:
            chunk = raw[x - a:x - a + 8]
            w = _word_at(img, x)
            if w and w[0]:
                if _in_text(w[1], img):
                    chunk = "fn"              # a pointer to code: layout-dependent value
                else:
                    inner = next((raw2[w[1] - a2:w[1] - a2 + 16] for nm2, a2, sz2, raw2 in img["data"]
                                  if a2 <= w[1] < a2 + sz2), None)
                    chunk = ("->", inner)
            return ("ptr", nm, chunk)
    return None


def object_starts(text, img):
    """Sorted addresses where a data object begins in this build: everything
    the code loads with lddw and everything a data pointer points at. A loaded
    object (vtable, &str, Location…) runs until the next one starts."""
    starts = set(decode_lddw(text, img.get("version", 0)).values()) | {v for _, _, v in data_pointers(img)}
    ends = [a + sz for _, a, sz, _ in img["data"]]
    return sorted(starts | set(ends))


def words_until_next_object(v, img, cap=32):
    import bisect
    bounds = img.get("object_starts")
    if not bounds:
        return 2
    i = bisect.bisect_right(bounds, v)
    nxt = bounds[i] if i < len(bounds) else v + 16
    return max(1, min(cap, (nxt - v) // 8))


def _load(v, img, nwords=2):
    """What a 64-bit load (lddw) points at, in a form that doesn't depend on
    where things were laid out:
      ('text', None, text_off)            a function address
      ('data', sig, [(word, text_off)])   a constant, described by CONTENT; for
                                          relocated data (vtables, &str, panic
                                          Locations) each word is resolved — code
                                          pointers become references, data
                                          pointers become what they point at
      ('const', sig, [])                  a plain 64-bit number"""
    if _in_text(v, img):
        return "text", None, v - img["text_addr"]
    for nm, a, sz, raw in img["data"]:
        if a <= v < a + sz:
            o = v - a
            if "rel" not in nm and img.get("version") != 3:
                return "data", ("data", nm, raw[o:o + 8]), []
            words, tt = [], []
            for w in range(nwords):
                if o + 8 * w + 8 > sz:
                    break
                is_ptr, x = ptr_value(struct.unpack_from("<Q", raw, o + 8 * w)[0], v + 8 * w, img)
                if is_ptr and _in_text(x, img):
                    words.append(("fn",))
                    tt.append((w, x - img["text_addr"]))
                elif is_ptr:
                    words.append(_pointee(x, img) or ("dangling",))
                else:
                    words.append(("raw", x))
            return "data", ("data", nm, tuple(words)), tt
    return "const", ("const", v), []


def match(orig_text, cand_text, cand_funcs, orig_img=None, cand_img=None):
    """Recover the link order by TILING the original .text with your bodies.

    A linked .text is function bodies laid end to end, so we walk the original
    from offset 0 and, at each position, consume the longest of your (masked)
    function bodies that matches there. Each step eats exactly one body, so a
    misplaced tiny stub can't shift everything after it.

    Phase A — geometry: the tiling gives the slot layout. Where nothing of
      yours matches, that's a gap (your source for the function there is wrong
      or missing); we resync at the next plausible function start.
    Phase B — identity: identical-bodied twins share a "class". Calls decide
      which twin sits in which slot: an already-named caller's call site, read
      in the ORIGINAL, points at a slot, and your build says which function
      that call site calls. Unique classes seed it; it runs to a fixpoint.

    orig_text: original .text bytes.  cand_text: your .text bytes.
    cand_funcs: [(name, rel_offset, size)]."""
    import bisect
    version = (orig_img or {}).get("version", 0)
    if cand_img and cand_img.get("version", 0) != version:
        raise SystemExit(f"your build is SBPF v{cand_img.get('version', 0)} but the original is v{version} — "
                         f"build with --target sbpfv{version}-solana-solana" if version else
                         "build for the original's SBPF version (v0: sbf-/sbpf-solana-solana)")
    mo = mask(orig_text, version)
    n = len(mo)
    ocalls = decode_calls(orig_text, version)
    starts = {0} | {t for t in ocalls.values() if 0 <= t < n}
    starts |= after_exit_starts(orig_text, starts, version)
    sorted_starts = sorted(starts)

    size = {nm: s for nm, _, s in cand_funcs}
    crel = {nm: r for nm, r, _ in cand_funcs}
    order = [nm for nm, _, _ in cand_funcs]

    # body classes: identical masked bodies are interchangeable geometry-wise
    classes = defaultdict(list)
    for nm in order:
        classes[mask(cand_text[crel[nm]:crel[nm] + size[nm]], version)].append(nm)
    count = {bd: len(m) for bd, m in classes.items()}
    long_idx = defaultdict(list)          # KEY-byte prefix -> bodies
    short_idx = defaultdict(dict)         # length -> {body: body} for bodies < KEY
    for bd in classes:
        if len(bd) >= KEY:
            long_idx[bd[:KEY]].append(bd)
        else:
            short_idx[len(bd)][bd] = bd

    def bodies_at(p):
        out = [bd for bd in long_idx.get(mo[p:p + KEY], ()) if mo[p:p + len(bd)] == bd]
        for ln, d in short_idx.items():
            bd = d.get(mo[p:p + ln])
            if bd is not None:
                out.append(bd)
        return out

    # ---- Phase A: tile.  Greedy longest-match fails (a 24-byte body can
    # swallow a 16-byte function plus the start of the next one), so solve it
    # properly: cost = original bytes left unexplained, plus GAP_OPEN for each
    # separate gap (so a broken function is reported as one gap instead of
    # being speckled with tiny look-alike stubs). Dynamic programming from the
    # end over (position, in-gap?) states, then a bounded backtracking walk
    # along optimal edges that respects how many copies of each body you have.
    INF = float("inf")
    best = {(n, 0): 0, (n, 1): 0}
    edges = {}
    next_start = {}
    j = len(sorted_starts)
    for p in range(n - 8 - (n % 8), -1, -8):
        while j > 0 and sorted_starts[j - 1] > p:
            j -= 1
        q = sorted_starts[j] if j < len(sorted_starts) else n
        cands = [(best.get((p + len(bd), 0), INF), bd) for bd in bodies_at(p)]
        cands = [(c, bd) for c, bd in cands if c < INF]
        cb = min((c for c, _ in cands), default=INF)
        next_start[p] = q
        for s in (0, 1):
            gap = (q - p) + (0 if s else GAP_OPEN) + best.get((q, 1), INF)
            m = min(cb, gap)
            best[(p, s)] = m
            opt = sorted((bd for c, bd in cands if c == m), key=len, reverse=True)
            edges[(p, s)] = (opt, q if gap == m else None)

    left = dict(count)
    stack, path, budget = [], [], 200000
    p, s, k = 0, 0, 0
    while p < n and budget > 0:
        budget -= 1
        opt, gq = edges[(p, s)]
        choices = opt + ([None] if gq is not None else [])
        while k < len(choices) and choices[k] is not None and left[choices[k]] == 0:
            k += 1
        if k < len(choices):
            c = choices[k]
            stack.append((p, s, k))
            if c is None:
                path.append(("gap", p, gq - p)); p, s, k = gq, 1, 0
            else:
                left[c] -= 1; path.append(("body", p, c)); p, s, k = p + len(c), 0, 0
            continue
        if not stack:
            break
        p, s, k = stack.pop()
        kind, _, c = path.pop()
        if kind == "body":
            left[c] += 1
        k += 1
    if p < n:   # no count-feasible optimal tiling within budget: finish leniently
        while p < n:
            opt, gq = edges[(p, s)]
            c = next((bd for bd in opt if left[bd] > 0), None)
            if c is not None:
                left[c] -= 1; path.append(("body", p, c)); p, s = p + len(c), 0
            else:   # out of copies of every optimal body here: explain it as a gap
                q = next_start[p]
                path.append(("gap", p, q - p)); p, s = q, 1
    slots, gaps = [], []
    for kind, p, x in path:
        if kind == "body":
            slots.append([p, x])
        elif gaps and gaps[-1]["offset"] + gaps[-1]["length"] == p:
            gaps[-1]["length"] += x
        else:
            gaps.append(dict(offset=p, length=x))

    # ---- Phase B: name the slots
    slot_start = [s[0] for s in slots]
    by_start = {s[0]: i for i, s in enumerate(slots)}
    def slot_of(off):
        i = bisect.bisect_right(slot_start, off) - 1
        return i if i >= 0 and off < slots[i][0] + len(slots[i][1]) else None

    fstarts = sorted((crel[nm], nm) for nm in order)
    fkeys = [r for r, _ in fstarts]
    def locate(t):
        i = bisect.bisect_right(fkeys, t) - 1
        if i < 0:
            return None
        r, nm = fstarts[i]
        return (nm, t - r) if t - r < size[nm] else None
    # Function references in each build, keyed (pc, word): direct calls and
    # loads of a function address use word -1; a code pointer found inside a
    # loaded vtable/struct uses its word index.
    orefs = [(pc, -1, t) for pc, t in ocalls.items()]
    crefs = [(pc, -1, t) for pc, t in decode_calls(cand_text, version).items()]
    out_data = defaultdict(dict)      # your fn -> {rel pc: what its lddw loads}
    slot_data_raw = {}                # original pc -> what its lddw loads
    if orig_img and cand_img:
        orig_img = dict(orig_img, object_starts=object_starts(orig_text, orig_img))
        cand_img = dict(cand_img, object_starts=object_starts(cand_text, cand_img))
        for text, img, refs, mine in ((orig_text, orig_img, orefs, False),
                                      (cand_text, cand_img, crefs, True)):
            for pc, v in decode_lddw(text, version).items():
                kind, sig, tt = _load(v, img, words_until_next_object(v, img))
                if kind == "text":
                    refs.append((pc, -1, tt))
                    continue
                refs.extend((pc, w, t) for w, t in tt)
                if not mine:
                    slot_data_raw[pc] = sig
                else:
                    a = locate(pc)
                    if a:
                        out_data[a[0]][a[1]] = sig
    out_calls = defaultdict(list)
    for pc, w, tgt in crefs:
        a, b = locate(pc), locate(tgt)
        if a and b:
            out_calls[a[0]].append(((a[1], w), b[0], b[1]))

    name = [None] * len(slots)
    how = [None] * len(slots)
    used = set()
    conflicts = []
    queue = []
    for i, (p, bd) in enumerate(slots):
        if len(classes[bd]) == 1:
            name[i], how[i] = classes[bd][0], "unique"
            used.add(name[i])
            queue.append(i)
    # original references per slot: rel offset in slot -> (target slot, delta)
    slot_calls = defaultdict(list)
    for pc, w, t in orefs:
        i, j = slot_of(pc), slot_of(t)
        if i is not None and j is not None:
            slot_calls[i].append(((pc - slots[i][0], w), j, t - slots[j][0]))
    slot_key = {i: {k: (j, d) for k, j, d in lst} for i, lst in slot_calls.items()}
    callers_of = defaultdict(set)
    for i, lst in slot_calls.items():
        for _, j, _ in lst:
            callers_of[j].add(i)
    slot_data = defaultdict(dict)
    for pc, c in slot_data_raw.items():
        i = slot_of(pc)
        if i is not None:
            slot_data[i][pc - slots[i][0]] = c

    def data_ok(i, m):
        """Do twin m's constant loads agree (by content) with the original slot?"""
        mine = out_data.get(m, {})
        for k, c in slot_data[i].items():
            o = mine.get(k)
            if o is None or o[0] != c[0]:
                continue                      # not comparable: no evidence
            if c[0] == "const" and o != c:
                return False
            if c[0] == "data" and o[1] == c[1] and o[2] != c[2]:
                return False
        return True
    # (data_ok compares content only; code pointers inside loaded data are
    # handled as references, like calls, in fits()/propagate())

    # Static evidence per slot: which twins load the same constants. If your
    # source differs so that NO twin agrees, ignore it rather than force a miss.
    allowed = {}
    for i, (p, bd) in enumerate(slots):
        cls = classes[bd]
        if len(cls) > 1:
            ok = [m for m in cls if data_ok(i, m)]
            allowed[i] = ok if ok else list(cls)

    def fits(i, m):
        """Does twin m agree with the slot's constants and every named callee?"""
        if i in allowed and m not in allowed[i]:
            return False
        mine = {k: (c, d) for k, c, d in out_calls[m]}
        for k, j, d in slot_calls[i]:
            if name[j] is not None and mine.get(k) not in (None, (name[j], d)):
                return False
        return True

    def assign(i, m, why, queue):
        name[i], how[i] = m, why
        used.add(m)
        queue.append(i)

    def propagate(queue):
        while queue:
            i = queue.pop()
            sk = slot_key.get(i, {})
            # forward: a named caller's reference, read in the original, lands
            # on a slot; your build says which function that reference names
            for k, callee, d in out_calls[name[i]]:
                hit = sk.get(k)
                if hit is None or hit[1] != d:
                    continue
                j = hit[0]
                if name[j] is not None:
                    if name[j] != callee and callee in classes[slots[j][1]]:
                        conflicts.append(dict(caller=name[i], callee=callee, slot=slots[j][0], holds=name[j]))
                    continue
                if callee in classes[slots[j][1]] and callee not in used and fits(j, callee):
                    assign(j, callee, "call-forced", queue)
            # reverse: now that slot i is named, its unnamed callers may be
            # down to one twin whose own calls agree
            for j in callers_of[i]:
                if name[j] is None:
                    ok = [m for m in classes[slots[j][1]] if m not in used and fits(j, m)]
                    if len(ok) == 1:
                        assign(j, ok[0], "callee-forced", queue)
    propagate(queue)

    def settle_data():
        """A twin that only one open slot accepts, or a slot only one free twin
        fits, is decided by its constants."""
        changed = True
        while changed:
            changed = False
            for i in list(allowed):
                if name[i] is None:
                    ok = [m for m in allowed[i] if m not in used and fits(i, m)]
                    if len(ok) == 1:
                        q = []
                        assign(i, ok[0], "data-forced", q)
                        propagate(q)
                        changed = True
    settle_data()

    # Anything still open is a genuine look-alike. Decide the most-constrained
    # slot first (fewest fitting twins), let the choice propagate, repeat — so
    # the arbitrary picks stay consistent with each other.
    while True:
        open_ = []
        for i, (p, bd) in enumerate(slots):
            if name[i] is None:
                free = [m for m in classes[bd] if m not in used]
                if free:
                    good = [m for m in free if fits(i, m)]
                    open_.append((len(good) or 10 ** 9, i, good or free))
        if not open_:
            break
        _, i, choice = min(open_)
        q = []
        assign(i, choice[0], "unresolved-twin", q)
        propagate(q)
        settle_data()

    rows = [dict(original=slots[i][0], candidate=crel[name[i]], symbol=name[i],
                 size=len(slots[i][1]), class_size=len(classes[slots[i][1]]),
                 resolved_by=how[i]) for i in range(len(slots)) if name[i] is not None]

    # ---- Constant order (the repo's constant-order.json, derived for you).
    # Once each slot is named, every constant load pairs YOUR constant's
    # address with the ORIGINAL's. That is where the linker must put each of
    # your constants. Two look-alike functions that differ only in WHICH copy
    # of an identical string they load are interchangeable in .text precisely
    # because this mapping moves the strings with them.
    const_map, const_conflicts = {}, []
    if orig_img and cand_img:
        olw, clw = decode_lddw(orig_text, version), decode_lddw(cand_text, version)
        def where(v, img):
            for nm, a, sz, _ in img["data"]:
                if a <= v < a + sz:
                    return nm, v - a
            return None
        back = {}
        for i in range(len(slots)):
            if name[i] is None:
                continue
            p, r = slots[i][0], crel[name[i]]
            for k in range(0, len(slots[i][1]), 8):
                vo, vc = olw.get(p + k), clw.get(r + k)
                if vo is None or vc is None:
                    continue
                wo, wc = where(vo, orig_img), where(vc, cand_img)
                if not wo or not wc or wo[0] != wc[0]:
                    continue
                key = (wc[0], wc[1])
                if key in const_map and const_map[key]["original"] != wo[1]:
                    const_conflicts.append(dict(section=wc[0], yours=wc[1], original=[const_map[key]["original"], wo[1]],
                                                symbol=name[i]))
                    continue
                const_map.setdefault(key, dict(section=wc[0], yours=wc[1], original=wo[1], first_user=name[i]))
                back.setdefault((wo[0], wo[1]), set()).add(wc[1])
        for (sec, off), ys in back.items():
            if len(ys) > 1:   # two of your constants land on one original spot: you duplicated a constant
                const_conflicts.append(dict(section=sec, original=off, yours=sorted(ys), symbol=None))
    const_rows = sorted(const_map.values(), key=lambda x: (x["section"], x["original"]))

    unmatched = [dict(symbol=nm, size=size[nm], candidate=crel[nm]) for nm in order if nm not in used]
    covered = sum(r["size"] for r in rows)
    by = defaultdict(int)
    for r in rows:
        by[r["resolved_by"]] += 1
    return dict(rows=rows, constants=const_rows, constant_conflicts=const_conflicts[:200],
                unmatched=unmatched, uncovered=gaps, conflicts=conflicts[:200],
                summary=dict(candidate_functions=len(cand_funcs), matched=len(rows),
                             resolved_by=dict(by), call_conflicts=len(conflicts),
                             unmatched=len(unmatched),
                             constants_mapped=len(const_rows), constant_conflicts=len(const_conflicts),
                             original_text_bytes=n, covered_bytes=covered,
                             coverage_pct=round(100 * covered / max(1, n), 2),
                             uncovered_ranges=len(gaps)))


def main():
    ap = argparse.ArgumentParser(description="Recover a Solana program's function link order.")
    ap.add_argument("--original", required=True, help="captured program.so (stripped is fine)")
    ap.add_argument("--candidate", required=True, help="your UNSTRIPPED build output")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    ob = open(a.original, "rb").read()
    cb = open(a.candidate, "rb").read()
    _, otext = text_of(ob)
    funcs, ctext_sec = functions_of(cb)
    ctext = cb[ctext_sec["off"]:ctext_sec["off"] + ctext_sec["size"]]
    # Local symbols can share a name across objects (e.g. two identical
    # closures); identify each function by name AND address internally.
    seen, cand, real, aliases = set(), [], {}, {}
    for nm, rel, size, al in funcs:
        uid = nm if nm not in seen else f"{nm}@0x{rel:x}"
        seen.add(nm)
        cand.append((uid, rel, size))
        real[uid], aliases[uid] = nm, al

    res = match(otext, ctext, cand, image_of(ob), image_of(cb))
    for r in res["rows"]:
        r["id"], r["symbol"] = r["symbol"], real[r["symbol"]]
        r["aliases"] = aliases.get(r["id"], [])
    for u in res["unmatched"]:
        u["id"], u["symbol"] = u["symbol"], real.get(u["symbol"], u["symbol"])
    os.makedirs(a.out, exist_ok=True)
    json.dump(res, open(os.path.join(a.out, "order-mapping.json"), "w"), indent=1)
    with open(os.path.join(a.out, "symbol-order.txt"), "w") as f:
        f.write("\n".join(r["symbol"] for r in res["rows"]) + "\n")
    with open(os.path.join(a.out, "text-order.ld"), "w") as f:
        f.write(".text : {\n" + "".join(f"    *(.text.{r['symbol']})\n" for r in res["rows"])
                + "    *(.text*)\n  } :text\n")

    s = res["summary"]
    print(f"matched {s['matched']}/{s['candidate_functions']} of your functions — resolved by: "
          + ", ".join(f"{k} {v}" for k, v in sorted(s["resolved_by"].items())))
    if s["resolved_by"].get("unresolved-twin"):
        print(f"  {s['resolved_by']['unresolved-twin']} are byte-identical twins nothing distinguishes — "
              "their placement can't change the bytes unless a call into them differs; compare.py will tell you")
    if s["call_conflicts"]:
        print(f"  {s['call_conflicts']} call-graph conflicts — a callee's body matches but a call site "
              "disagrees: usually a different inlining decision in your source")
    print(f"original .text covered: {s['covered_bytes']:,}/{s['original_text_bytes']:,} bytes "
          f"({s['coverage_pct']}%), {s['uncovered_ranges']} uncovered ranges")
    if res["unmatched"]:
        print(f"\n{len(res['unmatched'])} of your functions don't match the original yet — fix these first:")
        for u in sorted(res["unmatched"], key=lambda x: -x["size"])[:25]:
            print(f"  {u['size']:>7} B  {u['symbol'][:90]}")
    if res["uncovered"]:
        big = sorted(res["uncovered"], key=lambda g: -g["length"])[:10]
        print("\nlargest original ranges nothing of yours reproduces yet:")
        for g in big:
            print(f"  .text+0x{g['offset']:x}  {g['length']:,} bytes")
    print(f"\nwrote {a.out}/order-mapping.json, symbol-order.txt, text-order.ld")


if __name__ == "__main__":
    main()

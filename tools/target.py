#!/usr/bin/env python3
"""
target.py — turn a `try` run's to-do list into per-function targets.

For every function of yours that doesn't match the original yet, find the
range of the ORIGINAL it is supposed to become, render both as assembly with
the same names for calls, strings, panic locations and branch targets, diff
them, and score the distance (0 = this function now matches). That turns
"coverage went up or it didn't" into a signal that moves on every edit.

  python3 tools/target.py --run runs/<attempt> --original capture/<ID>/program.so [--out DIR]

How a target is found (strongest first):
  called-by      a function of yours that already matches calls (or loads the
                 address of) the broken one; the same call site in the original
                 says where it lives
  vtable         a matching function loads a vtable/fn table whose entry points
                 at the broken one; the original's table entry gives the place
  same-callees   the original range calls the same already-named functions
  neighbours     it sits between the same matched functions as in your build

Writes <out>/targets.json and one <n>-<name>.diff per target (original on the
left, yours on the right). Never copies bytes from the original into a build.
stdlib only.
"""
import argparse, bisect, difflib, json, re, struct, sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import linkorder as LO  # noqa: E402
import sbf  # noqa: E402
import decompile  # noqa: E402


# ------------------------------------------------------------ demangling ---
_ESC = {"$SP$": "@", "$BP$": "*", "$RF$": "&", "$LT$": "<", "$GT$": ">", "$LP$": "(",
        "$RP$": ")", "$C$": ","}


def demangle(sym):
    """Rust legacy mangling (_ZN…17h<hash>E) -> path, hash. Leaves anything else alone."""
    if not sym.startswith("_ZN") or not sym.endswith("E"):
        return sym, ""
    body, parts, i = sym[3:-1], [], 0
    while i < len(body) and body[i].isdigit():
        j = i
        while j < len(body) and body[j].isdigit():
            j += 1
        n = int(body[i:j])
        parts.append(body[j:j + n])
        i = j + n
    h = ""
    if parts and re.fullmatch(r"h[0-9a-f]{16}", parts[-1]):
        h = parts.pop()[1:]
    out = []
    for p in parts:
        if p.startswith("_$"):
            p = p[1:]
        for k, v in _ESC.items():
            p = p.replace(k, v)
        p = re.sub(r"\$u([0-9a-f]{2,6})\$", lambda m: chr(int(m.group(1), 16)), p)
        out.append(p.replace("..", "::"))
    return "::".join(out), h


def short(sym):
    path, h = demangle(sym)
    return f"{path}#{h[:4]}" if h else path


# ------------------------------------------------------------ one binary ---
class Binary:
    def __init__(self, raw, label):
        self.raw, self.label = raw, label
        self.sec, self.text = LO.text_of(raw)
        self.t0 = self.sec["addr"]
        self.img = LO.image_of(raw)
        self.version = self.img["version"]
        self.img["object_starts"] = LO.object_starts(self.text, self.img)
        self.sys = decompile.syscall_names(raw, self.sec)
        self.insns = sbf.decode(self.text, self.sys, self.version)
        self.pcs = [x.pc for x in self.insns]
        self.calls = LO.decode_calls(self.text, self.version)
        self.lddw = LO.decode_lddw(self.text, self.version)    # v2: keyed by the mov32 of a mov32+hor64 pair
        self.pair_hi = {hi for _lo, hi in LO.address_pairs(self.text)} if self.version == 2 else set()

    def insns_in(self, start, size):
        lo = bisect.bisect_left(self.pcs, start)
        hi = bisect.bisect_left(self.pcs, start + size)
        return self.insns[lo:hi]

    def in_text(self, v):
        return self.t0 <= v < self.t0 + len(self.text)

    def word(self, addr):
        return LO._word_at(self.img, addr)

    def section_of(self, v):
        for nm, a, sz, raw in self.img["data"]:
            if a <= v < a + sz:
                return nm, a, sz, raw
        return None

    def obj_words(self, v):
        return LO.words_until_next_object(v, self.img)

    def code_ptrs_in_object(self, v):
        """[(word index, text offset)] for code pointers inside the object at v."""
        out = []
        for w in range(self.obj_words(v)):
            got = self.word(v + 8 * w)
            if got and got[0] and self.in_text(got[1]):
                out.append((w, got[1] - self.t0))
        return out

    def describe(self, v, name_of, length=None):
        """Layout-independent text for what an lddw loads. `length` is the
        byte count the code pairs with a pointer into plain data (a &str)."""
        if self.in_text(v):
            return f"&{name_of(v - self.t0)}"
        hit = self.section_of(v)
        if not hit:
            return f"0x{v:x}"
        nm, a, sz, raw = hit
        w0, w1 = self.word(v), self.word(v + 8)
        if w0 and w0[0] and not self.in_text(w0[1]) and w1 and not w1[0]:
            target = self.section_of(w0[1])
            if target and 0 < w1[1] < 4096:
                s = target[3][w0[1] - target[1]:w0[1] - target[1] + w1[1]]
                if v + 24 <= a + sz:
                    line, col = struct.unpack_from("<II", raw, v - a + 16)
                    name = s[:-1] if s.endswith(b"\0") else s     # Rust >= 1.89: file name + NUL
                    if name.endswith(b".rs") and 0 < line < 1 << 20 and 0 < col < 1 << 12:
                        return f"panic_location({name.decode('latin1')}:{line}:{col})"
                if all(32 <= c < 127 for c in s):
                    return f'str("{s.decode()[:80]}")'
        ptrs = self.code_ptrs_in_object(v)
        if ptrs:
            return "table[" + ", ".join(f"{w}:{name_of(t)}" for w, t in ptrs[:6]) + \
                   (", …" if len(ptrs) > 6 else "") + "]"
        if "rel" not in nm:
            # Only this object's own bytes: neighbours are laid out differently
            # in each build. An object ends where the next referenced one starts;
            # a nearby `mov rX, n` is its length only if it fits inside that.
            bounds = self.img.get("object_starts") or []
            i = bisect.bisect_right(bounds, v)
            avail = (bounds[i] if i < len(bounds) else a + sz) - v
            n = length if length and length <= avail else min(8, avail)
            chunk = raw[v - a:v - a + n]
            if length and n == length and all(32 <= c < 127 or c in (9, 10) for c in chunk):
                return f'str("{sbf.printable(chunk, 80)}")'
            if len(chunk) > 32:
                import hashlib
                return f"{nm}[{len(chunk)} B {chunk[:16].hex()}… sha {hashlib.sha256(chunk).hexdigest()[:12]}]"
            return f"{nm}[{chunk.hex()}]"
        return f"{nm}+obj"

    def panic_sites(self, start, size):
        sites = []
        for x in self.insns_in(start, size):
            if x.pc in self.lddw:
                d = self.describe(self.lddw[x.pc], lambda t: "")
                if d.startswith("panic_location("):
                    sites.append(d[len("panic_location("):-1])
        return sites

    def render(self, start, size, name_of):
        """Normalized assembly lines for [start, start+size)."""
        lines = []
        body = self.insns_in(start, size)
        for i, x in enumerate(body):
            op = x.opcode
            if op == sbf.OP_CALL and x.target is not None:
                t = f"call {name_of(x.target)}"
            elif op == sbf.OP_CALL and x.pc in self.sys:
                t = f"call {self.sys[x.pc]}"
            elif x.pc in self.lddw:
                length = next((y.imm for y in body[i + 1:i + 6] if y.opcode == 0xB7 and 0 < y.imm <= 4096), None)
                t = f"lddw r{x.dst}, {self.describe(self.lddw[x.pc], name_of, length)}"
            elif x.pc in self.pair_hi:
                t = f"hor64 r{x.dst}  ; high half of the address above"
            elif sbf.is_branch(x) and x.target is not None:
                rel = x.target - start
                where = f"+0x{rel:x}" if 0 <= rel < size else "<outside>"
                t = re.sub(r"0x[0-9a-f]+$", where, x.text)
            else:
                t = x.text
            lines.append(t)
        return lines


def distance(a, b):
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    return sum(max(i2 - i1, j2 - j1) for tag, i1, i2, j1, j2 in sm.get_opcodes() if tag != "equal")


# ------------------------------------------------------------- source map ---
def inside(workspace, rel):
    """True if rel names a file inside the workspace. Paths come from the
    (untrusted) binary's panic strings: never follow them outside."""
    root = Path(workspace).resolve()
    try:
        path = (root / rel).resolve()
    except (OSError, ValueError):
        return False
    return root in path.parents and path.is_file() and not any(
        part in ("target", "vendor", ".git") for part in path.relative_to(root).parts)


def crate_dirs(workspace):
    """lib name -> crate directory, from every Cargo.toml in the workspace."""
    out = {}
    if not workspace:
        return out
    for toml in Path(workspace).rglob("Cargo.toml"):
        if any(p in ("target", "vendor", ".git") for p in toml.relative_to(workspace).parts):
            continue
        text = toml.read_text(errors="replace")
        pkg = re.search(r'(?ms)^\[package\].*?^name\s*=\s*"([^"]+)"', text)
        lib = re.search(r'(?ms)^\[lib\].*?^name\s*=\s*"([^"]+)"', text)
        name = (lib or pkg).group(1).replace("-", "_") if (lib or pkg) else None
        if name:
            out[name] = toml.parent
    return out


def source_file(path, panic_sites, crates, workspace):
    """Best guess of the file defining a function: its own panic locations,
    else its module path."""
    for site in panic_sites:
        f = site.rsplit(":", 2)[0]
        if workspace and inside(workspace, f):
            return f
    for m in re.finditer(r"([a-z_][a-z0-9_]*)((?:::[A-Za-z_][A-Za-z0-9_]*)+)", path):
        crate = m.group(1)
        if crate not in crates:
            continue
        segs = m.group(2).strip(":").split("::")
        root = crates[crate] / "src"
        for k in range(len(segs), 0, -1):
            for cand in (root.joinpath(*segs[:k]).with_suffix(".rs"), root.joinpath(*segs[:k], "mod.rs")):
                if cand.is_file():
                    return cand.relative_to(workspace).as_posix()
        lib = root / "lib.rs"
        if lib.is_file():
            return lib.relative_to(workspace).as_posix()
    return None


# ------------------------------------------------------------- targeting ---
def find_targets(orig, cand, mapping, workspace=None):
    rows = mapping["rows"]
    unmatched = [u for u in mapping["unmatched"] if "candidate" in u]
    gaps = mapping["uncovered"]
    o_named = {r["original"]: r for r in rows}                    # orig offset -> row
    c_to_o = {r["candidate"]: r["original"] for r in rows}
    funcs, _ = LO.functions_of(cand.raw)
    c_starts = sorted((rel, nm, sz) for nm, rel, sz, _ in funcs)
    c_keys = [r for r, _, _ in c_starts]
    by_c = {u["candidate"]: u for u in unmatched}

    def c_locate(t):
        i = bisect.bisect_right(c_keys, t) - 1
        if i < 0:
            return None
        rel, nm, sz = c_starts[i]
        return (rel, nm, t - rel) if t - rel < sz else None

    # original pieces inside the gaps, split at every place a function can start
    o_refs = set(orig.calls.values()) | {v - orig.t0 for v in orig.lddw.values() if orig.in_text(v)}
    o_refs |= {v - orig.t0 for _, _, v in LO.data_pointers(orig.img) if orig.in_text(v)}
    strong = sorted(o_refs | set(o_named) | {0})
    weak = LO.after_exit_starts(orig.text, set(strong))
    pieces = []
    for g in gaps:
        lo, hi = g["offset"], g["offset"] + g["length"]
        cuts = sorted({lo, hi} | {x for x in (o_refs | weak) if lo < x < hi})
        pieces += [(a, b) for a, b in zip(cuts, cuts[1:])]
    piece_at = {a: (a, b) for a, b in pieces}
    piece_starts = sorted(piece_at)

    def piece_of(off):
        i = bisect.bisect_right(piece_starts, off) - 1
        if i >= 0 and off < piece_at[piece_starts[i]][1]:
            return piece_starts[i]
        return None

    votes = defaultdict(lambda: defaultdict(list))                 # cand off -> piece -> reasons

    def vote(u_off, o_target, why):
        p = piece_of(o_target)
        if p is not None and p == o_target:
            votes[u_off][p].append(why)

    for r in rows:
        c, o, size = r["candidate"], r["original"], r["size"]
        for x in cand.insns_in(c, size):
            k = x.pc - c
            if x.opcode == sbf.OP_CALL and x.target is not None:
                hit = c_locate(x.target)
                if hit and hit[0] in by_c and (o + k) in orig.calls:
                    vote(hit[0], orig.calls[o + k] - hit[2], ("called-by", short(r["symbol"])))
            elif x.pc in cand.lddw and (o + k) in orig.lddw:
                vo, vc = orig.lddw[o + k], cand.lddw[x.pc]
                if cand.in_text(vc) and orig.in_text(vo):
                    hit = c_locate(vc - cand.t0)
                    if hit and hit[0] in by_c:
                        vote(hit[0], vo - orig.t0 - hit[2], ("address-taken-by", short(r["symbol"])))
                elif not cand.in_text(vc) and not orig.in_text(vo):
                    o_ptrs = dict(orig.code_ptrs_in_object(vo))
                    for w, t in cand.code_ptrs_in_object(vc):
                        hit = c_locate(t)
                        if hit and hit[0] in by_c and w in o_ptrs:
                            vote(hit[0], o_ptrs[w] - hit[2], ("vtable-of", short(r["symbol"])))

    # names for rendering: matched slots carry your symbol; filled in as we assign
    o_name = {o: short(r["symbol"]) for o, r in o_named.items()}

    def callee_names_c(off, size):
        out = set()
        for x in cand.insns_in(off, size):
            if x.opcode == sbf.OP_CALL and x.target is not None and x.target in c_to_o:
                out.add(o_name[c_to_o[x.target]])
        return out

    def callee_names_o(a, b):
        return {o_name[x.target] for x in orig.insns_in(a, b - a)
                if x.opcode == sbf.OP_CALL and x.target is not None and x.target in o_name}

    piece_callees = {a: callee_names_o(a, b) for a, b in pieces}
    # neighbours in your build: previous/next function that matched
    c_matched = sorted(c_to_o)
    proposals = []
    for u in unmatched:
        off, size = u["candidate"], u["size"]
        mine = callee_names_c(off, size)
        i = bisect.bisect_left(c_matched, off)
        prev_o = c_to_o[c_matched[i - 1]] if i > 0 else None
        next_o = c_to_o[c_matched[i]] if i < len(c_matched) else None
        for a, b in pieces:
            reasons = list(votes[off].get(a, []))
            score = 10.0 * len({x for x in reasons})
            if mine and piece_callees[a]:
                j = len(mine & piece_callees[a]) / len(mine | piece_callees[a])
                if j >= 0.5:
                    score += 3 * j
                    reasons.append(("same-callees", f"{len(mine & piece_callees[a])}/{len(mine | piece_callees[a])}"))
            prev_end = prev_o is not None and prev_o + o_named[prev_o]["size"] == a
            nxt = next_o is not None and next_o == b
            if prev_end or nxt:
                score += 1.0 + (1.0 if prev_end and nxt else 0)
                reasons.append(("neighbours", "between the same matched functions as in your build"))
            if score <= 0:
                continue
            ratio = min(size, b - a) / max(size, b - a)
            proposals.append((score + ratio, ratio, off, a, reasons))
    proposals.sort(key=lambda x: (-x[0], x[2], x[3]))
    assigned_u, assigned_p, pairs = set(), set(), []
    for score, ratio, off, a, reasons in proposals:
        if off in assigned_u or a in assigned_p:
            continue
        assigned_u.add(off); assigned_p.add(a)
        pairs.append((off, a, score, reasons))
    # a function may span several pieces (an early exit cut it): extend over
    # following pieces nobody claimed, up to the next referenced start
    ext = {}
    for off, a, score, reasons in pairs:
        end = piece_at[a][1]
        while end in piece_at and end not in assigned_p and end not in o_refs:
            end = piece_at[end][1]
        ext[a] = end
    for off, a, _, _ in pairs:
        o_name[a] = short(by_c[off]["symbol"])

    def name_o(t):
        if t in o_name:
            return o_name[t]
        p = piece_of(t)
        return f"orig_fn_{t:x}" if p is None or p == t else f"orig_fn_{p:x}+0x{t - p:x}"

    def name_c(t):
        hit = c_locate(t)
        if not hit:
            return f"fn_{t:x}"
        return short(hit[1]) + (f"+0x{hit[2]:x}" if hit[2] else "")

    crates = crate_dirs(workspace)
    targets = []
    for off, a, score, reasons in pairs:
        u = by_c[off]
        end = ext[a]
        left = orig.render(a, end - a, name_o)
        right = cand.render(off, u["size"], name_c)
        path, h = demangle(u["symbol"])
        mine_sites = cand.panic_sites(off, u["size"])
        targets.append(dict(
            symbol=u["symbol"], name=path, hash=h, your_offset=off, your_size=u["size"],
            original_offset=a, original_size=end - a, distance=distance(left, right),
            evidence=[dict(kind=k, detail=d) for k, d in reasons], score=round(score, 2),
            confidence="strong" if any(k in ("called-by", "address-taken-by", "vtable-of") for k, _ in reasons)
                       else "weak",
            panic_sites_original=orig.panic_sites(a, end - a), panic_sites_yours=mine_sites,
            source_file=source_file(path, mine_sites, crates, workspace),
            unmatched_callees=sorted({name_c(x.target) for x in cand.insns_in(off, u["size"])
                                      if x.opcode == sbf.OP_CALL and x.target is not None
                                      and c_locate(x.target) and c_locate(x.target)[0] in by_c}),
            _left=left, _right=right))
    # Functions that match as CODE but load different constants: a panic
    # location's line/column, a string, a number. Their instructions agree, so
    # linkorder counts them as matched, yet the bytes still differ.
    placeholder = re.compile(r"orig_fn_|\bfn_[0-9a-f]+")
    for r in rows:
        o, c, size = r["original"], r["candidate"], r["size"]
        lo = [x for x in orig.render(o, size, name_o) if x.startswith("lddw")]
        lc = [x for x in cand.render(c, size, name_c) if x.startswith("lddw")]
        if len(lo) != len(lc):
            continue
        diffs = [(a, b) for a, b in zip(lo, lc) if a != b and not placeholder.search(a + b)]
        if not diffs:
            continue
        path, h = demangle(r["symbol"])
        mine_sites = cand.panic_sites(c, size)
        targets.append(dict(
            kind="data", symbol=r["symbol"], name=path, hash=h, your_offset=c, your_size=size,
            original_offset=o, original_size=size, distance=len(diffs),
            evidence=[dict(kind="code-matches", detail="same instructions; loads different constants")],
            score=100.0, confidence="strong",
            panic_sites_original=orig.panic_sites(o, size), panic_sites_yours=mine_sites,
            source_file=source_file(path, mine_sites, crates, workspace), unmatched_callees=[],
            _left=[a for a, _ in diffs], _right=[b for _, b in diffs]))
    for t in targets:
        t.setdefault("kind", "code")
    # bottom-up: functions whose callees all match first, then nearest first
    # code before data (a wrong constant is often a consequence of code above
    # it still being off), then bottom-up, then strongest evidence, then nearest
    targets.sort(key=lambda t: (t["kind"] == "data", len(t["unmatched_callees"]), t["confidence"] != "strong",
                                t["distance"]))
    claimed = {a for _, a, _, _ in pairs} | {p for a in ext for p in piece_starts if a < p < ext[a]}
    unclaimed = [dict(original_offset=a, original_size=b - a, callees=sorted(piece_callees[a]),
                      panic_sites=orig.panic_sites(a, b - a))
                 for a, b in pieces if a not in claimed]
    orphans = [dict(symbol=u["symbol"], name=demangle(u["symbol"])[0], size=u["size"])
               for u in unmatched if u["candidate"] not in assigned_u]
    # Original functions with no counterpart that a target calls: describe them
    # by what the binary still says (size, panic lines, strings) so the model can
    # recognise which helper of its source they are.
    by_off = {u["original_offset"]: u for u in unclaimed}
    for t in targets:
        seen, out = set(), []
        for line in t["_left"]:
            for m in re.finditer(r"orig_fn_([0-9a-f]+)\b(?!\+)", line):
                off = int(m.group(1), 16)
                if off in by_off and off not in seen:
                    seen.add(off)
                    u = by_off[off]
                    strings = sorted({m2.group(1)[:60] for x in orig.render(off, u["original_size"], name_o)
                                      for m2 in re.finditer(r'str\("(.*?)"\)', x)})
                    out.append(dict(name=f"orig_fn_{off:x}", size=u["original_size"],
                                    panic_sites=u["panic_sites"][:6], strings=strings[:6], callees=u["callees"][:6]))
        t["missing_callees"] = out
    return targets, unclaimed, orphans


def unified(t, context=3):
    head = (f"# {t['name']}  (yours {t['your_size']} B at .text+0x{t['your_offset']:x}; "
            f"original {t['original_size']} B at .text+0x{t['original_offset']:x})\n"
            f"# distance {t['distance']} instructions; evidence: "
            + "; ".join(f"{e['kind']} {e['detail']}" for e in t["evidence"]) + "\n")
    body = difflib.unified_diff(t["_left"], t["_right"], "original", "yours", lineterm="", n=context)
    return head + "\n".join(body) + "\n"


def run_dir_inputs(run):
    run = Path(run)
    mapping = json.loads((run / "order" / "order-mapping.json").read_text())
    cand = (run / "capture" / "baseline.unstripped.so").read_bytes()
    cmd = run / "command.json"
    ws = json.loads(cmd.read_text()).get("cwd") if cmd.exists() else None
    return mapping, cand, ws


def analyze_run(run, original_path):
    mapping, cand_raw, ws = run_dir_inputs(run)
    orig = Binary(Path(original_path).read_bytes(), "original")
    cand = Binary(cand_raw, "yours")
    targets, unclaimed, orphans = find_targets(orig, cand, mapping, ws)
    return dict(summary=dict(targets=len(targets), strong=sum(t["confidence"] == "strong" for t in targets),
                             total_distance=sum(t["distance"] for t in targets),
                             unclaimed_original_ranges=len(unclaimed), orphans=len(orphans),
                             coverage_pct=mapping["summary"]["coverage_pct"]),
                targets=targets, unclaimed_original=unclaimed, orphans=orphans)


def write(result, out):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    for i, t in enumerate(result["targets"]):
        safe = re.sub(r"[^A-Za-z0-9_]+", "_", t["name"])[-60:]
        t["diff_file"] = f"{i:03d}-{safe}.diff"
        (out / t["diff_file"]).write_text(unified(t))
    clean = dict(result, targets=[{k: v for k, v in t.items() if not k.startswith("_")} for t in result["targets"]])
    (out / "targets.json").write_text(json.dumps(clean, indent=1) + "\n")
    return clean


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", required=True, type=Path, help="a try/attempt directory")
    ap.add_argument("--original", required=True, type=Path)
    ap.add_argument("--out", type=Path, default=None, help="default: <run>/targets")
    a = ap.parse_args()
    res = write(analyze_run(a.run, a.original), a.out or a.run / "targets")
    s = res["summary"]
    print(f"{s['targets']} targets ({s['strong']} with call-graph evidence), total distance "
          f"{s['total_distance']} instructions; {s['unclaimed_original_ranges']} original ranges "
          f"with no function of yours; {s['orphans']} of your functions with no place yet")
    for t in res["targets"][:15]:
        print(f"  d={t['distance']:>4}  {t['confidence']:6}  {t['name'][:80]}  -> .text+0x{t['original_offset']:x}"
              f"  [{t.get('source_file') or '?'}]")
    print(f"wrote {(a.out or a.run / 'targets')}/targets.json and one .diff per target")


if __name__ == "__main__":
    main()

"""Ground-truth test for linkorder.match().

Takes the real daos.fun program, cuts its .text into the 665 functions the
daosfun repo recovered, shuffles them like a fresh build would (re-pointing
calls, function-pointer loads and .data.rel.ro pointers the way a linker
does), then asks linkorder to recover the original order from bytes alone.
Pass = laying the functions out in the recovered order reproduces the
original .text and .data.rel.ro exactly."""
import sys, os, json, random, struct, bisect
HERE = os.path.dirname(os.path.abspath(__file__))
# Inputs: the live daos.fun program (solopen.py fetch 4FqThZWv3QKWkSyXCDmATpWkpEiCHq5yhkdGWpSEDAZM)
# and the daosfun-source repo, used ONLY for the function boundaries the test cuts along.
DAOS_SO = os.environ.get('DAOS_SO', 'capture/4FqThZWv3QKWkSyXCDmATpWkpEiCHq5yhkdGWpSEDAZM/program.so')
DAOS_MAP = os.environ.get('DAOS_MAP', 'daosfun-source/repro/order-mapping.json')
from collections import Counter
sys.path.insert(0, os.path.join(HERE, '..', 'tools')); import linkorder as L
b = open(DAOS_SO, 'rb').read(); sec, otext = L.text_of(b)
TA = sec['addr']; TN = len(otext)
oimg = L.image_of(b)
rows = json.load(open(DAOS_MAP))['rows']
st = sorted({r['original'] - TA for r in rows}); en = st[1:] + [len(otext)]
F = [(f'fn_{i}', s, e - s) for i, (s, e) in enumerate(zip(st, en))]
ostart = {nm: s for nm, s, _ in F}; osize = {nm: n for nm, _, n in F}; okeys = [s for _, s, _ in F]
def oloc(t): j = bisect.bisect_right(okeys, t) - 1; return F[j][0], t - F[j][1]
ocalls = L.decode_calls(otext)
olddw = {pc: v for pc, v in L.decode_lddw(otext).items() if TA <= v < TA + TN}

def layout(order):
    """Lay functions out in this order like a linker: bodies from the original,
    calls and function-address loads re-pointed. Returns (.text, pos)."""
    pos = {}; cur = 0
    for nm in order: pos[nm] = cur; cur += osize[nm]
    out = bytearray(cur)
    for nm in order:
        s, n = ostart[nm], osize[nm]; p = pos[nm]; out[p:p + n] = otext[s:s + n]
        for pc in range(s, s + n, 8):
            np_ = p + (pc - s)
            if pc in ocalls:
                g, d = oloc(ocalls[pc])
                if g in pos: struct.pack_into('<i', out, np_ + 4, (pos[g] + d - (np_ + 8)) // 8)
            if pc in olddw:
                g, d = oloc(olddw[pc] - TA); v = TA + pos.get(g, 0) + d
                struct.pack_into('<I', out, np_ + 4, v & 0xffffffff); struct.pack_into('<I', out, np_ + 12, v >> 32)
    return bytes(out), pos

RELRO_CODE_PTRS = 0
def relro(pos):
    """.data.rel.ro with pointers into .text (vtables, fn tables) re-pointed
    for this layout, in the binary's own encoding (address in the high half)."""
    global RELRO_CODE_PTRS
    nm, a, sz, raw = next(d for d in oimg['data'] if d[0] == '.data.rel.ro')
    r = bytearray(raw); moved = 0
    for o in range(0, sz - 7, 8):
        w = struct.unpack_from('<Q', raw, o)[0]
        is_ptr, v = L.ptr_value(w, a + o, oimg)
        if is_ptr and TA <= v < TA + TN:
            g, d = oloc(v - TA); struct.pack_into('<Q', r, o, L.encode_ptr(TA + pos.get(g, 0) + d, w)); moved += 1
    RELRO_CODE_PTRS = moved
    return bytes(r)

ident, _ = layout([nm for nm, _, _ in F])
assert ident == otext, 'self-relink failed'
orig_relro = relro(ostart)
assert orig_relro == next(d for d in oimg['data'] if d[0] == '.data.rel.ro')[3]
assert RELRO_CODE_PTRS > 0, 'harness found no code pointers in .data.rel.ro — vtables would go untested'

def run(seed, use_img=True):
    random.seed(seed); sh = F[:]; random.shuffle(sh)
    ctext, pos = layout([nm for nm, _, _ in sh])           # "your fresh build"
    cimg = dict(oimg); cimg['data'] = [(n, a, s, relro(pos) if n == '.data.rel.ro' else raw)
                                      for n, a, s, raw in oimg['data']]
    cand = [(nm, pos[nm], osize[nm]) for nm, _, _ in sh]
    res = L.match(otext, ctext, cand, oimg if use_img else None, cimg if use_img else None)
    emit = [r['symbol'] for r in res['rows']]
    assert len(emit) == 665 and len(set(emit)) == 665, (len(emit), len(set(emit)))
    rtext, rpos = layout(emit)
    # apply the recovered constant order, as the linker script would: each of
    # your constants is placed where the original had it
    cmap = {c['yours']: c['original'] for c in res['constants'] if c['section'] == '.rodata'}
    ro_a = next(a for n, a, s, raw in oimg['data'] if n == '.rodata')
    rt = bytearray(rtext)
    for pc, v in L.decode_lddw(rtext).items():
        if ro_a <= v < ro_a + 20819 and (v - ro_a) in cmap:
            nv = ro_a + cmap[v - ro_a]
            struct.pack_into('<I', rt, pc + 4, nv & 0xffffffff); struct.pack_into('<I', rt, pc + 12, nv >> 32)
    rtext = bytes(rt)
    rrelro = relro(rpos)
    dt = sum(1 for i in range(len(otext)) if rtext[i] != otext[i])
    dr = sum(1 for i in range(len(orig_relro)) if rrelro[i] != orig_relro[i])
    return res, emit, dt, dr

if __name__ == '__main__':
    ok = True
    seeds = [int(x) for x in sys.argv[1:]] or list(range(1, 9))
    for seed in seeds:
        res, emit, dt, dr = run(seed)
        s = res['summary']
        same = dt == 0 and dr == 0
        ok &= same
        print(f"seed {seed}: gaps {s['uncovered_ranges']} needs_fix {s['unmatched']} conflicts {s['call_conflicts']} "
              f"{dict(sorted(s['resolved_by'].items()))} consts {s['constants_mapped']}/{s['constant_conflicts']}c | relink: "
              + ('IDENTICAL .text + .data.rel.ro' if same else f'{dt} .text / {dr} .data.rel.ro bytes differ'))
    print('ALL IDENTICAL' if ok else 'NOT ALL IDENTICAL')

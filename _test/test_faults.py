"""Fault test: the candidate has 3 functions with wrong source (one opcode
changed), 1 function missing and 1 extra function. linkorder must name the
wrong ones in needs_fix, report gaps exactly where they sat in the original,
and still place everything else correctly."""
import sys, os; sys.argv = [sys.argv[0]]
exec(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'test_order.py')).read().split("if __name__")[0])
random.seed(42); sh = F[:]; random.shuffle(sh)
bad = {'fn_120', 'fn_300', 'fn_500'}; missing = 'fn_200'
sh = [x for x in sh if x[0] != missing]
ctext, pos = layout([nm for nm, _, _ in sh])
ct = bytearray(ctext)
for nm in bad:                                   # break one non-immediate byte
    p = pos[nm]; ct[p + 2] ^= 0x01               # dst/src register nibble of first insn
extra = bytes.fromhex('b700000000000000' '9500000000000000') * 3   # a 48-byte function nobody has
cand = [(nm, pos[nm], osize[nm]) for nm, _, _ in sh] + [('extra_fn', len(ct), len(extra))]
ct += extra
cimg = dict(oimg); cimg['data'] = [(n, a, s, relro(pos) if n == '.data.rel.ro' else raw) for n, a, s, raw in oimg['data']]
res = L.match(otext, bytes(ct), cand, oimg, cimg)
s = res['summary']
print('summary', s)
print('needs_fix', sorted(u['symbol'] for u in res['unmatched']))
print('gaps', res['uncovered'])
want = sorted([ostart[nm] for nm in bad | {missing}])
got = sorted(g['offset'] for g in res['uncovered'])
truth = {s_: nm for nm, s_, _ in F}
off_boundary = [r for r in res['rows'] if r['original'] not in truth]
wrong = [r for r in res['rows'] if r['original'] in truth and truth[r['original']] != r['symbol']
         and osize[truth[r['original']]] == r['size'] and r['class_size'] == 1]
for nm in sorted(bad | {missing}):
    print(nm, 'true slot', ostart[nm], 'size', osize[nm])
# assert, don't just print: this test has to be able to fail
assert got == want, f'gap offsets {got} != broken/missing slots {want}'
assert sorted(u['symbol'] for u in res['unmatched']) == sorted(bad | {'extra_fn'}), 'needs_fix != broken + extra'
assert not off_boundary, f'bodies placed off a function boundary: {off_boundary}'
assert not wrong, f'unique-body functions misplaced: {wrong}'
print('FAULT TEST PASSED')

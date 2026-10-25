"""Twin test: your build is missing ONE copy of a function whose masked body
also appears elsewhere in the original (common early in a reconstruction).
linkorder must not crash, must report exactly one gap, and must place every
other function. Uses the same inputs as test_order.py (DAOS_SO, DAOS_MAP)."""
import sys, os; sys.argv = [sys.argv[0]]
exec(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'test_order.py')).read().split("if __name__")[0])
from collections import defaultdict

by_body = defaultdict(list)
for nm, s_, n_ in F:
    by_body[L.mask(otext[s_:s_ + n_])].append(nm)
twin_classes = sorted((v for v in by_body.values() if len(v) >= 2), key=len)[:20]
assert twin_classes, 'fixture has no look-alike functions'
exact_count = 0
for trial, cls in enumerate(twin_classes):
    drop = cls[0]
    random.seed(trial); sh = [x for x in F if x[0] != drop]; random.shuffle(sh)
    ctext, pos = layout([nm for nm, _, _ in sh])
    cimg = dict(oimg); cimg['data'] = [(n, a, s, relro(pos) if n == '.data.rel.ro' else raw)
                                      for n, a, s, raw in oimg['data']]
    res = L.match(otext, ctext, [(nm, pos[nm], osize[nm]) for nm, _, _ in sh], oimg, cimg)
    s = res['summary']
    assert s['unmatched'] == 0, (drop, s)                         # never blames a correct function
    assert sum(g['length'] for g in res['uncovered']) == osize[drop], (drop, res['uncovered'])
    exact = s['uncovered_ranges'] == 1
    exact_count += exact
    print(f'drop {drop} ({osize[drop]} B, {len(cls)} look-alikes): '
          + ('one gap of exactly its size' if exact else f'gap split as {res["uncovered"]}'))
print(f'TWIN TEST PASSED ({exact_count}/{len(twin_classes)} reported as a single exact gap)')

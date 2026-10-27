#!/usr/bin/env python3
"""Compare Ghidra's listing of an analysed image with MAME unidasm (-arch cpu16) at the same addresses.

  real_compare.py <ghidra-listing> <mame-sweep.txt> <image.bin> <base-hex>

<ghidra-listing> lines: "<addr-hex> <length> <text>" (RealCheck.java). <mame-sweep.txt>: unidasm output of
the whole image (-basepc base). Every Ghidra instruction is looked up at the same address in MAME's
linear sweep and classified with compare.py's rules (exact / semantic / explained); an instruction
MAME's sweep does not start at (it fell out of step on data) is counted separately."""
import os, re, sys
from collections import Counter
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import compare  # noqa: E402

gl, ml, img, base = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4], 16)
data = open(img, 'rb').read()
rx = re.compile(r'([0-9a-f]+): ([0-9a-f ]+?)\s{2,}(.*)$')
recs = [(int(m.group(1), 16), m.group(3).strip()) for m in map(rx.match, open(ml).read().split('\n')) if m]
M = {}
for i, (a, t) in enumerate(recs[:-1]):
    n = recs[i + 1][0] - a
    M[a] = (0, 'BAD') if t.startswith('fdb') else (n, ' '.join(t.split()))
cnt = Counter()
bad = []
for l in open(gl):
    a, n, t = l.rstrip('\n').split(' ', 2)
    a, n = int(a, 16), int(n)
    if a not in M:
        cnt['MAME not in step here'] += 1
        continue
    b = data[a - base:a - base + 16]
    c, why = compare.classify((n, t), M[a], b)
    cnt[c + (f' ({why})' if why else '')] += 1
    if c == 'UNEXPLAINED':
        bad.append((hex(a), b[:n].hex(), t, M[a]))
tot = sum(cnt.values())
print(f'real code vs MAME, {tot} instructions: ' + ', '.join(f'{k} {v}' for k, v in cnt.most_common()))
for e in bad[:20]:
    print('   UNEXPLAINED', e)
sys.exit(1 if bad else 0)

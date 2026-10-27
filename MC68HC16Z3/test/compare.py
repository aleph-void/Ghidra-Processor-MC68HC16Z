#!/usr/bin/env python3
"""Compare Ghidra's decode (DumpSlots output) with MAME unidasm -arch cpu16 (mame_dis.py output).

  compare.py <ghidra.txt> <mame.txt> <corpus.bin> [--show N] [--summary]

Every slot is classified:
  exact      same mnemonic and operands after normalising only number notation ($1F / 0x1f / 31),
             case and spacing
  semantic   same instruction: same mnemonic and length, operands equal as numbers/registers after the
             spelling rewrites listed in SPELLING (each with its reason)
  both-bad   neither decodes the slot
  explained  a known difference class from EXPLAINED (each with its reason, confirmed in the manual)
  UNEXPLAINED anything else: the run fails
"""
import re, sys
from collections import Counter, defaultdict

SLOT = 16


def load(p):
    d = {}
    for l in open(p):
        f = l.rstrip('\n').split(' ', 2)
        d[int(f[0])] = (int(f[1]), f[2] if len(f) > 2 else '')
    return d


def num(t):
    neg = t.startswith('-')
    t = t.lstrip('-')
    if t.startswith('$'):
        v = int(t[1:], 16)
    elif t.lower().startswith('0x'):
        v = int(t, 16)
    else:
        v = int(t)
    return -v if neg else v


def norm(text, ghidra, spelling=True):
    """-> (mnemonic, [operands]) with numbers as ints and registers lower case.  With spelling=False
    only the number notation ($hex / 0xhex / decimal), case and spacing are normalised."""
    text = text.strip()
    if ' ' in text:
        mn, ops = text.split(' ', 1)
    else:
        mn, ops = text, ''
    mn = mn.lower()
    out = []
    for o in [x.strip() for x in ops.split(',')] if ops else []:
        o = o.lstrip('#')
        if ghidra and spelling:
            o = {'IX': 'x', 'IY': 'y', 'IZ': 'z'}.get(o, o)
            if re.fullmatch(r'-?0x[0-9a-fA-F]+:-?0x[0-9a-fA-F]+', o):   # bank:addr (IND20)
                b, a = o.split(':')
                o = str((num(b) << 16) | num(a))
        if re.fullmatch(r'-?(\$[0-9A-Fa-f]+|0x[0-9a-fA-F]+|\d+)', o):
            out.append(num(o))
        else:
            out.append(o.lower())
    return mn, out


# Spelling rewrites applied before the semantic comparison: (description, function(mn, ops, slotbytes))
SPELLING = [
    ('PSHM/PULM register lists: MAME prints "cc" and orders K before CCR, and "0" for an empty mask; '
     'the module prints CCR and an empty list. Compared as register sets', 'pshm/pulm'),
    ('MAME prints page-2 ORAA (17x7: IND16 and EXT) as "ora"; the manual (Table 6-36) names it ORAA', 'ora'),
]


def spell(mn, ops, ghidra):
    if mn in ('pshm', 'pulm'):
        regs = set()
        for o in ops:
            if o in (0, ''):
                continue
            regs.add({'cc': 'ccr'}.get(o, o))
        return mn, sorted(regs)
    if mn == 'ora' and not ghidra:
        return 'oraa', ops
    return mn, ops


def classify(g, m, b):
    gl, gt = g
    ml, mt = m
    if gl == 0 and ml == 0:
        return 'both-bad', None
    if gl and ml and gl == ml and norm(gt, True, False) == norm(mt, False, False):
        return 'exact', None
    if gl == ml and gl:
        gn = spell(*norm(gt, True), True)
        mn_ = spell(*norm(mt, False), False)
        if gn == mn_:
            return 'semantic', None
        # equal modulo 8/16/20-bit wrap of numbers
        if gn[0] == mn_[0] and len(gn[1]) == len(mn_[1]) and all(
                x == y or (isinstance(x, int) and isinstance(y, int) and
                           any((x - y) % (1 << w) == 0 for w in (8, 16, 20))) for x, y in zip(gn[1], mn_[1])):
            return 'semantic', 'signedness/width of a displayed number'
    for name, why, f in EXPLAINED:
        if f(g, m, b):
            return 'explained', name
    return 'UNEXPLAINED', None


def _z_nibble(g, m, b):
    return b[0] in (0x7A, 0xFA, 0x4B, 0x5B, 0x6B, 0x89, 0x99, 0xA9) and b[1] >> 4 != 0 and g[0] == 0 and m[0] == 4


def _reserved_mask_bit(g, m, b):
    if b[0] not in (0x34, 0x35) or not b[1] & 0x80 or g[0] != m[0]:
        return False
    gn = spell(*norm(g[1], True), True)
    mt = m[1].replace(', (reserved)', '').replace(' (reserved)', ' 0')
    return gn == spell(*norm(mt, False), False)


def _odd_target(g, m, b):
    if g[0] != m[0] or not g[0]:
        return False
    gn = spell(*norm(g[1], True), True)
    mn_ = spell(*norm(m[1], False), False)
    if gn[0] != mn_[0] or len(gn[1]) != len(mn_[1]) or gn[1][:-1] != mn_[1][:-1]:
        return False
    x, y = gn[1][-1], mn_[1][-1]
    return isinstance(x, int) and isinstance(y, int) and y & 1 and x == (y & 0xFFFFE)


EXPLAINED = [
    ('z nibble', 'JMP/JSR EXT20 and IND20 with a non-zero top nibble: the manual defines that nibble as the '
     '"z" zero extension of the 20-bit operand (Table 6-36 operand notation); the module rejects these '
     'encodings, MAME ignores the nibble', _z_nibble),
    ('PSHM/PULM bit 7', 'mask bit 7 is "(Reserved)" in the manual; MAME prints "(reserved)", the module '
     'ignores the bit', _reserved_mask_bit),
    ('odd branch target', 'an odd branch offset (or EXT20 address): the PC is word aligned and the manual says '
     'an odd offset is rounded down (CPU16RM 5.6.1 note); MAME prints the odd sum, the module the even '
     'address the CPU fetches from', _odd_target),
]


def main():
    gpath, mpath, bpath = sys.argv[1:4]
    show = int(sys.argv[sys.argv.index('--show') + 1]) if '--show' in sys.argv else 5
    G, M = load(gpath), load(mpath)
    data = open(bpath, 'rb').read()
    cnt = Counter()
    sub = Counter()
    ex = defaultdict(list)
    for s in sorted(G):
        b = data[s * SLOT:(s + 1) * SLOT]
        c, why = classify(G[s], M[s], b)
        cnt[c] += 1
        if why:
            sub[(c, why)] += 1
        if c == 'UNEXPLAINED':
            key = (G[s][1].split(' ')[0] if G[s][0] else 'BAD') + ' / ' + (M[s][1].split(' ')[0] if M[s][0] else 'BAD') + \
                  (' len %d/%d' % (G[s][0], M[s][0]))
            ex[key].append((s, b[:6].hex(), G[s], M[s]))
    n = sum(cnt.values())
    print(f'slots {n}: ' + ', '.join(f'{k} {v}' for k, v in cnt.most_common()))
    dec = n - cnt['both-bad']
    print(f'  exact {cnt["exact"]}/{dec} decodable ({100.0 * cnt["exact"] / max(dec, 1):.2f}%), '
          f'exact+semantic {cnt["exact"] + cnt["semantic"]}/{dec} ({100.0 * (cnt["exact"] + cnt["semantic"]) / max(dec, 1):.2f}%)')
    for (c, why), v in sub.most_common():
        print(f'  {c}: {why}: {v}')
    if '--summary' in sys.argv:
        for name, why, _ in EXPLAINED:
            print(f'  class "{name}": {why}')
    for k, v in sorted(ex.items(), key=lambda kv: -len(kv[1])):
        print(f'  UNEXPLAINED {k}: {len(v)}')
        for e in v[:show]:
            print('     ', e)
    sys.exit(1 if cnt['UNEXPLAINED'] else 0)


if __name__ == '__main__':
    main()

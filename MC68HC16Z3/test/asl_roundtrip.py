#!/usr/bin/env python3
"""Round trip through an independent assembler: Ghidra's disassembly text -> asl (Macro Assembler AS,
CPU 68HC16, run as a black box) -> bytes, compared with the original bytes of every decoded slot.

  asl_roundtrip.py <ghidra.txt> <corpus.bin> <workdir> [--show N]

<ghidra.txt> is DumpSlots output (slot length text). Each instruction is assembled at its own slot
address (ORG), in 1 MB chunks because the CPU16 address space is 20 bits. Two passes: the text as is,
and with ">" (force 16-bit) in front of every index offset and extended address, so that an IND16
form with a small offset is not re-encoded as IND8.

Classes:
  same bytes      asl produces exactly the original bytes (either pass)
  short form      asl produces the shorter encoding of the same instruction (an IMM16 operand that fits
                  in the sign-extended IMM8 form of ADDD/ADDE/AIX/AIY/AIZ/AIS); not an error
  odd offset      a branch with an odd offset: the module shows the even target the CPU fetches from
                  (CPU16RM 5.6.1 note); asl re-encodes that target with the even offset
  reserved mask bit 7  PSHM/PULM with the reserved mask bit 7 set: the module ignores the bit, asl cannot
                  express it
  asl: LDHI takes an operand  asl rejects LDHI without an operand and encodes "ldhi $1234" as 27B0 1234;
                  the manual's LDHI page lists no operand (its mode column says EXT, its operand column
                  "-") and the operation uses only XK:IX and YK:IY; Table 6-36 and MAME: INH, 2 bytes
  wrap            a branch whose target wraps around the 1 MB space: asl does not wrap PC-relative
                  distances
  MISMATCH        anything else: the run fails
"""
import os, re, subprocess, sys
from collections import Counter, defaultdict

ASL = os.environ.get('ASL') or os.path.expanduser('~/.cache/ghidra-rare-scratch/tools/asl/bin/asl')
P2BIN = os.environ.get('P2BIN') or os.path.join(os.path.dirname(ASL), 'p2bin')
SLOT = 16
CHUNK = 0x100000
NUM = re.compile(r'(-?)0x([0-9a-fA-F]+)')
SHORT_IMM = {'ADDD': (0x37, 0xB1, 0xFC), 'ADDE': (0x37, 0x31, 0x7C), 'AIX': (0x37, 0x3C, 0x3C),
             'AIY': (0x37, 0x3D, 0x3D), 'AIZ': (0x37, 0x3E, 0x3E), 'AIS': (0x37, 0x3F, 0x3F)}


def to_asl(text, force):
    mn, _, ops = text.partition(' ')
    ops = ops.strip()
    if mn in ('PSHM', 'PULM'):
        if not ops:
            return None
        ops = ','.join({'IX': 'x', 'IY': 'y', 'IZ': 'z'}.get(r, r.lower()) for r in ops.split(','))
        return f'{mn.lower()} {ops}'
    # IND20 bank:addr
    # IND20 bank:addr is a 20-bit offset, which asl writes as a signed number (-$80000..$7FFFF)
    def ind20(m):
        v = (int(m.group(1), 16) << 16) | int(m.group(2), 16)
        return '0x%x' % v if v < 0x80000 else '-0x%x' % (0x100000 - v)
    ops = re.sub(r'0x([0-9a-f]+):0x([0-9a-f]+)', ind20, ops)
    ops = NUM.sub(lambda m: f'{m.group(1)}${m.group(2)}', ops)
    if force and mn not in ('MAC', 'RMAC'):
        parts = ops.split(',')
        out = []
        for i, p in enumerate(parts):
            nxt = parts[i + 1].strip().upper() if i + 1 < len(parts) else ''
            isaddr = not p.startswith('#') and re.fullmatch(r'-?\$[0-9a-fA-F]+', p) is not None
            branch_target = i == len(parts) - 1 and (mn.startswith('B') or mn.startswith('LB')) and mn not in ('BCLR', 'BSET', 'BCLRW', 'BSETW', 'BITA', 'BITB')
            if isaddr and not branch_target and (nxt in ('X', 'Y', 'Z') or mn in ('LDED', 'STED', 'MOVB', 'MOVW') or len(parts) == 1 or nxt.startswith('#')):
                p = '>' + p
            out.append(p)
        ops = ','.join(out)
    return f'{mn.lower()} {ops}'.strip()


def assemble(lines, work, tag):
    """lines: list of (addr, text). Returns {addr: bytes} for the lines asl accepted."""
    src = os.path.join(work, f'{tag}.asm')
    good = list(lines)
    for _ in range(4):
        with open(src, 'w') as f:
            f.write('\tcpu 68HC16\n\tpadding off\n')
            for a, t in good:
                f.write(f'\torg ${a:x}\n\t{t}\n')
        r = subprocess.run([ASL, '-q', '-L', '-x', src], capture_output=True, text=True, cwd=work)
        bad = set()
        for m in re.finditer(r'\.asm\((\d+)\)', r.stdout + r.stderr):
            bad.add((int(m.group(1)) - 3) // 2)
        if not bad:
            break
        good = [g for i, g in enumerate(good) if i not in bad]
    lst = open(os.path.join(work, f'{tag}.lst'), errors='replace').read()
    out = {}
    for m in re.finditer(r'^\s*\d+/\s*([0-9A-F]+) : ((?:[0-9A-F]{2} )+)', lst, re.M):
        out[int(m.group(1), 16)] = bytes.fromhex(m.group(2))
    return out, len(lines) - len(good)


def main():
    gpath, bpath, work = sys.argv[1:4]
    show = int(sys.argv[sys.argv.index('--show') + 1]) if '--show' in sys.argv else 5
    os.makedirs(work, exist_ok=True)
    data = open(bpath, 'rb').read()
    G = {}
    for l in open(gpath):
        f = l.rstrip('\n').split(' ', 2)
        if int(f[1]):
            G[int(f[0])] = (int(f[1]), f[2])
    cnt = Counter()
    bad = defaultdict(list)
    for c0 in range(0, len(data), CHUNK):
        slots = [s for s in sorted(G) if c0 <= s * SLOT < c0 + CHUNK]
        res = []
        for force in (False, True):
            lines = []
            for s in slots:
                t = to_asl(G[s][1], force)
                if t is not None:
                    lines.append(((s * SLOT) % CHUNK, t))
            out, _ = assemble(lines, work, f'c{c0 >> 20}{int(force)}')
            res.append(out)
        for s in slots:
            n, text = G[s]
            orig = data[s * SLOT:s * SLOT + n]
            a = (s * SLOT) % CHUNK
            got = [r.get(a) for r in res]
            mn = text.split(' ')[0]
            if to_asl(text, False) is None:
                cnt['not assembled (empty PSHM/PULM list)'] += 1
            elif orig in got:
                cnt['same bytes'] += 1
            elif mn in SHORT_IMM and any(g and len(g) == 2 and g[0] == SHORT_IMM[mn][2] and len(orig) == 4 and
                                         orig[:2] == bytes(SHORT_IMM[mn][:2]) and
                                         ((g[1] ^ 0x80) - 0x80) & 0xFFFF == int.from_bytes(orig[2:4], 'big') for g in got):
                cnt['short form'] += 1
            elif any(g and len(g) == len(orig) and g[:-1] == orig[:-1] and orig[-1] & 1 and g[-1] == orig[-1] & 0xFE
                     for g in got) and re.search(r'0x[0-9a-f]+$', text):
                cnt['odd offset'] += 1
            elif mn in ('PSHM', 'PULM') and orig[1] & 0x80 and any(g == bytes([orig[0], orig[1] & 0x7F]) for g in got):
                cnt['reserved mask bit 7'] += 1
            elif mn == 'LDHI' and got == [None, None]:
                cnt['asl: LDHI takes an operand'] += 1
            elif got == [None, None] and re.search(r'0x[0-9a-f]+$', text) and (mn.startswith('B') or mn.startswith('LB')) and \
                    abs(int(text.rsplit('0x', 1)[1], 16) - a) > 0x80000:
                cnt['wrap'] += 1
            else:
                cnt['MISMATCH'] += 1
                bad[mn].append((hex(a), orig.hex(), text, [g.hex() if g else None for g in got], to_asl(text, True)))
    tot = sum(cnt.values())
    print(f'asl round trip, {tot} decoded slots: ' + ', '.join(f'{k} {v}' for k, v in cnt.most_common()))
    for k, v in sorted(bad.items(), key=lambda kv: -len(kv[1])):
        print(f'  MISMATCH {k}: {len(v)}')
        for e in v[:show]:
            print('     ', e)
    sys.exit(1 if cnt['MISMATCH'] else 0)


if __name__ == '__main__':
    main()

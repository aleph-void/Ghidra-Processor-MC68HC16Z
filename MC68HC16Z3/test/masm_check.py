#!/usr/bin/env python3
"""Decode check against encodings produced by Motorola's own assembler (MASM 4.6), as recorded in
docs/spec/isa-probe.tsv of HausRummel/M68HC16_Assembler (Apache-2.0; the table is the output of the
original DOS assembler for one probe operand per mnemonic and addressing mode).

  masm_check.py corpus <isa-probe.tsv> <out.bin>        one row per 16-byte slot (NOP padded)
  masm_check.py compare <isa-probe.tsv> <ghidra.txt>    same mnemonic and same length for every row

Rows the assembler rejected (no bytes) are skipped."""
import sys

PAD = bytes([0x27, 0x4C]) * 8


def rows(p):
    out = []
    for l in open(p, encoding='utf-8-sig'):
        f = l.rstrip('\n').split('\t')
        if len(f) < 4 or f[0] == 'mnemonic' or not f[2].strip():
            continue
        out.append((f[0], f[1], bytes.fromhex(f[2])))
    return out


# MASM accepts M68HC11-style spellings; each maps to the CPU16 instruction given by the manual's
# Table A-1 (M68HC11 instructions replaced by CPU16 ones) or to the CPU16 name of the same opcode (CMPX = CPX,
# LSLD = ASLD)
ALIAS = {'cmpx': 'cpx', 'cmpy': 'cpy', 'cmpz': 'cpz', 'cmps': 'cps', 'lsla': 'asla', 'lslb': 'aslb',
         'lsld': 'asld', 'lsle': 'asle', 'lsl': 'asl', 'lslw': 'aslw', 'lslm': 'aslm'}


def alias(mn):
    if mn in ALIAS:
        return ALIAS[mn]
    if mn in ('dex', 'inx', 'dey', 'iny', 'dez', 'inz', 'des', 'ins'):
        return 'ai' + mn[2]
    if mn[:3] in ('psh', 'pul') and mn[3:] in ('x', 'y', 'z', 'd', 'e', 'k', 'ccr', 'mb', 'm'):
        return mn[:3] + 'm' if mn[3:] not in ('a', 'b') else mn
    return mn


def main():
    mode, tsv, path = sys.argv[1:4]
    R = rows(tsv)
    if mode == 'corpus':
        open(path, 'wb').write(b''.join((b + PAD)[:16] for _, _, b in R))
        print(f'{len(R)} MASM rows')
        return
    G = {}
    for l in open(path):
        f = l.rstrip('\n').split(' ', 2)
        G[int(f[0])] = (int(f[1]), f[2] if len(f) > 2 else '')
    bad = []
    for i, (mn, md, b) in enumerate(R):
        n, t = G[i]
        gm = t.split(' ')[0].lower() if n else 'BAD'
        if gm != alias(mn.lower()) or n != len(b):
            bad.append((mn, md, b.hex(), n, t))
    print(f'   MASM encodings: {len(R) - len(bad)}/{len(R)} decode to the same mnemonic and length')
    for e in bad[:30]:
        print('   DIFF', e)
    sys.exit(1 if bad else 0)


if __name__ == '__main__':
    main()

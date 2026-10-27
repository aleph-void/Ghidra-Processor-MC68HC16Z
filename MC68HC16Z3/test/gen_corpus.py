#!/usr/bin/env python3
"""Decode-test corpora for the CPU16, one instruction per 16-byte slot, padded with NOP (274C) words.

  gen_corpus.py enum   <out.bin>            every page-1 opcode x every operand byte (65,536 slots) and every
                                            page-2/3/4 opcode (17xx, 27xx, 37xx) x 48 operand tails
  gen_corpus.py random <out.bin> <n> <seed> random 6-byte strings (a quarter start with a prefix byte)

CPU16 instructions are 2, 4 or 6 bytes and always word aligned, so a 16-byte slot always realigns
on the NOP padding even when a decoder disagrees on the length."""
import random, struct, sys

SLOT = 16
PAD = bytes([0x27, 0x4C]) * 8
EDGE16 = [0x0000, 0x0001, 0x007F, 0x0080, 0x00FF, 0x7FFE, 0x7FFF, 0x8000, 0x8001, 0xFFFE, 0xFFFF, 0x0102,
          0x1234, 0x0FFF, 0x000F, 0xF000]


def slot(b):
    return (bytes(b) + PAD)[:SLOT]


def enum(rng):
    out = []
    for op in range(256):
        for b in range(256):
            out.append(slot([op, b] + [rng.randrange(256) for _ in range(4)]))
    for pre in (0x17, 0x27, 0x37):
        for op in range(256):
            tails = [[e >> 8, e & 0xFF, f >> 8, f & 0xFF] for e, f in zip(EDGE16, reversed(EDGE16))]
            tails += [[rng.randrange(256) for _ in range(4)] for _ in range(48 - len(tails))]
            for t in tails:
                out.append(slot([pre, op] + t))
    return out


def rand(rng, n):
    out = []
    for _ in range(n):
        b = [rng.randrange(256) for _ in range(6)]
        if rng.random() < 0.25:
            b[0] = rng.choice((0x17, 0x27, 0x37))
        out.append(slot(b))
    return out


if __name__ == '__main__':
    mode, path = sys.argv[1], sys.argv[2]
    if mode == 'enum':
        data = enum(random.Random(1))
    else:
        data = rand(random.Random(int(sys.argv[4])), int(sys.argv[3]))
    open(path, 'wb').write(b''.join(data))
    print(f'{path}: {len(data)} slots')

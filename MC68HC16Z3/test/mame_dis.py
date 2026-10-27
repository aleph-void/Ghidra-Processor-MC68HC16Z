#!/usr/bin/env python3
"""Run MAME's unidasm (-arch cpu16) over a slot corpus and keep the instruction at each slot start.
Output lines: "<slot> <length> <text>" (length 0 and text "BAD" for MAME's "fdb" invalid words).
  mame_dis.py <corpus.bin> <out.txt> [slot-size=16]
MAME's CPU16 program counter is 20 bits, so the corpus is disassembled in 1 MB chunks, each at base 0:
slot addresses are the Ghidra addresses modulo 2^20, which is what the CPU's 20-bit PC sees."""
import os, re, subprocess, sys, tempfile

UNIDASM = os.environ.get('UNIDASM') or 'unidasm'
src, dst = sys.argv[1], sys.argv[2]
SLOT = int(sys.argv[3]) if len(sys.argv) > 3 else 16
data = open(src, 'rb').read()
CHUNK = 0x100000
rx = re.compile(r'([0-9a-f]+): ([0-9a-f ]+?)\s{2,}(.*)$')
with open(dst, 'w') as out, tempfile.TemporaryDirectory() as td:
    for c0 in range(0, len(data), CHUNK):
        p = os.path.join(td, 'c.bin')
        chunk = data[c0:c0 + CHUNK]
        open(p, 'wb').write(chunk + bytes([0x27, 0x4C]) * 4)
        txt = subprocess.run([UNIDASM, p, '-arch', 'cpu16'], capture_output=True, text=True, check=True).stdout
        recs = [(int(m.group(1), 16), m.group(3).strip()) for m in map(rx.match, txt.split('\n')) if m]
        for i, (a, t) in enumerate(recs[:-1]):
            if a % SLOT == 0 and a < len(chunk):
                n = recs[i + 1][0] - a
                if t.startswith('fdb'):
                    n, t = 0, 'BAD'
                out.write(f'{(c0 + a) // SLOT} {n} {" ".join(t.split())}\n')

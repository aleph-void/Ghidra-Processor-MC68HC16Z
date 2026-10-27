#!/usr/bin/env python3
"""reach.py <languages-dir> <reach.txt>: report constructors (by <file>:<line>) never reached."""
import re
import sys
from pathlib import Path

seen = set(open(sys.argv[2]).read().split())
tot, miss = 0, []
for fn in ("68HC16.slaspec", "68HC16_PSHM_PULM.sinc"):
    for i, l in enumerate((Path(sys.argv[1]) / fn).read_text().split("\n")):
        if re.match(r"^(:|[A-Za-z_]\w*:)", l):
            tot += 1
            if f"{fn}:{i + 1}" not in seen:
                miss.append(f"{fn}:{i + 1} {l[:110]}")
print(f"   constructors reached {tot - len(miss)}/{tot}")
for m in miss[:40]:
    print("   not reached:", m)
sys.exit(1 if miss else 0)

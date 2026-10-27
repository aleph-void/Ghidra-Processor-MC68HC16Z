#!/usr/bin/env python3
"""Random-state single-instruction tests for the emulator, with expectations from cpu16_model.py
(a model written from the CPU16 Reference Manual, not from the SLEIGH module).

  emu_fuzz.py <outdir> [cases-per-opcode=12] [seed=1]

Writes <outdir>/fuzz.bin (a 1 MB raw image holding one instruction per 8-byte slot from CODE upward)
and <outdir>/fuzz.txt in EmuCheck.java's format. Every operand byte the model reads is initialised
with a random value; every register is initialised; the expectation lists every register, flag and
written memory byte the manual defines after the instruction (undefined results are left out)."""
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cpu16_model as cm  # noqa: E402

CODE = 0xC0000
CODE_END = 0x100000
FLAGS = [('S', 15), ('MV', 14), ('H', 13), ('EV', 12), ('N', 11), ('Z', 10), ('V', 9), ('C', 8), ('IP', 5, 3),
         ('SM', 4)]
REGS16 = ['E', 'IX', 'IY', 'IZ', 'SP', 'HR', 'IR']
REGS8 = ['A', 'B', 'XMSK', 'YMSK']
REGS4 = ['XK', 'YK', 'ZK', 'EK', 'SK']


class Reject(Exception):
    pass


class Mem:
    def __init__(self, rng):
        self.rng = rng
        self.init = {}
        self.cur = {}
        self.written = set()

    def rb(self, a):
        if CODE <= a < CODE_END:
            raise Reject('operand in the code area')
        if a not in self.cur:
            v = self.rng.randrange(256)
            self.init[a] = v
            self.cur[a] = v
        return self.cur[a]

    def wb(self, a, v):
        if CODE <= a < CODE_END:
            raise Reject('write to the code area')
        if a == 0xFFFFF:
            raise Reject('word access wrapping at the top of memory')
        self.cur[a] = v
        self.written.add(a)


def rand_state(rng, pc):
    s = {r: rng.randrange(1 << 16) for r in REGS16}
    s.update({r: rng.randrange(256) for r in REGS8})
    s.update({r: rng.randrange(16) for r in REGS4})
    s['CCR'] = (rng.randrange(1 << 16) & 0xFFF0) | (pc >> 16)
    s['AM'] = rng.randrange(1 << 36)
    s['SL'] = rng.randrange(2)
    s['PC'] = pc
    # bias towards edge values that exercise carries, bank crossings and the MAC special cases
    if rng.random() < 0.3:
        for r in REGS16:
            if rng.random() < 0.3:
                s[r] = rng.choice((0, 1, 0x7F, 0x80, 0xFF, 0x7FFF, 0x8000, 0xFFFF, 0xFFFE))
        for r in ('A', 'B'):
            if rng.random() < 0.3:
                s[r] = rng.choice((0, 1, 0x7F, 0x80, 0xFF, 0x09, 0x99))
    # The module does not wrap SK:SP at the ends of the 1 MB space (decompiler stack tracking; see
    # GHIDRA-RARE.md): keep the stack pointer away from those two edges.
    if s['SK'] == 0 and s['SP'] < 0x40:
        s['SP'] |= 0x100
    if s['SK'] == 0xF and s['SP'] > 0xFFC0:
        s['SP'] &= 0xFEFF
    if rng.random() < 0.15:
        s['AM'] = rng.choice((0, 0x07FFFFFFF, 0x080000000, 0xF80000000, 0xF7FFFFFFF, 0x7FFFFFFFF,
                              0x800000000, 0x00000FFFF, 0x000018000, 0x000008000))
    return s


def operand_bytes(rng, row):
    pat = row['opnd']
    out = []
    for f in pat.split():
        n = cm.NBYTES[f]
        for _ in range(n):
            out.append(rng.choice((0, 1, 0x7F, 0x80, 0xFE, 0xFF)) if rng.random() < 0.15 else rng.randrange(256))
    mn, mode = row['mn'], row['mode']
    if mn in ('BCLRW', 'BSETW') and 'mmmm' not in pat:
        out += [rng.randrange(256), rng.randrange(256)]
    if mn in ('BRCLR', 'BRSET') and mode in ('IND16,X', 'IND16,Y', 'IND16,Z', 'EXT') and 'rrrr' not in pat:
        out += [rng.randrange(256), rng.randrange(256)]
    if mn in ('JMP', 'JSR'):
        out[0] &= 0x0F                     # the z nibble is a zero extension (see GHIDRA-RARE.md)
    return out


def fmt_regs(s, prefix_ok=True):
    items = []
    for r in REGS16 + REGS8 + REGS4:
        items.append(f'{r}={s[r]:x}')
    items.append(f'AM={s["AM"] & 0xFFFFFFFF:x}')
    items.append(f'AM_EXT={s["AM"] >> 32:x}')
    items.append(f'SL={s["SL"]:x}')
    return items


def make_case(rng, row, pc):
    code = bytes.fromhex(row['op']) + bytes(operand_bytes(rng, row))
    s0 = rand_state(rng, pc)
    mn = row['mn']
    if mn == 'DAA':
        # only the operand combinations Table 6-18 defines
        legal = [(0, range(0, 10), 0, range(0, 10)), (0, range(0, 9), 0, range(10, 16)),
                 (0, range(0, 10), 1, range(0, 4)), (0, range(10, 16), 0, range(0, 10)),
                 (0, range(9, 16), 0, range(10, 16)), (0, range(10, 16), 1, range(0, 4)),
                 (1, range(0, 3), 0, range(0, 10)), (1, range(0, 3), 0, range(10, 16)),
                 (1, range(0, 4), 1, range(0, 4))]
        c, hi, h, lo = rng.choice(legal)
        s0['A'] = (rng.choice(hi) << 4) | rng.choice(lo)
        s0['CCR'] = (s0['CCR'] & ~((1 << 8) | (1 << 13))) | (c << 8) | (h << 13)
    if mn == 'RMAC':
        s0['E'] = rng.choice((0, 1, 2, 3, 0xFFFF, 0x8000))
    if mn in ('EDIV', 'EDIVS', 'IDIV', 'FDIV') and rng.random() < 0.15:
        s0['IX'] = 0
    if mn == 'LPSTOP':
        s0['CCR'] |= 1 << 15
    mem = Mem(rng)
    cpu = cm.CPU(s0, mem)
    try:
        nxt = cpu.step(code + bytes(8))
    except cm.Undefined:
        raise Reject('undefined')
    if nxt == pc:
        raise Reject('branch to itself')
    if getattr(cpu, 'stack_wrap', False):
        raise Reject('SK:SP wraps at 1 MB (not modelled by the module, see GHIDRA-RARE.md)')
    if CODE <= nxt < CODE_END and nxt != pc + len(code) and (nxt - CODE) % 8 != 0:
        pass
    s1 = cpu.s
    init = [f'{k}' for k in fmt_regs(s0)] + [f'CCR={s0["CCR"]:x}']
    init += [f'm1:{a:x}={v:x}' for a, v in sorted(mem.init.items())]
    exp = []
    for item in fmt_regs(s1):
        r = item.split('=')[0]
        und = cpu.undef
        if r in und or (r in ('A', 'B') and 'D' in und):
            continue
        if r in ('AM', 'AM_EXT', 'SL') and 'AM' in und:
            continue
        exp.append(item)
    for fl in FLAGS:
        name, bit = fl[0], fl[1]
        width = fl[2] if len(fl) > 2 else 1
        if 'CCR.' + name in cpu.undef:
            continue
        exp.append(f'CCR.{bit}.{width}={(s1["CCR"] >> bit) & ((1 << width) - 1):x}')
    exp += [f'm1:{a:x}={mem.cur[a]:x}' for a in sorted(mem.written)]
    return code, nxt, init, exp


def main():
    out = sys.argv[1]
    per = int(sys.argv[2]) if len(sys.argv) > 2 else 12
    rng = random.Random(int(sys.argv[3]) if len(sys.argv) > 3 else 1)
    os.makedirs(out, exist_ok=True)
    img = bytearray(0x100000)
    lines = []
    pc = CODE
    skipped = {}
    for row in cm.load_rows():
        n = 0
        tries = 0
        while n < per and tries < per * 20:
            tries += 1
            try:
                code, nxt, init, exp = make_case(rng, row, pc)
            except Reject as e:
                skipped[str(e)] = skipped.get(str(e), 0) + 1
                continue
            if pc + 8 > CODE_END:
                break
            img[pc:pc + len(code)] = code
            name = f'{row["mn"]}_{row["mode"]}_{n}'.replace(',', '')
            lines.append(f'{name} {pc:x} {nxt:x} {",".join(init)} {",".join(exp)}')
            pc += 8
            n += 1
    open(os.path.join(out, 'fuzz.bin'), 'wb').write(img)
    open(os.path.join(out, 'fuzz.txt'), 'w').write('\n'.join(lines) + '\n')
    short = sum(1 for r in cm.load_rows()) * per - len(lines)
    print(f'{len(lines)} cases; rejected draws: {skipped}')
    if pc + 8 > CODE_END:
        sys.exit(f'the code area is full: {short} cases missing; use fewer cases per row')


if __name__ == '__main__':
    main()

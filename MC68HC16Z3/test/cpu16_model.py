#!/usr/bin/env python3
"""Reference model of CPU16 instruction semantics, written from the CPU16 Reference Manual
(CPU16RM/AD Rev. 1: section 6 instruction glossary, Table 6-36, section 3.3 memory management,
section 7.3 / 9.7 stacking rules, section 11 MAC unit). It does not look at the SLEIGH module.

It executes ONE instruction from a state and reports the new state, which registers/flags the manual
leaves undefined, and the next PC. emu_fuzz.py uses it to produce emulator test cases.

State: dict with A B E IX IY IZ SP XK YK ZK EK SK CCR(16 bits; low nibble = PK of the instruction)
HR IR AM(36 bits) SL XMSK YMSK PC (20-bit address of the instruction); memory is a callback
object with rb(a)/wb(a, v)."""
import json
import os

M20 = 0xFFFFF
HERE = os.path.dirname(os.path.abspath(__file__))

# CCR bits
S, MV, H, EV, N, Z, V, C = 15, 14, 13, 12, 11, 10, 9, 8
SM = 4


def sx(v, bits):
    v &= (1 << bits) - 1
    return v - (1 << bits) if v >> (bits - 1) else v


class Undefined(Exception):
    pass


def load_rows():
    return json.load(open(os.path.join(HERE, 'cpu16_opcodes.json')))


def load_table():
    """opcode bytes (tuple) -> (mnemonic, mode, operand pattern) from the manual's Table 6-36."""
    rows = json.load(open(os.path.join(HERE, 'cpu16_opcodes.json')))
    t = {}
    for r in rows:
        op = bytes.fromhex(r['op'])
        t[op] = (r['mn'], r['mode'], r['opnd'])
    return t


TABLE = load_table()
NBYTES = {'ff': 1, 'ii': 1, 'rr': 1, 'xoyo': 1, 'mm': 1, 'gggg': 2, 'hh': 1, 'll': 1, 'hhll': 2, 'jj': 1,
          'kk': 1, 'jjkk': 2, 'rrrr': 2, 'mmmm': 2, 'zg': 1, 'zb': 1, '—': 0}


def fields(pattern):
    out = []
    for f in pattern.split():
        out.append((f, NBYTES[f]))
    # BCLRW/BSETW and BRCLR/BRSET IND16/EXT carry a second line in the table (mask word / rrrr)
    return out


def decode(code):
    """code: bytes at PC -> (mnemonic, mode, {field: value}, length) or None."""
    if code[0] in (0x17, 0x27, 0x37):
        key = bytes(code[:2])
    else:
        key = bytes(code[:1])
    if key not in TABLE:
        return None
    mn, mode, pat = TABLE[key]
    pos = len(key)
    vals = {}
    for f, n in fields(pat):
        if n == 0:
            continue
        v = int.from_bytes(code[pos:pos + n], 'big')
        name = f
        while name in vals:
            name += "'"
        vals[name] = v
        pos += n
    if mn in ('BCLRW', 'BSETW') and 'mmmm' not in vals:
        vals['mmmm'] = int.from_bytes(code[pos:pos + 2], 'big')
        pos += 2
    if mn in ('BRCLR', 'BRSET') and mode in ('IND16,X', 'IND16,Y', 'IND16,Z', 'EXT') and 'rrrr' not in vals:
        vals['rrrr'] = int.from_bytes(code[pos:pos + 2], 'big')
        pos += 2
    # merge split byte fields
    if 'hh' in vals:
        vals['hhll'] = (vals.pop('hh') << 8) | vals.pop('ll')
    if "hh'" in vals:
        vals["hhll'"] = (vals.pop("hh'") << 8) | vals.pop("ll'")
    if 'jj' in vals:
        vals['jjkk'] = (vals.pop('jj') << 8) | vals.pop('kk')
    return mn, mode, vals, pos


class CPU:
    def __init__(self, st, mem):
        self.s = dict(st)
        self.m = mem
        self.undef = set()

    # ---- memory
    def rb(self, a):
        return self.m.rb(a & M20)

    def rw(self, a):
        return (self.rb(a) << 8) | self.rb(a + 1)

    def wb(self, a, v):
        self.m.wb(a & M20, v & 0xFF)

    def ww(self, a, v):
        self.wb(a, v >> 8)
        self.wb(a + 1, v)

    # ---- registers
    @property
    def D(self):
        return (self.s['A'] << 8) | self.s['B']

    @D.setter
    def D(self, v):
        self.s['A'] = (v >> 8) & 0xFF
        self.s['B'] = v & 0xFF

    def get(self, r):
        return self.D if r == 'D' else self.s[r]

    def put(self, r, v):
        if r == 'D':
            self.D = v & 0xFFFF
        else:
            self.s[r] = v & (0xFF if r in ('A', 'B') else 0xFFFF)

    def flag(self, b):
        return (self.s['CCR'] >> b) & 1

    def setf(self, b, v):
        self.s['CCR'] = (self.s['CCR'] & ~(1 << b)) | ((1 if v else 0) << b)

    def nz(self, v, w):
        self.setf(N, (v >> (w - 1)) & 1)
        self.setf(Z, (v & ((1 << w) - 1)) == 0)

    def x20(self, k, r):
        return ((self.s[k] << 16) | self.s[r]) & M20

    def setx20(self, k, r, v):
        if k == 'SK' and not 0 <= v < 1 << 20:
            self.stack_wrap = True       # SK:SP leaves the 1 MB space (emu_fuzz.py skips these)
        v &= M20
        self.s[k] = v >> 16
        self.s[r] = v & 0xFFFF

    @property
    def ssp(self):
        return self.x20('SK', 'SP')

    @ssp.setter
    def ssp(self, v):
        self.setx20('SK', 'SP', v)

    def push16(self, v):
        self.ww(self.ssp, v)
        self.ssp = self.ssp - 2

    def pull16(self):
        self.ssp = self.ssp + 2
        return self.rw(self.ssp)

    # ---- effective addresses (section 3.3.4, 4.3)
    IDX = {'X': ('XK', 'IX'), 'Y': ('YK', 'IY'), 'Z': ('ZK', 'IZ')}

    def ea(self, mode, f):
        if mode == 'EXT':
            return (self.s['EK'] << 16) | f['hhll']
        kind, reg = mode.split(',')
        k, r = self.IDX[reg]
        base = self.x20(k, r)
        if kind == 'IND8':
            return (base + f['ff']) & M20
        if kind == 'IND16':
            return (base + sx(f['gggg'], 16)) & M20
        if kind == 'E':
            return (base + sx(self.s['E'], 16)) & M20
        raise ValueError(mode)

    # ---- arithmetic helpers
    def add(self, a, b, c, w, hflag=False):
        m = (1 << w) - 1
        r = a + b + c
        res = r & m
        self.setf(C, r >> w)
        self.setf(V, ((a ^ res) & (b ^ res)) >> (w - 1) & 1)
        if hflag:
            self.setf(H, ((a & 0xF) + (b & 0xF) + c) >> 4)
        self.nz(res, w)
        return res

    def sub(self, a, b, c, w):
        m = (1 << w) - 1
        r = a - b - c
        res = r & m
        self.setf(C, r < 0)
        self.setf(V, ((a ^ b) & (a ^ res)) >> (w - 1) & 1)
        self.nz(res, w)
        return res

    def logic(self, res, w):
        self.nz(res, w)
        self.setf(V, 0)
        return res

    # ---- MAC unit (section 11)
    def am_flags(self, new, old_mv_unaffected=True):
        """EV from AM[35:31] (Table 11-1); MV set on sign overflow (sticky); SL latched on the
        first sign overflow after MV was clear."""
        top = (new >> 31) & 0x1F
        self.setf(EV, top not in (0, 0x1F))

    def am_add(self, val36):
        a = self.s['AM']
        r = (a + val36) & ((1 << 36) - 1)
        ov = ((a ^ r) & (val36 ^ r)) >> 35 & 1
        if ov:
            if not self.flag(MV):
                self.s['SL'] = (r >> 35) & 1
            self.setf(MV, 1)
        self.s['AM'] = r
        self.am_flags(r)

    def qual(self, reg, off, mask):
        r = self.s[reg]
        new = (r + sx(off, 4)) & 0xFFFF
        if mask == 0:
            return new
        m = mask & 0xFF
        return (r & ~m & 0xFFFF) | (new & m)

    # ---- execution
    def step(self, code):
        d = decode(code)
        if d is None:
            raise Undefined('opcode')
        mn, mode, f, ln = d
        pc = self.s['PC']
        self.next = (pc + ln) & M20
        self.pcp6 = (pc + 6) & M20            # PK:PC during execution (section 7.3)
        fn = getattr(self, 'op_' + mn, None)
        if fn is not None:
            fn(mode, f)
        else:
            self.generic(mn, mode, f)
        return self.next

    def branch(self, cond, off):
        if cond:
            self.next = (self.pcp6 + off) & M20 & ~1     # PC is word aligned (section 5.6.1 note)

    def operand(self, mode, f, w):
        if mode == 'IMM8':
            return f['ii']
        if mode == 'IMM16':
            return f['jjkk']
        a = self.ea(mode, f)
        return self.rb(a) if w == 8 else self.rw(a)

    ACC = {'A': ('A', 8), 'B': ('B', 8), 'D': ('D', 16), 'E': ('E', 16)}

    def generic(self, mn, mode, f):
        cc = self.cond(mn)
        if cc is not None:
            off = sx(f['rr'], 8) if mode == 'REL8' else sx(f['rrrr'], 16)
            self.branch(cc, off)
            return
        # accumulator ALU families
        for pre, kind in (('SUB', 'sub'), ('ADD', 'add'), ('SBC', 'sbc'), ('ADC', 'adc'), ('EOR', 'eor'),
                          ('LDA', 'ld'), ('LD', 'ld'), ('AND', 'and'), ('ORA', 'or'), ('OR', 'or'),
                          ('CMP', 'cmp'), ('CP', 'cmp'), ('BIT', 'bit'), ('STA', 'st'), ('ST', 'st')):
            if mn.startswith(pre) and len(mn) == len(pre) + 1:
                r = mn[-1]
                reg = {'A': 'A', 'B': 'B', 'D': 'D', 'E': 'E', 'X': 'IX', 'Y': 'IY', 'Z': 'IZ', 'S': 'SP'}[r]
                if kind in ('cmp',) and pre == 'CP' and r not in 'DEXYZS':
                    continue
                w = 8 if reg in ('A', 'B') else 16
                return self.alu(kind, reg, w, mode, f, mn)
        raise NotImplementedError(mn)

    def alu(self, kind, reg, w, mode, f, mn):
        a = self.get(reg)
        if kind == 'st':
            self.logic(a, w)
            ea = self.ea(mode, f)
            if w == 8:
                self.wb(ea, a)
            else:
                self.ww(ea, a)
            return
        if mn in ('ADDD', 'ADDE') and mode == 'IMM8':     # CPU16RM 4.3.1: sign-extended
            b = sx(f['ii'], 8) & 0xFFFF
        else:
            b = self.operand(mode, f, w)
        c = self.flag(C)
        h = w == 8
        if kind == 'add':
            self.put(reg, self.add(a, b, 0, w, h))
        elif kind == 'adc':
            self.put(reg, self.add(a, b, c, w, h))
        elif kind == 'sub':
            self.put(reg, self.sub(a, b, 0, w))
        elif kind == 'sbc':
            self.put(reg, self.sub(a, b, c, w))
        elif kind == 'cmp':
            self.sub(a, b, 0, w)
        elif kind == 'and':
            self.put(reg, self.logic(a & b, w))
        elif kind == 'or':
            self.put(reg, self.logic(a | b, w))
        elif kind == 'eor':
            self.put(reg, self.logic(a ^ b, w))
        elif kind == 'bit':
            self.logic(a & b, w)
        elif kind == 'ld':
            self.put(reg, self.logic(b, w))

    def cond(self, mn):
        name = mn[1:] if mn.startswith('B') else (mn[2:] if mn.startswith('LB') else None)
        if name is None or mn in ('BSR', 'LBSR', 'BCLR', 'BSET', 'BITA', 'BITB', 'BCLRW', 'BSETW', 'BRCLR',
                                  'BRSET', 'BGND'):
            return None
        fl = self.flag
        t = {'RA': True, 'RN': False, 'HI': not (fl(C) or fl(Z)), 'LS': bool(fl(C) or fl(Z)), 'CC': not fl(C),
             'CS': bool(fl(C)), 'NE': not fl(Z), 'EQ': bool(fl(Z)), 'VC': not fl(V), 'VS': bool(fl(V)),
             'PL': not fl(N), 'MI': bool(fl(N)), 'GE': not (fl(N) ^ fl(V)), 'LT': bool(fl(N) ^ fl(V)),
             'GT': not (fl(Z) or (fl(N) ^ fl(V))), 'LE': bool(fl(Z) or (fl(N) ^ fl(V))), 'MV': bool(fl(MV)),
             'EV': bool(fl(EV))}
        return t.get(name)

    # ---- read-modify-write memory and register unary ops
    def rmw(self, mn, mode, f):
        base = mn.rstrip('W') if mn.endswith('W') and mn not in ('ROW',) else mn
        word = mn.endswith('W')
        w = 16 if word else 8
        ea = self.ea(mode, f)
        v = self.rw(ea) if word else self.rb(ea)
        r = self.unary(base, v, w)
        if r is not None:
            if word:
                self.ww(ea, r)
            else:
                self.wb(ea, r)

    def unary(self, op, v, w):
        m = (1 << w) - 1
        top = w - 1
        c = self.flag(C)
        if op == 'CLR':
            self.setf(N, 0); self.setf(Z, 1); self.setf(V, 0); self.setf(C, 0)
            return 0
        if op == 'COM':
            r = (~v) & m
            self.nz(r, w); self.setf(V, 0); self.setf(C, 1)
            return r
        if op == 'NEG':
            r = (-v) & m
            self.nz(r, w); self.setf(V, r == 1 << top); self.setf(C, v != 0)
            return r
        if op == 'INC':
            r = (v + 1) & m
            self.nz(r, w); self.setf(V, v == (1 << top) - 1)
            return r
        if op == 'DEC':
            r = (v - 1) & m
            self.nz(r, w); self.setf(V, v == 1 << top)
            return r
        if op == 'TST':
            self.nz(v, w); self.setf(V, 0); self.setf(C, 0)
            return None
        if op == 'ASL':
            r = (v << 1) & m
            cc = v >> top
        elif op == 'ASR':
            r = (v >> 1) | (v & (1 << top))
            cc = v & 1
        elif op == 'LSR':
            r = v >> 1
            cc = v & 1
        elif op == 'ROL':
            r = ((v << 1) | c) & m
            cc = v >> top
        elif op == 'ROR':
            r = (v >> 1) | (c << top)
            cc = v & 1
        else:
            raise NotImplementedError(op)
        self.nz(r, w)
        self.setf(C, cc)
        self.setf(V, self.flag(N) ^ cc)
        return r

    def op_unary_reg(self, mn):
        reg = mn[-1]
        op = mn[:-1]
        w = 8 if reg in 'AB' else 16
        r = self.unary(op, self.get(reg), w)
        if r is not None:
            self.put(reg, r)

    def __getattr__(self, name):
        if name.startswith('op_'):
            mn = name[3:]
            for op in ('CLR', 'COM', 'NEG', 'INC', 'DEC', 'TST', 'ASL', 'ASR', 'LSR', 'ROL', 'ROR'):
                if mn.startswith(op) and mn not in ('ASLM', 'ASRM', 'CLRM'):
                    rest = mn[len(op):]
                    if rest in ('', 'W'):
                        return lambda mode, f: self.rmw(mn, mode, f)
                    if rest in ('A', 'B', 'D', 'E'):
                        return lambda mode, f: self.op_unary_reg(mn)
        raise AttributeError(name)

    # ---- individual instructions
    def op_ABA(self, mode, f):
        self.s['A'] = self.add(self.s['A'], self.s['B'], 0, 8, True)

    def op_SBA(self, mode, f):
        self.s['A'] = self.sub(self.s['A'], self.s['B'], 0, 8)

    def op_CBA(self, mode, f):
        self.sub(self.s['A'], self.s['B'], 0, 8)

    def op_ADE(self, mode, f):
        self.s['E'] = self.add(self.s['E'], self.D, 0, 16)

    def op_SDE(self, mode, f):
        self.s['E'] = self.sub(self.s['E'], self.D, 0, 16)

    def _abx(self, k, r):
        self.setx20(k, r, self.x20(k, r) + self.s['B'])

    def op_ABX(self, mode, f): self._abx('XK', 'IX')

    def op_ABY(self, mode, f): self._abx('YK', 'IY')

    def op_ABZ(self, mode, f): self._abx('ZK', 'IZ')

    def _a20(self, k, r, v):
        self.setx20(k, r, self.x20(k, r) + sx(v, 16))

    def op_ADX(self, mode, f): self._a20('XK', 'IX', self.D)

    def op_ADY(self, mode, f): self._a20('YK', 'IY', self.D)

    def op_ADZ(self, mode, f): self._a20('ZK', 'IZ', self.D)

    def op_AEX(self, mode, f): self._a20('XK', 'IX', self.s['E'])

    def op_AEY(self, mode, f): self._a20('YK', 'IY', self.s['E'])

    def op_AEZ(self, mode, f): self._a20('ZK', 'IZ', self.s['E'])

    def _ai(self, k, r, mode, f, zflag=True):
        imm = sx(f['ii'], 8) if mode == 'IMM8' else sx(f['jjkk'], 16)
        self.setx20(k, r, self.x20(k, r) + imm)
        if zflag:
            self.setf(Z, self.s[r] == 0)

    def op_AIX(self, mode, f): self._ai('XK', 'IX', mode, f)

    def op_AIY(self, mode, f): self._ai('YK', 'IY', mode, f)

    def op_AIZ(self, mode, f): self._ai('ZK', 'IZ', mode, f)

    def op_AIS(self, mode, f): self._ai('SK', 'SP', mode, f, False)

    def op_ANDP(self, mode, f):
        self.s['CCR'] = (self.s['CCR'] & (f['jjkk'] | 0x000F)) & 0xFFFF

    def op_ORP(self, mode, f):
        self.s['CCR'] = (self.s['CCR'] | (f['jjkk'] & 0xFFF0)) & 0xFFFF

    def _bitop(self, mode, f, setbits, word):
        ea = self.ea(mode, f)
        if word:
            v = self.rw(ea)
            m = f['mmmm']
            r = (v | m) if setbits else (v & ~m & 0xFFFF)
            self.ww(ea, r)
            self.logic(r, 16)
        else:
            v = self.rb(ea)
            m = f['mm']
            r = (v | m) if setbits else (v & ~m & 0xFF)
            self.wb(ea, r)
            self.logic(r, 8)

    def op_BSET(self, mode, f): self._bitop(mode, f, True, False)

    def op_BCLR(self, mode, f): self._bitop(mode, f, False, False)

    def op_BSETW(self, mode, f): self._bitop(mode, f, True, True)

    def op_BCLRW(self, mode, f): self._bitop(mode, f, False, True)

    def _brbit(self, mode, f, clr):
        v = self.rb(self.ea(mode, f))
        m = f['mm']
        cond = (v & m) == 0 if clr else ((~v) & m) == 0
        off = sx(f['rr'], 8) if mode.startswith('IND8') else sx(f['rrrr'], 16)
        self.branch(cond, off)

    def op_BRCLR(self, mode, f): self._brbit(mode, f, True)

    def op_BRSET(self, mode, f): self._brbit(mode, f, False)

    def call(self, stacked, target):
        self.push16(stacked & 0xFFFF)
        self.push16((self.s['CCR'] & 0xFFF0) | (stacked >> 16))
        self.next = target & M20 & ~1

    def op_BSR(self, mode, f):
        # BSR stacks PK:PC - 2 so that RTS (which subtracts 2) resumes after the 2-byte BSR
        # (CPU16RM 5.6.5 note and A.5.1). The branch target is PK:PC + offset like every other
        # branch: the glossary's "(PK : PC) - $0002 => PK : PC" line only describes the stacked
        # value; MAME and asl both encode BSR offsets from the address of BSR + 6.
        st = (self.pcp6 - 2) & M20
        self.call(st, self.pcp6 + sx(f['rr'], 8))

    def op_LBSR(self, mode, f):
        self.call(self.pcp6, self.pcp6 + sx(f['rrrr'], 16))

    def jtarget(self, mode, f):
        if mode == 'EXT20':
            z = f['zb']
            if z >> 4:
                raise Undefined('z nibble')
            return ((z & 0xF) << 16) | f['hhll']
        z = f['zg']
        if z >> 4:
            raise Undefined('z nibble')
        off = ((z & 0xF) << 16) | f['gggg']
        reg = {'X': 'IX', 'Y': 'IY', 'Z': 'IZ'}[mode[-1]]
        return (self.s[reg] + off) & M20           # $0:(index register) + 20-bit offset; no extension

    def op_JMP(self, mode, f):
        self.next = self.jtarget(mode, f) & ~1

    def op_JSR(self, mode, f):
        self.call(self.pcp6, self.jtarget(mode, f))

    def op_RTS(self, mode, f):
        pkw = self.pull16()
        pc = self.pull16()
        self.next = ((((pkw & 0xF) << 16) | pc) - 2) & M20 & ~1

    def op_RTI(self, mode, f):
        ccr = self.pull16()
        pc = self.pull16()
        self.s['CCR'] = ccr
        self.next = ((((ccr & 0xF) << 16) | pc) - 6) & M20 & ~1

    def trap(self, vector):
        st = (self.pcp6 + 2) & M20
        self.push16(st & 0xFFFF)
        self.push16((self.s['CCR'] & 0xFFF0) | (st >> 16))
        self.next = self.rw(vector) & ~1     # PK cleared: bank 0

    def op_SWI(self, mode, f):
        self.trap(0x000C)

    def op_NOP(self, mode, f):
        pass

    def op_BGND(self, mode, f):
        raise Undefined('BGND: depends on BDM state')

    def op_WAI(self, mode, f):
        raise Undefined('WAI')

    def op_LPSTOP(self, mode, f):
        if not self.flag(S):
            raise Undefined('LPSTOP stops the clock')

    # transfers
    def tr(self, src, dst, flags):
        v = self.get(src)
        self.put(dst, v)
        if flags:
            self.logic(v, 8 if dst in 'AB' else 16)

    def op_TAB(self, mode, f): self.tr('A', 'B', True)

    def op_TBA(self, mode, f): self.tr('B', 'A', True)

    def op_TDE(self, mode, f): self.tr('D', 'E', True)

    def op_TED(self, mode, f): self.tr('E', 'D', True)

    def op_TAP(self, mode, f):
        self.s['CCR'] = (self.s['A'] << 8) | (self.s['CCR'] & 0xFF)

    def op_TPA(self, mode, f):
        self.s['A'] = self.s['CCR'] >> 8

    def op_TDP(self, mode, f):
        self.s['CCR'] = (self.D & 0xFFF0) | (self.s['CCR'] & 0xF)

    def op_TPD(self, mode, f):
        self.D = (self.s['CCR'] & 0xFFF0) | (self.pcp6 >> 16)

    def xg(self, a, b):
        va, vb = self.get(a), self.get(b)
        self.put(a, vb)
        self.put(b, va)

    def op_XGAB(self, mode, f): self.xg('A', 'B')

    def op_XGDE(self, mode, f): self.xg('D', 'E')

    def op_XGDX(self, mode, f): self.xg('D', 'IX')

    def op_XGDY(self, mode, f): self.xg('D', 'IY')

    def op_XGDZ(self, mode, f): self.xg('D', 'IZ')

    def op_XGEX(self, mode, f): self.xg('E', 'IX')

    def op_XGEY(self, mode, f): self.xg('E', 'IY')

    def op_XGEZ(self, mode, f): self.xg('E', 'IZ')

    def _t20(self, sk, sr, dk, dr, delta):
        self.setx20(dk, dr, self.x20(sk, sr) + delta)

    def op_TSX(self, mode, f): self._t20('SK', 'SP', 'XK', 'IX', 2)

    def op_TSY(self, mode, f): self._t20('SK', 'SP', 'YK', 'IY', 2)

    def op_TSZ(self, mode, f): self._t20('SK', 'SP', 'ZK', 'IZ', 2)

    def op_TXS(self, mode, f): self._t20('XK', 'IX', 'SK', 'SP', -2)

    def op_TYS(self, mode, f): self._t20('YK', 'IY', 'SK', 'SP', -2)

    def op_TZS(self, mode, f): self._t20('ZK', 'IZ', 'SK', 'SP', -2)

    def op_TXY(self, mode, f): self._t20('XK', 'IX', 'YK', 'IY', 0)

    def op_TXZ(self, mode, f): self._t20('XK', 'IX', 'ZK', 'IZ', 0)

    def op_TYX(self, mode, f): self._t20('YK', 'IY', 'XK', 'IX', 0)

    def op_TYZ(self, mode, f): self._t20('YK', 'IY', 'ZK', 'IZ', 0)

    def op_TZX(self, mode, f): self._t20('ZK', 'IZ', 'XK', 'IX', 0)

    def op_TZY(self, mode, f): self._t20('ZK', 'IZ', 'YK', 'IY', 0)

    def kb(self, k):
        self.s['B'] = self.s[k] & 0xF

    def bk(self, k):
        self.s[k] = self.s['B'] & 0xF

    def op_TBEK(self, mode, f): self.bk('EK')

    def op_TBXK(self, mode, f): self.bk('XK')

    def op_TBYK(self, mode, f): self.bk('YK')

    def op_TBZK(self, mode, f): self.bk('ZK')

    def op_TBSK(self, mode, f): self.bk('SK')

    def op_TEKB(self, mode, f): self.kb('EK')

    def op_TXKB(self, mode, f): self.kb('XK')

    def op_TYKB(self, mode, f): self.kb('YK')

    def op_TZKB(self, mode, f): self.kb('ZK')

    def op_TSKB(self, mode, f): self.kb('SK')

    def op_SXT(self, mode, f):
        self.s['A'] = 0xFF if self.s['B'] & 0x80 else 0
        self.nz(self.s['A'], 8)

    def op_MUL(self, mode, f):
        self.D = self.s['A'] * self.s['B']
        self.setf(C, self.D >> 7 & 1)

    def op_EMUL(self, mode, f):
        r = self.s['E'] * self.D
        self.s['E'], self.D = r >> 16, r & 0xFFFF
        self.setf(N, r >> 31 & 1); self.setf(Z, r == 0); self.setf(C, r >> 15 & 1)

    def op_EMULS(self, mode, f):
        r = (sx(self.s['E'], 16) * sx(self.D, 16)) & 0xFFFFFFFF
        self.s['E'], self.D = r >> 16, r & 0xFFFF
        self.setf(N, r >> 31 & 1); self.setf(Z, r == 0); self.setf(C, r >> 15 & 1)

    def op_FMULS(self, mode, f):
        e, d = sx(self.s['E'], 16), sx(self.D, 16)
        r = ((e * d) << 1) & 0xFFFFFFFF
        self.s['E'], self.D = r >> 16, r & 0xFFFF
        self.setf(N, r >> 31 & 1); self.setf(Z, r == 0); self.setf(C, r >> 15 & 1)
        self.setf(V, e == -32768 and d == -32768)

    def op_IDIV(self, mode, f):
        d, x = self.D, self.s['IX']
        self.setf(C, x == 0)
        self.setf(V, 0)
        if x == 0:
            self.s['IX'] = 0xFFFF
            self.undef.add('D')
        else:
            self.s['IX'], self.D = d // x, d % x
        self.setf(Z, self.s['IX'] == 0)

    def op_FDIV(self, mode, f):
        d, x = self.D, self.s['IX']
        self.setf(V, x <= d)
        self.setf(C, x == 0)
        if x <= d:
            self.s['IX'] = 0xFFFF
            self.undef.add('D')
        else:
            q = (d << 16) // x
            self.s['IX'], self.D = q, (d << 16) % x
        self.setf(Z, self.s['IX'] == 0)

    def _ediv(self, signed):
        x = self.s['IX']
        if x == 0:
            # division by zero: exception through vector 8 ($0010); flags undefined
            for b in ('N', 'Z', 'V', 'C'):
                self.undef.add('CCR.' + b)
            self.trap(0x0010)
            return
        ed = (self.s['E'] << 16) | self.D
        if signed:
            a, b = sx(ed, 32), sx(x, 16)
            q = abs(a) // abs(b)
            if (a < 0) != (b < 0):
                q = -q
            r = a - q * b
            ovf = not (-32768 <= q <= 32767)
            neg_div = b < 0
        else:
            q, r = divmod(ed, x)
            ovf = q > 0xFFFF
            b = x
        self.setf(V, ovf)
        if ovf:
            for k in ('N', 'Z', 'C'):
                self.undef.add('CCR.' + k)
            self.undef.update(('IX', 'D'))
            return
        self.s['IX'] = q & 0xFFFF
        self.D = r & 0xFFFF
        self.nz(q & 0xFFFF, 16)
        self.setf(C, 2 * abs(r) >= abs(b))

    def op_EDIV(self, mode, f): self._ediv(False)

    def op_EDIVS(self, mode, f): self._ediv(True)

    def op_DAA(self, mode, f):
        a = self.s['A']
        hi, lo = a >> 4, a & 0xF
        c, h = self.flag(C), self.flag(H)
        corr = 0
        if h or lo > 9:
            corr |= 0x06
        if c or hi > 9 or (hi > 8 and lo > 9):
            corr |= 0x60
            newc = 1
        else:
            newc = 0
        r = (a + corr) & 0xFF
        self.s['A'] = r
        self.nz(r, 8)
        self.setf(C, newc)
        self.undef.add('CCR.V')

    # stack byte pushes (glossary PSHA/PULA)
    def op_PSHA(self, mode, f):
        self.ssp = self.ssp + 1
        self.wb(self.ssp, self.s['A'])
        self.ssp = self.ssp - 2

    def op_PSHB(self, mode, f):
        self.ssp = self.ssp + 1
        self.wb(self.ssp, self.s['B'])
        self.ssp = self.ssp - 2

    def op_PULA(self, mode, f):
        self.ssp = self.ssp + 2
        self.s['A'] = self.rb(self.ssp)
        self.ssp = self.ssp - 1

    def op_PULB(self, mode, f):
        self.ssp = self.ssp + 2
        self.s['B'] = self.rb(self.ssp)
        self.ssp = self.ssp - 1

    def kword(self):
        return (self.s['EK'] << 12) | (self.s['XK'] << 8) | (self.s['YK'] << 4) | self.s['ZK']

    def op_PSHM(self, mode, f):
        m = f['ii']
        regs = [lambda: self.D, lambda: self.s['E'], lambda: self.s['IX'], lambda: self.s['IY'],
                lambda: self.s['IZ'], self.kword, lambda: (self.s['CCR'] & 0xFFF0) | (self.pcp6 >> 16)]
        for b in range(7):
            if m >> b & 1:
                self.push16(regs[b]())

    def op_PULM(self, mode, f):
        m = f['ii']
        for b in range(7):
            if m >> b & 1:
                v = self.pull16()
                if b == 0:
                    self.s['CCR'] = v            # PK field: see the module notes (program flow)
                elif b == 1:
                    self.s['EK'], self.s['XK'], self.s['YK'], self.s['ZK'] = v >> 12, v >> 8 & 0xF, v >> 4 & 0xF, v & 0xF
                elif b == 2:
                    self.s['IZ'] = v
                elif b == 3:
                    self.s['IY'] = v
                elif b == 4:
                    self.s['IX'] = v
                elif b == 5:
                    self.s['E'] = v
                elif b == 6:
                    self.D = v

    def op_MOVB(self, mode, f):
        self._mov(mode, f, 8)

    def op_MOVW(self, mode, f):
        self._mov(mode, f, 16)

    def _mov(self, mode, f, w):
        ixp = self.x20('XK', 'IX')
        if mode == 'IXP_to_EXT':
            src, dst = ixp, (self.s['EK'] << 16) | f['hhll']
        elif mode == 'EXT_to_IXP':
            src, dst = (self.s['EK'] << 16) | f['hhll'], ixp
        else:
            src, dst = (self.s['EK'] << 16) | f['hhll'], (self.s['EK'] << 16) | f["hhll'"]
        v = self.rb(src) if w == 8 else self.rw(src)
        if w == 8:
            self.wb(dst, v)
        else:
            self.ww(dst, v)
        self.logic(v, w)
        if mode != 'EXT_to_EXT':
            self.setx20('XK', 'IX', ixp + sx(f['ff'], 8))

    def op_LDED(self, mode, f):
        a = self.ea(mode, f)
        self.s['E'] = self.rw(a)
        self.D = self.rw(a + 2)

    def op_STED(self, mode, f):
        a = self.ea(mode, f)
        self.ww(a, self.s['E'])
        self.ww(a + 2, self.D)

    def op_LDHI(self, mode, f):
        self.s['HR'] = self.rw(self.x20('XK', 'IX'))
        self.s['IR'] = self.rw(self.x20('YK', 'IY'))

    def op_TDMSK(self, mode, f):
        self.s['XMSK'], self.s['YMSK'] = self.s['A'], self.s['B']

    def am_set32(self, v32):
        v = sx(v32, 32) & ((1 << 36) - 1)
        self.s['AM'] = v
        self.setf(MV, 0)
        self.setf(EV, 0)

    def op_TEDM(self, mode, f):
        self.am_set32((self.s['E'] << 16) | self.D)

    def op_TEM(self, mode, f):
        self.am_set32(self.s['E'] << 16)

    def op_CLRM(self, mode, f):
        self.s['AM'] = 0
        self.setf(MV, 0)
        self.setf(EV, 0)

    def op_ACED(self, mode, f):
        self.am_add(sx((self.s['E'] << 16) | self.D, 32) & ((1 << 36) - 1))

    def op_ACE(self, mode, f):
        self.am_add((sx(self.s['E'], 16) << 16) & ((1 << 36) - 1))

    def op_ASLM(self, mode, f):
        a = self.s['AM']
        r = (a << 1) & ((1 << 36) - 1)
        self.setf(C, a >> 35)
        if (a ^ r) >> 35 & 1:
            if not self.flag(MV):
                self.s['SL'] = r >> 35
            self.setf(MV, 1)
        self.s['AM'] = r
        self.am_flags(r)
        self.setf(N, r >> 35)

    def op_ASRM(self, mode, f):
        a = self.s['AM']
        r = (a >> 1) | (a & (1 << 35))
        self.setf(C, a & 1)
        self.s['AM'] = r
        self.am_flags(r)
        self.setf(N, r >> 35)

    def sat(self):
        if self.flag(MV):
            return 0x7FFF if self.s['SL'] else 0x8000
        return 0x8000 if self.s['AM'] >> 35 else 0x7FFF

    def op_TMET(self, mode, f):
        if self.flag(SM) and (self.flag(EV) or self.flag(MV)):
            e = self.sat()
        else:
            e = (self.s['AM'] >> 16) & 0xFFFF
        self.s['E'] = e
        self.nz(e, 16)

    def op_TMER(self, mode, f):
        a = self.s['AM']
        low = a & 0xFFFF
        up = low > 0x8000 or (low == 0x8000 and (a >> 16) & 1)
        t = (a + (0x10000 if up else 0)) & ~0xFFFF & ((1 << 36) - 1)
        if up and ((a ^ t) & ~a) >> 35 & 1:        # rounding overflowed into AM35
            if not self.flag(MV):
                self.s['SL'] = t >> 35
            self.setf(MV, 1)
        if ((t >> 31) & 0x1F) not in (0, 0x1F):
            self.setf(EV, 1)
        if self.flag(SM) and (self.flag(EV) or self.flag(MV)):
            e = self.sat()
        else:
            e = (t >> 16) & 0xFFFF
        self.s['E'] = e
        self.nz(e, 16)

    def op_TMXED(self, mode, f):
        a = self.s['AM']
        self.s['IX'] = ((0xFFF0 if a >> 35 else 0) | (a >> 32 & 0xF))
        self.s['E'] = (a >> 16) & 0xFFFF
        self.D = a & 0xFFFF

    def mac_once(self, xo, yo, is_mac):
        hr, ir = sx(self.s['HR'], 16), sx(self.s['IR'], 16)
        prod = (hr * ir) << 1
        if is_mac:
            ed = prod & 0xFFFFFFFF
            self.s['E'], self.D = ed >> 16, ed & 0xFFFF
            self.setf(V, hr == -32768 and ir == -32768)
        self.am_add(prod & ((1 << 36) - 1))
        if is_mac:
            self.s['IZ'] = self.s['HR']
        self.s['IX'] = self.qual('IX', xo, self.s['XMSK'])
        self.s['IY'] = self.qual('IY', yo, self.s['YMSK'])
        self.s['HR'] = self.rw(self.x20('XK', 'IX'))
        self.s['IR'] = self.rw(self.x20('YK', 'IY'))

    def op_MAC(self, mode, f):
        self.mac_once(f['xoyo'] >> 4, f['xoyo'] & 0xF, True)

    def op_RMAC(self, mode, f):
        n = 0
        while True:
            self.mac_once(f['xoyo'] >> 4, f['xoyo'] & 0xF, False)
            self.s['E'] = (self.s['E'] - 1) & 0xFFFF
            n += 1
            if self.s['E'] & 0x8000:
                break
            if n > 64:
                raise Undefined('long RMAC')
        self.undef.update(('E', 'D'))

    def op_PSHMAC(self, mode, f):
        am = self.s['AM']
        for v in ((self.s['XMSK'] << 8) | self.s['YMSK'], (self.s['SL'] << 15) | (am >> 32 & 0xF),
                  am >> 16 & 0xFFFF, am & 0xFFFF, self.s['IR'], self.s['HR']):
            self.push16(v)

    def op_PULMAC(self, mode, f):
        self.s['HR'] = self.pull16()
        self.s['IR'] = self.pull16()
        lo = self.pull16()
        hi = self.pull16()
        ext = self.pull16()
        self.s['AM'] = ((ext & 0xF) << 32) | (hi << 16) | lo
        self.s['SL'] = ext >> 15
        mk = self.pull16()
        self.s['XMSK'], self.s['YMSK'] = mk >> 8, mk & 0xFF

#!/usr/bin/env python3
"""Hand-computed emulator tests for the CPU16 module.

  emu_tests.py <outdir>      writes <outdir>/emu.bin (1 MB raw image) and <outdir>/emu_cases.txt

Every expectation below was worked out by hand from the CPU16 Reference Manual (CPU16RM), never
copied from the module's output; the comment on each case shows the arithmetic. Opcodes come from
cpu16_opcodes.json (Table 6-36 of the manual). The cases run in EmuCheck.java; XFAIL_ cases carry a
deliberately wrong expectation that must be reported.

CCR bits: S 15, MV 14, H 13, EV 12, N 11, Z 10, V 9, C 8, IP 7:5, SM 4, PK 3:0.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OPS = {(r['mn'], r['mode']): r['op'] for r in json.load(open(os.path.join(HERE, 'cpu16_opcodes.json')))}

F = {'S': 15, 'MV': 14, 'H': 13, 'EV': 12, 'N': 11, 'Z': 10, 'V': 9, 'C': 8, 'SM': 4}


def ins(mn, mode, operand=''):
    return bytes.fromhex(OPS[(mn, mode)] + operand.replace(' ', ''))


def flags(**kw):
    return ','.join(f'CCR.{F[k]}.1={v:x}' for k, v in kw.items())


# (name, code address, [instructions], stop address (None = after the code), extra code {addr: bytes},
#  init, expect)
CASES = []


def case(name, addr, code, init, expect, stop=None, extra=None):
    CASES.append((name, addr, code, stop, extra or {}, init, expect))


A = 0x10000   # code lives in bank 1, so stacked PK fields are 1

# ---- ALU and flags
# $7F + $01 = $80: half carry out of bit 3, signed overflow, negative, no carry
case('ADDA_HNV', A + 0x000, [ins('ADDA', 'IMM8', '01')], 'A=7f,CCR=0',
     'A=80,' + flags(H=1, N=1, Z=0, V=1, C=0))
# $00 + $FF + C(1) = $100: A = 0, carry out, half carry (0 + F + 1 = $10), no overflow (0 + -1 + 1)
case('ADCA_wrap', A + 0x010, [ins('ADCA', 'IMM8', 'FF')], 'A=0,CCR=100',
     'A=0,' + flags(H=1, N=0, Z=1, V=0, C=1))
# $0000 - $0001 = $FFFF with borrow
case('SUBD_borrow', A + 0x020, [ins('SUBD', 'IMM16', '0001')], 'D=0,CCR=0',
     'D=ffff,' + flags(N=1, Z=0, V=0, C=1))
# $80 - $7F - C(1) = $00: -128 - 127 - 1 = -256 overflows; 128 >= 128 so no borrow
case('SBCB_ovf', A + 0x030, [ins('SBCB', 'IMM8', '7F')], 'B=80,CCR=100',
     'B=0,' + flags(N=0, Z=1, V=1, C=0))
# $15 + $27 = $3C (H = 0: 5 + 7 < $10); DAA: low digit C > 9 adds $06 -> $42, C stays 0
case('ADDA_DAA', A + 0x040, [ins('ADDA', 'IMM8', '27'), ins('DAA', 'INH')], 'A=15,CCR=0',
     'A=42,' + flags(N=0, Z=0, C=0))
# $1234 * $0010 = $00012340 -> E = $0001, D = $2340; C = D15 = 0
case('EMUL', A + 0x050, [ins('EMUL', 'INH')], 'E=1234,D=10,CCR=0',
     'E=1,D=2340,' + flags(N=0, Z=0, C=0))
# $00010000 / 3 = $5555 remainder 1; C = (2 * 1 >= 3) = 0
case('EDIV', A + 0x060, [ins('EDIV', 'INH')], 'E=1,D=0,IX=3,CCR=0',
     'IX=5555,D=1,' + flags(N=0, Z=0, V=0, C=0))
# divide by zero: exception through vector 8 ($0010 holds $1234). Stacked: PK:PC + 2 = $10078 ->
# $0078 at SP, then CCR | PK(1) = $0001; PK = 0
case('EDIV_div0', A + 0x070, [ins('EDIV', 'INH')], 'E=1,D=0,IX=0,SK=0,SP=f00,CCR=0,m2:10=1234',
     'SP=efc,m2:f00=78,m2:efe=1', stop=0x01234)

# ---- MAC unit and E:D
# MAC 2,2: HR*IR = $4000*$4000 = $10000000, << 1 = $20000000 -> E:D and AM; IZ = old HR;
# IX, IY += 2 (masks 0); HR, IR reloaded from XK:IX = $23002 and YK:IY = $23102
case('MAC', A + 0x080, [ins('MAC', 'IMM8', '22')],
     'HR=4000,IR=4000,AM=0,AM_EXT=0,XMSK=0,YMSK=0,XK=2,YK=2,IX=3000,IY=3100,CCR=0,m2:23002=1111,m2:23102=2222',
     'E=2000,D=0,AM=20000000,AM_EXT=0,IZ=4000,IX=3002,IY=3102,HR=1111,IR=2222,' + flags(V=0, EV=0, MV=0))
# (-1) * (-1): E:D = $80000000, AM accumulates +1.0 = $0:80000000 -> AM[35:31] = 00001, EV = 1; V = 1
case('MAC_minus1', A + 0x090, [ins('MAC', 'IMM8', '00')],
     'HR=8000,IR=8000,AM=0,AM_EXT=0,XMSK=0,YMSK=0,XK=2,YK=2,IX=3000,IY=3000,CCR=0,m2:23000=1234',
     'E=8000,D=0,AM=80000000,AM_EXT=0,IZ=8000,HR=1234,IR=1234,' + flags(V=1, EV=1, MV=0))
# $7:FFFFFFFF (36-bit maximum) + E:D = 1 overflows to $8:00000000: MV = 1, SL latches 1, EV = 1
case('ACED_ovf', A + 0x0A0, [ins('ACED', 'INH')], 'E=0,D=1,AM=ffffffff,AM_EXT=7,SL=0,CCR=0',
     'AM=0,AM_EXT=8,SL=1,' + flags(MV=1, EV=1))
# TMER: AM = $0:00018000, low word = $8000 and AM16 = 1 -> round up to $0:00020000; E = $0002
case('TMER_round', A + 0x0B0, [ins('TMER', 'INH')], 'AM=18000,AM_EXT=0,CCR=0',
     'E=2,AM=18000,' + flags(N=0, Z=0, EV=0, MV=0))
# TMET with SM = 1, EV = 1, MV = 0, AM35 = 0: saturates to $7FFF
case('TMET_sat', A + 0x0C0, [ins('TMET', 'INH')], 'AM=80000000,AM_EXT=0,CCR=1010',
     'E=7fff,' + flags(N=0, Z=0))
# ASLM: $8:00000001 << 1 = $0:00000002; C = old AM35 = 1; AM35 changed: MV = 1, SL = new sign 0
case('ASLM', A + 0x0D0, [ins('ASLM', 'INH')], 'AM=1,AM_EXT=8,SL=1,CCR=0',
     'AM=2,AM_EXT=0,SL=0,' + flags(C=1, MV=1, N=0, EV=0))

# ---- addressing modes, incl. the K-register bank extension
# IND8,X: XK:IX = $2FFF8 + $10 = $30008 (the sum crosses into bank 3)
case('IND8X_bank', A + 0x100, [ins('LDAA', 'IND8,X', '10')], 'XK=2,IX=fff8,CCR=0,m1:30008=5a',
     'A=5a,' + flags(N=0, Z=0, V=0))
# IND16,Y with a negative offset: $30001 + (-2) = $2FFFF (word straddles banks 2 and 3)
case('IND16Y_neg', A + 0x110, [ins('LDD', 'IND16,Y', 'FFFE')], 'YK=3,IY=1,CCR=0,m1:2ffff=12,m1:30000=34',
     'D=1234,' + flags(N=0, Z=0, V=0))
# EXT uses EK: $5:4000
case('EXT_EK', A + 0x120, [ins('LDAB', 'EXT', '4000')], 'EK=5,CCR=0,m1:54000=80', 'B=80,' + flags(N=1, Z=0, V=0))
# TBEK then EXT: B = 7 -> EK = 7; LDAA $0010 reads $7:0010
case('TBEK_EXT', A + 0x130, [ins('TBEK', 'INH'), ins('LDAA', 'EXT', '0010')], 'B=7,EK=0,CCR=0,m1:70010=1',
     'EK=7,A=1,' + flags(N=0, Z=0))
# E,Z: ZK:IZ = $4:0100, E = $FFF0 (-16) -> $4:00F0
case('EZ_store', A + 0x140, [ins('STAA', 'E,Z')], 'A=77,E=fff0,ZK=4,IZ=100,CCR=0', 'm1:400f0=77,' + flags(N=0, Z=0, V=0))
# AIX #$10: XK:IX = $1FFF8 + $10 = $20008 (carry into XK), Z = 0
case('AIX_carry', A + 0x150, [ins('AIX', 'IMM8', '10')], 'XK=1,IX=fff8,CCR=0', 'XK=2,IX=8,' + flags(Z=0))
# AIX #8: $1FFF8 + 8 = $20000: IX = 0 so Z = 1
case('AIX_zero', A + 0x160, [ins('AIX', 'IMM8', '08')], 'XK=1,IX=fff8,CCR=0', 'XK=2,IX=0,' + flags(Z=1))
# MOVB IXP to EXT: source XK:IX = $2FFFF, destination EK:$1000 = $6:1000; then XK:IX + 2 = $30001
case('MOVB_IXP', A + 0x170, [ins('MOVB', 'IXP_to_EXT', '02 1000')], 'XK=2,IX=ffff,EK=6,CCR=0,m1:2ffff=c3',
     'm1:61000=c3,XK=3,IX=1,' + flags(N=1, Z=0, V=0))

# ---- branches (PC-relative to the instruction address + 6)
# BNE with Z = 0: $10180 + 6 + $0A = $10190
case('BNE_taken', A + 0x180, [ins('BNE', 'REL8', '0A')], 'CCR=0', '', stop=A + 0x190)
# BEQ with Z = 0 falls through
case('BEQ_not', A + 0x1A0, [ins('BEQ', 'REL8', '0A')], 'CCR=0', '', stop=A + 0x1A2)
# LBRA -$10: $101C0 + 6 - $10 = $101B6
case('LBRA_back', A + 0x1C0, [ins('LBRA', 'REL16', 'FFF0')], 'CCR=0', '', stop=A + 0x1B6)
# BRSET IND8,X: byte at $2:0005 = $83, mask $81 all set -> $101E0 + 6 + $20 = $10206
case('BRSET_taken', A + 0x1E0, [ins('BRSET', 'IND8,X', '81 05 20')], 'XK=2,IX=0,CCR=0,m1:20005=83', '',
     stop=A + 0x206)
# BRCLR EXT: byte at $2:0006 = $01, mask $01 not clear -> falls through to $10220 + 6
case('BRCLR_not', A + 0x220, [ins('BRCLR', 'EXT', '01 0006 0040')], 'EK=2,CCR=0,m1:20006=1', '', stop=A + 0x226)

# ---- calls, returns, stack
# JSR $1:2000 from $10240; RTS there. Stacked: PC = $10240 + 6 -> $0246 at $0F00, CCR | PK = $0001 at
# $0EFE. RTS pulls PK = 1 and PC $0246, returns to $10246 - 2 = $10244
case('JSR_RTS', A + 0x240, [ins('JSR', 'EXT20', '01 2000')], 'SK=0,SP=f00,CCR=0', 'SP=f00,m2:f00=246,m2:efe=1',
     stop=A + 0x244, extra={0x12000: ins('RTS', 'INH')})
# BSR +$3E from $10260 -> $10260 + 6 + $3E = $102A4 (RTS); BSR stacks PK:PC - 2 = $10264, RTS returns to
# $10262
case('BSR_RTS', A + 0x260, [ins('BSR', 'REL8', '3E')], 'SK=0,SP=f00,CCR=0', 'SP=f00,m2:f00=264,m2:efe=1',
     stop=A + 0x262, extra={A + 0x2A4: ins('RTS', 'INH')})
# RTI: frame CCR = $0901 (N, C, PK = 1), PC = $2006 -> PK:PC - 6 = $12000
case('RTI', A + 0x2C0, [ins('RTI', 'INH')], 'SK=0,SP=efc,CCR=0,m2:efe=901,m2:f00=2006',
     'SP=f00,' + flags(N=1, C=1, Z=0), stop=0x12000)
# PSHM D,E,CCR (mask $43): D at $0F00, E at $0EFE, CCR | PK = $0101 at $0EFC; SP = $0EFA
case('PSHM', A + 0x2E0, [ins('PSHM', 'IMM8', '43')], 'D=1111,E=2222,SK=0,SP=f00,CCR=100',
     'SP=efa,m2:f00=1111,m2:efe=2222,m2:efc=101')
# PULM E,D (mask $60): E from $0EFE first (bit 5), then D from $0F00 (bit 6)
case('PULM', A + 0x300, [ins('PULM', 'IMM8', '60')], 'SK=0,SP=efc,m2:efe=aaaa,m2:f00=bbbb',
     'SP=f00,E=aaaa,D=bbbb')
# PSHA: SP + 1 = $0F01 receives A, then SP - 2: SP = $0EFF
case('PSHA', A + 0x320, [ins('PSHA', 'INH')], 'A=5a,SK=0,SP=f00', 'SP=eff,m1:f01=5a')
# SWI from $10340: stacks PK:PC + 2 = $10348 -> $0348, CCR | PK = $0001; PK = 0, PC = ($000C) = $3000
case('SWI', A + 0x340, [ins('SWI', 'INH')], 'SK=0,SP=f00,CCR=0,m2:c=3000', 'SP=efc,m2:f00=348,m2:efe=1',
     stop=0x03000)
# JMP IND20,X: $0:FFF0 + $10010 = $20000; XK (5) is not used
case('JMP_IND20', A + 0x360, [ins('JMP', 'IND20,X', '01 0010')], 'XK=5,IX=fff0', '', stop=0x20000)
# TPD: D = CCR with the PK of the running code (bank 1)
case('TPD_PK', A + 0x380, [ins('TPD', 'INH')], 'CCR=8000', 'D=8001')
# LPSTOP with S = 1 is a NOP
case('LPSTOP_S1', A + 0x3A0, [ins('LPSTOP', 'INH')], 'CCR=8000', '')

# ---- the deliberately wrong expectation: ADDA_HNV clears C, this case claims C = 1
case('XFAIL_ADDA_C', A + 0x3C0, [ins('ADDA', 'IMM8', '01')], 'A=7f,CCR=0', 'A=80,' + flags(C=1))


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    img = bytearray(0x100000)
    lines = []
    for name, addr, code, stop, extra, init, expect in CASES:
        b = b''.join(code)
        img[addr:addr + len(b)] = b
        for a, x in extra.items():
            img[a:a + len(x)] = x
        stop = addr + len(b) if stop is None else stop
        lines.append(f'{name} {addr:x} {stop:x} {init or "-"} {expect or "-"}')
    open(os.path.join(out, 'emu.bin'), 'wb').write(img)
    open(os.path.join(out, 'emu_cases.txt'), 'w').write('\n'.join(lines) + '\n')
    print(f'{len(CASES)} cases')


if __name__ == '__main__':
    main()

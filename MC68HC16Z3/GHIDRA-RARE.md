# MC68HC16 (CPU16) in Ghidra-Rare

This is HausRummel's MC68HC16 processor module, verified and fixed for
[Ghidra-Rare](https://github.com/aleph-void/Ghidra-Rare). Upstream, license, authors and the list of
every change are in [CREDITS.md](CREDITS.md); the upstream [README](../README.md) describes the module.

- Extension name: `HC16` (module directory `MC68HC16Z3/`, as upstream)
- Languages (unchanged from upstream; no collision with Ghidra 12.1.x/12.2 or another Ghidra-Rare module):
  `68HC16:BE:24:cpu16` (bare CPU16 core), `68HC16:BE:24:default` (MC68HC16Z2/Z3 peripheral map),
  `68HC16:BE:24:JTEC` (Chrysler JTEC+ preset). All share `68HC16.sla`.
- Builds and runs on Ghidra 12.1.3, 12.1.4 and 12.2 (`tools/build-module.sh --standard --name HC16`; the
  hand-computed emulator cases pass on each).

## How to test

```
GHIDRA_INSTALL_DIR=<scratch Ghidra 12.1.x> MC68HC16Z3/test/run-tests.sh <workdir>          # ~10 min
GHIDRA_INSTALL_DIR=<scratch Ghidra 12.1.x> MC68HC16Z3/test/run-tests.sh <workdir> --real   # + real code
```

The suite symlinks the module into `<Ghidra>/Ghidra/Processors/HC16` when nothing is there. It needs MAME's
`unidasm` and `asl` (Macro Assembler AS) for steps 6 and 7; `--real` needs network access and docker (the
GNU hc16 toolchain is an i386 program from 1998, built in an i386 Debian container on first use). Headless
projects go to `$PROJ_DIR` (default `$TMPDIR`), which must not be under a dot directory.

| Step | What it checks |
|---|---|
| 1 | `68HC16_PSHM_PULM.sinc.py` reproduces the checked-in `.sinc` |
| 2 | the spec compiles; the tracked `68HC16.sla` is identical to a fresh compile |
| 3 | upstream's own vectors (`tests/run_disasm_tests.py`, 74 vectors) |
| 4 | 37 hand-computed emulator cases plus one deliberately wrong expectation (`emu_tests.py`) |
| 5 | random-state emulator differential: 30,240 single-instruction cases, 36 for every opcode/mode row of the manual's Table 6-36, expectations from `cpu16_model.py` (a model written from the CPU16RM glossary pages, not from the module) |
| 6 | decode differential against MAME `unidasm -arch cpu16` (`compare.py`) |
| 7 | asl round trip: Ghidra's text re-assembled by asl, bytes compared (`asl_roundtrip.py`) |
| 8 | every SLEIGH constructor reached (`Reach.java`) |
| 9 (`--real`) | encodings produced by Motorola's MASM 4.6 decode to the same mnemonic and length (`masm_check.py`) |
| 10 (`--real`) | zlib 1.3.1 compiled with the GNU hc16 GCC 2.8.1, analysed, decompiled, compared with MAME (`real-binaries.sh`) |

## Results

| Area | State |
|---|---|
| Decode | Every page-1 opcode x every second byte with random tails, every `17xx`/`27xx`/`37xx` opcode x 48 operand tails (102,400 slots), and 50,000 random slots, against MAME: 0 unexplained differences. Opcode corpus: 92,180 slots MAME decodes; 84,473 exact, 1,050 semantic (signed vs unsigned display of the same number), 6,657 explained (4,481 odd branch offsets the module shows rounded to the even target the CPU fetches; 1,920 JMP/JSR with a non-zero "z" nibble that the module rejects and MAME ignores; 256 PSHM/PULM with the reserved mask bit 7); 10,220 slots neither decodes. Random corpus: 42,010 exact, 583 semantic, 3,571 explained, 3,836 neither. asl round trip: 85,436 + 42,559 decoded slots re-assemble to the same bytes; the rest are the same three classes, asl's LDHI bug (below), 36 shorter-but-equal IMM8 forms, 20 branches wrapping at 1 MB and 6 empty PSHM/PULM lists asl cannot write; 0 mismatches. Motorola MASM 4.6 encodings: 856/856 rows decode to the same instruction and length. Constructors reached: 1,372/1,372 |
| Semantics | Full p-code: every addressing mode with the 20-bit bank arithmetic of the K-register fields (XK/YK/ZK for indexed modes, EK for EXT, carries across 64 KB banks), PC-relative branches (PK:PC + 6), BRSET/BRCLR, JSR/BSR/LBSR/RTS/RTI/SWI frames, PSHM/PULM/PSHA/PULA, the divide-by-zero exception, all ALU flags incl. H/V/N/Z/C, the E and E:D operations, EMUL/EDIV/FDIV/IDIV, and the 36-bit MAC unit (AM, EV, MV, SL latch, saturation, convergent rounding, modulo-qualified MAC/RMAC). Emulator: 37/37 hand-computed cases, broken expectation detected; 30,240/30,240 random-state cases against the manual model |
| Real code | zlib 1.3.1 (adler32, compress, crc32, deflate, inffast, inftrees, trees, uncompr, zutil) built with GNU hc16 GCC 2.8.1, linked at 0x400 and imported raw: 21,173 instructions, 89 functions, 0 bad-instruction or error bookmarks, 89/89 functions decompile; every instruction agrees with MAME at the same address (20,539 exact, 634 semantic) |
| Doesn't work | See "Known gaps" below: SK:SP is not wrapped at the 1 MB boundary; WAI, BGND and LPSTOP with S = 0 are pcodeops; asynchronous exceptions are not modelled; GNU hc16 GCC runtime calls need `HC16GccInlineArgs.java` |
| Unverified | No physical hardware and no freely licensed MC68HC16 firmware (the JTEC+ firmware the module was written for is proprietary): real code is compiled C from one compiler; hand-written code is covered only by the MASM probe rows. The Z2/Z3 peripheral maps, the JTEC+ preset and the empirical calling conventions in the `.cspec` files were not checked against firmware. Reserved encodings (PSHM/PULM bit 7, a non-zero "z" nibble) have no documented behaviour |

## What changed (summary; details in CREDITS.md and the commit messages)

Found by the tests above and fixed in the module:

- Branch targets wrapped at 24 instead of 20 bits and odd targets were shown unaligned; `ADDD #imm8` and
  `E,X` operands printed wrongly.
- Indexed addresses were formed in 16 bits (an offset never crossed a bank); `,Z` and EXT used context
  constants instead of the ZK/EK registers; JMP/JSR IND20 added the extension field the manual says is not
  used.
- The stack used the wrong convention (pre-decrement), calls stored no return frame and RTS returned
  through the PC register, PSHM pushed in reverse order, PSHMAC/PULMAC used a different frame, SL was
  missing.
- ADC/SBC carries, ROR overflow, TDE/TED/EMUL/FMULS/FDIV/IDIV/EDIV flags, AIX/ADX/AEX bank carries,
  MOVB/MOVW post-increment, and the whole MAC unit (36-bit carries, EV/MV/SL, saturation, rounding).
- The helper scripts were in `data/GhidraScripts/`, which Ghidra does not search; they are now in
  `ghidra_scripts/`.

## Upstream's own limitations and claims

Upstream has no issues; its README lists these, now updated in the README:

- *"Static bank resolution via context ... assumes the bank registers are effectively constant"*: fixed.
  The p-code uses the EK/XK/YK/ZK registers; the `.pspec` `tracked_set` keeps constant banks for the
  decompiler unless the code changes them.
- *"BGND, WAI and LPSTOP lift to opaque pseudo-ops ... WAI's context stacking intentionally not
  modeled"*: the CPU16's WAI stacks nothing (that is the M68HC11's WAI), so nothing is missing there;
  LPSTOP with S = 1 is now the NOP the manual describes. The remaining pseudo-ops wait for hardware events
  (below).
- *Calling conventions are empirical* (no ABI for hand-written CPU16 code): unchanged and stated as such.
- Helper scripts "run via Ghidra's Script Manager": they were not listed there (wrong directory); fixed.

The closed issue of the chirpy8 alternative ("JSR instruction is off by +1") does not apply: JSR EXT20 and
IND20 targets decode and execute exactly (test cases `JSR_RTS` and `JMP_IND20`, MASM probe rows).

## Known gaps

- **SK:SP is not wrapped at 1 MB.** A push at SK:SP = $00000 continues below 0 instead of wrapping to
  $FFFFE (likewise AIS across either end). Wrapping needs a mask on every stack-pointer update, which stops
  the decompiler from tracking stack variables; real stacks never sit at the ends of the address space.
  The random-state test skips the few such cases.
- **WAI, BGND, LPSTOP with S = 0** are pcodeops: they stop the CPU until an interrupt, a reset or a
  background-debug command, or (BGND) depend on whether BDM was enabled by hardware.
- **Asynchronous exceptions** (interrupts, bus errors, RMAC suspension and resumption) are not part of
  instruction semantics. SWI and the EDIV/EDIVS divide-by-zero exception are modelled.
- **PULM with the CCR bit** restores the flags, IP and SM; the PK field it pulls does not redirect the
  instruction stream (Ghidra's PC carries the bank), matching every use in practice (RTI restores PK:PC).
- **Results the manual leaves undefined** (D after IDIV/FDIV by zero, IX and D after EDIV/EDIVS overflow,
  V after DAA, E and D after RMAC) are left unchanged by the p-code.
- **GNU hc16 GCC 2.8.1 output**: calls to its runtime routines carry inline argument words after the JSR,
  which disassemble as phantom instructions. Run `ghidra_scripts/HC16GccInlineArgs.java` on programs that
  keep the routine names (the real-code test does: 48 call sites, 113 words); stripped programs need the
  call sites marked by hand.
- **JMP/JSR with a non-zero "z" nibble** (the top 4 bits of the 24-bit operand, which the manual defines as
  the zero extension of the 20-bit address) are not decoded. MAME ignores the nibble; no documentation
  says what the CPU does.

## Reference tools: confirmed bugs and differences

- **asl** (Macro Assembler AS, `CPU 68HC16`): LDHI requires an operand and is assembled as four bytes
  (`ldhi $1234` gives `27 B0 12 34`). The manual's LDHI page lists no operand (its mode column says "EXT",
  its operand column "—"), the operation reads only XK:IX and YK:IY, Table 6-36 and MAME give a two-byte
  INH instruction, and Motorola's MASM 4.6 emits `27 B0`. asl also does not wrap PC-relative distances at
  the 1 MB boundary.
- **MAME** `unidasm -arch cpu16`: prints page-2 ORAA (`17 47`/`17 57`/`17 67`/`17 77`) as `ora` (the manual
  and every other page: ORAA). It decodes JMP/JSR with a non-zero z nibble by ignoring the nibble, prints
  odd branch targets the CPU cannot fetch, prints the post-modified MOVB/MOVW offset unsigned although the
  manual defines it as signed, and prints `(reserved)` for PSHM/PULM mask bit 7.
- **The CPU16 Reference Manual** itself: the BSR page's operation line ("(PK : PC) − $0002 ⇒ PK : PC" before
  the offset is added) describes only the stacked value; the branch target is PK:PC + offset like every
  other branch (Motorola MASM 4.6 encodes `bsr *` as `36 FA`, the same offset as `bra *`). The LDHI page
  gives mode "EXT" for an instruction without an operand. The LPSTOP operation line ("If S, then enter
  low-power mode") contradicts its description (S = 1: NOP), which the module follows. The notation list
  calls `rr` an "8-bit unsigned relative offset"; branches treat it as signed.

## Alternatives

- [chirpy8/ghidra_68HC16](https://github.com/chirpy8/ghidra_68HC16) (Apache-2.0, `6076bfd`): 365
  constructors, 32-bit address space. Against MAME on the same opcode corpus it agrees on mnemonic and length
  for 99.44 % of the slots MAME decodes (this module: 97.92 %, the difference being the 1,920 non-zero
  z-nibble JMP/JSR it rejects), with 512 length disagreements and 49 slots MAME rejects. Its JSR/RTS stack a
  correct frame, but its RTS restores all CCR flags (the manual: PK only). No tests. Nothing was borrowed.
- [rimwall/Ghidra-HC16-Processor](https://github.com/rimwall/Ghidra-HC16-Processor) (no license, `a93a108`):
  916 constructors in a 16-bit address space, so the 20-bit banked addresses cannot be represented;
  98.87 % mnemonic-and-length agreement with MAME, 588 slots with a different mnemonic; JSR stacks the
  address of the next instruction instead of PK:PC. No tests. Compared only.

This module (HausRummel) is the most complete of the three and the only one with banked 20-bit p-code, the
MAC unit and tests.

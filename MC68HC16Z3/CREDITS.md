# Credits

## Upstream

- Repository: <https://github.com/HausRummel/Ghidra-Processor-MC68HC16Z>
- Commit: `b33c800bda7afe777e987252fd5d8a5301408e85` (2026-09-14, "Merge pull request #13 from
  HausRummel/checkout-v5")
- License: Apache License 2.0 (`LICENSE` in the repository root, copied here unchanged)
- Authors, from `git log` of that commit (2026-02-21 to 2026-09-14):
  - HausRummel (@HausRummel; commits as "HausRummel", "Hausrummel" and "david"): the module
  - László Dániel (@laszlodaniel): PSHM/PULM sub-constructors and the generator's hex masks (PR #1)
  - Claude (Anthropic) is credited as author or co-author ("Claude", "Claude Opus 4.8", "Claude Opus 5")
    on several upstream commits made with @HausRummel
- The reference manuals under `data/Manual/` (Motorola CPU16RM/AD and MC68HC16ZUM) are bundled by upstream
  and remain the property of their copyright holders.

## Ghidra-Rare changes

Branch `ghidra-rare` of the fork, on top of the upstream commit. Each change is its own commit; the
commit messages give the details and the evidence.

1. **Branch targets and display** (`52fd857`): PC-relative targets wrap at 20 bits and are word aligned
   (an odd offset or JMP/JSR EXT20 address executes from the even address below it, CPU16RM 5.6.1);
   `ADDD #imm8` prints its sign-extended operand; accumulator-offset modes print `E,X` / `E,Y` / `E,Z`.
   `tests/corpus/40_jmp_jsr.disasm`: the odd JMP target vector expects the aligned address.
2. **Effective addresses** (`9008249`): every indexed mode adds in 20 bits (offsets cross 64 KB banks,
   IND16 and E offsets are signed); the p-code reads the live `EK`/`ZK` registers instead of the
   `ctxEK`/`ctxZK` constants, with `<tracked_set>` defaults in the three `.pspec` files so the decompiler
   still sees constant banks; JMP/JSR IND20 do not use the extension field.
3. **P-code semantics** (`0a8e7dc`): stack convention (SK:SP points to the next free word), JSR/BSR/LBSR
   /SWI stack frames, RTS/RTI, PSHM/PULM order and the `.sinc` generator, PSHMAC/PULMAC frame and the SL
   bit, the divide-by-zero exception, LPSTOP with S = 1, ADC/SBC flags, ROR overflow, TDE/TED,
   EMUL/EMULS/FMULS/FDIV/EDIV/EDIVS flags and results, 20-bit AIX/ADX/AEX families, and the 36-bit MAC
   unit (ACE, ACED, ASLM, ASRM, TMER, TMET, MAC, RMAC, EV/MV/SL, saturation).
4. **MOVB/MOVW post-modified index** (`c287471`): the signed offset updates the 20-bit XK:IX and prints
   signed.
5. **IDIV** (`42a6c37`): Z reflects the `$FFFF` quotient after a division by zero.
6. **Helper scripts** (`d066b44`): `data/GhidraScripts/` moved to `ghidra_scripts/` (the directory
   Ghidra's Script Manager searches); new `HC16GccInlineArgs.java` for GNU hc16 GCC runtime calls with
   inline argument words.
7. **README.md** (repository root): the limitation and stale-claim updates listed in `GHIDRA-RARE.md`,
   and a pointer to this fork's notes and Releases page.
8. **Additions** (own commit): `GHIDRA-RARE.md`, this file, `LICENSE`, `test/`, a Ghidra-Rare style
   `build.gradle`, `extension.properties` with `name=HC16` and `version=@extversion@`, and an output path
   argument for `data/languages/68HC16_PSHM_PULM.sinc.py` (used by the test suite to check that the
   generator reproduces the checked-in `.sinc`).

`68HC16.sla` stays tracked, as upstream intends (a drop-in install needs no SLEIGH compile). Every commit
that changes the SLEIGH source regenerates it; the compiler output is deterministic and identical for
Ghidra 12.1.3, 12.1.4 and 12.2, and `test/run-tests.sh` fails when the tracked file differs from a fresh
compile.

## Sources used for the verification

- Motorola *CPU16 Reference Manual* (CPU16RM/AD Rev. 1), Freescale reprint, fetched from the Wayback
  Machine copy of `http://www.freescale.com/files/microcontrollers/doc/ref_manual/CPU16RM.pdf`
  (SHA-256 `f8890827d8d5ba69e3469d4a94514004de5f01b09ae7057e0e0c722aa4574524`; the same text as the copy
  upstream bundles). The instruction-set summary (Table 6-36) is the source of `test/cpu16_opcodes.json`;
  the glossary pages are the source of `test/cpu16_model.py` and of the hand-computed emulator cases.
- MAME `unidasm -arch cpu16` (GPL; run as a black box) as the decode reference.
- The Macro Assembler AS (`asl`, `CPU 68HC16`; GPL; black box) for the round trip.
- Motorola MASM 4.6 encodings recorded in `docs/spec/isa-probe.tsv` of
  [HausRummel/M68HC16_Assembler](https://github.com/HausRummel/M68HC16_Assembler) (Apache-2.0), commit
  `4d7914ba0d8bc402672f85116fb59e14a00e79da`; fetched by the test suite, not copied.
- The GNU hc16 cross toolchain (GCC 2.8.1, binutils 2.9.1, Real-Time Systems Inc.;
  [steve-m/hc16-toolchain](https://github.com/steve-m/hc16-toolchain) commit `fa35692`; GPL; built and run
  as a black box) and zlib 1.3.1 (zlib license) for real compiled code; fetched and built by
  `test/real-binaries.sh`, never committed.
- Alternatives compared, nothing borrowed: [chirpy8/ghidra_68HC16](https://github.com/chirpy8/ghidra_68HC16)
  (Apache-2.0, `6076bfd`) and [rimwall/Ghidra-HC16-Processor](https://github.com/rimwall/Ghidra-HC16-Processor)
  (no license, `a93a108`).

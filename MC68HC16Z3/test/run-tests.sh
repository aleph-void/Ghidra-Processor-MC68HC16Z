#!/usr/bin/env bash
# MC68HC16 (CPU16) module test suite (Ghidra-Rare). Everything here needs no downloaded input.
#
#   GHIDRA_INSTALL_DIR=<scratch Ghidra 12.1.x> MC68HC16Z3/test/run-tests.sh [workdir] [--real]
#
# 1. 68HC16_PSHM_PULM.sinc.py reproduces the checked-in .sinc
# 2. the spec compiles; the checked-in 68HC16.sla (upstream ships it for drop-in installs) is identical
#    to a fresh compile; .sla < 16 MB
# 3. upstream's own disassembly vectors (tests/run_disasm_tests.py)
# 4. p-code: hand-computed emulator cases (emu_tests.py), incl. a deliberately wrong expectation that
#    must be reported
# 5. p-code: random-state single-instruction differential against cpu16_model.py, a model of the CPU16
#    Reference Manual (emu_fuzz.py, 36 cases per opcode/mode row of the manual's Table 6-36)
# 6. decode differential against MAME unidasm -arch cpu16: every page-1 opcode x every second byte,
#    every 17xx/27xx/37xx opcode x 48 operand tails, 50,000 random slots; compare.py classifies every
#    difference and fails on an unexplained one
# 7. asl round trip (Macro Assembler AS, CPU 68HC16): Ghidra's text re-assembled, bytes compared
# 8. every SLEIGH constructor is reached by those corpora
# --real adds (test/real-binaries.sh, downloads pinned inputs):
# 9. decode of the encodings Motorola's MASM 4.6 produced (isa-probe.tsv of HausRummel/M68HC16_Assembler)
# 10. zlib 1.3.1 compiled with the GNU hc16 cross compiler (GCC 2.8.1), analysed, decompiled and compared
#     with MAME at the same addresses (needs docker for the i386 toolchain build)
#
# Environment: GHIDRA_INSTALL_DIR (scratch Ghidra; the module is symlinked as Ghidra/Processors/HC16
# when nothing is there), JAVA_HOME, UNIDASM (MAME unidasm), ASL/P2BIN (asl), PROJ_DIR (headless
# projects; must not be under a dot directory).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
MOD=$(cd "$HERE/.." && pwd)
REPO=$(cd "$MOD/.." && pwd)
L=$MOD/data/languages
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR to a scratch Ghidra 12.1.x}"
REAL=0
ARGS=()
for a in "$@"; do if [[ $a == --real ]]; then REAL=1; else ARGS+=("$a"); fi; done
W=$(readlink -m "${ARGS[0]:-${TMPDIR:-/tmp}/hc16-tests}")
mkdir -p "$W"
UNIDASM=${UNIDASM:-$(command -v unidasm || true)}
: "${ASL:=$(command -v asl || echo "$HOME/.cache/ghidra-rare-scratch/tools/asl/bin/asl")}"
export ASL UNIDASM GHIDRA_INSTALL_DIR
LANGID=68HC16:BE:24:cpu16
fail=0

P=$GHIDRA_INSTALL_DIR/Ghidra/Processors/HC16
if [[ ! -e $P ]]; then ln -s "$MOD" "$P"; elif [[ $(readlink -f "$P") != "$MOD" ]]; then
	echo "warning: $P exists and is not this module" >&2; fi

echo "== 1. generator reproduces 68HC16_PSHM_PULM.sinc"
python3 "$L/68HC16_PSHM_PULM.sinc.py" "$W/pshm.sinc"
cmp "$W/pshm.sinc" "$L/68HC16_PSHM_PULM.sinc" && echo "   identical"

echo "== 2. SLEIGH compiles; checked-in .sla is up to date"
"$GHIDRA_INSTALL_DIR/support/sleigh" "$L/68HC16.slaspec" "$W/68HC16.sla" >"$W/sleigh.log" 2>&1 ||
	{ grep -E "ERROR" "$W/sleigh.log"; exit 1; }
cmp "$W/68HC16.sla" "$L/68HC16.sla" && echo "   68HC16.sla identical to a fresh compile ($(stat -c %s "$L/68HC16.sla") bytes)" ||
	{ echo "   68HC16.sla is stale: run support/sleigh on 68HC16.slaspec"; fail=1; }
(($(stat -c %s "$W/68HC16.sla") < 16 * 1024 * 1024))

echo "== 3. upstream disassembly vectors (tests/run_disasm_tests.py)"
# the harness creates its Ghidra project next to itself: run a copy outside any dot directory
UP=$(mktemp -d "${PROJ_DIR:-${TMPDIR:-/tmp}}/hc16-uptests.XXXXXX")
cp -r "$REPO/tests/." "$UP"
(cd "$UP" && python3 run_disasm_tests.py --no-allow-skip >"$W/uptests.log" 2>&1) || fail=1
grep -v WARNING "$W/uptests.log" | tail -2 | sed 's/^/   /'
rm -rf "$UP"

echo "== 4. emulator: hand-computed cases"
mkdir -p "$W/emu"
python3 "$HERE/emu_tests.py" "$W/emu"
"$HERE/ghidra-script.sh" raw $LANGID "$W/emu/emu.bin" EmuCheck.java "$W/emu/emu_cases.txt" "$W/emu/out.txt"
echo "   $(tail -1 "$W/emu/out.txt")"
grep -q ", 0 failed, 1 broken expectations detected" "$W/emu/out.txt" || { grep -v "^PASS" "$W/emu/out.txt" | head -20; fail=1; }

echo "== 5. emulator: random-state differential against the manual model"
mkdir -p "$W/fuzz"
python3 "$HERE/emu_fuzz.py" "$W/fuzz" 36 1
"$HERE/ghidra-script.sh" raw $LANGID "$W/fuzz/fuzz.bin" EmuCheck.java "$W/fuzz/fuzz.txt" "$W/fuzz/out.txt" reuse
echo "   $(tail -1 "$W/fuzz/out.txt")"
grep -q ", 0 failed" "$W/fuzz/out.txt" || { grep "^FAIL" "$W/fuzz/out.txt" | head -20; fail=1; }

echo "== 6. decode differential against MAME unidasm -arch cpu16"
python3 "$HERE/gen_corpus.py" enum "$W/enum.bin"
python3 "$HERE/gen_corpus.py" random "$W/rand.bin" 50000 1
"$HERE/ghidra-script.sh" raw $LANGID "$W/enum.bin" DumpSlots.java "$W/enum.gh" 16
"$HERE/ghidra-script.sh" raw $LANGID "$W/rand.bin" DumpSlots.java "$W/rand.gh" 16
if [[ -n $UNIDASM ]]; then
	for c in enum rand; do
		UNIDASM=$UNIDASM python3 "$HERE/mame_dis.py" "$W/$c.bin" "$W/$c.mt"
		echo "   $c:"
		python3 "$HERE/compare.py" "$W/$c.gh" "$W/$c.mt" "$W/$c.bin" --show 5 --summary | sed 's/^/   /' || fail=1
	done
else
	echo "   skipped (no unidasm)"
fi

echo "== 7. asl round trip"
if [[ -x $ASL ]]; then
	for c in enum rand; do
		python3 "$HERE/asl_roundtrip.py" "$W/$c.gh" "$W/$c.bin" "$W/asl-$c" --show 5 | sed 's/^/   /' || fail=1
	done
else
	echo "   skipped (no asl)"
fi

echo "== 8. every constructor is reached"
cat "$W/enum.bin" "$W/rand.bin" > "$W/reach.bin"
"$HERE/ghidra-script.sh" raw $LANGID "$W/reach.bin" Reach.java "$W/reach.txt" 16
python3 "$HERE/reach.py" "$L" "$W/reach.txt" || fail=1

if ((REAL)); then
	echo "== 9-10. real code"
	"$HERE/real-binaries.sh" "$W/real" || fail=1
fi

if ((fail)); then echo "FAILED"; exit 1; fi
echo "all tests passed"

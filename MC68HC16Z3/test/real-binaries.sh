#!/usr/bin/env bash
# Real-code checks for the MC68HC16 module (called by run-tests.sh --real). Nothing fetched here is
# committed; every input is pinned by URL and SHA-256.
#
#   GHIDRA_INSTALL_DIR=... MC68HC16Z3/test/real-binaries.sh <workdir>
#
# A. Motorola MASM 4.6 encodings: docs/spec/isa-probe.tsv of HausRummel/M68HC16_Assembler (Apache-2.0),
#    the output of the original DOS assembler for one operand per mnemonic and addressing mode; every
#    row must decode to the same mnemonic (or the manual's CPU16 name for an M68HC11 spelling) and length.
# B. zlib 1.3.1 (zlib license) compiled with the GNU hc16 cross compiler: GCC 2.8.1 / binutils 2.9.1 for
#    hc16-coff (github.com/steve-m/hc16-toolchain, GPL; built as an i386 program in docker, run as a black
#    box). The linked image is imported raw, functions are created at the symbol addresses, it is
#    analysed and every function decompiled; the listing is compared with MAME at the same addresses.
#    inflate.c is left out: cc1 2.8.1 aborts on it ("Unable to find a register to spill") at every -O.
#    The runtime routines (___hc16_mulsi ...) and the inflate entry points are stubbed with empty C
#    functions: the toolchain's libgcc sources carry an "All Rights Reserved" notice, so they are not used.
#
# Environment: HC16TC (toolchain tree; default ~/.cache/ghidra-rare-scratch/tools/hc16-toolchain-src, built
# on first use), UNIDASM.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(readlink -m "${1:?workdir}")
mkdir -p "$W/dl"
UNIDASM=${UNIDASM:-$(command -v unidasm)}
LANGID=68HC16:BE:24:cpu16
fail=0

fetch() { # url sha256 out
	[[ -f $3 ]] || curl -sSL --retry 3 -o "$3" "$1"
	echo "$2  $3" | sha256sum -c --quiet - || { echo "checksum mismatch: $3" >&2; rm -f "$3"; exit 1; }
}

echo "== A. Motorola MASM 4.6 encodings"
MASM_COMMIT=4d7914ba0d8bc402672f85116fb59e14a00e79da
fetch "https://raw.githubusercontent.com/HausRummel/M68HC16_Assembler/$MASM_COMMIT/docs/spec/isa-probe.tsv" \
	add7004e4133e452dc3785de4c683728b27e16ff5b384478adaa958f142d20b3 "$W/dl/isa-probe.tsv"
python3 "$HERE/masm_check.py" corpus "$W/dl/isa-probe.tsv" "$W/masm.bin" >/dev/null
"$HERE/ghidra-script.sh" raw $LANGID "$W/masm.bin" DumpSlots.java "$W/masm.gh" 16
python3 "$HERE/masm_check.py" compare "$W/dl/isa-probe.tsv" "$W/masm.gh" || fail=1

echo "== B. zlib 1.3.1 built with GNU hc16 GCC 2.8.1"
TC=${HC16TC:-$HOME/.cache/ghidra-rare-scratch/tools/hc16-toolchain-src}
TC_COMMIT=fa35692
IMG=hc16-toolchain-build:local
if ! docker image inspect $IMG >/dev/null 2>&1; then
	mkdir -p "$W/docker"
	cat > "$W/docker/Dockerfile" <<'EOF'
FROM docker.io/i386/debian:bookworm
RUN apt-get update && apt-get install -y --no-install-recommends build-essential make flex bison texinfo autoconf gperf && apt-get clean
EOF
	docker build -q -t $IMG "$W/docker"
fi
if [[ ! -x $TC/build/gcc/xgcc ]]; then
	git clone -q https://github.com/steve-m/hc16-toolchain "$TC"
	git -C "$TC" checkout -q $TC_COMMIT
	# keep the generated parsers/lexers/info files that ship in the tree: a checkout gives every file
	# the same time, and the 1998 grammars do not build with a current bison
	find "$TC" -type f \( -name '*.y' -o -name '*.l' -o -name '*.gperf' -o -name '*.texi' -o -name '*.texinfo' \) \
		-exec touch -d '2000-01-01 00:00' {} +
	# GCC 2.8.1 / binutils 2.9.1 need old C (gnu89, common symbols); only the C front end builds with a
	# current bison
	docker run --rm -u "$(id -u):$(id -g)" -v "$TC":/w -w /w $IMG sh -c '
		./one-tree-0.sh && rm -rf build && mkdir build && cd build &&
		CFLAGS="-O1 -std=gnu89 -fcommon -w" setarch i686 ../src/configure --target=hc16-coff \
			--host=i686-pc-linux-gnu --prefix=/w/inst >../config.log 2>&1 &&
		make -w LANGUAGES=c CFLAGS="-O1 -std=gnu89 -fcommon -w" >../build.log 2>&1' ||
		{ echo "toolchain build failed, see $TC/build.log" >&2; exit 1; }
fi
mkdir -p "$TC/hc16bin"
ln -sf ../build/gas/as-new "$TC/hc16bin/as"
ln -sf ../build/ld/ld-new "$TC/hc16bin/ld"
tool() { # run a toolchain program in the container, in $W/zlib
	local p=$1
	shift
	case $p in
	gcc) set -- /tc/build/gcc/xgcc -B/tc/build/gcc/ -B/tc/hc16bin/ "$@" ;;
	ld) set -- /tc/build/ld/ld-new "$@" ;;
	nm) set -- /tc/build/binutils/nm-new "$@" ;;
	objcopy) set -- /tc/build/binutils/objcopy "$@" ;;
	esac
	docker run --rm -u "$(id -u):$(id -g)" -v "$TC":/tc:ro -v "$W/zlib":/z -w /z $IMG "$@"
}
fetch https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz \
	9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23 "$W/dl/zlib-1.3.1.tar.gz"
rm -rf "$W/zlib" && mkdir -p "$W/zlib/o"
tar -xzf "$W/dl/zlib-1.3.1.tar.gz" -C "$W/zlib"
OBJS=()
for f in adler32:-O2 compress:-O2 crc32:-O2 inffast:-O2 uncompr:-O2 zutil:-O2 deflate:-O0 trees:-O0 inftrees:-O0; do
	tool gcc "${f#*:}" -DZ_SOLO -DNO_GZIP -Izlib-1.3.1 -c "zlib-1.3.1/${f%:*}.c" -o "o/${f%:*}.o" 2>/dev/null
	OBJS+=("o/${f%:*}.o")
done
export LC_ALL=C
tool nm "${OBJS[@]}" | awk '$1=="U"{print $2}' | sort -u >"$W/zlib/undef.txt"
tool nm "${OBJS[@]}" | awk 'NF==3{print $3}' | sort -u >"$W/zlib/def.txt"
comm -23 "$W/zlib/undef.txt" "$W/zlib/def.txt" | sed 's/^_//; s/.*/void &(void) {}/' >"$W/zlib/stubs.c"
tool gcc -O2 -c stubs.c -o o/stubs.o
tool ld -Ttext 0x400 -Tdata 0xD000 -Tbss 0xE100 -e 0x400 -o zlib.out "${OBJS[@]}" o/stubs.o 2>&1 | grep -v "entry symbol" || true
tool objcopy -O binary -R .ctors -R .bss -R .heap -R .stack zlib.out zlib.bin
tool nm -n zlib.out | awk '($2=="T"||$2=="t") && $3 !~ /^L[0-9]/ && $3 !~ /^\./ {print $3, $1}' >"$W/zlib/entries.txt"
echo "   image $(stat -c %s "$W/zlib/zlib.bin") bytes at 0x400, $(wc -l <"$W/zlib/entries.txt") function symbols"
BASE_ADDR=0x400 "$HERE/ghidra-script.sh" raw-analyze $LANGID "$W/zlib/zlib.bin" RealCheck.java \
	"$W/zlib/summary.txt" "$W/zlib/listing.txt" 1000 "$W/zlib/entries.txt" gcc-inline-args
grep -E "^(instructions|functions|bookmark|decompiled)" "$W/zlib/summary.txt" | sed 's/^/   /'
grep -q "^bookmark Error" "$W/zlib/summary.txt" && { grep "^Error" "$W/zlib/summary.txt" | head; fail=1; }
grep -q "failed 0 " "$W/zlib/summary.txt" || fail=1
"$UNIDASM" "$W/zlib/zlib.bin" -arch cpu16 -basepc 400 >"$W/zlib/mame.txt"
python3 "$HERE/real_compare.py" "$W/zlib/listing.txt" "$W/zlib/mame.txt" "$W/zlib/zlib.bin" 400 | sed 's/^/   /' || fail=1

((fail == 0))

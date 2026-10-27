// Runs the p-code semantic tests produced by emu_tests.py in Ghidra's p-code emulator.
// The program must be emu.bin imported raw at address 0.
// Script args: <tests.txt> <outfile> [reuse]
//   "reuse" keeps one emulator for all cases (much faster); use it only when every case initialises
//   all registers and every memory byte it reads (emu_fuzz.py does).
//   tests.txt lines: <name> <start-hex> <stop-hex> <init|-> <expect>
//   init/expect items: reg=hex or m<size>:<addr-hex>=hex (big-endian memory of 1/2/4/8 bytes)
//   An expect item TRAP=<name> means the program must stop at a pcodeop (a hardware trap or bus
//   operation) with that name instead of reaching the stop address; the other items are then
//   checked against the state at that point.
// A test whose name starts with XFAIL_ must be reported as failing: it proves that the checks can fail.
//@category Testing

import java.io.PrintStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.pcode.emulate.EmulateExecutionState;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;

public class EmuCheck extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		PrintStream out = new PrintStream(args[1]);
		reuse = args.length > 2 && args[2].equals("reuse");
		int pass = 0, fail = 0, xfail = 0;
		for (String line : Files.readAllLines(Path.of(args[0]))) {
			line = line.trim();
			if (line.isEmpty() || line.startsWith("#")) {
				continue;
			}
			String[] f = line.split("\\s+");
			String err = runOne(f);
			boolean expectFail = f[0].startsWith("XFAIL_");
			if (expectFail) {
				if (err == null) {
					fail++;
					out.println("FAIL " + f[0] + ": the deliberately wrong expectation was accepted");
				}
				else {
					xfail++;
					out.println("PASS " + f[0] + " (wrong expectation detected: " + err + ")");
				}
			}
			else if (err == null) {
				pass++;
				out.println("PASS " + f[0]);
			}
			else {
				fail++;
				out.println("FAIL " + f[0] + ": " + err);
			}
		}
		out.printf("emulator tests: %d passed, %d failed, %d broken expectations detected%n", pass, fail,
			xfail);
		out.close();
	}

	private Register reg(String name) {
		Register r = currentProgram.getRegister(name);
		if (r == null) {
			r = currentProgram.getRegister(name.toUpperCase());
		}
		if (r == null) {
			throw new IllegalArgumentException("no register " + name);
		}
		return r;
	}

	private static final int MAX_STEPS = 1000;
	private boolean reuse;
	private boolean cleanStop;
	private EmulatorHelper shared;

	private String runOne(String[] f) throws Exception {
		Address start = toAddr(Long.parseUnsignedLong(f[1], 16));
		Address stop = toAddr(Long.parseUnsignedLong(f[2], 16));
		EmulatorHelper emu = reuse && shared != null ? shared : new EmulatorHelper(currentProgram);
		boolean ok = false;
		cleanStop = false;
		try {
			if (!f[3].equals("-")) {
				for (String kv : f[3].split(",")) {
					set(emu, kv);
				}
			}
			emu.writeRegister(emu.getPCRegister(), start.getOffset());
			String trap = null;
			for (String kv : f[4].split(",")) {
				if (kv.startsWith("TRAP=")) {
					trap = kv.substring(5);
				}
			}
			// step with a limit, so that a wrong branch target cannot run away
			boolean reached = false, faulted = false;
			for (int n = 0; n < MAX_STEPS; n++) {
				if (!emu.step(monitor)) {
					faulted = true;
					break;
				}
				if (emu.getExecutionAddress().equals(stop)) {
					reached = true;
					break;
				}
			}
			if (trap != null) {
				String err = String.valueOf(emu.getLastError());
				if (!faulted || !err.contains(trap)) {
					return "expected a trap in " + trap + " but state is " + emu.getEmulateExecutionState() +
						" at " + emu.getExecutionAddress() + " (" + err + ")";
				}
			}
			else if (!reached) {
				return "did not reach " + stop + " (state " + emu.getEmulateExecutionState() + " at " +
					emu.getExecutionAddress() + ", " + emu.getLastError() + ")";
			}
			cleanStop = reached;
			StringBuilder bad = new StringBuilder();
			for (String kv : f[4].equals("-") ? new String[0] : f[4].split(",")) {
				if (kv.startsWith("TRAP=")) {
					continue;
				}
				String[] p = kv.split("=");
				BigInteger want = new BigInteger(p[1], 16);
				BigInteger got;
				if (p[0].startsWith("m") && p[0].contains(":")) {
					int size = Integer.parseInt(p[0].substring(1, p[0].indexOf(':')));
					Address a = toAddr(Long.parseUnsignedLong(p[0].substring(p[0].indexOf(':') + 1), 16));
					byte[] b = emu.readMemory(a, size);
					got = BigInteger.ZERO;
					for (int i = 0; i < size; i++) {
						got = got.shiftLeft(8).or(BigInteger.valueOf(b[i] & 0xff));
					}
					want = want.and(BigInteger.ONE.shiftLeft(size * 8).subtract(BigInteger.ONE));
				}
				else {
					// "REG.bit.width" compares a bit field of a register (CPU16 CCR flags)
					String[] q = p[0].split("\\.");
					Register r = reg(q[0]);
					int shift = q.length == 3 ? Integer.parseInt(q[1]) : 0;
					int width = q.length == 3 ? Integer.parseInt(q[2]) : r.getBitLength();
					BigInteger mask = BigInteger.ONE.shiftLeft(width).subtract(BigInteger.ONE);
					want = want.and(mask);
					got = emu.readRegister(r).shiftRight(shift).and(mask);
				}
				if (!want.equals(got)) {
					bad.append(String.format(" %s=%x (want %x)", p[0], got, want));
				}
			}
			ok = true;
			return bad.length() == 0 ? null : bad.toString().trim();
		}
		finally {
			if (reuse && ok && cleanStop) {
				shared = emu;
			}
			else {
				emu.dispose();
				shared = null;
			}
		}
	}

	private void set(EmulatorHelper emu, String kv) throws Exception {
		String[] p = kv.split("=");
		BigInteger v = new BigInteger(p[1], 16);
		if (p[0].startsWith("m") && p[0].contains(":")) {
			int size = Integer.parseInt(p[0].substring(1, p[0].indexOf(':')));
			Address a = toAddr(Long.parseUnsignedLong(p[0].substring(p[0].indexOf(':') + 1), 16));
			byte[] b = new byte[size];
			for (int i = 0; i < size; i++) {
				b[i] = v.shiftRight(8 * (size - 1 - i)).byteValue();
			}
			emu.writeMemory(a, b);
		}
		else {
			emu.writeRegister(reg(p[0]), v);
		}
	}
}

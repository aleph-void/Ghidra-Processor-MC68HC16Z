// HC16GccInlineArgs.java
// For code built with the GNU hc16 cross compiler (GCC 2.8.1, hc16-coff; github.com/steve-m/hc16-toolchain):
// its runtime routines for 32-bit and float arithmetic (___hc16_mulsi, ___hc16_udivsi, ___hc16_addsf ...) are
// called as
//         jsr  ___hc16_mulsi
//         dc.w 44,36,48          ; stack offsets of the target and the operands
// and return past the inline words. Ghidra cannot know that, so it disassembles the words as phantom
// instructions (usually COM n,X, which also write memory in the decompiled code). This script turns
// the words after every call to a known routine into data and sets the call's fall-through past them.
//
// The program must have the runtime routines' names (a linked image with symbols). The word counts were
// observed in the compiler's assembler output; add others with the script argument or prompt as
// "name=words,name=words".
//
// Ghidra-Rare addition (see GHIDRA-RARE.md).
// @category MC68HC16

import java.util.HashMap;
import java.util.Map;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

public class HC16GccInlineArgs extends GhidraScript {

	private static final String DEFAULTS =
		"___hc16_mulsi=3,___hc16_divsi=3,___hc16_udivsi=3,___hc16_modsi=3,___hc16_umodsi=3," +
			"___hc16_ashlsi=2,___hc16_ashrsi=2,___hc16_lshrsi=2,___hc16_negsi=2," +
			"___hc16_addsf=3,___hc16_subsf=3,___hc16_mulsf=3,___hc16_divsf=3,___hc16_negsf=2," +
			"___hc16_cmpsf=2,___hc16_fix_truncsfsi=2,___hc16_floatsisf=2,___hc16_fix_truncsfhi=1," +
			"___hc16_fixuns_truncsfhi=1,___hc16_floathisf=1,___hc16_floatunshisf=1";

	@Override
	protected void run() throws Exception {
		Map<String, Integer> words = new HashMap<>();
		parse(DEFAULTS, words);
		String[] args = getScriptArgs();
		if (args.length > 0) {
			parse(args[0], words);
		}
		else if (!isRunningHeadless()) {
			parse(askString("HC16GccInlineArgs", "Extra routines (name=words,...), or empty", ""), words);
		}
		int sites = 0;
		SymbolIterator it = currentProgram.getSymbolTable().getAllSymbols(true);
		while (it.hasNext() && !monitor.isCancelled()) {
			Symbol s = it.next();
			Integer k = words.get(s.getName());
			if (k == null) {
				continue;
			}
			for (Reference r : getReferencesTo(s.getAddress())) {
				if (!r.getReferenceType().isCall()) {
					continue;
				}
				Instruction call = getInstructionAt(r.getFromAddress());
				if (call == null) {
					continue;
				}
				Address args0 = call.getMaxAddress().add(1);
				Address after = args0.add(2L * k);
				clearListing(args0, after.subtract(1));
				for (int i = 0; i < k; i++) {
					createWord(args0.add(2L * i));
				}
				call.setFallThrough(after);
				disassemble(after);
				sites++;
			}
		}
		println("HC16GccInlineArgs: " + sites + " call sites fixed");
	}

	private static void parse(String spec, Map<String, Integer> words) {
		for (String item : spec.split(",")) {
			String[] kv = item.trim().split("=");
			if (kv.length == 2) {
				words.put(kv[0].trim(), Integer.parseInt(kv[1].trim()));
			}
		}
	}
}

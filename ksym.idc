// Rename functions that are exported via `EXPORT_SYMBOL` and 
// `EXPORT_SYMBOL_GPL` in a Linux kernel.

#include <idc.idc>

// Get start address of a segment by name.
//     name - name of segment
// returns: linear address of the start of the segment
//          BADSEL - Segment not found
static SegStartByName(name) {
	auto segBase = SegByName(name);
	if (segBase == BADSEL) {
		return BADSEL;
	}
	
	return SegByBase(segBase);
}

// Decode a symbol table by converting even members to a function pointer, and odd members to a string pointer.
//     segname - Name of the segment containing the symbol table
static DecodeSymtab(segname) {
#ifdef __EA64__
	Message("Detected IDA 64-bits: assuming program is 64-bits.\n");
	auto flags = FF_QWRD;
	auto size = 8;
#else
	Message("Detected IDA 32-bits: assuming program is 32-bits.\n");
	auto flags = FF_DWRD;
	auto size = 4;
#endif
	
	auto ksymtab = SegStartByName(segname);
	if (ksymtab == BADSEL) {
		Warning("ksymtab segment not found!");
		return;
	}
	
	auto ksymtab_end = SegEnd(ksymtab);
	
	Message("found ksymtab %x - %x\n", ksymtab, ksymtab_end);
	
	// Have to undefine it to bypass the "Directly convert to data?" prompt.
	Message("Undefining the table...\n");
	MakeUnknown(ksymtab, ksymtab_end - ksymtab, DOUNK_SIMPLE | DOUNK_EXPAND | DOUNK_DELNAMES);
	
	auto addr;
	for (addr = ksymtab; addr != ksymtab_end; addr = addr + size) {
		auto result = MakeData(addr, flags, size, BADADDR);
		if (result == 1) {
			// ok
		}
		else {
			// failure
			Warning("Error converting at 0x%x\n", addr);
			return;
		}
	}
}

// Read a pointer-sized int.
//     ea - Pointer's address
static ReadPtr(ea) {
#ifdef __EA64__
	return Qword(ea);
#else
	return Dword(ea);
#endif
}

// Rename functions mentionned in a symbol table
//     segname - Name of the segment in which the symbol table is
static ApplySymtab(segname) {
	auto symtab_start = SegStartByName(segname);
	auto symtab_end = SegEnd(symtab_start);
	
	if (symtab_start == BADSEL) {
		Warning("Segment %s not found", segname);
		return;
	}
	
	auto ea = symtab_start;
	while (ea < symtab_end) {
		auto fun_ea = ReadPtr(ea);
		ea = ea + ItemSize(ea);
		
		auto fun_name = GetString(ReadPtr(ea), -1, ASCSTR_C);
		ea = ea + ItemSize(ea);
		
		Message("Renaming %x to %s\n", fun_ea, fun_name);
		if (! MakeNameEx(fun_ea, fun_name, SN_NOCHECK | SN_NOWARN)) {
			fun_name = "_" + fun_name;
			MakeName(fun_ea, fun_name);
		}
	}
}

static main() {
	DecodeSymtab("__ksymtab");
	DecodeSymtab("__ksymtab_gpl");
	
	ApplySymtab("__ksymtab");
	ApplySymtab("__ksymtab_gpl");
}
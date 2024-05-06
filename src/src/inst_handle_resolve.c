#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include "global.h"
#include "disassemble.h"
#include "insthandler_arm.h"
#include "reverse_exe.h"
#include "inst_opd.h"

/*
void reverse_operation(valset_u *src1, valset_u *src2, valset_u *dst, x86_insn_t) {
}
*/

int translate_datatype_to_byte(cs_insn* insn) {
	// return memory size modified, according to the instruction
	if (!insn) {
		LOG(stderr, "Error: In translate_datatype_to_bytes(cs_insn* insn), insn is NULL\n");
		assert(0);
	}
	return arm_get_datatype(insn);
}


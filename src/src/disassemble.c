#include <stdio.h>
#include <capstone/capstone.h>
#include <assert.h>
#include <reverse_log.h>
#include "disassemble.h"


cs_arm_op* get_empty_sp() {
	cs_arm_op *sp = (cs_arm_op *)calloc(1,sizeof(cs_arm_op)); // No explict free then. Freed when the program exit.
	sp->type = ARM_OP_REG;
	sp->reg = ARM_REG_SP;
	return sp;
}
cs_arm_op* get_empty_sp_mem() {
	cs_arm_op *sp = (cs_arm_op *)calloc(1,sizeof(cs_arm_op)); // No explict free then. Freed when the program exit.
	sp->type = ARM_OP_MEM;
	sp->mem.base = ARM_REG_SP;
	return sp;
}
mem_access_type check_mem_access(cs_insn* insn) {
	switch (insn->id)
	{
	case ARM_INS_ADR:
	case ARM_INS_LDR:
	case ARM_INS_LDRB:
	case ARM_INS_LDRSB:
	case ARM_INS_LDRH:
	case ARM_INS_LDRSH:
	case ARM_INS_LDRD:
	case ARM_INS_TBB:
	case ARM_INS_TBH:
	case ARM_INS_LDREX:
	case ARM_INS_LDREXB:
	case ARM_INS_LDREXH:
	case ARM_INS_LDREXD:
		return mem_read;
	
	case ARM_INS_STR:
	case ARM_INS_STRB:
	case ARM_INS_STRH:
	case ARM_INS_STRD:
	case ARM_INS_STREX:
	case ARM_INS_STREXB:
	case ARM_INS_STREXH:
	case ARM_INS_STREXD:
		return mem_write;
	default:
		return mem_none;
	}
}

void arm_parse_ops(cs_insn* insn, arm_ops_parser* parser, uint8_t* nsrc, uint8_t* ndst) {
	if (insn->detail == NULL) {
		return;
	}
	uint8_t src_num = 0;
	uint8_t dst_num = 0;
	cs_arm_op* op;
	cs_arm_op* op_wb;
	uint8_t total_ops = insn->detail->arm.op_count;
	mem_access_type mem_ac_type;
	parser->op_num = 0;
	for (uint8_t i = 0; i < insn->detail->arm.op_count; i++) {
		op = &(insn->detail->arm.operands[i]);
		switch (op->type)
		{
		case ARM_OP_REG:
			if (op->access & CS_AC_WRITE) {
				parser->op[parser->op_num] = op;
				parser->op_usage[parser->op_num] = op_dst;
				parser->op_num++;
				dst_num++;

			}
			if (op->access & CS_AC_READ) {
				parser->op[parser->op_num] = op;
				parser->op_usage[parser->op_num] = op_src;
				parser->op_num++;
				src_num++;
			}
			break;			
		case ARM_OP_MEM:
			mem_ac_type = check_mem_access(insn);
			if (insn->detail->writeback) {
				// arm.operands[total_ops] is empty, 
				// thus can be used to store the extra writeback op
				op_wb = &(insn->detail->arm.operands[total_ops]);
				total_ops++;
				op_wb->type = ARM_OP_REG;
				op_wb->reg = op->mem.base;
				op_wb->access = CS_AC_WRITE;
				parser->op[parser->op_num] = op_wb;
				parser->op_usage[parser->op_num] = op_writeback;
				parser->op_num++;
				dst_num++;
			}
			if (mem_ac_type == mem_write) {
				parser->op[parser->op_num] = op;
				parser->op_usage[parser->op_num] = op_dst;
				parser->op_num++;
				dst_num++;
			}
			if (mem_ac_type == mem_read) {
				parser->op[parser->op_num] = op;
				parser->op_usage[parser->op_num] = op_src;
				parser->op_num++;
				src_num++;
			} 
			
			break;
		case ARM_OP_IMM:
			parser->op[parser->op_num] = op;
			parser->op_usage[parser->op_num] = op_src;
			parser->op_num++;
			src_num++;
			break;	
		default:
			break;
		}
	}
	*nsrc = src_num;
	*ndst = dst_num;
	return;
}


uint8_t arm_get_dst_operand(cs_insn* insn, cs_arm_op** dst) {
	uint8_t num = 0;
	if (insn->detail == NULL) {
		return num;
	}
	uint8_t special_ops = 0;
	mem_access_type mem_ac;
	cs_arm_op* op;
	bool writeback = false;
	for (int i = 0; i < insn->detail->arm.op_count; i++) {
		op = &(insn->detail->arm.operands[i]);
		switch (op->type)	
		{
		case ARM_OP_REG:
			if (op->access & CS_AC_WRITE) {
				dst[num++] = op;
			}
			break;
		case ARM_OP_MEM:
			mem_ac = check_mem_access(insn);
			if (mem_ac == mem_write){
				dst[num++] = op;
			}
			
			// hidden writeback register
			if (insn->detail->writeback){
				assert (!writeback);
				op = &(insn->detail->arm.operands[insn->detail->arm.op_count]);
				op->access = CS_AC_WRITE;
				op->type = ARM_OP_REG;
				op->reg = insn->detail->arm.operands[i].mem.base;
				dst[num++] = op;
				writeback = true;
			}
			break;
		}
	}
	// push and pop instruction may implicitly use sp many times
	if (insn->id == ARM_INS_PUSH || insn->id == ARM_INS_POP) {
		if (insn->detail->arm.op_count * 2 > NOPD) {
			printf("ERROR: NOPD is smaller than regs actually need. (%d)\n",insn->detail->arm.op_count * 2);
			exit(0);
		}
		for (int i = 0; i < insn->detail->arm.op_count; i++) {
			if (insn->id == ARM_INS_PUSH) {
				// when push, sp -= 4 then [sp] = nr
				dst[num++] = get_empty_sp_mem();
			}
			dst[num++] = get_empty_sp();
		}
	} 
	return num;
}

uint8_t arm_get_src_operand(cs_insn* insn, cs_arm_op** src) {
	uint8_t num = 0;
	if (insn->detail == NULL) {
		return num;
	}
	mem_access_type mem_ac;
	cs_arm_op* op;

	for (int i = 0; i < insn->detail->arm.op_count; i++) {
		op = &(insn->detail->arm.operands[i]);
		switch (op->type)
		{
		case ARM_OP_REG:
			if (op->access & CS_AC_READ) {
				src[num++] = op;
			}
			break;
		case ARM_OP_MEM:
			mem_ac = check_mem_access(insn);
			if (mem_ac == mem_read){
				src[num++] = op;
			}
			break;
		case ARM_OP_IMM:
			src[num++] = op;
			break;
		}
	}
	// push and pop instruction may implicitly use sp many times
	if (insn->id == ARM_INS_POP) {
		if (insn->detail->arm.op_count * 2 > NOPD) {
			printf("ERROR: NOPD is smaller than regs actually need.\n");
			exit(0);
		}
		for (int i = 0; i < insn->detail->arm.op_count; i++) {
			src[num++] = get_empty_sp_mem();
		}
	} 
	return num;
}

arm_datatype arm_get_datatype(cs_insn* insn) {
	// note instruction modifies 4 bytes?
	if (!insn) {
		LOG(stderr, "DEBUG: insn is NULL in arm_get_datatype\n");
		assert(0);
	}
	// note check if the insn is the crash site (not executed)
	if (insn == re_ds.root) {
		return op_dword;
	}
	switch (insn->id)
	{
		case ARM_INS_UXTB:
		case ARM_INS_SXTB:
		case ARM_INS_STRB:
		case ARM_INS_LDRB:
			return op_byte;
		case ARM_INS_UXTH:
		case ARM_INS_SXTH:
		case ARM_INS_STRH:
		case ARM_INS_LDRH:
			return op_word;
		default:
			return op_dword;
	}
}
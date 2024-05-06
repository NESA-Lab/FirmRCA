#ifndef __INST_OPD__
#define __INST_OPD__
#include <capstone/capstone.h>
#include "reverse_exe.h"

#define GET_VALUE_OK 0
#define BAD_ADDRESS -1

// int get_index_from_x86_reg_t(arm_reg reg);

// void get_value_from_xmm_reg(x86_reg_t reg, valset_u *value);

// int get_regval_from_coredum(x86_reg_t reg, valset_u *value);

int get_memval_from_coredump(re_list_t *entry, valset_u *value);

int get_value_from_coredump(re_list_t *entry, valset_u *value);

int get_immediate_from_opd(cs_arm_op *opd, valset_u *value);

void search_value_from_coredump(valset_u searchvalue, cs_insn* inst, unsigned **dp, unsigned *num);

// cs_arm_op * x86_implicit_operand_1st( cs_insn *insn );

// cs_arm_op * x86_implicit_operand_2nd( cs_insn *insn );

// cs_arm_op * x86_implicit_operand_3rd( cs_insn *insn );

// cs_arm_op *x86_implicit_operand_new(cs_insn *inst);

// cs_arm_op *find_implicit_operand(cs_insn *insn, cs_arm_op *opd);

// cs_arm_op *add_new_implicit_operand(cs_insn *insn, cs_arm_op *opd);

// void convert_offset_to_exp(cs_arm_op *opd);

unsigned search_address_of_value(valset_u vt, cs_insn* inst);

#endif

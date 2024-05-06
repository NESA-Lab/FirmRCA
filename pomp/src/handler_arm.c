#include "insthandler_arm.h"
#include <capstone/capstone.h>

cs_arm_op* create_arm_opd(){
    cs_arm_op *opd = (cs_arm_op*)malloc(sizeof(cs_arm_op));
    if (!opd) {
        LOG(stderr, "ERROR: malloc error in create_arm_opd\n");
        exit(1);
    }
    memset(opd, 0, sizeof(cs_arm_op));
    return opd;
}
void invalid_handler(re_list_t *instnode){
   
}


void stm_handler(cs_insn* insn, arm_ops_parser* parser, uint8_t* nsrc, uint8_t* ndst, bool increase) {
    //e.g. stmia r0, {r1, r2, r3}
    uint8_t src_num = 0;
    uint8_t dst_num = 0;
    cs_arm_op* op = NULL;
    cs_arm_op* op_wb = NULL;
    uint8_t total_ops = (insn->detail->arm.op_count) << 1;
    mem_access_type mem_ac_type;
    parser->op_num = 0;
    for (uint8_t i = 0; i < insn->detail->arm.op_count; i++) {
        op = &(insn->detail->arm.operands[i]);
        assert(op->type == ARM_OP_REG);
        if (i == 0) {
            // base reg
            if (insn->detail->writeback) {
                // e.g. stmia r0!, {r1, r2, r3}
                op_wb = &(insn->detail->arm.operands[total_ops]);
                total_ops++;
                op_wb->type = ARM_OP_REG;
                op_wb->reg = op->reg;
                op_wb->access = CS_AC_WRITE;
                parser->op[parser->op_num] = op_wb;
                parser->op_usage[parser->op_num] = op_writeback;
                parser->op_num++; // writeback register placed at start
                dst_num++;
            } 
            parser->op[parser->op_num] = op;
            parser->op_usage[parser->op_num] = op_src;
            parser->op_num++;
            src_num++;
           
        } else {
            // reglist
            // generate an implicit memory write
            parser->op[parser->op_num] = create_arm_opd();
            parser->op[parser->op_num]->type = ARM_OP_MEM;
            parser->op[parser->op_num]->access = CS_AC_WRITE;
            parser->op[parser->op_num]->mem.base = insn->detail->arm.operands[0].reg;
            if (increase) {
                parser->op[parser->op_num]->mem.disp = (i-1) << 2;
            } else {
                parser->op[parser->op_num]->mem.disp = -((i-1) << 2);
            }
            parser->op_usage[parser->op_num] = op_dst;
            parser->op_num++;
            dst_num++;

            // generate normal reg use
            parser->op[parser->op_num] = op;
            parser->op_usage[parser->op_num] = op_src;
            parser->op_num++;
            src_num++;
        }
    }
    *nsrc = src_num;
    *ndst = dst_num;
}

void ldm_handler(cs_insn* insn, arm_ops_parser* parser, uint8_t* nsrc, uint8_t* ndst, bool increase) {
    //e.g. ldmia r0, {r1, r2, r3}
    uint8_t src_num = 0;
    uint8_t dst_num = 0;
    cs_arm_op* op = NULL;
    cs_arm_op* op_wb = NULL;
    uint8_t total_ops = (insn->detail->arm.op_count) << 1;
    mem_access_type mem_ac_type;
    parser->op_num = 0;
    for (uint8_t i = 0; i < insn->detail->arm.op_count; i++) {
        op = &(insn->detail->arm.operands[i]);
        assert(op->type == ARM_OP_REG);
        if (i == 0) {
            // base reg
            if (insn->detail->writeback) {
                // e.g. ldmia r0!, {r1, r2, r3}
                op_wb = &(insn->detail->arm.operands[total_ops]);
                total_ops++;
                op_wb->type = ARM_OP_REG;
                op_wb->reg = op->reg;
                op_wb->access = CS_AC_WRITE;
                parser->op[parser->op_num] = op_wb;
                parser->op_usage[parser->op_num] = op_writeback;
                parser->op_num++; // writeback register placed at start
                dst_num++;
            } 
            parser->op[parser->op_num] = op;
            parser->op_usage[parser->op_num] = op_src;
            parser->op_num++;
            src_num++;
           
        } else {
            // reglist
            // generate an implicit memory read
            parser->op[parser->op_num] = create_arm_opd();
            parser->op[parser->op_num]->type = ARM_OP_MEM;
            parser->op[parser->op_num]->access = CS_AC_READ;
            parser->op[parser->op_num]->mem.base = insn->detail->arm.operands[0].reg;
            if (increase) {
                parser->op[parser->op_num]->mem.disp = (i-1) << 2;
            } else {
                parser->op[parser->op_num]->mem.disp = -((i-1) << 2);
            }
            parser->op_usage[parser->op_num] = op_src;
            parser->op_num++;
            src_num++;

            // generate normal reg def
            parser->op[parser->op_num] = op;
            parser->op_usage[parser->op_num] = op_dst;
            parser->op_num++;
            dst_num++;
        }
    }
    *nsrc = src_num;
    *ndst = dst_num;
}
#ifdef FRCA
void general_handler(re_list_t *instnode) {
    cs_insn *inst;
    cs_arm_op *src[MOPD], *dst[MOPD];
    uint8_t nsrc, ndst;
    re_list_t re_deflist, re_uselist, re_instlist;  	
    re_list_t *def,*usesrc;
	valset_u tempval; 
    arm_ops_parser parser;
    arm_op_usage usage;
    // mem_access helper does not record the last instruction (crash site)
    bool read_memac = CAST2_INST(instnode->node)->inst_index == 0 ? false : true;
    inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;

    // Capstone cannot perfectly/correctly handle some instructions.
    switch (inst->id)
    {
    case ARM_INS_STM:
        stm_handler(inst, &parser, &nsrc, &ndst, true);
        break;
    case ARM_INS_STMDB:
        stm_handler(inst, &parser, &nsrc, &ndst, false);
        break;
    case ARM_INS_LDM:
        ldm_handler(inst, &parser, &nsrc, &ndst, true);
        break;
    case ARM_INS_LDMDB:
        ldm_handler(inst, &parser, &nsrc, &ndst, false);
        break;
    default:
        arm_parse_ops(inst, &parser, &nsrc, &ndst);
        break;
    }

    print_parser_info(ndst, nsrc, &parser);

	INIT_LIST_HEAD(&re_deflist.deflist);
	INIT_LIST_HEAD(&re_uselist.uselist);
	INIT_LIST_HEAD(&re_instlist.instlist);	

    for (int i = 0; i < parser.op_num; i++) {
        usage = parser.op_usage[i];
        switch (usage) {
            case op_src:
                if (parser.op[i]->type == ARM_OP_REG || parser.op[i]->type == ARM_OP_IMM) {
                    add_new_use(parser.op[i], inst, usage, Opd, &re_uselist);
                } else if (parser.op[i]->type == ARM_OP_MEM) {
                    add_new_use(parser.op[i], inst, usage, Opd, &re_uselist);
                    split_expression_to_use(parser.op[i], inst, usage, &re_uselist);
                }
                break;
            case op_dst:
                if (parser.op[i]->type == ARM_OP_REG){
                    add_new_define(parser.op[i], inst, usage, read_memac, &re_deflist);
                } else if (parser.op[i]->type == ARM_OP_MEM) {
                    add_new_define(parser.op[i], inst, usage, read_memac, &re_deflist);
                    split_expression_to_use(parser.op[i], inst, usage, &re_uselist);
                }
                break;
            case op_writeback:
                    //emphasize: the writeback register is DEFNODE
                    add_new_define(parser.op[i], inst, usage, false, &re_deflist);
                break;
            default:
                assert(0);
        }
    }

#ifdef VERBOSE
    print_memac(instnode);
#endif

	add_to_instlist(instnode, &re_instlist);
	re_resolve(&re_deflist, &re_uselist, &re_instlist);
}
#else
void general_handler(re_list_t *instnode) {
    cs_insn *inst;
    cs_arm_op *src[MOPD], *dst[MOPD];
    uint8_t nsrc, ndst;
    re_list_t re_deflist, re_uselist, re_instlist;  	
    re_list_t *def,*usesrc;
	valset_u tempval; 

    inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;
	
	ndst = arm_get_dst_operand(inst, dst);
	nsrc = arm_get_src_operand(inst, src);

	//	for debugginf use	
	print_operand_info(ndst, nsrc, dst, src);

	INIT_LIST_HEAD(&re_deflist.deflist);
	INIT_LIST_HEAD(&re_uselist.uselist);
	INIT_LIST_HEAD(&re_instlist.instlist);	
	
    // Handler special instruction that modify one register multi-times
    if (inst->id == ARM_INS_POP) {
        for (int i = 0; i < nsrc; i++) {
            // Step1. add def reg
            if (dst[i]->type == ARM_OP_REG ) {
                add_new_define(dst[i], inst);
            } else if (dst[i]->type == ARM_OP_MEM) {
                add_new_define(dst[i], inst);
                split_expression_to_use(dst[i], inst);
            }
            // Step2. add def sp
            if (dst[i+nsrc]->type == ARM_OP_REG ) {
                add_new_define(dst[i+nsrc], inst);
            } else if (dst[i+nsrc]->type == ARM_OP_MEM) {
                add_new_define(dst[i+nsrc], inst);
                split_expression_to_use(dst[i+nsrc], inst);
            }
            // Step3. add use mem
            if (src[i]->type == ARM_OP_REG || src[i]->type == ARM_OP_IMM) {
                add_new_use(src[i], Opd, inst);
            } else if (src[i]->type == ARM_OP_MEM) {
                add_new_use(src[i], Opd, inst);
                split_expression_to_use(src[i], inst);
            }

        }
        goto skip;
    }
    for (int i = 0; i < ndst; i++) {
        if (dst[i]->type == ARM_OP_REG ) {
            add_new_define(dst[i], inst);
        } else if (dst[i]->type == ARM_OP_MEM) {
            add_new_define(dst[i], inst);
            split_expression_to_use(dst[i], inst);
        }
    }

    for (int i = 0; i < nsrc; i++) {
        if (src[i]->type == ARM_OP_REG || src[i]->type == ARM_OP_IMM) {
            add_new_use(src[i], Opd, inst);
        } else if (src[i]->type == ARM_OP_MEM) {
            add_new_use(src[i], Opd, inst);
            split_expression_to_use(src[i], inst);
        }
    }

skip:

	add_to_instlist(instnode, &re_instlist);
	re_resolve(&re_deflist, &re_uselist, &re_instlist);
}
#endif
//instruction resolvers
void invalid_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void asr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void it_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void ldrbt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void ldr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	valset_u  vt = {0};

    traverse_inst_operand(inst, src, dst, re_uselist, re_deflist, &nuse, &ndef);

    assert(nuse == 1 && ndef == 1);

    LOG(stdout, "ldr_resolver: nuse = %d, ndef = %d\n", nuse, ndef);

    if (CAST2_INST(inst->node)->inst_index == 0) {
        // crash site, not executed, so the beforeval is equal to afterval
        CAST2_DEF(dst[0]->node)->beforeval = CAST2_DEF(dst[0]->node)->afterval;
        CAST2_DEF(dst[0]->node)->val_stat |= BeforeKnown;
        return;
    }


    if (CAST2_USE(src[0]->node)->val_known &&
        !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)) {
            vt = CAST2_USE(src[0]->node)->val;
            assign_def_after_value(dst[0], vt);
            add_to_deflist(dst[0], re_deflist);
        }
    
    if (!CAST2_USE(src[0]->node)->val_known &&
         (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
            vt = CAST2_DEF(dst[0]->node)->afterval;
            assign_use_value(src[0],vt);
            add_to_uselist(src[0], re_uselist);
         }
}

void ldrht_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void ldrsbt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void ldrsht_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void ldrt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void lsl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void lsr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void ror_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void rrx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void strbt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void strt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vld1_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vld2_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vld3_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vld4_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vst1_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vst2_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vst3_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vst4_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

#ifdef FRCA
void ldrb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	valset_u  vt = {0};

    traverse_inst_operand(inst, src, dst, re_uselist, re_deflist, &nuse, &ndef);
    
    assert (nuse == 1 && ndef <= 2);
    LOG(stdout, "ldrb_resolver: nuse = %d, ndef = %d\n", nuse, ndef);


    for (int i = 0; i < ndef; i++) {
        switch (CAST2_DEF(dst[i]->node)->usage) {
            case op_writeback:
                if ((CAST2_DEF(dst[i]->node)->val_stat == AfterKnown) &&
                    (CAST2_USE(src[0]->node)->operand->mem.index == 0)) {
                    // Operand2 type: [rm] #imm or [rm, #imm]!
                    assert(CAST2_USE(src[0]->node)->operand->mem.base == CAST2_DEF(dst[i]->node)->operand->reg);
                    assert(CAST2_USE(src[0]->node)->operand->type == ARM_OP_MEM);
                    vt = CAST2_DEF(dst[i]->node)->afterval;
                    vt.dword -= CAST2_USE(src[0]->node)->operand->mem.disp;
                    assign_def_before_value(dst[i], vt);
                    add_to_deflist(dst[i], re_deflist);
                }
                break;
            case op_src:
            case op_dst:
                if (CAST2_INST(inst->node)->inst_index == 0) {
                        // crash site, not executed, so the beforeval is equal to afterval
                        CAST2_DEF(dst[i]->node)->beforeval = CAST2_DEF(dst[i]->node)->afterval;
                        CAST2_DEF(dst[i]->node)->val_stat |= BeforeKnown;
                        return;
                    }
                if (CAST2_USE(src[0]->node)->val_known &&
                    !(CAST2_DEF(dst[i]->node)->val_stat & AfterKnown)) {
                        vt = CAST2_USE(src[0]->node)->val;
                        vt.dword &= 0xff;
                        assign_def_after_value(dst[i], vt);
                        add_to_deflist(dst[i], re_deflist);
                    }
                break;
        }
    }
}
#else
void ldrb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	valset_u  vt = {0};

    traverse_inst_operand(inst, src, dst, re_uselist, re_deflist, &nuse, &ndef);

    // assert(nuse == 1 && ndef == 1);

    LOG(stdout, "ldrb_resolver: nuse = %d, ndef = %d\n", nuse, ndef);

    if (CAST2_INST(inst->node)->inst_index == 0) {
        // crash site, not executed, so the beforeval is equal to afterval
        CAST2_DEF(dst[0]->node)->beforeval = CAST2_DEF(dst[0]->node)->afterval;
        CAST2_DEF(dst[0]->node)->val_stat |= BeforeKnown;
        return;
    }


    if (CAST2_USE(src[0]->node)->val_known &&
        !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)) {
            vt = CAST2_USE(src[0]->node)->val;
            vt.dword &= 0xff;
            assign_def_after_value(dst[0], vt);
            add_to_deflist(dst[0], re_deflist);
        }
    

}
#endif
void ldrh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	valset_u  vt = {0};

    traverse_inst_operand(inst, src, dst, re_uselist, re_deflist, &nuse, &ndef);

    assert(nuse == 1 && ndef == 1);

    LOG(stdout, "ldrh_resolver: nuse = %d, ndef = %d\n", nuse, ndef);

    if (CAST2_INST(inst->node)->inst_index == 0) {
        // crash site, not executed, so the beforeval is equal to afterval
        CAST2_DEF(dst[0]->node)->beforeval = CAST2_DEF(dst[0]->node)->afterval;
        CAST2_DEF(dst[0]->node)->val_stat |= BeforeKnown;
        return;
    }


    if (CAST2_USE(src[0]->node)->val_known &&
        !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)) {
            vt = CAST2_USE(src[0]->node)->val;
            vt.dword &= 0xffff;
            assign_def_after_value(dst[0], vt);
            add_to_deflist(dst[0], re_deflist);
        }

}

void ldrsb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	valset_u  vt = {0};

    traverse_inst_operand(inst, src, dst, re_uselist, re_deflist, &nuse, &ndef);

    // assert(nuse == 1 && ndef == 1);

    LOG(stdout, "ldrsb_resolver: nuse = %d, ndef = %d\n", nuse, ndef);

    if (CAST2_INST(inst->node)->inst_index == 0) {
        // crash site, not executed, so the beforeval is equal to afterval
        CAST2_DEF(dst[0]->node)->beforeval = CAST2_DEF(dst[0]->node)->afterval;
        CAST2_DEF(dst[0]->node)->val_stat |= BeforeKnown;
        return;
    }


    if (CAST2_USE(src[0]->node)->val_known &&
        !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)) {
            vt = CAST2_USE(src[0]->node)->val;
            vt.dword &= 0xff;
            if (vt.dword & 0x80) {
                vt.dword |= 0xffffff00;
            }
            assign_def_after_value(dst[0], vt);
            add_to_deflist(dst[0], re_deflist);
        }

}

void ldrsh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	valset_u  vt = {0};

    traverse_inst_operand(inst, src, dst, re_uselist, re_deflist, &nuse, &ndef);

    // assert(nuse == 1 && ndef == 1);

    LOG(stdout, "ldrsh_resolver: nuse = %d, ndef = %d\n", nuse, ndef);

    if (CAST2_INST(inst->node)->inst_index == 0) {
        // crash site, not executed, so the beforeval is equal to afterval
        CAST2_DEF(dst[0]->node)->beforeval = CAST2_DEF(dst[0]->node)->afterval;
        CAST2_DEF(dst[0]->node)->val_stat |= BeforeKnown;
        return;
    }


    if (CAST2_USE(src[0]->node)->val_known &&
        !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)) {
            vt = CAST2_USE(src[0]->node)->val;
            vt.dword &= 0xffff;
            if (vt.dword & 0x8000) {
                vt.dword |= 0xffff0000;
            }
            assign_def_after_value(dst[0], vt);
            add_to_deflist(dst[0], re_deflist);
        }
}

void movs_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    mov_resolver(inst, re_deflist, re_uselist);
}

void mov_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	valset_u  vt = {0};

    traverse_inst_operand(inst, src, dst, re_uselist, re_deflist, &nuse, &ndef);

    // assert(nuse == 1 && ndef == 1);

    LOG(stdout, "mov_resolver: nuse = %d, ndef = %d\n", nuse, ndef);

    if (CAST2_USE(src[0]->node)->val_known &&
        !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)) {
            vt = CAST2_USE(src[0]->node)->val;
            assign_def_after_value(dst[0], vt);
            add_to_deflist(dst[0], re_deflist);
        }
    
    if (!CAST2_USE(src[0]->node)->val_known &&
         (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
            vt = CAST2_DEF(dst[0]->node)->afterval;
            assign_use_value(src[0],vt);
            add_to_uselist(src[0], re_uselist);
         }
}

void str_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	valset_u  vt = {0};

    traverse_inst_operand(inst, src, dst, re_uselist, re_deflist, &nuse, &ndef);

    LOG(stdout, "str_resolver: nuse = %d, ndef = %d\n", nuse, ndef);

    // assert(nuse == 1 && ndef == 1);

    if (CAST2_INST(inst->node)->inst_index == 0) {
        // crash site, not executed, so the beforeval is equal to afterval
        CAST2_DEF(dst[0]->node)->beforeval = CAST2_DEF(dst[0]->node)->afterval;
        CAST2_DEF(dst[0]->node)->val_stat |= BeforeKnown;
        return;
    }

    if (CAST2_USE(src[0]->node)->val_known &&
        !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)) {
            vt = CAST2_USE(src[0]->node)->val;
            assign_def_after_value(dst[0], vt);
            add_to_deflist(dst[0], re_deflist);
        }
    
    if (!CAST2_USE(src[0]->node)->val_known &&
         (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
            vt = CAST2_DEF(dst[0]->node)->afterval;
            assign_use_value(src[0],vt);
            add_to_uselist(src[0], re_uselist);
         }
    
}

void adc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void add_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	valset_u  vt = {0};

    traverse_inst_operand(inst, src, dst, re_uselist, re_deflist, &nuse, &ndef);

    LOG(stdout, "add_resolver: nuse = %d, ndef = %d\n", nuse, ndef);
    assert(nuse == 2 && ndef == 1);

    // 1 verify and 3 calculates
    if (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown &&
        CAST2_USE(src[0]->node)->val_known &&
        CAST2_USE(src[1]->node)->val_known) {
            vt.dword = CAST2_USE(src[0]->node)->val.dword + CAST2_USE(src[1]->node)->val.dword;
            assert_val(dst[0], vt, false);
    }

    if (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown &&
        CAST2_USE(src[0]->node)->val_known &&
        !CAST2_USE(src[1]->node)->val_known) {
            vt.dword = CAST2_DEF(dst[0]->node)->afterval.dword - CAST2_USE(src[0]->node)->val.dword;
            assign_use_value(src[1], vt);
            add_to_uselist(src[1], re_uselist);
    }

    if (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown &&
        !CAST2_USE(src[0]->node)->val_known &&
        CAST2_USE(src[1]->node)->val_known) {
            vt.dword = CAST2_DEF(dst[0]->node)->afterval.dword - CAST2_USE(src[1]->node)->val.dword;
            assign_use_value(src[0], vt);
            add_to_uselist(src[0], re_uselist);
    }

    if (!(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown) &&
        CAST2_USE(src[0]->node)->val_known &&
        CAST2_USE(src[1]->node)->val_known) {
            vt.dword = CAST2_USE(src[0]->node)->val.dword + CAST2_USE(src[1]->node)->val.dword;
            assign_def_after_value(dst[0], vt);
            add_to_deflist(dst[0], re_deflist);
    }
    
}

void adr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void aesd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void aese_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void aesimc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void aesmc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void and_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	valset_u  vt = {0};

    traverse_inst_operand(inst, src, dst, re_uselist, re_deflist, &nuse, &ndef);

    LOG(stdout, "and_resolver: nuse = %d, ndef = %d\n", nuse, ndef);
    assert(nuse == 2 && ndef == 1);

    // 1 verify and 1 calculate
    if (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown &&
        CAST2_USE(src[0]->node)->val_known &&
        CAST2_USE(src[1]->node)->val_known) {
            vt.dword = CAST2_USE(src[0]->node)->val.dword & CAST2_USE(src[1]->node)->val.dword;
            assert_val(dst[0], vt, false);
    }

    if (!(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown) &&
        CAST2_USE(src[0]->node)->val_known &&
        CAST2_USE(src[1]->node)->val_known) {
            vt.dword = CAST2_USE(src[0]->node)->val.dword & CAST2_USE(src[1]->node)->val.dword;
            assign_def_after_value(dst[0], vt);
            add_to_deflist(dst[0], re_deflist);
    }
    
}

void vdot_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vcvt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vcvtb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vcvtt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void bfc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void bfi_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void bic_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void bkpt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void bl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void blx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void bx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void bxj_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void b_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void cx1_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void cx1a_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void cx1d_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void cx1da_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void cx2_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void cx2a_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void cx2d_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void cx2da_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void cx3_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void cx3a_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void cx3d_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void cx3da_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vcx1a_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vcx1_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vcx2a_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vcx2_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vcx3a_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vcx3_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void cdp_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void cdp2_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void clrex_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void clz_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void cmn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void cmp_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void cps_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void crc32b_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void crc32cb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void crc32ch_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void crc32cw_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void crc32h_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void crc32w_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void dbg_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void dmb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void dsb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void eor_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	valset_u  vt = {0};

    traverse_inst_operand(inst, src, dst, re_uselist, re_deflist, &nuse, &ndef);

    LOG(stdout, "eor_resolver: nuse = %d, ndef = %d\n", nuse, ndef);
    assert(nuse == 2 && ndef == 1);

    // 1 verify and 3 calculates
    if (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown &&
        CAST2_USE(src[0]->node)->val_known &&
        CAST2_USE(src[1]->node)->val_known) {
            vt.dword = CAST2_USE(src[0]->node)->val.dword ^ CAST2_USE(src[1]->node)->val.dword;
            assert_val(dst[0], vt, false);
    }

    if (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown &&
        CAST2_USE(src[0]->node)->val_known &&
        !CAST2_USE(src[1]->node)->val_known) {
            vt.dword = CAST2_DEF(dst[0]->node)->afterval.dword ^ CAST2_USE(src[0]->node)->val.dword;
            assign_use_value(src[1], vt);
            add_to_uselist(src[1], re_uselist);
    }

    if (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown &&
        !CAST2_USE(src[0]->node)->val_known &&
        CAST2_USE(src[1]->node)->val_known) {
            vt.dword = CAST2_DEF(dst[0]->node)->afterval.dword ^ CAST2_USE(src[1]->node)->val.dword;
            assign_use_value(src[0], vt);
            add_to_uselist(src[0], re_uselist);
    }
    if (!(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown) &&
        CAST2_USE(src[0]->node)->val_known &&
        CAST2_USE(src[1]->node)->val_known) {
            vt.dword = CAST2_USE(src[0]->node)->val.dword ^ CAST2_USE(src[1]->node)->val.dword;
            assign_def_after_value(dst[0], vt);
            add_to_deflist(dst[0], re_deflist);
    }
}

void eret_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmov_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void fldmdbx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void fldmiax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmrs_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void fstmdbx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void fstmiax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void hint_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void hlt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void hvc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void isb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void lda_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void ldab_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void ldaex_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void ldaexb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void ldaexd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void ldaexh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void ldah_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void ldc2l_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void ldc2_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void ldcl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void ldc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void ldmda_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void ldmdb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	valset_u  vt = {0};

    traverse_inst_operand(inst, src, dst, re_uselist, re_deflist, &nuse, &ndef);

    LOG(stdout, "ldmdb_resolver: nuse = %d, ndef = %d\n", nuse, ndef);

    // if (CAST2_INST(inst->node)->inst_index == 0) {
    //     // crash site, not executed, so the beforeval is equal to afterval
    //     CAST2_DEF(dst[0]->node)->beforeval = CAST2_DEF(dst[0]->node)->afterval;
    //     CAST2_DEF(dst[0]->node)->val_stat |= BeforeKnown;
    //     return;
    // }


    // if (CAST2_USE(src[0]->node)->val_known &&
    //     !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)) {
    //         vt = CAST2_USE(src[0]->node)->val;
    //         assign_def_after_value(dst[0], vt);
    //         add_to_deflist(dst[0], re_deflist);
    //     }
    
    // if (!CAST2_USE(src[0]->node)->val_known &&
    //      (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
    //         vt = CAST2_DEF(dst[0]->node)->afterval;
    //         assign_use_value(src[0],vt);
    //         add_to_uselist(src[0], re_uselist);
    //      }
}

void ldm_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	valset_u  vt = {0};

    traverse_inst_operand(inst, src, dst, re_uselist, re_deflist, &nuse, &ndef);

    LOG(stdout, "ldm_resolver: nuse = %d, ndef = %d\n", nuse, ndef);

    // if (CAST2_INST(inst->node)->inst_index == 0) {
    //     // crash site, not executed, so the beforeval is equal to afterval
    //     CAST2_DEF(dst[0]->node)->beforeval = CAST2_DEF(dst[0]->node)->afterval;
    //     CAST2_DEF(dst[0]->node)->val_stat |= BeforeKnown;
    //     return;
    // }


    // if (CAST2_USE(src[0]->node)->val_known &&
    //     !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)) {
    //         vt = CAST2_USE(src[0]->node)->val;
    //         assign_def_after_value(dst[0], vt);
    //         add_to_deflist(dst[0], re_deflist);
    //     }
    
    // if (!CAST2_USE(src[0]->node)->val_known &&
    //      (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
    //         vt = CAST2_DEF(dst[0]->node)->afterval;
    //         assign_use_value(src[0],vt);
    //         add_to_uselist(src[0], re_uselist);
    //      }
}

void ldmib_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void ldrd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void ldrex_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void ldrexb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void ldrexd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void ldrexh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void mcr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void mcr2_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void mcrr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void mcrr2_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void mla_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void mls_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void movt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void movw_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void mrc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void mrc2_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void mrrc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void mrrc2_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void mrs_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void msr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void mul_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void asrl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void dlstp_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void lctp_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void letp_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void lsll_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void lsrl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void sqrshr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void sqrshrl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void sqshl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void sqshll_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void srshr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void srshrl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void uqrshl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void uqrshll_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void uqshl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void uqshll_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void urshr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void urshrl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vabav_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vabd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vabs_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vadc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vadci_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vaddlva_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vaddlv_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vaddva_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vaddv_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vadd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vand_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vbic_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vbrsr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vcadd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vcls_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vclz_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vcmla_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vcmp_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vcmul_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vctp_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vcvta_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vcvtm_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vcvtn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vcvtp_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vddup_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vdup_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vdwdup_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void veor_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vfmas_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vfma_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vfms_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vhadd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vhcadd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vhsub_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vidup_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void viwdup_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vld20_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vld21_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vld40_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vld41_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vld42_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vld43_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vldrb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vldrd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vldrh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vldrw_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmaxav_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmaxa_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmaxnmav_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmaxnma_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmaxnmv_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmaxnm_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmaxv_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vminav_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmina_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vminnmav_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vminnma_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vminnmv_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vminnm_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vminv_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmin_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmladava_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmladavax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmladav_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmladavx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmlaldava_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmlaldavax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmlaldav_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmlaldavx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmlas_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmla_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmlsdava_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmlsdavax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmlsdav_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmlsdavx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmlsldava_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmlsldavax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmlsldav_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmlsldavx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmovlb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmovlt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmovnb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmovnt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmulh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmullb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmullt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmul_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmvn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vneg_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vorn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vorr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vpnot_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vpsel_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vpst_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vpt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqabs_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqadd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqdmladhx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqdmladh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqdmlah_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqdmlash_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqdmlsdhx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqdmlsdh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqdmulh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqdmullb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqdmullt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqmovnb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqmovnt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqmovunb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqmovunt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqneg_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqrdmladhx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqrdmladh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqrdmlah_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqrdmlash_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqrdmlsdhx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqrdmlsdh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqrdmulh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqrshl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqrshrnb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqrshrnt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqrshrunb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqrshrunt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqshlu_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqshl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqshrnb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqshrnt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqshrunb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqshrunt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqsub_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vrev16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vrev32_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vrev64_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vrhadd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vrinta_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vrintm_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vrintn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vrintp_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vrintx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vrintz_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vrmlaldavha_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vrmlaldavhax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vrmlaldavh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vrmlaldavhx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vrmlsldavha_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vrmlsldavhax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vrmlsldavh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vrmlsldavhx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vrmulh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vrshl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vrshrnb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vrshrnt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vrshr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vsbc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vsbci_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vshlc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vshllb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vshllt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vshl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vshrnb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vshrnt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vshr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vsli_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vsri_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vst20_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vst21_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vst40_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vst41_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vst42_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vst43_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vstrb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vstrd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vstrh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vstrw_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vsub_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void wlstp_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void mvn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void orr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	valset_u  vt = {0};

    traverse_inst_operand(inst, src, dst, re_uselist, re_deflist, &nuse, &ndef);

    LOG(stdout, "orr_resolver: nuse = %d, ndef = %d\n", nuse, ndef);
    // assert(nuse == 2 && ndef == 1);

    // 1 verify and 1 calculate
    if (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown &&
        CAST2_USE(src[0]->node)->val_known &&
        CAST2_USE(src[1]->node)->val_known) {
            vt.dword = CAST2_USE(src[0]->node)->val.dword | CAST2_USE(src[1]->node)->val.dword;
            assert_val(dst[0], vt, false);
    }

    if (!(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown) &&
        CAST2_USE(src[0]->node)->val_known &&
        CAST2_USE(src[1]->node)->val_known) {
            vt.dword = CAST2_USE(src[0]->node)->val.dword | CAST2_USE(src[1]->node)->val.dword;
            assign_def_after_value(dst[0], vt);
            add_to_deflist(dst[0], re_deflist);
    }
}

void pkhbt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void pkhtb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void pldw_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void pld_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void pli_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void qadd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void qadd16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void qadd8_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void qasx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void qdadd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void qdsub_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void qsax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void qsub_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void qsub16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void qsub8_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void rbit_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void rev_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void rev16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void revsh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void rfeda_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void rfedb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void rfeia_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void rfeib_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void rsb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	valset_u  vt = {0};

    traverse_inst_operand(inst, src, dst, re_uselist, re_deflist, &nuse, &ndef);

    LOG(stdout, "rsb_resolver: nuse = %d, ndef = %d\n", nuse, ndef);
    assert(nuse == 2 && ndef == 1);

    // 1 verify and 3 calculates
    if (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown &&
        CAST2_USE(src[0]->node)->val_known &&
        CAST2_USE(src[1]->node)->val_known) {
            vt.dword = CAST2_USE(src[0]->node)->val.dword - CAST2_USE(src[1]->node)->val.dword;
            assert_val(dst[0], vt, false);
    }

    if (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown &&
        CAST2_USE(src[0]->node)->val_known &&
        !CAST2_USE(src[1]->node)->val_known) {
            vt.dword = CAST2_USE(src[0]->node)->val.dword - CAST2_DEF(dst[0]->node)->afterval.dword;
            assign_use_value(src[1], vt);
            add_to_uselist(src[1], re_uselist);
    }

    if (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown &&
        !CAST2_USE(src[0]->node)->val_known &&
        CAST2_USE(src[1]->node)->val_known) {
            vt.dword = CAST2_DEF(dst[0]->node)->afterval.dword + CAST2_USE(src[1]->node)->val.dword;
            assign_use_value(src[0], vt);
            add_to_uselist(src[0], re_uselist);
    }

    if (!(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown) &&
        CAST2_USE(src[0]->node)->val_known &&
        CAST2_USE(src[1]->node)->val_known) {
            vt.dword = CAST2_USE(src[0]->node)->val.dword - CAST2_USE(src[1]->node)->val.dword;
            assign_def_after_value(dst[0], vt);
            add_to_deflist(dst[0], re_deflist);
    }
}

void rsc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void sadd16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void sadd8_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void sasx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void sb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void sbc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void sbfx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void sdiv_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void sel_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void setend_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void setpan_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void sha1c_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void sha1h_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void sha1m_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void sha1p_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void sha1su0_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void sha1su1_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void sha256h_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void sha256h2_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void sha256su0_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void sha256su1_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void shadd16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void shadd8_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void shasx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void shsax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void shsub16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void shsub8_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void smc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void smlabb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void smlabt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void smlad_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void smladx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void smlal_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void smlalbb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void smlalbt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void smlald_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void smlaldx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void smlaltb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void smlaltt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void smlatb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void smlatt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void smlawb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void smlawt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void smlsd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void smlsdx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void smlsld_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void smlsldx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void smmla_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void smmlar_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void smmls_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void smmlsr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void smmul_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void smmulr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void smuad_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void smuadx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void smulbb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void smulbt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void smull_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void smultb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void smultt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void smulwb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void smulwt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void smusd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void smusdx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void srsda_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void srsdb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void srsia_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void srsib_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void ssat_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void ssat16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void ssax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void ssub16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void ssub8_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void stc2l_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void stc2_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void stcl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void stc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void stl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void stlb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void stlex_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void stlexb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void stlexd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void stlexh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void stlh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void stmda_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void stmdb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	valset_u  vt = {0};

    traverse_inst_operand(inst, src, dst, re_uselist, re_deflist, &nuse, &ndef);

    LOG(stdout, "stmdb_resolver: nuse = %d, ndef = %d\n", nuse, ndef);

    // if (CAST2_INST(inst->node)->inst_index == 0) {
    //     // crash site, not executed, so the beforeval is equal to afterval
    //     CAST2_DEF(dst[0]->node)->beforeval = CAST2_DEF(dst[0]->node)->afterval;
    //     CAST2_DEF(dst[0]->node)->val_stat |= BeforeKnown;
    //     return;
    // }


    // if (CAST2_USE(src[0]->node)->val_known &&
    //     !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)) {
    //         vt = CAST2_USE(src[0]->node)->val;
    //         assign_def_after_value(dst[0], vt);
    //         add_to_deflist(dst[0], re_deflist);
    //     }
    
    // if (!CAST2_USE(src[0]->node)->val_known &&
    //      (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
    //         vt = CAST2_DEF(dst[0]->node)->afterval;
    //         assign_use_value(src[0],vt);
    //         add_to_uselist(src[0], re_uselist);
    //      }
}

void stm_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	valset_u  vt = {0};

    traverse_inst_operand(inst, src, dst, re_uselist, re_deflist, &nuse, &ndef);

    LOG(stdout, "stm_resolver: nuse = %d, ndef = %d\n", nuse, ndef);

    // if (CAST2_INST(inst->node)->inst_index == 0) {
    //     // crash site, not executed, so the beforeval is equal to afterval
    //     CAST2_DEF(dst[0]->node)->beforeval = CAST2_DEF(dst[0]->node)->afterval;
    //     CAST2_DEF(dst[0]->node)->val_stat |= BeforeKnown;
    //     return;
    // }


    // if (CAST2_USE(src[0]->node)->val_known &&
    //     !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)) {
    //         vt = CAST2_USE(src[0]->node)->val;
    //         assign_def_after_value(dst[0], vt);
    //         add_to_deflist(dst[0], re_deflist);
    //     }
    
    // if (!CAST2_USE(src[0]->node)->val_known &&
    //      (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
    //         vt = CAST2_DEF(dst[0]->node)->afterval;
    //         assign_use_value(src[0],vt);
    //         add_to_uselist(src[0], re_uselist);
    //      }
}

void stmib_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void strb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	valset_u  vt = {0};

    traverse_inst_operand(inst, src, dst, re_uselist, re_deflist, &nuse, &ndef);

    LOG(stdout, "strb_resolver: nuse = %d, ndef = %d\n", nuse, ndef);

    assert(nuse == 1 && ndef == 1);

    if (CAST2_INST(inst->node)->inst_index == 0) {
        // crash site, not executed, so the beforeval is equal to afterval
        CAST2_DEF(dst[0]->node)->beforeval = CAST2_DEF(dst[0]->node)->afterval;
        CAST2_DEF(dst[0]->node)->val_stat |= BeforeKnown;
        return;
    }

    if (CAST2_USE(src[0]->node)->val_known &&
        !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)) {
            vt = CAST2_USE(src[0]->node)->val;
            vt.dword &= 0xff;
            assign_def_after_value(dst[0], vt);
            add_to_deflist(dst[0], re_deflist);
        }

    
}

void strd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void strex_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void strexb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void strexd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void strexh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void strh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	valset_u  vt = {0};

    traverse_inst_operand(inst, src, dst, re_uselist, re_deflist, &nuse, &ndef);

    LOG(stdout, "strh_resolver: nuse = %d, ndef = %d\n", nuse, ndef);

    // assert(nuse == 1 && ndef == 1);

    if (CAST2_INST(inst->node)->inst_index == 0) {
        // crash site, not executed, so the beforeval is equal to afterval
        CAST2_DEF(dst[0]->node)->beforeval = CAST2_DEF(dst[0]->node)->afterval;
        CAST2_DEF(dst[0]->node)->val_stat |= BeforeKnown;
        return;
    }

    if (CAST2_USE(src[0]->node)->val_known &&
        !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)) {
            vt = CAST2_USE(src[0]->node)->val;
            vt.dword &= 0xffff;
            assign_def_after_value(dst[0], vt);
            add_to_deflist(dst[0], re_deflist);
        }

}

void strht_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void sub_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	valset_u  vt = {0};

    traverse_inst_operand(inst, src, dst, re_uselist, re_deflist, &nuse, &ndef);

    LOG(stdout, "sub_resolver: nuse = %d, ndef = %d\n", nuse, ndef);
    // assert(nuse == 2 && ndef == 1);

    // 1 verify and 3 calculates
    if (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown &&
        CAST2_USE(src[0]->node)->val_known &&
        CAST2_USE(src[1]->node)->val_known) {
            vt.dword = CAST2_USE(src[0]->node)->val.dword - CAST2_USE(src[1]->node)->val.dword;
            assert_val(dst[0], vt, false);
    }

    if (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown &&
        CAST2_USE(src[0]->node)->val_known &&
        !CAST2_USE(src[1]->node)->val_known) {
            vt.dword = CAST2_USE(src[0]->node)->val.dword - CAST2_DEF(dst[0]->node)->afterval.dword;
            assign_use_value(src[1], vt);
            add_to_uselist(src[1], re_uselist);
    }

    if (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown &&
        !CAST2_USE(src[0]->node)->val_known &&
        CAST2_USE(src[1]->node)->val_known) {
            vt.dword = CAST2_DEF(dst[0]->node)->afterval.dword + CAST2_USE(src[1]->node)->val.dword;
            assign_use_value(src[0], vt);
            add_to_uselist(src[0], re_uselist);
    }

    if (!(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown) &&
        CAST2_USE(src[0]->node)->val_known &&
        CAST2_USE(src[1]->node)->val_known) {
            vt.dword = CAST2_USE(src[0]->node)->val.dword - CAST2_USE(src[1]->node)->val.dword;
            assign_def_after_value(dst[0], vt);
            add_to_deflist(dst[0], re_deflist);
    }
}

void svc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void swp_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void swpb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void sxtab_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void sxtab16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void sxtah_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void sxtb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	valset_u  vt = {0};

    traverse_inst_operand(inst, src, dst, re_uselist, re_deflist, &nuse, &ndef);

    LOG(stdout, "sxtb_resolver: nuse = %d, ndef = %d\n", nuse, ndef);

    // assert(nuse == 1 && ndef == 1);

    if (CAST2_USE(src[0]->node)->val_known &&
        !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)) {
            vt = CAST2_USE(src[0]->node)->val;
            vt.dword &= 0xff;
            if (vt.dword & 0x80) {
                vt.dword |= 0xffffff00;
            }
            assign_def_after_value(dst[0], vt);
            add_to_deflist(dst[0], re_deflist);
        }
    

        
}

void sxtb16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void sxth_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	valset_u  vt = {0};

    traverse_inst_operand(inst, src, dst, re_uselist, re_deflist, &nuse, &ndef);

    LOG(stdout, "sxtb_resolver: nuse = %d, ndef = %d\n", nuse, ndef);

    // assert(nuse == 1 && ndef == 1);

    if (CAST2_USE(src[0]->node)->val_known &&
        !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)) {
            vt = CAST2_USE(src[0]->node)->val;
            vt.dword &= 0xffff;
            if (vt.dword & 0x8000) {
                vt.dword |= 0xffff0000;
            }
            assign_def_after_value(dst[0], vt);
            add_to_deflist(dst[0], re_deflist);
        }

}

void teq_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void trap_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void tsb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void tst_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void uadd16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void uadd8_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void uasx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void ubfx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void udf_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void udiv_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void uhadd16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void uhadd8_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void uhasx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void uhsax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void uhsub16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void uhsub8_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void umaal_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void umlal_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void umull_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void uqadd16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void uqadd8_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void uqasx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void uqsax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void uqsub16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void uqsub8_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void usad8_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void usada8_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void usat_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void usat16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void usax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void usub16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void usub8_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void uxtab_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void uxtab16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void uxtah_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void uxtb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	valset_u  vt = {0};

    traverse_inst_operand(inst, src, dst, re_uselist, re_deflist, &nuse, &ndef);

    LOG(stdout, "uxtb_resolver: nuse = %d, ndef = %d\n", nuse, ndef);

    // assert(nuse == 1 && ndef == 1);

    if (CAST2_USE(src[0]->node)->val_known &&
        !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)) {
            vt = CAST2_USE(src[0]->node)->val;
            vt.dword &= 0xff;
            assign_def_after_value(dst[0], vt);
            add_to_deflist(dst[0], re_deflist);
        }
 
        
}

void uxtb16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void uxth_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	valset_u  vt = {0};

    traverse_inst_operand(inst, src, dst, re_uselist, re_deflist, &nuse, &ndef);

    LOG(stdout, "uxth_resolver: nuse = %d, ndef = %d\n", nuse, ndef);

    // assert(nuse == 1 && ndef == 1);

    if (CAST2_USE(src[0]->node)->val_known &&
        !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)) {
            vt = CAST2_USE(src[0]->node)->val;
            vt.dword &= 0xffff;
            assign_def_after_value(dst[0], vt);
            add_to_deflist(dst[0], re_deflist);
        }

}

void vabal_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vaba_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vabdl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vacge_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vacgt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vaddhn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vaddl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vaddw_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vfmab_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vfmat_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vbif_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vbit_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vbsl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vceq_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vcge_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vcgt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vcle_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vclt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vcmpe_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vcnt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vdiv_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vext_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vfmal_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vfmsl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vfnma_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vfnms_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vins_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vjcvt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vldmdb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vldmia_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vldr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vlldm_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vlstm_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmlal_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmls_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmlsl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmmla_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmovx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmovl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmovn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmsr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vmull_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vnmla_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vnmls_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vnmul_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vpadal_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vpaddl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vpadd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vpmax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vpmin_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqdmlal_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqdmlsl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqdmull_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqmovun_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqmovn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqrdmlsh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqrshrn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqrshrun_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqshrn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vqshrun_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vraddhn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vrecpe_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vrecps_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vrintr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vrshrn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vrsqrte_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vrsqrts_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vrsra_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vrsubhn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vscclrm_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vsdot_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vseleq_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vselge_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vselgt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vselvs_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vshll_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vshrn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vsmmla_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vsqrt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vsra_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vstmdb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vstmia_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vstr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vsubhn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vsubl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vsubw_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vsudot_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vswp_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vtbl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vtbx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vcvtr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vtrn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vtst_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vudot_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vummla_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vusdot_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vusmmla_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vuzp_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vzip_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void addw_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void aut_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void autg_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void bfl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void bflx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void bf_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void bfcsel_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void bfx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void bti_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void bxaut_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void clrm_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void csel_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void csinc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void csinv_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void csneg_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void dcps1_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void dcps2_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void dcps3_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void dls_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void le_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void orn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void pac_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void pacbti_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void pacg_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void sg_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void subs_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void subw_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void tbb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void tbh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void tt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void tta_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void ttat_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void ttt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void wls_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void blxns_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void bxns_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void cbnz_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void cbz_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}
#ifdef FRCA
void pop_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
}
#else
void pop_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    re_list_t *entry;
    re_list_t *dst[NOPD], *src[NOPD];
    // re_list_t
    int nuse, ndef;
    valset_u vt = {0};
    traverse_inst_operand(inst, src, dst, re_uselist, re_deflist, &nuse, &ndef);

    LOG(stdout, "pop_resolver: nuse = %d, ndef = %d\n", nuse, ndef);

    for (int i = 0; i < nuse; i++) {
        //   |  dst   |  src   |
        //   -------------------
        // 0 |  nr1   |  [sp]3 |  0
        // 1 |  sp2   |  sp4   |
        // 2 |  nr5   |  [sp]7 |  1
        // 3 |  sp7   |  sp8   |
        int sp_idx = i * 2 + 1;
        int nr_idx = ndef - (i+1) * 2;
        int sp_mem_idx = i;
        def_node_t *sp = CAST2_DEF(dst[sp_idx]->node);
        def_node_t *nr = CAST2_DEF(dst[nr_idx]->node);
        use_node_t *sp_mem = CAST2_USE(src[sp_mem_idx]->node);
        // printf("sp node id = %d, nr node id = %d, sp_mem id = %d\n", dst[sp_idx]->id, dst[nr_idx]->id, src[sp_mem_idx]->id);
        if (sp->val_stat & AfterKnown && sp->val_stat & BeforeKnown)
        {
            if (sp->afterval.dword - 4 != sp->beforeval.dword) {
                LOG(stdout, "ERROR!! In pop resolver, sp->afterval != sp->beforeval + 4\n");
            }
        }

        if (sp->val_stat & AfterKnown && !(sp->val_stat & BeforeKnown)) {
            vt.dword = sp->afterval.dword - 4;
            assign_def_before_value(dst[sp_idx], vt);
            add_to_deflist(dst[sp_idx], re_deflist);
        }

        if (!(sp->val_stat & AfterKnown) && sp->val_stat & BeforeKnown) {
            vt.dword  = sp->beforeval.dword + 4;
            assign_def_after_value(dst[sp_idx], vt);
            add_to_deflist(dst[sp_idx], re_deflist);
        }

        if (sp_mem->val_known && nr->val_stat & AfterKnown) {
            if (sp_mem->val.dword != nr->afterval.dword) {
                LOG(stdout, "ERROR!! In pop resolver, nr->afterval != sp_mem->val\n");
            }
        }
        if (sp_mem->val_known && !(nr->val_stat & AfterKnown)) {
            vt.dword = sp_mem->val.dword;
            assign_def_after_value(dst[nr_idx], vt);
            add_to_deflist(dst[nr_idx], re_deflist);
        }

        if (!sp_mem->val_known && nr->val_stat & AfterKnown) {
            vt.dword = nr->afterval.dword;
            assign_use_value(src[sp_mem_idx], vt);
            add_to_uselist(src[sp_mem_idx], re_uselist);
        }
    }
}
#endif

#ifdef FRCA
void push_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    // Data events help resolve memory aliases
}
#else 
void push_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    re_list_t *entry;
    re_list_t *dst[NOPD], *src[NOPD];
    // re_list_t
    int nuse, ndef;
    valset_u vt = {0};
    traverse_inst_operand(inst, src, dst, re_uselist, re_deflist, &nuse, &ndef);

    LOG(stdout, "push_resolver: nuse = %d, ndef = %d\n", nuse, ndef);

    for (int i = 0; i < nuse; i++) {
        //   |  dst     |  src   |
        //   ---------------------
        // 0 |  sp1     |  sp3   |  
        // 1 |  [sp]2   |  sp6   |  
        // 2 |  sp4     |  nr7   |  0
        // 3 |  [sp]5   |  nr8   |  1
        int sp_idx = 2 * i;
        int sp_mem_idx = 2 * i + 1;
        int nr_idx = i;
        def_node_t *sp = CAST2_DEF(dst[sp_idx]->node);
        def_node_t *sp_mem = CAST2_DEF(dst[sp_mem_idx]->node);
        use_node_t *nr = CAST2_USE(src[nr_idx]->node);
        // printf("sp node id = %d, sp_mem node id = %d, nr id = %d\n", dst[sp_idx]->id, dst[sp_mem_idx]->id, src[nr_idx]->id);

        if (sp->val_stat & AfterKnown && sp->val_stat & BeforeKnown) {
            if (sp->afterval.dword + 4 != sp->beforeval.dword) {
                LOG(stdout, "ERROR!! In push resolver, sp->afterval != sp->beforeval - 4\n");
            }
        }

        if (sp->val_stat & AfterKnown && !(sp->val_stat & BeforeKnown)) {
            vt.dword  = sp->afterval.dword + 4;
            assign_def_before_value(dst[sp_idx], vt);
            add_to_deflist(dst[sp_idx], re_deflist);
        }

        if (!(sp->val_stat & AfterKnown) && sp->val_stat & BeforeKnown) {
            vt.dword  = sp->beforeval.dword - 4;
            assign_def_after_value(dst[sp_idx], vt);
            add_to_deflist(dst[sp_idx], re_deflist);
        }

        if (nr->val_known && sp_mem->val_stat & AfterKnown) {
            if (nr->val.dword != sp_mem->afterval.dword) {
                LOG(stdout, "ERROR!! In push resolver, nr->val != sp_mem->afterval\n");
            }
        }
        if (nr->val_known && !(sp_mem->val_stat & AfterKnown)) {
            vt.dword = nr->val.dword;
            assign_def_after_value(dst[sp_mem_idx], vt);
            add_to_deflist(dst[sp_mem_idx], re_deflist);
        }

        if (!nr->val_known && sp_mem->val_stat & AfterKnown) {
            vt.dword = sp_mem->afterval.dword;
            assign_use_value(src[nr_idx], vt);
            add_to_uselist(src[nr_idx], re_uselist);
        }
    }
}

#endif
void brkdiv0_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vpop_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}

void vpush_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
return 0;
}


//instruction post resolvers
int invalid_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int asr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int it_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int ldrbt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int ldr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int ldrht_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int ldrsbt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int ldrsht_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int ldrt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int lsl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int lsr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

// int ror_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
//     return 0;                    
// }

int rrx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int strbt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int strt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vld1_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vld2_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vld3_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vld4_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vst1_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vst2_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vst3_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vst4_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int ldrb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int ldrh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int ldrsb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int ldrsh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int movs_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

// int mov_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
//     return 0;                    
// }

int str_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int adc_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

// int add_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
//     return 0;                    
// }

int adr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int aesd_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int aese_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int aesimc_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int aesmc_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

// int and_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
//     return 0;                    
// }

int vdot_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vcvt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vcvtb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vcvtt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int bfc_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int bfi_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int bic_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int bkpt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int bl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int blx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int bx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int bxj_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int b_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int cx1_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int cx1a_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int cx1d_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int cx1da_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int cx2_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int cx2a_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int cx2d_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int cx2da_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int cx3_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int cx3a_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int cx3d_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int cx3da_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vcx1a_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vcx1_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vcx2a_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vcx2_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vcx3a_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vcx3_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int cdp_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int cdp2_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int clrex_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int clz_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int cmn_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

// int cmp_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
//     return 0;                    
// }

int cps_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int crc32b_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int crc32cb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int crc32ch_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int crc32cw_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int crc32h_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int crc32w_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int dbg_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int dmb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int dsb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int eor_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int eret_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmov_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int fldmdbx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int fldmiax_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmrs_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int fstmdbx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int fstmiax_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int hint_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int hlt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int hvc_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int isb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int lda_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int ldab_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int ldaex_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int ldaexb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int ldaexd_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int ldaexh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int ldah_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int ldc2l_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int ldc2_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int ldcl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int ldc_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int ldmda_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int ldmdb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int ldm_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int ldmib_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int ldrd_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int ldrex_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int ldrexb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int ldrexd_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int ldrexh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int mcr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int mcr2_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int mcrr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int mcrr2_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int mla_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int mls_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int movt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int movw_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int mrc_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int mrc2_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int mrrc_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int mrrc2_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int mrs_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int msr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

// int mul_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
//     return 0;                    
// }

int asrl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int dlstp_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int lctp_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int letp_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int lsll_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int lsrl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int sqrshr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int sqrshrl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int sqshl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int sqshll_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int srshr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int srshrl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int uqrshl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int uqrshll_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int uqshl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int uqshll_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int urshr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int urshrl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vabav_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vabd_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vabs_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vadc_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vadci_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vaddlva_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vaddlv_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vaddva_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vaddv_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vadd_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vand_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vbic_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vbrsr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vcadd_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vcls_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vclz_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vcmla_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vcmp_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vcmul_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vctp_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vcvta_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vcvtm_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vcvtn_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vcvtp_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vddup_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vdup_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vdwdup_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int veor_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vfmas_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vfma_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vfms_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vhadd_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vhcadd_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vhsub_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vidup_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int viwdup_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vld20_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vld21_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vld40_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vld41_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vld42_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vld43_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vldrb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vldrd_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vldrh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vldrw_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmaxav_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmaxa_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmaxnmav_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmaxnma_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmaxnmv_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmaxnm_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmaxv_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmax_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vminav_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmina_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vminnmav_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vminnma_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vminnmv_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vminnm_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vminv_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmin_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmladava_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmladavax_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmladav_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmladavx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmlaldava_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmlaldavax_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmlaldav_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmlaldavx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmlas_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmla_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmlsdava_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmlsdavax_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmlsdav_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmlsdavx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmlsldava_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmlsldavax_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmlsldav_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmlsldavx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmovlb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmovlt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmovnb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmovnt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmulh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmullb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmullt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmul_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmvn_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vneg_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vorn_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vorr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vpnot_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vpsel_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vpst_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vpt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqabs_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqadd_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqdmladhx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqdmladh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqdmlah_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqdmlash_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqdmlsdhx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqdmlsdh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqdmulh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqdmullb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqdmullt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqmovnb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqmovnt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqmovunb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqmovunt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqneg_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqrdmladhx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqrdmladh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqrdmlah_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqrdmlash_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqrdmlsdhx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqrdmlsdh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqrdmulh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqrshl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqrshrnb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqrshrnt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqrshrunb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqrshrunt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqshlu_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqshl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqshrnb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqshrnt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqshrunb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqshrunt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqsub_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vrev16_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vrev32_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vrev64_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vrhadd_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vrinta_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vrintm_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vrintn_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vrintp_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vrintx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vrintz_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vrmlaldavha_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vrmlaldavhax_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vrmlaldavh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vrmlaldavhx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vrmlsldavha_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vrmlsldavhax_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vrmlsldavh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vrmlsldavhx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vrmulh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vrshl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vrshrnb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vrshrnt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vrshr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vsbc_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vsbci_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vshlc_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vshllb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vshllt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vshl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vshrnb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vshrnt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vshr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vsli_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vsri_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vst20_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vst21_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vst40_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vst41_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vst42_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vst43_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vstrb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vstrd_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vstrh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vstrw_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vsub_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int wlstp_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int mvn_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int orr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int pkhbt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int pkhtb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int pldw_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int pld_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int pli_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int qadd_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int qadd16_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int qadd8_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int qasx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int qdadd_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int qdsub_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int qsax_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int qsub_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int qsub16_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int qsub8_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int rbit_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int rev_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int rev16_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int revsh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int rfeda_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int rfedb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int rfeia_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int rfeib_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int rsb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int rsc_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int sadd16_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int sadd8_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int sasx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int sb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int sbc_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int sbfx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int sdiv_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int sel_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int setend_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int setpan_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int sha1c_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int sha1h_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int sha1m_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int sha1p_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int sha1su0_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int sha1su1_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int sha256h_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int sha256h2_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int sha256su0_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int sha256su1_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int shadd16_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int shadd8_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int shasx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int shsax_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int shsub16_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int shsub8_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int smc_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int smlabb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int smlabt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int smlad_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int smladx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int smlal_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int smlalbb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int smlalbt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int smlald_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int smlaldx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int smlaltb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int smlaltt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int smlatb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int smlatt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int smlawb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int smlawt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int smlsd_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int smlsdx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int smlsld_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int smlsldx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int smmla_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int smmlar_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int smmls_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int smmlsr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int smmul_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int smmulr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int smuad_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int smuadx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int smulbb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int smulbt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int smull_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int smultb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int smultt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int smulwb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int smulwt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int smusd_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int smusdx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int srsda_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int srsdb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int srsia_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int srsib_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int ssat_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int ssat16_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int ssax_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int ssub16_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int ssub8_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int stc2l_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int stc2_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int stcl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int stc_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int stl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int stlb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int stlex_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int stlexb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int stlexd_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int stlexh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int stlh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int stmda_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int stmdb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int stm_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int stmib_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int strb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int strd_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int strex_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int strexb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int strexd_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int strexh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int strh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int strht_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

// int sub_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
//     return 0;                    
// }

int svc_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int swp_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int swpb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int sxtab_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int sxtab16_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int sxtah_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int sxtb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int sxtb16_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int sxth_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int teq_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int trap_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int tsb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int tst_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int uadd16_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int uadd8_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int uasx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int ubfx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int udf_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int udiv_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int uhadd16_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int uhadd8_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int uhasx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int uhsax_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int uhsub16_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int uhsub8_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int umaal_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int umlal_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int umull_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int uqadd16_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int uqadd8_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int uqasx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int uqsax_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int uqsub16_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int uqsub8_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int usad8_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int usada8_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int usat_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int usat16_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int usax_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int usub16_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int usub8_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int uxtab_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int uxtab16_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int uxtah_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int uxtb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int uxtb16_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int uxth_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vabal_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vaba_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vabdl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vacge_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vacgt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vaddhn_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vaddl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vaddw_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vfmab_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vfmat_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vbif_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vbit_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vbsl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vceq_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vcge_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vcgt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vcle_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vclt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vcmpe_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vcnt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vdiv_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vext_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vfmal_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vfmsl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vfnma_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vfnms_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vins_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vjcvt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vldmdb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vldmia_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vldr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vlldm_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vlstm_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmlal_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmls_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmlsl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmmla_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmovx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmovl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmovn_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmsr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vmull_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vnmla_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vnmls_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vnmul_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vpadal_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vpaddl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vpadd_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vpmax_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vpmin_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqdmlal_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqdmlsl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqdmull_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqmovun_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqmovn_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqrdmlsh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqrshrn_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqrshrun_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqshrn_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vqshrun_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vraddhn_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vrecpe_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vrecps_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vrintr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vrshrn_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vrsqrte_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vrsqrts_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vrsra_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vrsubhn_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vscclrm_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vsdot_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vseleq_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vselge_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vselgt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vselvs_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vshll_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vshrn_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vsmmla_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vsqrt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vsra_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vstmdb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vstmia_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vstr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vsubhn_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vsubl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vsubw_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vsudot_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vswp_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vtbl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vtbx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vcvtr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vtrn_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vtst_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vudot_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vummla_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vusdot_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vusmmla_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vuzp_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vzip_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int addw_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int aut_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int autg_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int bfl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int bflx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int bf_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int bfcsel_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int bfx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int bti_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int bxaut_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int clrm_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int csel_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int csinc_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int csinv_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int csneg_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int dcps1_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int dcps2_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int dcps3_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int dls_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int le_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int orn_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int pac_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int pacbti_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int pacg_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int sg_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int subs_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int subw_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int tbb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int tbh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int tt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int tta_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int ttat_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int ttt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int wls_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int blxns_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int bxns_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int cbnz_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int cbz_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

// int pop_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
//     return 0;                    
// }

// int push_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
//     return 0;                    
// }

int brkdiv0_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vpop_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

int vpush_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    return 0;                    
}

#ifdef VSA
#if defined (ALIAS_MODULE) && (ALIAS_MODULE == VSA_MODULE)
// vsa handlers
void invalid_vs_handler(re_list_t *instnode){
return 0;
    

}

void general_vs_handler(re_list_t *instnode){
return 0;
    

}

void asr_vs_handler(re_list_t *instnode){
return 0;
    

}

void it_vs_handler(re_list_t *instnode){
return 0;
    

}

void ldrbt_vs_handler(re_list_t *instnode){
return 0;
    

}

void ldr_vs_handler(re_list_t *instnode){
    //print_info_of_current_inst(instnode);

	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	
	// traverse all the operands to fill all value set
	// (including value set and address value) of operands
	vs_traverse_inst_operand(instnode, src, dst, &nuse, &ndef);
    
    if (nuse != 1 || ndef != 1) {
        LOG(stdout, "NOTE ldr_vs_handler: nuse = %d and ndef %d\n", nuse, ndef);
    }
	// just fill the value set of destination operand
	// with the value set of destination operand
	assign_def_after_value_set(dst[0], &CAST2_USE(src[0]->node)->valset);
}

void ldrht_vs_handler(re_list_t *instnode){
return 0;
    

}

void ldrsbt_vs_handler(re_list_t *instnode){
return 0;
    

}

void ldrsht_vs_handler(re_list_t *instnode){
return 0;
    

}

void ldrt_vs_handler(re_list_t *instnode){
return 0;
    

}

void lsl_vs_handler(re_list_t *instnode){
    re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	
	// traverse all the operands to fill all value set
	// (including value set and address value) of operands
	vs_traverse_inst_operand(instnode, src, dst, &nuse, &ndef);
	if (nuse != 2 || ndef != 1) {
        LOG(stdout, "NOTE lsl_vs_handler: nuse = %d and ndef %d\n", nuse, ndef);
    }
	
    if (!list_empty(&CAST2_DEF(dst[0]->node)->aft_valset.list) &&
	    !list_empty(&CAST2_USE(src[0]->node)->valset.list) &&
	    !list_empty(&CAST2_USE(src[1]->node)->valset.list)) {
		return;
	}
    valset_shl(&CAST2_DEF(dst[0]->node)->aft_valset,
		  &CAST2_USE(src[0]->node)->valset,
		  &CAST2_USE(src[1]->node)->valset);
    
    

}

void lsr_vs_handler(re_list_t *instnode){
    re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	
	// traverse all the operands to fill all value set
	// (including value set and address value) of operands
	vs_traverse_inst_operand(instnode, src, dst, &nuse, &ndef);
	if (nuse != 2 || ndef != 1) {
        LOG(stdout, "NOTE lsr_vs_handler: nuse = %d and ndef %d\n", nuse, ndef);
    }
	
    if (!list_empty(&CAST2_DEF(dst[0]->node)->aft_valset.list) &&
	    !list_empty(&CAST2_USE(src[0]->node)->valset.list) &&
	    !list_empty(&CAST2_USE(src[1]->node)->valset.list)) {
		return;
	}
    valset_shr(&CAST2_DEF(dst[0]->node)->aft_valset,
		  &CAST2_USE(src[0]->node)->valset,
		  &CAST2_USE(src[1]->node)->valset);
    

}

void ror_vs_handler(re_list_t *instnode){
return 0;
    

}

void rrx_vs_handler(re_list_t *instnode){
return 0;
    

}

void strbt_vs_handler(re_list_t *instnode){
return 0;
    

}

void strt_vs_handler(re_list_t *instnode){
return 0;
    

}

void vld1_vs_handler(re_list_t *instnode){
return 0;
    

}

void vld2_vs_handler(re_list_t *instnode){
return 0;
    

}

void vld3_vs_handler(re_list_t *instnode){
return 0;
    

}

void vld4_vs_handler(re_list_t *instnode){
return 0;
    

}

void vst1_vs_handler(re_list_t *instnode){
return 0;
    

}

void vst2_vs_handler(re_list_t *instnode){
return 0;
    

}

void vst3_vs_handler(re_list_t *instnode){
return 0;
    

}

void vst4_vs_handler(re_list_t *instnode){
return 0;
    

}

void ldrb_vs_handler(re_list_t *instnode){
    re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	
	// traverse all the operands to fill all value set
	// (including value set and address value) of operands
	vs_traverse_inst_operand(instnode, src, dst, &nuse, &ndef);
	if (nuse != 1 || ndef != 1) {
        LOG(stdout, "NOTE ldrb_vs_handler: nuse = %d and ndef %d\n", nuse, ndef);
    }
	
	// just fill the value set of destination operand
	// with the value set of destination operand
	assign_def_after_value_set(dst[0], &CAST2_USE(src[0]->node)->valset);

	sign_extend_value_set(&CAST2_DEF(dst[0]->node)->aft_valset,
		arm_get_datatype(CAST2_DEF(dst[0]->node)->inst));
}

void ldrh_vs_handler(re_list_t *instnode){
       	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	
	// traverse all the operands to fill all value set
	// (including value set and address value) of operands
	vs_traverse_inst_operand(instnode, src, dst, &nuse, &ndef);
	if (nuse != 1 || ndef != 1) {
        LOG(stdout, "NOTE ldrh_vs_handler: nuse = %d and ndef %d\n", nuse, ndef);
    }
	
	// just fill the value set of destination operand
	// with the value set of destination operand
	assign_def_after_value_set(dst[0], &CAST2_USE(src[0]->node)->valset);

	sign_extend_value_set(&CAST2_DEF(dst[0]->node)->aft_valset,
		arm_get_datatype(CAST2_DEF(dst[0]->node)->inst));
    

}

void ldrsb_vs_handler(re_list_t *instnode){
   	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	
	// traverse all the operands to fill all value set
	// (including value set and address value) of operands
	vs_traverse_inst_operand(instnode, src, dst, &nuse, &ndef);
	if (nuse != 1 || ndef != 1) {
        LOG(stdout, "NOTE ldrsb_vs_handler: nuse = %d and ndef %d\n", nuse, ndef);
    }
	
	// just fill the value set of destination operand
	// with the value set of destination operand
	assign_def_after_value_set(dst[0], &CAST2_USE(src[0]->node)->valset);

	sign_extend_value_set(&CAST2_DEF(dst[0]->node)->aft_valset,
		arm_get_datatype(CAST2_DEF(dst[0]->node)->inst));
    

}

void ldrsh_vs_handler(re_list_t *instnode){
return 0;
    

}

void movs_vs_handler(re_list_t *instnode){
    re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	
	// traverse all the operands to fill all value set
	// (including value set and address value) of operands
	vs_traverse_inst_operand(instnode, src, dst, &nuse, &ndef);
	// assert(nuse == 1 && ndef ==1);
    if (nuse != 1 || ndef != 1) {
        LOG(stdout, "NOTE movs_vs_handler: nuse = %d and ndef %d\n", nuse, ndef);
    }
	assign_def_after_value_set(dst[0], &CAST2_USE(src[0]->node)->valset);
}

void mov_vs_handler(re_list_t *instnode){
    re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	
	// traverse all the operands to fill all value set
	// (including value set and address value) of operands
	vs_traverse_inst_operand(instnode, src, dst, &nuse, &ndef);
	// assert(nuse == 1 && ndef ==1);
    if (nuse != 1 || ndef != 1) {
        LOG(stdout, "NOTE mov_vs_handler: nuse = %d and ndef %d\n", nuse, ndef);
    }
	assign_def_after_value_set(dst[0], &CAST2_USE(src[0]->node)->valset);

}

void str_vs_handler(re_list_t *instnode){
    re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	
	// traverse all the operands to fill all value set
	// (including value set and address value) of operands
	vs_traverse_inst_operand(instnode, src, dst, &nuse, &ndef);
	if (nuse != 1 || ndef != 1) {
        LOG(stdout, "NOTE str_vs_handler: nuse = %d and ndef %d\n", nuse, ndef);
    }
	
	assign_def_after_value_set(dst[0], &CAST2_USE(src[0]->node)->valset);

}

void adc_vs_handler(re_list_t *instnode){
return 0;
    

}

void add_vs_handler(re_list_t *instnode){
	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	
	// traverse all the operands to fill all value set
	// (including value set and address value) of operands
	vs_traverse_inst_operand(instnode, src, dst, &nuse, &ndef);
	// assert(nuse == 2 && ndef ==1);

	if (!list_empty(&CAST2_DEF(dst[0]->node)->aft_valset.list) &&
	    !list_empty(&CAST2_USE(src[0]->node)->valset.list) &&
	    !list_empty(&CAST2_USE(src[1]->node)->valset.list)) {
		return;
	}

	valset_add(&CAST2_DEF(dst[0]->node)->aft_valset,
		  &CAST2_USE(src[0]->node)->valset,
		  &CAST2_USE(src[1]->node)->valset);
}

void adr_vs_handler(re_list_t *instnode){
return 0;
    

}

void aesd_vs_handler(re_list_t *instnode){
return 0;
    

}

void aese_vs_handler(re_list_t *instnode){
return 0;
    

}

void aesimc_vs_handler(re_list_t *instnode){
return 0;
    

}

void aesmc_vs_handler(re_list_t *instnode){
return 0;
    

}

void and_vs_handler(re_list_t *instnode){
    re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	
	// traverse all the operands to fill all value set
	// (including value set and address value) of operands
	vs_traverse_inst_operand(instnode, src, dst, &nuse, &ndef);
	if (nuse != 2 || ndef != 1) {
        LOG(stdout, "NOTE orr_vs_handler: nuse = %d and ndef %d\n", nuse, ndef);
    }
	
    if (!list_empty(&CAST2_DEF(dst[0]->node)->aft_valset.list) &&
	    !list_empty(&CAST2_USE(src[0]->node)->valset.list) &&
	    !list_empty(&CAST2_USE(src[1]->node)->valset.list)) {
		return;
	}
    valset_and(&CAST2_DEF(dst[0]->node)->aft_valset,
		  &CAST2_USE(src[0]->node)->valset,
		  &CAST2_USE(src[1]->node)->valset);
    

}

void vdot_vs_handler(re_list_t *instnode){
return 0;
    

}

void vcvt_vs_handler(re_list_t *instnode){
return 0;
    

}

void vcvtb_vs_handler(re_list_t *instnode){
return 0;
    

}

void vcvtt_vs_handler(re_list_t *instnode){
return 0;
    

}

void bfc_vs_handler(re_list_t *instnode){
return 0;
    

}

void bfi_vs_handler(re_list_t *instnode){
return 0;
    

}

void bic_vs_handler(re_list_t *instnode){
    re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	
	// traverse all the operands to fill all value set
	// (including value set and address value) of operands
	vs_traverse_inst_operand(instnode, src, dst, &nuse, &ndef);
	if (nuse != 2 || ndef != 1) {
        LOG(stdout, "NOTE orr_vs_handler: nuse = %d and ndef %d\n", nuse, ndef);
    }
	
    if (!list_empty(&CAST2_DEF(dst[0]->node)->aft_valset.list) &&
	    !list_empty(&CAST2_USE(src[0]->node)->valset.list) &&
	    !list_empty(&CAST2_USE(src[1]->node)->valset.list)) {
		return;
	}
    valset_bic(&CAST2_DEF(dst[0]->node)->aft_valset,
		  &CAST2_USE(src[0]->node)->valset,
		  &CAST2_USE(src[1]->node)->valset);
    

}

void bkpt_vs_handler(re_list_t *instnode){
return 0;
    

}

void bl_vs_handler(re_list_t *instnode){
return 0;
    // 

}

void blx_vs_handler(re_list_t *instnode){
return 0;
    // 

}

void bx_vs_handler(re_list_t *instnode){
return 0;
    

}

void bxj_vs_handler(re_list_t *instnode){
return 0;
    

}

void b_vs_handler(re_list_t *instnode){
return 0;
    

}

void cx1_vs_handler(re_list_t *instnode){
return 0;
    

}

void cx1a_vs_handler(re_list_t *instnode){
return 0;
    

}

void cx1d_vs_handler(re_list_t *instnode){
return 0;
    

}

void cx1da_vs_handler(re_list_t *instnode){
return 0;
    

}

void cx2_vs_handler(re_list_t *instnode){
return 0;
    

}

void cx2a_vs_handler(re_list_t *instnode){
return 0;
    

}

void cx2d_vs_handler(re_list_t *instnode){
return 0;
    

}

void cx2da_vs_handler(re_list_t *instnode){
return 0;
    

}

void cx3_vs_handler(re_list_t *instnode){
return 0;
    

}

void cx3a_vs_handler(re_list_t *instnode){
return 0;
    

}

void cx3d_vs_handler(re_list_t *instnode){
return 0;
    

}

void cx3da_vs_handler(re_list_t *instnode){
return 0;
    

}

void vcx1a_vs_handler(re_list_t *instnode){
return 0;
    

}

void vcx1_vs_handler(re_list_t *instnode){
return 0;
    

}

void vcx2a_vs_handler(re_list_t *instnode){
return 0;
    

}

void vcx2_vs_handler(re_list_t *instnode){
return 0;
    

}

void vcx3a_vs_handler(re_list_t *instnode){
return 0;
    

}

void vcx3_vs_handler(re_list_t *instnode){
return 0;
    

}

void cdp_vs_handler(re_list_t *instnode){
return 0;
    

}

void cdp2_vs_handler(re_list_t *instnode){
return 0;
    

}

void clrex_vs_handler(re_list_t *instnode){
return 0;
    

}

void clz_vs_handler(re_list_t *instnode){
return 0;
    

}

void cmn_vs_handler(re_list_t *instnode){
return 0;
    

}

void cmp_vs_handler(re_list_t *instnode){
   	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	
	// traverse all the operands to fill all value set
	// (including value set and address value) of operands
	vs_traverse_inst_operand(instnode, src, dst, &nuse, &ndef);

}

void cps_vs_handler(re_list_t *instnode){
return 0;
    

}

void crc32b_vs_handler(re_list_t *instnode){
return 0;
    

}

void crc32cb_vs_handler(re_list_t *instnode){
return 0;
    

}

void crc32ch_vs_handler(re_list_t *instnode){
return 0;
    

}

void crc32cw_vs_handler(re_list_t *instnode){
return 0;
    

}

void crc32h_vs_handler(re_list_t *instnode){
return 0;
    

}

void crc32w_vs_handler(re_list_t *instnode){
return 0;
    

}

void dbg_vs_handler(re_list_t *instnode){
return 0;
    

}

void dmb_vs_handler(re_list_t *instnode){
return 0;
    

}

void dsb_vs_handler(re_list_t *instnode){
return 0;
    

}

void eor_vs_handler(re_list_t *instnode){
return 0;
    

}

void eret_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmov_vs_handler(re_list_t *instnode){
return 0;
    

}

void fldmdbx_vs_handler(re_list_t *instnode){
return 0;
    

}

void fldmiax_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmrs_vs_handler(re_list_t *instnode){
return 0;
    

}

void fstmdbx_vs_handler(re_list_t *instnode){
return 0;
    

}

void fstmiax_vs_handler(re_list_t *instnode){
return 0;
    

}

void hint_vs_handler(re_list_t *instnode){
return 0;
    

}

void hlt_vs_handler(re_list_t *instnode){
return 0;
    

}

void hvc_vs_handler(re_list_t *instnode){
return 0;
    

}

void isb_vs_handler(re_list_t *instnode){
return 0;
    

}

void lda_vs_handler(re_list_t *instnode){
return 0;
    

}

void ldab_vs_handler(re_list_t *instnode){
return 0;
    

}

void ldaex_vs_handler(re_list_t *instnode){
return 0;
    

}

void ldaexb_vs_handler(re_list_t *instnode){
return 0;
    

}

void ldaexd_vs_handler(re_list_t *instnode){
return 0;
    

}

void ldaexh_vs_handler(re_list_t *instnode){
return 0;
    

}

void ldah_vs_handler(re_list_t *instnode){
return 0;
    

}

void ldc2l_vs_handler(re_list_t *instnode){
return 0;
    

}

void ldc2_vs_handler(re_list_t *instnode){
return 0;
    

}

void ldcl_vs_handler(re_list_t *instnode){
return 0;
    

}

void ldc_vs_handler(re_list_t *instnode){
return 0;
    

}

void ldmda_vs_handler(re_list_t *instnode){
return 0;
    

}

void ldmdb_vs_handler(re_list_t *instnode){
return 0;
    

}

void ldm_vs_handler(re_list_t *instnode){
return 0;
    

}

void ldmib_vs_handler(re_list_t *instnode){
return 0;
    

}

void ldrd_vs_handler(re_list_t *instnode){
return 0;
    

}

void ldrex_vs_handler(re_list_t *instnode){
return 0;
    

}

void ldrexb_vs_handler(re_list_t *instnode){
return 0;
    

}

void ldrexd_vs_handler(re_list_t *instnode){
return 0;
    

}

void ldrexh_vs_handler(re_list_t *instnode){
return 0;
    

}

void mcr_vs_handler(re_list_t *instnode){
return 0;
    

}

void mcr2_vs_handler(re_list_t *instnode){
return 0;
    

}

void mcrr_vs_handler(re_list_t *instnode){
return 0;
    

}

void mcrr2_vs_handler(re_list_t *instnode){
return 0;
    

}

void mla_vs_handler(re_list_t *instnode){
return 0;
    

}

void mls_vs_handler(re_list_t *instnode){
return 0;
    

}

void movt_vs_handler(re_list_t *instnode){
return 0;
    

}

void movw_vs_handler(re_list_t *instnode){
return 0;
    

}

void mrc_vs_handler(re_list_t *instnode){
return 0;
    

}

void mrc2_vs_handler(re_list_t *instnode){
return 0;
    

}

void mrrc_vs_handler(re_list_t *instnode){
return 0;
    

}

void mrrc2_vs_handler(re_list_t *instnode){
return 0;
    

}

void mrs_vs_handler(re_list_t *instnode){
return 0;
    

}

void msr_vs_handler(re_list_t *instnode){
return 0;
    

}

void mul_vs_handler(re_list_t *instnode){
return 0;
    

}

void asrl_vs_handler(re_list_t *instnode){
return 0;
    

}

void dlstp_vs_handler(re_list_t *instnode){
return 0;
    

}

void lctp_vs_handler(re_list_t *instnode){
return 0;
    

}

void letp_vs_handler(re_list_t *instnode){
return 0;
    

}

void lsll_vs_handler(re_list_t *instnode){
return 0;
    

}

void lsrl_vs_handler(re_list_t *instnode){
return 0;
    

}

void sqrshr_vs_handler(re_list_t *instnode){
return 0;
    

}

void sqrshrl_vs_handler(re_list_t *instnode){
return 0;
    

}

void sqshl_vs_handler(re_list_t *instnode){
return 0;
    

}

void sqshll_vs_handler(re_list_t *instnode){
return 0;
    

}

void srshr_vs_handler(re_list_t *instnode){
return 0;
    

}

void srshrl_vs_handler(re_list_t *instnode){
return 0;
    

}

void uqrshl_vs_handler(re_list_t *instnode){
return 0;
    

}

void uqrshll_vs_handler(re_list_t *instnode){
return 0;
    

}

void uqshl_vs_handler(re_list_t *instnode){
return 0;
    

}

void uqshll_vs_handler(re_list_t *instnode){
return 0;
    

}

void urshr_vs_handler(re_list_t *instnode){
return 0;
    

}

void urshrl_vs_handler(re_list_t *instnode){
return 0;
    

}

void vabav_vs_handler(re_list_t *instnode){
return 0;
    

}

void vabd_vs_handler(re_list_t *instnode){
return 0;
    

}

void vabs_vs_handler(re_list_t *instnode){
return 0;
    

}

void vadc_vs_handler(re_list_t *instnode){
return 0;
    

}

void vadci_vs_handler(re_list_t *instnode){
return 0;
    

}

void vaddlva_vs_handler(re_list_t *instnode){
return 0;
    

}

void vaddlv_vs_handler(re_list_t *instnode){
return 0;
    

}

void vaddva_vs_handler(re_list_t *instnode){
return 0;
    

}

void vaddv_vs_handler(re_list_t *instnode){
return 0;
    

}

void vadd_vs_handler(re_list_t *instnode){
return 0;
    

}

void vand_vs_handler(re_list_t *instnode){
return 0;
    

}

void vbic_vs_handler(re_list_t *instnode){
return 0;
    

}

void vbrsr_vs_handler(re_list_t *instnode){
return 0;
    

}

void vcadd_vs_handler(re_list_t *instnode){
return 0;
    

}

void vcls_vs_handler(re_list_t *instnode){
return 0;
    

}

void vclz_vs_handler(re_list_t *instnode){
return 0;
    

}

void vcmla_vs_handler(re_list_t *instnode){
return 0;
    

}

void vcmp_vs_handler(re_list_t *instnode){
return 0;
    

}

void vcmul_vs_handler(re_list_t *instnode){
return 0;
    

}

void vctp_vs_handler(re_list_t *instnode){
return 0;
    

}

void vcvta_vs_handler(re_list_t *instnode){
return 0;
    

}

void vcvtm_vs_handler(re_list_t *instnode){
return 0;
    

}

void vcvtn_vs_handler(re_list_t *instnode){
return 0;
    

}

void vcvtp_vs_handler(re_list_t *instnode){
return 0;
    

}

void vddup_vs_handler(re_list_t *instnode){
return 0;
    

}

void vdup_vs_handler(re_list_t *instnode){
return 0;
    

}

void vdwdup_vs_handler(re_list_t *instnode){
return 0;
    

}

void veor_vs_handler(re_list_t *instnode){
return 0;
    

}

void vfmas_vs_handler(re_list_t *instnode){
return 0;
    

}

void vfma_vs_handler(re_list_t *instnode){
return 0;
    

}

void vfms_vs_handler(re_list_t *instnode){
return 0;
    

}

void vhadd_vs_handler(re_list_t *instnode){
return 0;
    

}

void vhcadd_vs_handler(re_list_t *instnode){
return 0;
    

}

void vhsub_vs_handler(re_list_t *instnode){
return 0;
    

}

void vidup_vs_handler(re_list_t *instnode){
return 0;
    

}

void viwdup_vs_handler(re_list_t *instnode){
return 0;
    

}

void vld20_vs_handler(re_list_t *instnode){
return 0;
    

}

void vld21_vs_handler(re_list_t *instnode){
return 0;
    

}

void vld40_vs_handler(re_list_t *instnode){
return 0;
    

}

void vld41_vs_handler(re_list_t *instnode){
return 0;
    

}

void vld42_vs_handler(re_list_t *instnode){
return 0;
    

}

void vld43_vs_handler(re_list_t *instnode){
return 0;
    

}

void vldrb_vs_handler(re_list_t *instnode){
return 0;
    

}

void vldrd_vs_handler(re_list_t *instnode){
return 0;
    

}

void vldrh_vs_handler(re_list_t *instnode){
return 0;
    

}

void vldrw_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmaxav_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmaxa_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmaxnmav_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmaxnma_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmaxnmv_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmaxnm_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmaxv_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmax_vs_handler(re_list_t *instnode){
return 0;
    

}

void vminav_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmina_vs_handler(re_list_t *instnode){
return 0;
    

}

void vminnmav_vs_handler(re_list_t *instnode){
return 0;
    

}

void vminnma_vs_handler(re_list_t *instnode){
return 0;
    

}

void vminnmv_vs_handler(re_list_t *instnode){
return 0;
    

}

void vminnm_vs_handler(re_list_t *instnode){
return 0;
    

}

void vminv_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmin_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmladava_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmladavax_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmladav_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmladavx_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmlaldava_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmlaldavax_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmlaldav_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmlaldavx_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmlas_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmla_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmlsdava_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmlsdavax_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmlsdav_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmlsdavx_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmlsldava_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmlsldavax_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmlsldav_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmlsldavx_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmovlb_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmovlt_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmovnb_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmovnt_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmulh_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmullb_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmullt_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmul_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmvn_vs_handler(re_list_t *instnode){
return 0;
    

}

void vneg_vs_handler(re_list_t *instnode){
return 0;
    

}

void vorn_vs_handler(re_list_t *instnode){
return 0;
    

}

void vorr_vs_handler(re_list_t *instnode){
return 0;
    

}

void vpnot_vs_handler(re_list_t *instnode){
return 0;
    

}

void vpsel_vs_handler(re_list_t *instnode){
return 0;
    

}

void vpst_vs_handler(re_list_t *instnode){
return 0;
    

}

void vpt_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqabs_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqadd_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqdmladhx_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqdmladh_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqdmlah_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqdmlash_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqdmlsdhx_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqdmlsdh_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqdmulh_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqdmullb_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqdmullt_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqmovnb_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqmovnt_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqmovunb_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqmovunt_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqneg_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqrdmladhx_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqrdmladh_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqrdmlah_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqrdmlash_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqrdmlsdhx_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqrdmlsdh_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqrdmulh_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqrshl_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqrshrnb_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqrshrnt_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqrshrunb_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqrshrunt_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqshlu_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqshl_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqshrnb_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqshrnt_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqshrunb_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqshrunt_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqsub_vs_handler(re_list_t *instnode){
return 0;
    

}

void vrev16_vs_handler(re_list_t *instnode){
return 0;
    

}

void vrev32_vs_handler(re_list_t *instnode){
return 0;
    

}

void vrev64_vs_handler(re_list_t *instnode){
return 0;
    

}

void vrhadd_vs_handler(re_list_t *instnode){
return 0;
    

}

void vrinta_vs_handler(re_list_t *instnode){
return 0;
    

}

void vrintm_vs_handler(re_list_t *instnode){
return 0;
    

}

void vrintn_vs_handler(re_list_t *instnode){
return 0;
    

}

void vrintp_vs_handler(re_list_t *instnode){
return 0;
    

}

void vrintx_vs_handler(re_list_t *instnode){
return 0;
    

}

void vrintz_vs_handler(re_list_t *instnode){
return 0;
    

}

void vrmlaldavha_vs_handler(re_list_t *instnode){
return 0;
    

}

void vrmlaldavhax_vs_handler(re_list_t *instnode){
return 0;
    

}

void vrmlaldavh_vs_handler(re_list_t *instnode){
return 0;
    

}

void vrmlaldavhx_vs_handler(re_list_t *instnode){
return 0;
    

}

void vrmlsldavha_vs_handler(re_list_t *instnode){
return 0;
    

}

void vrmlsldavhax_vs_handler(re_list_t *instnode){
return 0;
    

}

void vrmlsldavh_vs_handler(re_list_t *instnode){
return 0;
    

}

void vrmlsldavhx_vs_handler(re_list_t *instnode){
return 0;
    

}

void vrmulh_vs_handler(re_list_t *instnode){
return 0;
    

}

void vrshl_vs_handler(re_list_t *instnode){
return 0;
    

}

void vrshrnb_vs_handler(re_list_t *instnode){
return 0;
    

}

void vrshrnt_vs_handler(re_list_t *instnode){
return 0;
    

}

void vrshr_vs_handler(re_list_t *instnode){
return 0;
    

}

void vsbc_vs_handler(re_list_t *instnode){
return 0;
    

}

void vsbci_vs_handler(re_list_t *instnode){
return 0;
    

}

void vshlc_vs_handler(re_list_t *instnode){
return 0;
    

}

void vshllb_vs_handler(re_list_t *instnode){
return 0;
    

}

void vshllt_vs_handler(re_list_t *instnode){
return 0;
    

}

void vshl_vs_handler(re_list_t *instnode){
return 0;
    

}

void vshrnb_vs_handler(re_list_t *instnode){
return 0;
    

}

void vshrnt_vs_handler(re_list_t *instnode){
return 0;
    

}

void vshr_vs_handler(re_list_t *instnode){
return 0;
    

}

void vsli_vs_handler(re_list_t *instnode){
return 0;
    

}

void vsri_vs_handler(re_list_t *instnode){
return 0;
    

}

void vst20_vs_handler(re_list_t *instnode){
return 0;
    

}

void vst21_vs_handler(re_list_t *instnode){
return 0;
    

}

void vst40_vs_handler(re_list_t *instnode){
return 0;
    

}

void vst41_vs_handler(re_list_t *instnode){
return 0;
    

}

void vst42_vs_handler(re_list_t *instnode){
return 0;
    

}

void vst43_vs_handler(re_list_t *instnode){
return 0;
    

}

void vstrb_vs_handler(re_list_t *instnode){
return 0;
    

}

void vstrd_vs_handler(re_list_t *instnode){
return 0;
    

}

void vstrh_vs_handler(re_list_t *instnode){
return 0;
    

}

void vstrw_vs_handler(re_list_t *instnode){
return 0;
    

}

void vsub_vs_handler(re_list_t *instnode){
return 0;
    

}

void wlstp_vs_handler(re_list_t *instnode){
return 0;
    

}

void mvn_vs_handler(re_list_t *instnode){
return 0;
    

}

void orr_vs_handler(re_list_t *instnode){
    re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	
	// traverse all the operands to fill all value set
	// (including value set and address value) of operands
	vs_traverse_inst_operand(instnode, src, dst, &nuse, &ndef);
	if (nuse != 2 || ndef != 1) {
        LOG(stdout, "NOTE orr_vs_handler: nuse = %d and ndef %d\n", nuse, ndef);
    }
	
    if (!list_empty(&CAST2_DEF(dst[0]->node)->aft_valset.list) &&
	    !list_empty(&CAST2_USE(src[0]->node)->valset.list) &&
	    !list_empty(&CAST2_USE(src[1]->node)->valset.list)) {
		return;
	}
    valset_or(&CAST2_DEF(dst[0]->node)->aft_valset,
		  &CAST2_USE(src[0]->node)->valset,
		  &CAST2_USE(src[1]->node)->valset);
}

void pkhbt_vs_handler(re_list_t *instnode){
return 0;
    

}

void pkhtb_vs_handler(re_list_t *instnode){
return 0;
    

}

void pldw_vs_handler(re_list_t *instnode){
return 0;
    

}

void pld_vs_handler(re_list_t *instnode){
return 0;
    

}

void pli_vs_handler(re_list_t *instnode){
return 0;
    

}

void qadd_vs_handler(re_list_t *instnode){
return 0;
    

}

void qadd16_vs_handler(re_list_t *instnode){
return 0;
    

}

void qadd8_vs_handler(re_list_t *instnode){
return 0;
    

}

void qasx_vs_handler(re_list_t *instnode){
return 0;
    

}

void qdadd_vs_handler(re_list_t *instnode){
return 0;
    

}

void qdsub_vs_handler(re_list_t *instnode){
return 0;
    

}

void qsax_vs_handler(re_list_t *instnode){
return 0;
    

}

void qsub_vs_handler(re_list_t *instnode){
return 0;
    

}

void qsub16_vs_handler(re_list_t *instnode){
return 0;
    

}

void qsub8_vs_handler(re_list_t *instnode){
return 0;
    

}

void rbit_vs_handler(re_list_t *instnode){
return 0;
    

}

void rev_vs_handler(re_list_t *instnode){
return 0;
    

}

void rev16_vs_handler(re_list_t *instnode){
return 0;
    

}

void revsh_vs_handler(re_list_t *instnode){
return 0;
    

}

void rfeda_vs_handler(re_list_t *instnode){
return 0;
    

}

void rfedb_vs_handler(re_list_t *instnode){
return 0;
    

}

void rfeia_vs_handler(re_list_t *instnode){
return 0;
    

}

void rfeib_vs_handler(re_list_t *instnode){
return 0;
    

}

void rsb_vs_handler(re_list_t *instnode){
return 0;
    

}

void rsc_vs_handler(re_list_t *instnode){
return 0;
    

}

void sadd16_vs_handler(re_list_t *instnode){
return 0;
    

}

void sadd8_vs_handler(re_list_t *instnode){
return 0;
    

}

void sasx_vs_handler(re_list_t *instnode){
return 0;
    

}

void sb_vs_handler(re_list_t *instnode){
return 0;
    

}

void sbc_vs_handler(re_list_t *instnode){
return 0;
    

}

void sbfx_vs_handler(re_list_t *instnode){
return 0;
    

}

void sdiv_vs_handler(re_list_t *instnode){
return 0;
    

}

void sel_vs_handler(re_list_t *instnode){
return 0;
    

}

void setend_vs_handler(re_list_t *instnode){
return 0;
    

}

void setpan_vs_handler(re_list_t *instnode){
return 0;
    

}

void sha1c_vs_handler(re_list_t *instnode){
return 0;
    

}

void sha1h_vs_handler(re_list_t *instnode){
return 0;
    

}

void sha1m_vs_handler(re_list_t *instnode){
return 0;
    

}

void sha1p_vs_handler(re_list_t *instnode){
return 0;
    

}

void sha1su0_vs_handler(re_list_t *instnode){
return 0;
    

}

void sha1su1_vs_handler(re_list_t *instnode){
return 0;
    

}

void sha256h_vs_handler(re_list_t *instnode){
return 0;
    

}

void sha256h2_vs_handler(re_list_t *instnode){
return 0;
    

}

void sha256su0_vs_handler(re_list_t *instnode){
return 0;
    

}

void sha256su1_vs_handler(re_list_t *instnode){
return 0;
    

}

void shadd16_vs_handler(re_list_t *instnode){
return 0;
    

}

void shadd8_vs_handler(re_list_t *instnode){
return 0;
    

}

void shasx_vs_handler(re_list_t *instnode){
return 0;
    

}

void shsax_vs_handler(re_list_t *instnode){
return 0;
    

}

void shsub16_vs_handler(re_list_t *instnode){
return 0;
    

}

void shsub8_vs_handler(re_list_t *instnode){
return 0;
    

}

void smc_vs_handler(re_list_t *instnode){
return 0;
    

}

void smlabb_vs_handler(re_list_t *instnode){
return 0;
    

}

void smlabt_vs_handler(re_list_t *instnode){
return 0;
    

}

void smlad_vs_handler(re_list_t *instnode){
return 0;
    

}

void smladx_vs_handler(re_list_t *instnode){
return 0;
    

}

void smlal_vs_handler(re_list_t *instnode){
return 0;
    

}

void smlalbb_vs_handler(re_list_t *instnode){
return 0;
    

}

void smlalbt_vs_handler(re_list_t *instnode){
return 0;
    

}

void smlald_vs_handler(re_list_t *instnode){
return 0;
    

}

void smlaldx_vs_handler(re_list_t *instnode){
return 0;
    

}

void smlaltb_vs_handler(re_list_t *instnode){
return 0;
    

}

void smlaltt_vs_handler(re_list_t *instnode){
return 0;
    

}

void smlatb_vs_handler(re_list_t *instnode){
return 0;
    

}

void smlatt_vs_handler(re_list_t *instnode){
return 0;
    

}

void smlawb_vs_handler(re_list_t *instnode){
return 0;
    

}

void smlawt_vs_handler(re_list_t *instnode){
return 0;
    

}

void smlsd_vs_handler(re_list_t *instnode){
return 0;
    

}

void smlsdx_vs_handler(re_list_t *instnode){
return 0;
    

}

void smlsld_vs_handler(re_list_t *instnode){
return 0;
    

}

void smlsldx_vs_handler(re_list_t *instnode){
return 0;
    

}

void smmla_vs_handler(re_list_t *instnode){
return 0;
    

}

void smmlar_vs_handler(re_list_t *instnode){
return 0;
    

}

void smmls_vs_handler(re_list_t *instnode){
return 0;
    

}

void smmlsr_vs_handler(re_list_t *instnode){
return 0;
    

}

void smmul_vs_handler(re_list_t *instnode){
return 0;
    

}

void smmulr_vs_handler(re_list_t *instnode){
return 0;
    

}

void smuad_vs_handler(re_list_t *instnode){
return 0;
    

}

void smuadx_vs_handler(re_list_t *instnode){
return 0;
    

}

void smulbb_vs_handler(re_list_t *instnode){
return 0;
    

}

void smulbt_vs_handler(re_list_t *instnode){
return 0;
    

}

void smull_vs_handler(re_list_t *instnode){
return 0;
    

}

void smultb_vs_handler(re_list_t *instnode){
return 0;
    

}

void smultt_vs_handler(re_list_t *instnode){
return 0;
    

}

void smulwb_vs_handler(re_list_t *instnode){
return 0;
    

}

void smulwt_vs_handler(re_list_t *instnode){
return 0;
    

}

void smusd_vs_handler(re_list_t *instnode){
return 0;
    

}

void smusdx_vs_handler(re_list_t *instnode){
return 0;
    

}

void srsda_vs_handler(re_list_t *instnode){
return 0;
    

}

void srsdb_vs_handler(re_list_t *instnode){
return 0;
    

}

void srsia_vs_handler(re_list_t *instnode){
return 0;
    

}

void srsib_vs_handler(re_list_t *instnode){
return 0;
    

}

void ssat_vs_handler(re_list_t *instnode){
return 0;
    

}

void ssat16_vs_handler(re_list_t *instnode){
return 0;
    

}

void ssax_vs_handler(re_list_t *instnode){
return 0;
    

}

void ssub16_vs_handler(re_list_t *instnode){
return 0;
    

}

void ssub8_vs_handler(re_list_t *instnode){
return 0;
    

}

void stc2l_vs_handler(re_list_t *instnode){
return 0;
    

}

void stc2_vs_handler(re_list_t *instnode){
return 0;
    

}

void stcl_vs_handler(re_list_t *instnode){
return 0;
    

}

void stc_vs_handler(re_list_t *instnode){
return 0;
    

}

void stl_vs_handler(re_list_t *instnode){
return 0;
    

}

void stlb_vs_handler(re_list_t *instnode){
return 0;
    

}

void stlex_vs_handler(re_list_t *instnode){
return 0;
    

}

void stlexb_vs_handler(re_list_t *instnode){
return 0;
    

}

void stlexd_vs_handler(re_list_t *instnode){
return 0;
    

}

void stlexh_vs_handler(re_list_t *instnode){
return 0;
    

}

void stlh_vs_handler(re_list_t *instnode){
return 0;
    

}

void stmda_vs_handler(re_list_t *instnode){
return 0;
    

}

void stmdb_vs_handler(re_list_t *instnode){
return 0;
    

}

void stm_vs_handler(re_list_t *instnode){
return 0;
    

}

void stmib_vs_handler(re_list_t *instnode){
return 0;
    

}

void strb_vs_handler(re_list_t *instnode){
    re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	
	// traverse all the operands to fill all value set
	// (including value set and address value) of operands
	vs_traverse_inst_operand(instnode, src, dst, &nuse, &ndef);
	if (nuse != 1 || ndef != 1) {
        LOG(stdout, "NOTE strb_vs_handler: nuse = %d and ndef %d\n", nuse, ndef);
    }
	assign_def_after_value_set_nms_bits(dst[0], &CAST2_USE(src[0]->node)->valset, 0, 8, 2);
}

void strd_vs_handler(re_list_t *instnode){
return 0;
    

}

void strex_vs_handler(re_list_t *instnode){
return 0;
    

}

void strexb_vs_handler(re_list_t *instnode){
return 0;
    

}

void strexd_vs_handler(re_list_t *instnode){
return 0;
    

}

void strexh_vs_handler(re_list_t *instnode){
return 0;
    

}

void strh_vs_handler(re_list_t *instnode){
    re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	
	// traverse all the operands to fill all value set
	// (including value set and address value) of operands
	vs_traverse_inst_operand(instnode, src, dst, &nuse, &ndef);
	if (nuse != 1 || ndef != 1) {
        LOG(stdout, "NOTE strh_vs_handler: nuse = %d and ndef %d\n", nuse, ndef);
    }
	assign_def_after_value_set_nms_bits(dst[0], &CAST2_USE(src[0]->node)->valset, 0, 16, 2);
    

}

void strht_vs_handler(re_list_t *instnode){
return 0;
    

}

void sub_vs_handler(re_list_t *instnode){
   	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	
	// traverse all the operands to fill all value set
	// (including value set and address value) of operands
	vs_traverse_inst_operand(instnode, src, dst, &nuse, &ndef);
	assert(nuse == 2 && ndef ==1);
	
	if (!list_empty(&CAST2_DEF(dst[0]->node)->aft_valset.list) &&
	    !list_empty(&CAST2_USE(src[0]->node)->valset.list) &&
	    !list_empty(&CAST2_USE(src[1]->node)->valset.list)) {
		return;
	}

	valset_sub(&CAST2_DEF(dst[0]->node)->aft_valset,
		  &CAST2_USE(src[0]->node)->valset,
		  &CAST2_USE(src[1]->node)->valset);

}

void svc_vs_handler(re_list_t *instnode){
return 0;
    

}

void swp_vs_handler(re_list_t *instnode){
return 0;
    

}

void swpb_vs_handler(re_list_t *instnode){
return 0;
    

}

void sxtab_vs_handler(re_list_t *instnode){
return 0;
    

}

void sxtab16_vs_handler(re_list_t *instnode){
return 0;
    

}

void sxtah_vs_handler(re_list_t *instnode){
return 0;
    

}

void sxtb_vs_handler(re_list_t *instnode){
return 0;
    

}

void sxtb16_vs_handler(re_list_t *instnode){
return 0;
    

}

void sxth_vs_handler(re_list_t *instnode){
return 0;
    

}

void teq_vs_handler(re_list_t *instnode){
return 0;
    

}

void trap_vs_handler(re_list_t *instnode){
return 0;
    

}

void tsb_vs_handler(re_list_t *instnode){
return 0;
    

}

void tst_vs_handler(re_list_t *instnode){
return 0;
    

}

void uadd16_vs_handler(re_list_t *instnode){
return 0;
    

}

void uadd8_vs_handler(re_list_t *instnode){
return 0;
    

}

void uasx_vs_handler(re_list_t *instnode){
return 0;
    

}

void ubfx_vs_handler(re_list_t *instnode){
return 0;
    

}

void udf_vs_handler(re_list_t *instnode){
return 0;
    

}

void udiv_vs_handler(re_list_t *instnode){
return 0;
    

}

void uhadd16_vs_handler(re_list_t *instnode){
return 0;
    

}

void uhadd8_vs_handler(re_list_t *instnode){
return 0;
    

}

void uhasx_vs_handler(re_list_t *instnode){
return 0;
    

}

void uhsax_vs_handler(re_list_t *instnode){
return 0;
    

}

void uhsub16_vs_handler(re_list_t *instnode){
return 0;
    

}

void uhsub8_vs_handler(re_list_t *instnode){
return 0;
    

}

void umaal_vs_handler(re_list_t *instnode){
return 0;
    

}

void umlal_vs_handler(re_list_t *instnode){
return 0;
    

}

void umull_vs_handler(re_list_t *instnode){
return 0;
    

}

void uqadd16_vs_handler(re_list_t *instnode){
return 0;
    

}

void uqadd8_vs_handler(re_list_t *instnode){
return 0;
    

}

void uqasx_vs_handler(re_list_t *instnode){
return 0;
    

}

void uqsax_vs_handler(re_list_t *instnode){
return 0;
    

}

void uqsub16_vs_handler(re_list_t *instnode){
return 0;
    

}

void uqsub8_vs_handler(re_list_t *instnode){
return 0;
    

}

void usad8_vs_handler(re_list_t *instnode){
return 0;
    

}

void usada8_vs_handler(re_list_t *instnode){
return 0;
    

}

void usat_vs_handler(re_list_t *instnode){
return 0;
    

}

void usat16_vs_handler(re_list_t *instnode){
return 0;
    

}

void usax_vs_handler(re_list_t *instnode){
return 0;
    

}

void usub16_vs_handler(re_list_t *instnode){
return 0;
    

}

void usub8_vs_handler(re_list_t *instnode){
return 0;
    

}

void uxtab_vs_handler(re_list_t *instnode){
return 0;
    

}

void uxtab16_vs_handler(re_list_t *instnode){
return 0;
    

}

void uxtah_vs_handler(re_list_t *instnode){
return 0;
    

}

void uxtb_vs_handler(re_list_t *instnode){
return 0;
    

}

void uxtb16_vs_handler(re_list_t *instnode){
return 0;
    

}

void uxth_vs_handler(re_list_t *instnode){
    re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	
	// traverse all the operands to fill all value set
	// (including value set and address value) of operands
	vs_traverse_inst_operand(instnode, src, dst, &nuse, &ndef);
	if (nuse != 1 || ndef != 1) {
        LOG(stdout, "NOTE uxth_vs_handler: nuse = %d and ndef %d\n", nuse, ndef);
    }
	assign_def_after_value_set_nms_bits(dst[0], &CAST2_USE(src[0]->node)->valset, 0, 16, 0);
    

}

void vabal_vs_handler(re_list_t *instnode){
return 0;
    

}

void vaba_vs_handler(re_list_t *instnode){
return 0;
    

}

void vabdl_vs_handler(re_list_t *instnode){
return 0;
    

}

void vacge_vs_handler(re_list_t *instnode){
return 0;
    

}

void vacgt_vs_handler(re_list_t *instnode){
return 0;
    

}

void vaddhn_vs_handler(re_list_t *instnode){
return 0;
    

}

void vaddl_vs_handler(re_list_t *instnode){
return 0;
    

}

void vaddw_vs_handler(re_list_t *instnode){
return 0;
    

}

void vfmab_vs_handler(re_list_t *instnode){
return 0;
    

}

void vfmat_vs_handler(re_list_t *instnode){
return 0;
    

}

void vbif_vs_handler(re_list_t *instnode){
return 0;
    

}

void vbit_vs_handler(re_list_t *instnode){
return 0;
    

}

void vbsl_vs_handler(re_list_t *instnode){
return 0;
    

}

void vceq_vs_handler(re_list_t *instnode){
return 0;
    

}

void vcge_vs_handler(re_list_t *instnode){
return 0;
    

}

void vcgt_vs_handler(re_list_t *instnode){
return 0;
    

}

void vcle_vs_handler(re_list_t *instnode){
return 0;
    

}

void vclt_vs_handler(re_list_t *instnode){
return 0;
    

}

void vcmpe_vs_handler(re_list_t *instnode){
return 0;
    

}

void vcnt_vs_handler(re_list_t *instnode){
return 0;
    

}

void vdiv_vs_handler(re_list_t *instnode){
return 0;
    

}

void vext_vs_handler(re_list_t *instnode){
return 0;
    

}

void vfmal_vs_handler(re_list_t *instnode){
return 0;
    

}

void vfmsl_vs_handler(re_list_t *instnode){
return 0;
    

}

void vfnma_vs_handler(re_list_t *instnode){
return 0;
    

}

void vfnms_vs_handler(re_list_t *instnode){
return 0;
    

}

void vins_vs_handler(re_list_t *instnode){
return 0;
    

}

void vjcvt_vs_handler(re_list_t *instnode){
return 0;
    

}

void vldmdb_vs_handler(re_list_t *instnode){
return 0;
    

}

void vldmia_vs_handler(re_list_t *instnode){
return 0;
    

}

void vldr_vs_handler(re_list_t *instnode){
return 0;
    

}

void vlldm_vs_handler(re_list_t *instnode){
return 0;
    

}

void vlstm_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmlal_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmls_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmlsl_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmmla_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmovx_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmovl_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmovn_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmsr_vs_handler(re_list_t *instnode){
return 0;
    

}

void vmull_vs_handler(re_list_t *instnode){
return 0;
    

}

void vnmla_vs_handler(re_list_t *instnode){
return 0;
    

}

void vnmls_vs_handler(re_list_t *instnode){
return 0;
    

}

void vnmul_vs_handler(re_list_t *instnode){
return 0;
    

}

void vpadal_vs_handler(re_list_t *instnode){
return 0;
    

}

void vpaddl_vs_handler(re_list_t *instnode){
return 0;
    

}

void vpadd_vs_handler(re_list_t *instnode){
return 0;
    

}

void vpmax_vs_handler(re_list_t *instnode){
return 0;
    

}

void vpmin_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqdmlal_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqdmlsl_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqdmull_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqmovun_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqmovn_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqrdmlsh_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqrshrn_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqrshrun_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqshrn_vs_handler(re_list_t *instnode){
return 0;
    

}

void vqshrun_vs_handler(re_list_t *instnode){
return 0;
    

}

void vraddhn_vs_handler(re_list_t *instnode){
return 0;
    

}

void vrecpe_vs_handler(re_list_t *instnode){
return 0;
    

}

void vrecps_vs_handler(re_list_t *instnode){
return 0;
    

}

void vrintr_vs_handler(re_list_t *instnode){
return 0;
    

}

void vrshrn_vs_handler(re_list_t *instnode){
return 0;
    

}

void vrsqrte_vs_handler(re_list_t *instnode){
return 0;
    

}

void vrsqrts_vs_handler(re_list_t *instnode){
return 0;
    

}

void vrsra_vs_handler(re_list_t *instnode){
return 0;
    

}

void vrsubhn_vs_handler(re_list_t *instnode){
return 0;
    

}

void vscclrm_vs_handler(re_list_t *instnode){
return 0;
    

}

void vsdot_vs_handler(re_list_t *instnode){
return 0;
    

}

void vseleq_vs_handler(re_list_t *instnode){
return 0;
    

}

void vselge_vs_handler(re_list_t *instnode){
return 0;
    

}

void vselgt_vs_handler(re_list_t *instnode){
return 0;
    

}

void vselvs_vs_handler(re_list_t *instnode){
return 0;
    

}

void vshll_vs_handler(re_list_t *instnode){
return 0;
    

}

void vshrn_vs_handler(re_list_t *instnode){
return 0;
    

}

void vsmmla_vs_handler(re_list_t *instnode){
return 0;
    

}

void vsqrt_vs_handler(re_list_t *instnode){
return 0;
    

}

void vsra_vs_handler(re_list_t *instnode){
return 0;
    

}

void vstmdb_vs_handler(re_list_t *instnode){
return 0;
    

}

void vstmia_vs_handler(re_list_t *instnode){
return 0;
    

}

void vstr_vs_handler(re_list_t *instnode){
return 0;
    

}

void vsubhn_vs_handler(re_list_t *instnode){
return 0;
    

}

void vsubl_vs_handler(re_list_t *instnode){
return 0;
    

}

void vsubw_vs_handler(re_list_t *instnode){
return 0;
    

}

void vsudot_vs_handler(re_list_t *instnode){
return 0;
    

}

void vswp_vs_handler(re_list_t *instnode){
return 0;
    

}

void vtbl_vs_handler(re_list_t *instnode){
return 0;
    

}

void vtbx_vs_handler(re_list_t *instnode){
return 0;
    

}

void vcvtr_vs_handler(re_list_t *instnode){
return 0;
    

}

void vtrn_vs_handler(re_list_t *instnode){
return 0;
    

}

void vtst_vs_handler(re_list_t *instnode){
return 0;
    

}

void vudot_vs_handler(re_list_t *instnode){
return 0;
    

}

void vummla_vs_handler(re_list_t *instnode){
return 0;
    

}

void vusdot_vs_handler(re_list_t *instnode){
return 0;
    

}

void vusmmla_vs_handler(re_list_t *instnode){
return 0;
    

}

void vuzp_vs_handler(re_list_t *instnode){
return 0;
    

}

void vzip_vs_handler(re_list_t *instnode){
return 0;
    

}

void addw_vs_handler(re_list_t *instnode){
return 0;
    

}

void aut_vs_handler(re_list_t *instnode){
return 0;
    

}

void autg_vs_handler(re_list_t *instnode){
return 0;
    

}

void bfl_vs_handler(re_list_t *instnode){
return 0;
    

}

void bflx_vs_handler(re_list_t *instnode){
return 0;
    

}

void bf_vs_handler(re_list_t *instnode){
return 0;
    

}

void bfcsel_vs_handler(re_list_t *instnode){
return 0;
    

}

void bfx_vs_handler(re_list_t *instnode){
return 0;
    

}

void bti_vs_handler(re_list_t *instnode){
return 0;
    

}

void bxaut_vs_handler(re_list_t *instnode){
return 0;
    

}

void clrm_vs_handler(re_list_t *instnode){
return 0;
    

}

void csel_vs_handler(re_list_t *instnode){
return 0;
    

}

void csinc_vs_handler(re_list_t *instnode){
return 0;
    

}

void csinv_vs_handler(re_list_t *instnode){
return 0;
    

}

void csneg_vs_handler(re_list_t *instnode){
return 0;
    

}

void dcps1_vs_handler(re_list_t *instnode){
return 0;
    

}

void dcps2_vs_handler(re_list_t *instnode){
return 0;
    

}

void dcps3_vs_handler(re_list_t *instnode){
return 0;
    

}

void dls_vs_handler(re_list_t *instnode){
return 0;
    

}

void le_vs_handler(re_list_t *instnode){
return 0;
    

}

void orn_vs_handler(re_list_t *instnode){
return 0;
    

}

void pac_vs_handler(re_list_t *instnode){
return 0;
    

}

void pacbti_vs_handler(re_list_t *instnode){
return 0;
    

}

void pacg_vs_handler(re_list_t *instnode){
return 0;
    

}

void sg_vs_handler(re_list_t *instnode){
return 0;
    

}

void subs_vs_handler(re_list_t *instnode){
return 0;
    

}

void subw_vs_handler(re_list_t *instnode){
return 0;
    

}

void tbb_vs_handler(re_list_t *instnode){
return 0;
    

}

void tbh_vs_handler(re_list_t *instnode){
return 0;
    

}

void tt_vs_handler(re_list_t *instnode){
return 0;
    

}

void tta_vs_handler(re_list_t *instnode){
return 0;
    

}

void ttat_vs_handler(re_list_t *instnode){
return 0;
    

}

void ttt_vs_handler(re_list_t *instnode){
return 0;
    

}

void wls_vs_handler(re_list_t *instnode){
return 0;
    

}

void blxns_vs_handler(re_list_t *instnode){
return 0;
    

}

void bxns_vs_handler(re_list_t *instnode){
return 0;
    

}

void cbnz_vs_handler(re_list_t *instnode){
return 0;
    

}

void cbz_vs_handler(re_list_t *instnode){
return 0;
    

}

void pop_vs_handler(re_list_t *instnode){
    re_list_t *entry;
    re_list_t *dst[NOPD], *src[NOPD];
    int nuse, ndef;
    re_value_set head;
    
    INIT_LIST_HEAD(&head.list);

    vs_traverse_inst_operand(instnode, src, dst, &nuse, &ndef);

    // update sp value set
    for (int i = 1; i < ndef; i+=2) {
        valset_add_offset(&CAST2_DEF(dst[i]->node)->aft_valset,
		   &CAST2_DEF(dst[i]->node)->bef_valset,
		   ADDR_SIZE_IN_BYTE);
    }

    // update stack value set
    for (int i = 0; i < ndef; i+=2) {
        assign_def_after_value_set(dst[i], &CAST2_USE(src[i/2]->node)->valset);
    }
}

void push_vs_handler(re_list_t *instnode){
    re_list_t *entry;
    re_list_t *dst[NOPD], *src[NOPD];
    int nuse, ndef;
    re_value_set head;
    
    INIT_LIST_HEAD(&head.list);

    vs_traverse_inst_operand(instnode, src, dst, &nuse, &ndef);

    // update sp value set
    for (int i = 1; i < ndef; i+=2) {
        valset_add_offset(&CAST2_DEF(dst[i]->node)->aft_valset,
		   &CAST2_DEF(dst[i]->node)->bef_valset,
		   -ADDR_SIZE_IN_BYTE);
    }
    // handle all use
    for (int i = 0; i < nuse; i++) {
        fork_value_set(&head, &CAST2_USE(src[i]->node)->valset);
        if (CAST2_USE(src[i]->node)->operand->type == ARM_OP_IMM) {
            sign_extend_value_set(&head, arm_get_datatype(CAST2_USE(src[i]->node)->inst));
        }
	}

    // update stack value set
    for (int i = 0; i < ndef; i+=2) {
        assign_def_after_value_set(dst[i], &head);
    }
    vs_traverse_inst_operand(instnode, src, dst, &nuse, &ndef);
}


void brkdiv0_vs_handler(re_list_t *instnode){
return 0;
    

}

void vpop_vs_handler(re_list_t *instnode){
return 0;
    

}

void vpush_vs_handler(re_list_t *instnode){
return 0;
    

}
#endif
#endif
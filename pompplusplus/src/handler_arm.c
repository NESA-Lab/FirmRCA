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
    LOG(stdout, "Please fill invalid_resolver \n");
}

void asr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill asr_resolver \n");
}

void it_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill it_resolver \n");
}

void ldrbt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill ldrbt_resolver \n");
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
    LOG(stdout, "Please fill ldrht_resolver \n");
}

void ldrsbt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill ldrsbt_resolver \n");
}

void ldrsht_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill ldrsht_resolver \n");
}

void ldrt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill ldrt_resolver \n");
}

void lsl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill lsl_resolver \n");
}

void lsr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill lsr_resolver \n");
}

void ror_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill ror_resolver \n");
}

void rrx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill rrx_resolver \n");
}

void strbt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill strbt_resolver \n");
}

void strt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill strt_resolver \n");
}

void vld1_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vld1_resolver \n");
}

void vld2_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vld2_resolver \n");
}

void vld3_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vld3_resolver \n");
}

void vld4_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vld4_resolver \n");
}

void vst1_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vst1_resolver \n");
}

void vst2_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vst2_resolver \n");
}

void vst3_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vst3_resolver \n");
}

void vst4_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vst4_resolver \n");
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
    
    // note hard
    // if (!CAST2_USE(src[0]->node)->val_known &&
    //      (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
    //         vt = CAST2_DEF(dst[0]->node)->afterval;
    //         assign_use_value(src[0],vt);
    //         add_to_uselist(src[0], re_uselist);
    //      }
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
    
    // note hard
    // if (!CAST2_USE(src[0]->node)->val_known &&
    //      (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
    //         vt = CAST2_DEF(dst[0]->node)->afterval;
    //         assign_use_value(src[0],vt);
    //         add_to_uselist(src[0], re_uselist);
    //      }
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
    
    // note hard
    // if (!CAST2_USE(src[0]->node)->val_known &&
    //      (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
    //         vt = CAST2_DEF(dst[0]->node)->afterval;
    //         assign_use_value(src[0],vt);
    //         add_to_uselist(src[0], re_uselist);
    //      }
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
    
    // note hard
    // if (!CAST2_USE(src[0]->node)->val_known &&
    //      (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
    //         vt = CAST2_DEF(dst[0]->node)->afterval;
    //         assign_use_value(src[0],vt);
    //         add_to_uselist(src[0], re_uselist);
    //      }
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
    LOG(stdout, "Please fill adc_resolver \n");
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
    LOG(stdout, "Please fill adr_resolver \n");
}

void aesd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill aesd_resolver \n");
}

void aese_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill aese_resolver \n");
}

void aesimc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill aesimc_resolver \n");
}

void aesmc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill aesmc_resolver \n");
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
    LOG(stdout, "Please fill vdot_resolver \n");
}

void vcvt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vcvt_resolver \n");
}

void vcvtb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vcvtb_resolver \n");
}

void vcvtt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vcvtt_resolver \n");
}

void bfc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill bfc_resolver \n");
}

void bfi_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill bfi_resolver \n");
}

void bic_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill bic_resolver \n");
}

void bkpt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill bkpt_resolver \n");
}

void bl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill bl_resolver \n");
}

void blx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill blx_resolver \n");
}

void bx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill bx_resolver \n");
}

void bxj_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill bxj_resolver \n");
}

void b_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill b_resolver \n");
}

void cx1_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill cx1_resolver \n");
}

void cx1a_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill cx1a_resolver \n");
}

void cx1d_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill cx1d_resolver \n");
}

void cx1da_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill cx1da_resolver \n");
}

void cx2_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill cx2_resolver \n");
}

void cx2a_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill cx2a_resolver \n");
}

void cx2d_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill cx2d_resolver \n");
}

void cx2da_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill cx2da_resolver \n");
}

void cx3_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill cx3_resolver \n");
}

void cx3a_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill cx3a_resolver \n");
}

void cx3d_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill cx3d_resolver \n");
}

void cx3da_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill cx3da_resolver \n");
}

void vcx1a_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vcx1a_resolver \n");
}

void vcx1_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vcx1_resolver \n");
}

void vcx2a_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vcx2a_resolver \n");
}

void vcx2_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vcx2_resolver \n");
}

void vcx3a_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vcx3a_resolver \n");
}

void vcx3_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vcx3_resolver \n");
}

void cdp_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill cdp_resolver \n");
}

void cdp2_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill cdp2_resolver \n");
}

void clrex_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill clrex_resolver \n");
}

void clz_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill clz_resolver \n");
}

void cmn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill cmn_resolver \n");
}

void cmp_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill cmp_resolver \n");
}

void cps_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill cps_resolver \n");
}

void crc32b_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill crc32b_resolver \n");
}

void crc32cb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill crc32cb_resolver \n");
}

void crc32ch_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill crc32ch_resolver \n");
}

void crc32cw_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill crc32cw_resolver \n");
}

void crc32h_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill crc32h_resolver \n");
}

void crc32w_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill crc32w_resolver \n");
}

void dbg_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill dbg_resolver \n");
}

void dmb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill dmb_resolver \n");
}

void dsb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill dsb_resolver \n");
}

void eor_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	valset_u  vt = {0};

    traverse_inst_operand(inst, src, dst, re_uselist, re_deflist, &nuse, &ndef);

    LOG(stdout, "eor_resolver: nuse = %d, ndef = %d\n", nuse, ndef);
    assert(nuse == 2 && ndef == 1);// note for eor r1, r1; nuse = 1?

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
    LOG(stdout, "Please fill eret_resolver \n");
}

void vmov_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmov_resolver \n");
}

void fldmdbx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill fldmdbx_resolver \n");
}

void fldmiax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill fldmiax_resolver \n");
}

void vmrs_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmrs_resolver \n");
}

void fstmdbx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill fstmdbx_resolver \n");
}

void fstmiax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill fstmiax_resolver \n");
}

void hint_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill hint_resolver \n");
}

void hlt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill hlt_resolver \n");
}

void hvc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill hvc_resolver \n");
}

void isb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill isb_resolver \n");
}

void lda_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill lda_resolver \n");
}

void ldab_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill ldab_resolver \n");
}

void ldaex_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill ldaex_resolver \n");
}

void ldaexb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill ldaexb_resolver \n");
}

void ldaexd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill ldaexd_resolver \n");
}

void ldaexh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill ldaexh_resolver \n");
}

void ldah_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill ldah_resolver \n");
}

void ldc2l_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill ldc2l_resolver \n");
}

void ldc2_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill ldc2_resolver \n");
}

void ldcl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill ldcl_resolver \n");
}

void ldc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill ldc_resolver \n");
}

void ldmda_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill ldmda_resolver \n");
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
    LOG(stdout, "Please fill ldmib_resolver \n");
}

void ldrd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill ldrd_resolver \n");
}

void ldrex_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill ldrex_resolver \n");
}

void ldrexb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill ldrexb_resolver \n");
}

void ldrexd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill ldrexd_resolver \n");
}

void ldrexh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill ldrexh_resolver \n");
}

void mcr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill mcr_resolver \n");
}

void mcr2_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill mcr2_resolver \n");
}

void mcrr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill mcrr_resolver \n");
}

void mcrr2_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill mcrr2_resolver \n");
}

void mla_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill mla_resolver \n");
}

void mls_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill mls_resolver \n");
}

void movt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill movt_resolver \n");
}

void movw_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill movw_resolver \n");
}

void mrc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill mrc_resolver \n");
}

void mrc2_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill mrc2_resolver \n");
}

void mrrc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill mrrc_resolver \n");
}

void mrrc2_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill mrrc2_resolver \n");
}

void mrs_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill mrs_resolver \n");
}

void msr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill msr_resolver \n");
}

void mul_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill mul_resolver \n");
}

void asrl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill asrl_resolver \n");
}

void dlstp_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill dlstp_resolver \n");
}

void lctp_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill lctp_resolver \n");
}

void letp_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill letp_resolver \n");
}

void lsll_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill lsll_resolver \n");
}

void lsrl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill lsrl_resolver \n");
}

void sqrshr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill sqrshr_resolver \n");
}

void sqrshrl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill sqrshrl_resolver \n");
}

void sqshl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill sqshl_resolver \n");
}

void sqshll_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill sqshll_resolver \n");
}

void srshr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill srshr_resolver \n");
}

void srshrl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill srshrl_resolver \n");
}

void uqrshl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill uqrshl_resolver \n");
}

void uqrshll_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill uqrshll_resolver \n");
}

void uqshl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill uqshl_resolver \n");
}

void uqshll_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill uqshll_resolver \n");
}

void urshr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill urshr_resolver \n");
}

void urshrl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill urshrl_resolver \n");
}

void vabav_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vabav_resolver \n");
}

void vabd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vabd_resolver \n");
}

void vabs_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vabs_resolver \n");
}

void vadc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vadc_resolver \n");
}

void vadci_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vadci_resolver \n");
}

void vaddlva_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vaddlva_resolver \n");
}

void vaddlv_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vaddlv_resolver \n");
}

void vaddva_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vaddva_resolver \n");
}

void vaddv_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vaddv_resolver \n");
}

void vadd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vadd_resolver \n");
}

void vand_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vand_resolver \n");
}

void vbic_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vbic_resolver \n");
}

void vbrsr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vbrsr_resolver \n");
}

void vcadd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vcadd_resolver \n");
}

void vcls_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vcls_resolver \n");
}

void vclz_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vclz_resolver \n");
}

void vcmla_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vcmla_resolver \n");
}

void vcmp_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vcmp_resolver \n");
}

void vcmul_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vcmul_resolver \n");
}

void vctp_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vctp_resolver \n");
}

void vcvta_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vcvta_resolver \n");
}

void vcvtm_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vcvtm_resolver \n");
}

void vcvtn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vcvtn_resolver \n");
}

void vcvtp_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vcvtp_resolver \n");
}

void vddup_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vddup_resolver \n");
}

void vdup_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vdup_resolver \n");
}

void vdwdup_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vdwdup_resolver \n");
}

void veor_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill veor_resolver \n");
}

void vfmas_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vfmas_resolver \n");
}

void vfma_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vfma_resolver \n");
}

void vfms_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vfms_resolver \n");
}

void vhadd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vhadd_resolver \n");
}

void vhcadd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vhcadd_resolver \n");
}

void vhsub_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vhsub_resolver \n");
}

void vidup_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vidup_resolver \n");
}

void viwdup_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill viwdup_resolver \n");
}

void vld20_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vld20_resolver \n");
}

void vld21_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vld21_resolver \n");
}

void vld40_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vld40_resolver \n");
}

void vld41_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vld41_resolver \n");
}

void vld42_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vld42_resolver \n");
}

void vld43_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vld43_resolver \n");
}

void vldrb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vldrb_resolver \n");
}

void vldrd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vldrd_resolver \n");
}

void vldrh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vldrh_resolver \n");
}

void vldrw_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vldrw_resolver \n");
}

void vmaxav_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmaxav_resolver \n");
}

void vmaxa_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmaxa_resolver \n");
}

void vmaxnmav_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmaxnmav_resolver \n");
}

void vmaxnma_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmaxnma_resolver \n");
}

void vmaxnmv_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmaxnmv_resolver \n");
}

void vmaxnm_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmaxnm_resolver \n");
}

void vmaxv_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmaxv_resolver \n");
}

void vmax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmax_resolver \n");
}

void vminav_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vminav_resolver \n");
}

void vmina_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmina_resolver \n");
}

void vminnmav_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vminnmav_resolver \n");
}

void vminnma_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vminnma_resolver \n");
}

void vminnmv_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vminnmv_resolver \n");
}

void vminnm_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vminnm_resolver \n");
}

void vminv_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vminv_resolver \n");
}

void vmin_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmin_resolver \n");
}

void vmladava_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmladava_resolver \n");
}

void vmladavax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmladavax_resolver \n");
}

void vmladav_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmladav_resolver \n");
}

void vmladavx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmladavx_resolver \n");
}

void vmlaldava_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmlaldava_resolver \n");
}

void vmlaldavax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmlaldavax_resolver \n");
}

void vmlaldav_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmlaldav_resolver \n");
}

void vmlaldavx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmlaldavx_resolver \n");
}

void vmlas_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmlas_resolver \n");
}

void vmla_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmla_resolver \n");
}

void vmlsdava_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmlsdava_resolver \n");
}

void vmlsdavax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmlsdavax_resolver \n");
}

void vmlsdav_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmlsdav_resolver \n");
}

void vmlsdavx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmlsdavx_resolver \n");
}

void vmlsldava_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmlsldava_resolver \n");
}

void vmlsldavax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmlsldavax_resolver \n");
}

void vmlsldav_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmlsldav_resolver \n");
}

void vmlsldavx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmlsldavx_resolver \n");
}

void vmovlb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmovlb_resolver \n");
}

void vmovlt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmovlt_resolver \n");
}

void vmovnb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmovnb_resolver \n");
}

void vmovnt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmovnt_resolver \n");
}

void vmulh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmulh_resolver \n");
}

void vmullb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmullb_resolver \n");
}

void vmullt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmullt_resolver \n");
}

void vmul_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmul_resolver \n");
}

void vmvn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmvn_resolver \n");
}

void vneg_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vneg_resolver \n");
}

void vorn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vorn_resolver \n");
}

void vorr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vorr_resolver \n");
}

void vpnot_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vpnot_resolver \n");
}

void vpsel_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vpsel_resolver \n");
}

void vpst_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vpst_resolver \n");
}

void vpt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vpt_resolver \n");
}

void vqabs_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqabs_resolver \n");
}

void vqadd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqadd_resolver \n");
}

void vqdmladhx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqdmladhx_resolver \n");
}

void vqdmladh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqdmladh_resolver \n");
}

void vqdmlah_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqdmlah_resolver \n");
}

void vqdmlash_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqdmlash_resolver \n");
}

void vqdmlsdhx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqdmlsdhx_resolver \n");
}

void vqdmlsdh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqdmlsdh_resolver \n");
}

void vqdmulh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqdmulh_resolver \n");
}

void vqdmullb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqdmullb_resolver \n");
}

void vqdmullt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqdmullt_resolver \n");
}

void vqmovnb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqmovnb_resolver \n");
}

void vqmovnt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqmovnt_resolver \n");
}

void vqmovunb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqmovunb_resolver \n");
}

void vqmovunt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqmovunt_resolver \n");
}

void vqneg_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqneg_resolver \n");
}

void vqrdmladhx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqrdmladhx_resolver \n");
}

void vqrdmladh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqrdmladh_resolver \n");
}

void vqrdmlah_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqrdmlah_resolver \n");
}

void vqrdmlash_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqrdmlash_resolver \n");
}

void vqrdmlsdhx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqrdmlsdhx_resolver \n");
}

void vqrdmlsdh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqrdmlsdh_resolver \n");
}

void vqrdmulh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqrdmulh_resolver \n");
}

void vqrshl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqrshl_resolver \n");
}

void vqrshrnb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqrshrnb_resolver \n");
}

void vqrshrnt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqrshrnt_resolver \n");
}

void vqrshrunb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqrshrunb_resolver \n");
}

void vqrshrunt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqrshrunt_resolver \n");
}

void vqshlu_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqshlu_resolver \n");
}

void vqshl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqshl_resolver \n");
}

void vqshrnb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqshrnb_resolver \n");
}

void vqshrnt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqshrnt_resolver \n");
}

void vqshrunb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqshrunb_resolver \n");
}

void vqshrunt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqshrunt_resolver \n");
}

void vqsub_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqsub_resolver \n");
}

void vrev16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vrev16_resolver \n");
}

void vrev32_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vrev32_resolver \n");
}

void vrev64_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vrev64_resolver \n");
}

void vrhadd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vrhadd_resolver \n");
}

void vrinta_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vrinta_resolver \n");
}

void vrintm_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vrintm_resolver \n");
}

void vrintn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vrintn_resolver \n");
}

void vrintp_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vrintp_resolver \n");
}

void vrintx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vrintx_resolver \n");
}

void vrintz_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vrintz_resolver \n");
}

void vrmlaldavha_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vrmlaldavha_resolver \n");
}

void vrmlaldavhax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vrmlaldavhax_resolver \n");
}

void vrmlaldavh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vrmlaldavh_resolver \n");
}

void vrmlaldavhx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vrmlaldavhx_resolver \n");
}

void vrmlsldavha_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vrmlsldavha_resolver \n");
}

void vrmlsldavhax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vrmlsldavhax_resolver \n");
}

void vrmlsldavh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vrmlsldavh_resolver \n");
}

void vrmlsldavhx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vrmlsldavhx_resolver \n");
}

void vrmulh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vrmulh_resolver \n");
}

void vrshl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vrshl_resolver \n");
}

void vrshrnb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vrshrnb_resolver \n");
}

void vrshrnt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vrshrnt_resolver \n");
}

void vrshr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vrshr_resolver \n");
}

void vsbc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vsbc_resolver \n");
}

void vsbci_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vsbci_resolver \n");
}

void vshlc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vshlc_resolver \n");
}

void vshllb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vshllb_resolver \n");
}

void vshllt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vshllt_resolver \n");
}

void vshl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vshl_resolver \n");
}

void vshrnb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vshrnb_resolver \n");
}

void vshrnt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vshrnt_resolver \n");
}

void vshr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vshr_resolver \n");
}

void vsli_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vsli_resolver \n");
}

void vsri_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vsri_resolver \n");
}

void vst20_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vst20_resolver \n");
}

void vst21_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vst21_resolver \n");
}

void vst40_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vst40_resolver \n");
}

void vst41_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vst41_resolver \n");
}

void vst42_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vst42_resolver \n");
}

void vst43_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vst43_resolver \n");
}

void vstrb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vstrb_resolver \n");
}

void vstrd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vstrd_resolver \n");
}

void vstrh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vstrh_resolver \n");
}

void vstrw_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vstrw_resolver \n");
}

void vsub_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vsub_resolver \n");
}

void wlstp_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill wlstp_resolver \n");
}

void mvn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill mvn_resolver \n");
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
    LOG(stdout, "Please fill pkhbt_resolver\n");
}

void pkhtb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill pkhtb_resolver\n");
}

void pldw_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill pldw_resolver\n");
}

void pld_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill pld_resolver\n");
}

void pli_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill pli_resolver\n");
}

void qadd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill qadd_resolver\n");
}

void qadd16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill qadd16_resolver\n");
}

void qadd8_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill qadd8_resolver\n");
}

void qasx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill qasx_resolver\n");
}

void qdadd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill qdadd_resolver\n");
}

void qdsub_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill qdsub_resolver\n");
}

void qsax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill qsax_resolver\n");
}

void qsub_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill qsub_resolver\n");
}

void qsub16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill qsub16_resolver\n");
}

void qsub8_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill qsub8_resolver\n");
}

void rbit_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill rbit_resolver\n");
}

void rev_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill rev_resolver\n");
}

void rev16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill rev16_resolver\n");
}

void revsh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill revsh_resolver\n");
}

void rfeda_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill rfeda_resolver\n");
}

void rfedb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill rfedb_resolver\n");
}

void rfeia_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill rfeia_resolver\n");
}

void rfeib_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill rfeib_resolver\n");
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
    LOG(stdout, "Please fill rsc_resolver\n");
}

void sadd16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill sadd16_resolver\n");
}

void sadd8_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill sadd8_resolver\n");
}

void sasx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill sasx_resolver\n");
}

void sb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill sb_resolver\n");
}

void sbc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill sbc_resolver\n");
}

void sbfx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill sbfx_resolver\n");
}

void sdiv_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill sdiv_resolver\n");
}

void sel_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill sel_resolver\n");
}

void setend_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill setend_resolver\n");
}

void setpan_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill setpan_resolver\n");
}

void sha1c_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill sha1c_resolver\n");
}

void sha1h_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill sha1h_resolver\n");
}

void sha1m_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill sha1m_resolver\n");
}

void sha1p_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill sha1p_resolver\n");
}

void sha1su0_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill sha1su0_resolver\n");
}

void sha1su1_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill sha1su1_resolver\n");
}

void sha256h_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill sha256h_resolver\n");
}

void sha256h2_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill sha256h2_resolver\n");
}

void sha256su0_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill sha256su0_resolver\n");
}

void sha256su1_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill sha256su1_resolver\n");
}

void shadd16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill shadd16_resolver\n");
}

void shadd8_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill shadd8_resolver\n");
}

void shasx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill shasx_resolver\n");
}

void shsax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill shsax_resolver\n");
}

void shsub16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill shsub16_resolver\n");
}

void shsub8_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill shsub8_resolver\n");
}

void smc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill smc_resolver\n");
}

void smlabb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill smlabb_resolver\n");
}

void smlabt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill smlabt_resolver\n");
}

void smlad_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill smlad_resolver\n");
}

void smladx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill smladx_resolver\n");
}

void smlal_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill smlal_resolver\n");
}

void smlalbb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill smlalbb_resolver\n");
}

void smlalbt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill smlalbt_resolver\n");
}

void smlald_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill smlald_resolver\n");
}

void smlaldx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill smlaldx_resolver\n");
}

void smlaltb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill smlaltb_resolver\n");
}

void smlaltt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill smlaltt_resolver\n");
}

void smlatb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill smlatb_resolver\n");
}

void smlatt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill smlatt_resolver\n");
}

void smlawb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill smlawb_resolver\n");
}

void smlawt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill smlawt_resolver\n");
}

void smlsd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill smlsd_resolver\n");
}

void smlsdx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill smlsdx_resolver\n");
}

void smlsld_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill smlsld_resolver\n");
}

void smlsldx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill smlsldx_resolver\n");
}

void smmla_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill smmla_resolver\n");
}

void smmlar_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill smmlar_resolver\n");
}

void smmls_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill smmls_resolver\n");
}

void smmlsr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill smmlsr_resolver\n");
}

void smmul_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill smmul_resolver\n");
}

void smmulr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill smmulr_resolver\n");
}

void smuad_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill smuad_resolver\n");
}

void smuadx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill smuadx_resolver\n");
}

void smulbb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill smulbb_resolver\n");
}

void smulbt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill smulbt_resolver\n");
}

void smull_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill smull_resolver\n");
}

void smultb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill smultb_resolver\n");
}

void smultt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill smultt_resolver\n");
}

void smulwb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill smulwb_resolver\n");
}

void smulwt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill smulwt_resolver\n");
}

void smusd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill smusd_resolver\n");
}

void smusdx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill smusdx_resolver\n");
}

void srsda_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill srsda_resolver\n");
}

void srsdb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill srsdb_resolver\n");
}

void srsia_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill srsia_resolver\n");
}

void srsib_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill srsib_resolver\n");
}

void ssat_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill ssat_resolver\n");
}

void ssat16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill ssat16_resolver\n");
}

void ssax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill ssax_resolver\n");
}

void ssub16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill ssub16_resolver\n");
}

void ssub8_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill ssub8_resolver\n");
}

void stc2l_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill stc2l_resolver\n");
}

void stc2_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill stc2_resolver\n");
}

void stcl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill stcl_resolver\n");
}

void stc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill stc_resolver\n");
}

void stl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill stl_resolver\n");
}

void stlb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill stlb_resolver\n");
}

void stlex_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill stlex_resolver\n");
}

void stlexb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill stlexb_resolver\n");
}

void stlexd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill stlexd_resolver\n");
}

void stlexh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill stlexh_resolver\n");
}

void stlh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill stlh_resolver\n");
}

void stmda_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill stmda_resolver\n");
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
    LOG(stdout, "Please fill stmib_resolver\n");
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
    
    // note hard to recover source from destination?
    // if (!CAST2_USE(src[0]->node)->val_known &&
    //      (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
    //         vt = CAST2_DEF(dst[0]->node)->afterval;
    //         assign_use_value(src[0],vt);
    //         add_to_uselist(src[0], re_uselist);
    //      }
    
}

void strd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill strd_resolver\n");
}

void strex_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill strex_resolver\n");
}

void strexb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill strexb_resolver\n");
}

void strexd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill strexd_resolver\n");
}

void strexh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill strexh_resolver\n");
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


    // note hard to recover source from destination?
    // if (!CAST2_USE(src[0]->node)->val_known &&
    //      (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
    //         vt = CAST2_DEF(dst[0]->node)->afterval;
    //         assign_use_value(src[0],vt);
    //         add_to_uselist(src[0], re_uselist);
    //      }
}

void strht_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill strht_resolver\n");
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
    LOG(stdout, "Please fill svc_resolver\n");
}

void swp_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill swp_resolver\n");
}

void swpb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill swpb_resolver\n");
}

void sxtab_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill sxtab_resolver\n");
}

void sxtab16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill sxtab16_resolver\n");
}

void sxtah_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill sxtah_resolver\n");
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
    
    // note hard to recover source?
    // if (!CAST2_USE(src[0]->node)->val_known &&
    //      (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
    //         vt = CAST2_DEF(dst[0]->node)->afterval;
    //         assign_use_value(src[0],vt);
    //         add_to_uselist(src[0], re_uselist);
    //      }
        
}

void sxtb16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill sxtb16_resolver\n");
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
    
    // note hard to recover source?
    // if (!CAST2_USE(src[0]->node)->val_known &&
    //      (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
    //         vt = CAST2_DEF(dst[0]->node)->afterval;
    //         assign_use_value(src[0],vt);
    //         add_to_uselist(src[0], re_uselist);
    //      }
}

void teq_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill teq_resolver\n");
}

void trap_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill trap_resolver\n");
}

void tsb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill tsb_resolver\n");
}

void tst_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill tst_resolver\n");
}

void uadd16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill uadd16_resolver\n");
}

void uadd8_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill uadd8_resolver\n");
}

void uasx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill uasx_resolver\n");
}

void ubfx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill ubfx_resolver\n");
}

void udf_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill udf_resolver\n");
}

void udiv_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill udiv_resolver\n");
}

void uhadd16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill uhadd16_resolver\n");
}

void uhadd8_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill uhadd8_resolver\n");
}

void uhasx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill uhasx_resolver\n");
}

void uhsax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill uhsax_resolver\n");
}

void uhsub16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill uhsub16_resolver\n");
}

void uhsub8_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill uhsub8_resolver\n");
}

void umaal_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill umaal_resolver\n");
}

void umlal_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill umlal_resolver\n");
}

void umull_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill umull_resolver\n");
}

void uqadd16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill uqadd16_resolver\n");
}

void uqadd8_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill uqadd8_resolver\n");
}

void uqasx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill uqasx_resolver\n");
}

void uqsax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill uqsax_resolver\n");
}

void uqsub16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill uqsub16_resolver\n");
}

void uqsub8_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill uqsub8_resolver\n");
}

void usad8_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill usad8_resolver\n");
}

void usada8_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill usada8_resolver\n");
}

void usat_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill usat_resolver\n");
}

void usat16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill usat16_resolver\n");
}

void usax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill usax_resolver\n");
}

void usub16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill usub16_resolver\n");
}

void usub8_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill usub8_resolver\n");
}

void uxtab_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill uxtab_resolver\n");
}

void uxtab16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill uxtab16_resolver\n");
}

void uxtah_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill uxtah_resolver\n");
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
    
    // note hard to recover source?
    // if (!CAST2_USE(src[0]->node)->val_known &&
    //      (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
    //         vt = CAST2_DEF(dst[0]->node)->afterval;
    //         assign_use_value(src[0],vt);
    //         add_to_uselist(src[0], re_uselist);
    //      }
        
}

void uxtb16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill uxtb16_resolver\n");
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
    
    // note hard to recover source?
    // if (!CAST2_USE(src[0]->node)->val_known &&
    //      (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
    //         vt = CAST2_DEF(dst[0]->node)->afterval;
    //         assign_use_value(src[0],vt);
    //         add_to_uselist(src[0], re_uselist);
    //      }
}

void vabal_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vabal_resolver\n");
}

void vaba_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vaba_resolver\n");
}

void vabdl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vabdl_resolver\n");
}

void vacge_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vacge_resolver\n");
}

void vacgt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vacgt_resolver\n");
}

void vaddhn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vaddhn_resolver\n");
}

void vaddl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vaddl_resolver\n");
}

void vaddw_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vaddw_resolver\n");
}

void vfmab_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vfmab_resolver\n");
}

void vfmat_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vfmat_resolver\n");
}

void vbif_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vbif_resolver\n");
}

void vbit_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vbit_resolver\n");
}

void vbsl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vbsl_resolver\n");
}

void vceq_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vceq_resolver\n");
}

void vcge_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vcge_resolver\n");
}

void vcgt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vcgt_resolver\n");
}

void vcle_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vcle_resolver\n");
}

void vclt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vclt_resolver\n");
}

void vcmpe_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vcmpe_resolver\n");
}

void vcnt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vcnt_resolver\n");
}

void vdiv_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vdiv_resolver\n");
}

void vext_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vext_resolver\n");
}

void vfmal_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vfmal_resolver\n");
}

void vfmsl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vfmsl_resolver\n");
}

void vfnma_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vfnma_resolver\n");
}

void vfnms_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vfnms_resolver\n");
}

void vins_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vins_resolver\n");
}

void vjcvt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vjcvt_resolver\n");
}

void vldmdb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vldmdb_resolver\n");
}

void vldmia_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vldmia_resolver\n");
}

void vldr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vldr_resolver\n");
}

void vlldm_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vlldm_resolver\n");
}

void vlstm_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vlstm_resolver\n");
}

void vmlal_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmlal_resolver\n");
}

void vmls_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmls_resolver\n");
}

void vmlsl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmlsl_resolver\n");
}

void vmmla_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmmla_resolver\n");
}

void vmovx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmovx_resolver\n");
}

void vmovl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmovl_resolver\n");
}

void vmovn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmovn_resolver\n");
}

void vmsr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmsr_resolver\n");
}

void vmull_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vmull_resolver\n");
}

void vnmla_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vnmla_resolver\n");
}

void vnmls_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vnmls_resolver\n");
}

void vnmul_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vnmul_resolver\n");
}

void vpadal_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vpadal_resolver\n");
}

void vpaddl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vpaddl_resolver\n");
}

void vpadd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vpadd_resolver\n");
}

void vpmax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vpmax_resolver\n");
}

void vpmin_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vpmin_resolver\n");
}

void vqdmlal_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqdmlal_resolver\n");
}

void vqdmlsl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqdmlsl_resolver\n");
}

void vqdmull_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqdmull_resolver\n");
}

void vqmovun_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqmovun_resolver\n");
}

void vqmovn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqmovn_resolver\n");
}

void vqrdmlsh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqrdmlsh_resolver\n");
}

void vqrshrn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqrshrn_resolver\n");
}

void vqrshrun_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqrshrun_resolver\n");
}

void vqshrn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqshrn_resolver\n");
}

void vqshrun_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vqshrun_resolver\n");
}

void vraddhn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vraddhn_resolver\n");
}

void vrecpe_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vrecpe_resolver\n");
}

void vrecps_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vrecps_resolver\n");
}

void vrintr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vrintr_resolver\n");
}

void vrshrn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vrshrn_resolver\n");
}

void vrsqrte_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vrsqrte_resolver\n");
}

void vrsqrts_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vrsqrts_resolver\n");
}

void vrsra_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vrsra_resolver\n");
}

void vrsubhn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vrsubhn_resolver\n");
}

void vscclrm_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vscclrm_resolver\n");
}

void vsdot_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vsdot_resolver\n");
}

void vseleq_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vseleq_resolver\n");
}

void vselge_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vselge_resolver\n");
}

void vselgt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vselgt_resolver\n");
}

void vselvs_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vselvs_resolver\n");
}

void vshll_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vshll_resolver\n");
}

void vshrn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vshrn_resolver\n");
}

void vsmmla_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vsmmla_resolver\n");
}

void vsqrt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vsqrt_resolver\n");
}

void vsra_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vsra_resolver\n");
}

void vstmdb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vstmdb_resolver\n");
}

void vstmia_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vstmia_resolver\n");
}

void vstr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vstr_resolver\n");
}

void vsubhn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vsubhn_resolver\n");
}

void vsubl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vsubl_resolver\n");
}

void vsubw_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vsubw_resolver\n");
}

void vsudot_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vsudot_resolver\n");
}

void vswp_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vswp_resolver\n");
}

void vtbl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vtbl_resolver\n");
}

void vtbx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vtbx_resolver\n");
}

void vcvtr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vcvtr_resolver\n");
}

void vtrn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vtrn_resolver\n");
}

void vtst_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vtst_resolver\n");
}

void vudot_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vudot_resolver\n");
}

void vummla_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vummla_resolver\n");
}

void vusdot_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vusdot_resolver\n");
}

void vusmmla_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vusmmla_resolver\n");
}

void vuzp_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vuzp_resolver\n");
}

void vzip_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vzip_resolver\n");
}

void addw_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill addw_resolver\n");
}

void aut_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill aut_resolver\n");
}

void autg_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill autg_resolver\n");
}

void bfl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill bfl_resolver\n");
}

void bflx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill bflx_resolver\n");
}

void bf_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill bf_resolver\n");
}

void bfcsel_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill bfcsel_resolver\n");
}

void bfx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill bfx_resolver\n");
}

void bti_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill bti_resolver\n");
}

void bxaut_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill bxaut_resolver\n");
}

void clrm_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill clrm_resolver\n");
}

void csel_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill csel_resolver\n");
}

void csinc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill csinc_resolver\n");
}

void csinv_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill csinv_resolver\n");
}

void csneg_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill csneg_resolver\n");
}

void dcps1_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill dcps1_resolver\n");
}

void dcps2_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill dcps2_resolver\n");
}

void dcps3_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill dcps3_resolver\n");
}

void dls_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill dls_resolver\n");
}

void le_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill le_resolver\n");
}

void orn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill orn_resolver\n");
}

void pac_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill pac_resolver\n");
}

void pacbti_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill pacbti_resolver\n");
}

void pacg_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill pacg_resolver\n");
}

void sg_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill sg_resolver\n");
}

void subs_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill subs_resolver\n");
}

void subw_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill subw_resolver\n");
}

void tbb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill tbb_resolver\n");
}

void tbh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill tbh_resolver\n");
}

void tt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill tt_resolver\n");
}

void tta_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill tta_resolver\n");
}

void ttat_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill ttat_resolver\n");
}

void ttt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill ttt_resolver\n");
}

void wls_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill wls_resolver\n");
}

void blxns_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill blxns_resolver\n");
}

void bxns_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill bxns_resolver\n");
}

void cbnz_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill cbnz_resolver\n");
}

void cbz_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill cbz_resolver\n");
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
    LOG(stdout, "Please fill brkdiv0_resolver\n");
}

void vpop_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vpop_resolver\n");
}

void vpush_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist){
    LOG(stdout, "Please fill vpush_resolver\n");
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
    LOG(stdout, "Please fill invalid_vs_handler VSA\n");
    

}

void general_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill general_vs_handler VSA\n");
    

}

void asr_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill asr_vs_handler VSA\n");
    

}

void it_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill it_vs_handler VSA\n");
    

}

void ldrbt_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill ldrbt_vs_handler VSA\n");
    

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
    LOG(stdout, "Please fill ldrht_vs_handler VSA\n");
    

}

void ldrsbt_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill ldrsbt_vs_handler VSA\n");
    

}

void ldrsht_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill ldrsht_vs_handler VSA\n");
    

}

void ldrt_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill ldrt_vs_handler VSA\n");
    

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
    LOG(stdout, "Please fill ror_vs_handler VSA\n");
    

}

void rrx_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill rrx_vs_handler VSA\n");
    

}

void strbt_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill strbt_vs_handler VSA\n");
    

}

void strt_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill strt_vs_handler VSA\n");
    

}

void vld1_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vld1_vs_handler VSA\n");
    

}

void vld2_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vld2_vs_handler VSA\n");
    

}

void vld3_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vld3_vs_handler VSA\n");
    

}

void vld4_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vld4_vs_handler VSA\n");
    

}

void vst1_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vst1_vs_handler VSA\n");
    

}

void vst2_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vst2_vs_handler VSA\n");
    

}

void vst3_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vst3_vs_handler VSA\n");
    

}

void vst4_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vst4_vs_handler VSA\n");
    

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
    LOG(stdout, "Please fill ldrsh_vs_handler VSA\n");
    

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
    LOG(stdout, "Please fill adc_vs_handler VSA\n");
    

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
    LOG(stdout, "Please fill adr_vs_handler VSA\n");
    

}

void aesd_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill aesd_vs_handler VSA\n");
    

}

void aese_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill aese_vs_handler VSA\n");
    

}

void aesimc_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill aesimc_vs_handler VSA\n");
    

}

void aesmc_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill aesmc_vs_handler VSA\n");
    

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
    LOG(stdout, "Please fill vdot_vs_handler VSA\n");
    

}

void vcvt_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vcvt_vs_handler VSA\n");
    

}

void vcvtb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vcvtb_vs_handler VSA\n");
    

}

void vcvtt_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vcvtt_vs_handler VSA\n");
    

}

void bfc_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill bfc_vs_handler VSA\n");
    

}

void bfi_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill bfi_vs_handler VSA\n");
    

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
    LOG(stdout, "Please fill bkpt_vs_handler VSA\n");
    

}

void bl_vs_handler(re_list_t *instnode){
    // LOG(stdout, "Please fill bl_vs_handler VSA\n");
    // 

}

void blx_vs_handler(re_list_t *instnode){
    // LOG(stdout, "Please fill blx_vs_handler VSA\n");
    // 

}

void bx_vs_handler(re_list_t *instnode){
    // LOG(stdout, "Please fill bx_vs_handler VSA\n");
    

}

void bxj_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill bxj_vs_handler VSA\n");
    

}

void b_vs_handler(re_list_t *instnode){
    // LOG(stdout, "Please fill b_vs_handler VSA\n");
    

}

void cx1_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill cx1_vs_handler VSA\n");
    

}

void cx1a_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill cx1a_vs_handler VSA\n");
    

}

void cx1d_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill cx1d_vs_handler VSA\n");
    

}

void cx1da_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill cx1da_vs_handler VSA\n");
    

}

void cx2_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill cx2_vs_handler VSA\n");
    

}

void cx2a_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill cx2a_vs_handler VSA\n");
    

}

void cx2d_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill cx2d_vs_handler VSA\n");
    

}

void cx2da_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill cx2da_vs_handler VSA\n");
    

}

void cx3_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill cx3_vs_handler VSA\n");
    

}

void cx3a_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill cx3a_vs_handler VSA\n");
    

}

void cx3d_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill cx3d_vs_handler VSA\n");
    

}

void cx3da_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill cx3da_vs_handler VSA\n");
    

}

void vcx1a_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vcx1a_vs_handler VSA\n");
    

}

void vcx1_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vcx1_vs_handler VSA\n");
    

}

void vcx2a_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vcx2a_vs_handler VSA\n");
    

}

void vcx2_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vcx2_vs_handler VSA\n");
    

}

void vcx3a_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vcx3a_vs_handler VSA\n");
    

}

void vcx3_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vcx3_vs_handler VSA\n");
    

}

void cdp_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill cdp_vs_handler VSA\n");
    

}

void cdp2_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill cdp2_vs_handler VSA\n");
    

}

void clrex_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill clrex_vs_handler VSA\n");
    

}

void clz_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill clz_vs_handler VSA\n");
    

}

void cmn_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill cmn_vs_handler VSA\n");
    

}

void cmp_vs_handler(re_list_t *instnode){
    // note is this useful?
   	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	
	// traverse all the operands to fill all value set
	// (including value set and address value) of operands
	vs_traverse_inst_operand(instnode, src, dst, &nuse, &ndef);

}

void cps_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill cps_vs_handler VSA\n");
    

}

void crc32b_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill crc32b_vs_handler VSA\n");
    

}

void crc32cb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill crc32cb_vs_handler VSA\n");
    

}

void crc32ch_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill crc32ch_vs_handler VSA\n");
    

}

void crc32cw_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill crc32cw_vs_handler VSA\n");
    

}

void crc32h_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill crc32h_vs_handler VSA\n");
    

}

void crc32w_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill crc32w_vs_handler VSA\n");
    

}

void dbg_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill dbg_vs_handler VSA\n");
    

}

void dmb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill dmb_vs_handler VSA\n");
    

}

void dsb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill dsb_vs_handler VSA\n");
    

}

void eor_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill eor_vs_handler VSA\n");
    

}

void eret_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill eret_vs_handler VSA\n");
    

}

void vmov_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmov_vs_handler VSA\n");
    

}

void fldmdbx_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill fldmdbx_vs_handler VSA\n");
    

}

void fldmiax_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill fldmiax_vs_handler VSA\n");
    

}

void vmrs_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmrs_vs_handler VSA\n");
    

}

void fstmdbx_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill fstmdbx_vs_handler VSA\n");
    

}

void fstmiax_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill fstmiax_vs_handler VSA\n");
    

}

void hint_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill hint_vs_handler VSA\n");
    

}

void hlt_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill hlt_vs_handler VSA\n");
    

}

void hvc_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill hvc_vs_handler VSA\n");
    

}

void isb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill isb_vs_handler VSA\n");
    

}

void lda_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill lda_vs_handler VSA\n");
    

}

void ldab_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill ldab_vs_handler VSA\n");
    

}

void ldaex_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill ldaex_vs_handler VSA\n");
    

}

void ldaexb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill ldaexb_vs_handler VSA\n");
    

}

void ldaexd_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill ldaexd_vs_handler VSA\n");
    

}

void ldaexh_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill ldaexh_vs_handler VSA\n");
    

}

void ldah_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill ldah_vs_handler VSA\n");
    

}

void ldc2l_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill ldc2l_vs_handler VSA\n");
    

}

void ldc2_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill ldc2_vs_handler VSA\n");
    

}

void ldcl_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill ldcl_vs_handler VSA\n");
    

}

void ldc_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill ldc_vs_handler VSA\n");
    

}

void ldmda_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill ldmda_vs_handler VSA\n");
    

}

void ldmdb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill ldmdb_vs_handler VSA\n");
    

}

void ldm_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill ldm_vs_handler VSA\n");
    

}

void ldmib_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill ldmib_vs_handler VSA\n");
    

}

void ldrd_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill ldrd_vs_handler VSA\n");
    

}

void ldrex_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill ldrex_vs_handler VSA\n");
    

}

void ldrexb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill ldrexb_vs_handler VSA\n");
    

}

void ldrexd_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill ldrexd_vs_handler VSA\n");
    

}

void ldrexh_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill ldrexh_vs_handler VSA\n");
    

}

void mcr_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill mcr_vs_handler VSA\n");
    

}

void mcr2_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill mcr2_vs_handler VSA\n");
    

}

void mcrr_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill mcrr_vs_handler VSA\n");
    

}

void mcrr2_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill mcrr2_vs_handler VSA\n");
    

}

void mla_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill mla_vs_handler VSA\n");
    

}

void mls_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill mls_vs_handler VSA\n");
    

}

void movt_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill movt_vs_handler VSA\n");
    

}

void movw_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill movw_vs_handler VSA\n");
    

}

void mrc_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill mrc_vs_handler VSA\n");
    

}

void mrc2_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill mrc2_vs_handler VSA\n");
    

}

void mrrc_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill mrrc_vs_handler VSA\n");
    

}

void mrrc2_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill mrrc2_vs_handler VSA\n");
    

}

void mrs_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill mrs_vs_handler VSA\n");
    

}

void msr_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill msr_vs_handler VSA\n");
    

}

void mul_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill mul_vs_handler VSA\n");
    

}

void asrl_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill asrl_vs_handler VSA\n");
    

}

void dlstp_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill dlstp_vs_handler VSA\n");
    

}

void lctp_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill lctp_vs_handler VSA\n");
    

}

void letp_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill letp_vs_handler VSA\n");
    

}

void lsll_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill lsll_vs_handler VSA\n");
    

}

void lsrl_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill lsrl_vs_handler VSA\n");
    

}

void sqrshr_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill sqrshr_vs_handler VSA\n");
    

}

void sqrshrl_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill sqrshrl_vs_handler VSA\n");
    

}

void sqshl_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill sqshl_vs_handler VSA\n");
    

}

void sqshll_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill sqshll_vs_handler VSA\n");
    

}

void srshr_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill srshr_vs_handler VSA\n");
    

}

void srshrl_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill srshrl_vs_handler VSA\n");
    

}

void uqrshl_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill uqrshl_vs_handler VSA\n");
    

}

void uqrshll_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill uqrshll_vs_handler VSA\n");
    

}

void uqshl_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill uqshl_vs_handler VSA\n");
    

}

void uqshll_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill uqshll_vs_handler VSA\n");
    

}

void urshr_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill urshr_vs_handler VSA\n");
    

}

void urshrl_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill urshrl_vs_handler VSA\n");
    

}

void vabav_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vabav_vs_handler VSA\n");
    

}

void vabd_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vabd_vs_handler VSA\n");
    

}

void vabs_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vabs_vs_handler VSA\n");
    

}

void vadc_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vadc_vs_handler VSA\n");
    

}

void vadci_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vadci_vs_handler VSA\n");
    

}

void vaddlva_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vaddlva_vs_handler VSA\n");
    

}

void vaddlv_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vaddlv_vs_handler VSA\n");
    

}

void vaddva_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vaddva_vs_handler VSA\n");
    

}

void vaddv_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vaddv_vs_handler VSA\n");
    

}

void vadd_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vadd_vs_handler VSA\n");
    

}

void vand_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vand_vs_handler VSA\n");
    

}

void vbic_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vbic_vs_handler VSA\n");
    

}

void vbrsr_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vbrsr_vs_handler VSA\n");
    

}

void vcadd_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vcadd_vs_handler VSA\n");
    

}

void vcls_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vcls_vs_handler VSA\n");
    

}

void vclz_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vclz_vs_handler VSA\n");
    

}

void vcmla_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vcmla_vs_handler VSA\n");
    

}

void vcmp_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vcmp_vs_handler VSA\n");
    

}

void vcmul_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vcmul_vs_handler VSA\n");
    

}

void vctp_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vctp_vs_handler VSA\n");
    

}

void vcvta_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vcvta_vs_handler VSA\n");
    

}

void vcvtm_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vcvtm_vs_handler VSA\n");
    

}

void vcvtn_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vcvtn_vs_handler VSA\n");
    

}

void vcvtp_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vcvtp_vs_handler VSA\n");
    

}

void vddup_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vddup_vs_handler VSA\n");
    

}

void vdup_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vdup_vs_handler VSA\n");
    

}

void vdwdup_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vdwdup_vs_handler VSA\n");
    

}

void veor_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill veor_vs_handler VSA\n");
    

}

void vfmas_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vfmas_vs_handler VSA\n");
    

}

void vfma_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vfma_vs_handler VSA\n");
    

}

void vfms_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vfms_vs_handler VSA\n");
    

}

void vhadd_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vhadd_vs_handler VSA\n");
    

}

void vhcadd_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vhcadd_vs_handler VSA\n");
    

}

void vhsub_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vhsub_vs_handler VSA\n");
    

}

void vidup_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vidup_vs_handler VSA\n");
    

}

void viwdup_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill viwdup_vs_handler VSA\n");
    

}

void vld20_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vld20_vs_handler VSA\n");
    

}

void vld21_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vld21_vs_handler VSA\n");
    

}

void vld40_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vld40_vs_handler VSA\n");
    

}

void vld41_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vld41_vs_handler VSA\n");
    

}

void vld42_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vld42_vs_handler VSA\n");
    

}

void vld43_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vld43_vs_handler VSA\n");
    

}

void vldrb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vldrb_vs_handler VSA\n");
    

}

void vldrd_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vldrd_vs_handler VSA\n");
    

}

void vldrh_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vldrh_vs_handler VSA\n");
    

}

void vldrw_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vldrw_vs_handler VSA\n");
    

}

void vmaxav_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmaxav_vs_handler VSA\n");
    

}

void vmaxa_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmaxa_vs_handler VSA\n");
    

}

void vmaxnmav_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmaxnmav_vs_handler VSA\n");
    

}

void vmaxnma_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmaxnma_vs_handler VSA\n");
    

}

void vmaxnmv_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmaxnmv_vs_handler VSA\n");
    

}

void vmaxnm_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmaxnm_vs_handler VSA\n");
    

}

void vmaxv_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmaxv_vs_handler VSA\n");
    

}

void vmax_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmax_vs_handler VSA\n");
    

}

void vminav_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vminav_vs_handler VSA\n");
    

}

void vmina_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmina_vs_handler VSA\n");
    

}

void vminnmav_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vminnmav_vs_handler VSA\n");
    

}

void vminnma_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vminnma_vs_handler VSA\n");
    

}

void vminnmv_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vminnmv_vs_handler VSA\n");
    

}

void vminnm_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vminnm_vs_handler VSA\n");
    

}

void vminv_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vminv_vs_handler VSA\n");
    

}

void vmin_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmin_vs_handler VSA\n");
    

}

void vmladava_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmladava_vs_handler VSA\n");
    

}

void vmladavax_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmladavax_vs_handler VSA\n");
    

}

void vmladav_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmladav_vs_handler VSA\n");
    

}

void vmladavx_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmladavx_vs_handler VSA\n");
    

}

void vmlaldava_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmlaldava_vs_handler VSA\n");
    

}

void vmlaldavax_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmlaldavax_vs_handler VSA\n");
    

}

void vmlaldav_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmlaldav_vs_handler VSA\n");
    

}

void vmlaldavx_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmlaldavx_vs_handler VSA\n");
    

}

void vmlas_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmlas_vs_handler VSA\n");
    

}

void vmla_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmla_vs_handler VSA\n");
    

}

void vmlsdava_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmlsdava_vs_handler VSA\n");
    

}

void vmlsdavax_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmlsdavax_vs_handler VSA\n");
    

}

void vmlsdav_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmlsdav_vs_handler VSA\n");
    

}

void vmlsdavx_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmlsdavx_vs_handler VSA\n");
    

}

void vmlsldava_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmlsldava_vs_handler VSA\n");
    

}

void vmlsldavax_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmlsldavax_vs_handler VSA\n");
    

}

void vmlsldav_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmlsldav_vs_handler VSA\n");
    

}

void vmlsldavx_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmlsldavx_vs_handler VSA\n");
    

}

void vmovlb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmovlb_vs_handler VSA\n");
    

}

void vmovlt_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmovlt_vs_handler VSA\n");
    

}

void vmovnb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmovnb_vs_handler VSA\n");
    

}

void vmovnt_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmovnt_vs_handler VSA\n");
    

}

void vmulh_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmulh_vs_handler VSA\n");
    

}

void vmullb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmullb_vs_handler VSA\n");
    

}

void vmullt_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmullt_vs_handler VSA\n");
    

}

void vmul_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmul_vs_handler VSA\n");
    

}

void vmvn_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmvn_vs_handler VSA\n");
    

}

void vneg_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vneg_vs_handler VSA\n");
    

}

void vorn_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vorn_vs_handler VSA\n");
    

}

void vorr_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vorr_vs_handler VSA\n");
    

}

void vpnot_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vpnot_vs_handler VSA\n");
    

}

void vpsel_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vpsel_vs_handler VSA\n");
    

}

void vpst_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vpst_vs_handler VSA\n");
    

}

void vpt_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vpt_vs_handler VSA\n");
    

}

void vqabs_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqabs_vs_handler VSA\n");
    

}

void vqadd_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqadd_vs_handler VSA\n");
    

}

void vqdmladhx_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqdmladhx_vs_handler VSA\n");
    

}

void vqdmladh_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqdmladh_vs_handler VSA\n");
    

}

void vqdmlah_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqdmlah_vs_handler VSA\n");
    

}

void vqdmlash_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqdmlash_vs_handler VSA\n");
    

}

void vqdmlsdhx_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqdmlsdhx_vs_handler VSA\n");
    

}

void vqdmlsdh_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqdmlsdh_vs_handler VSA\n");
    

}

void vqdmulh_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqdmulh_vs_handler VSA\n");
    

}

void vqdmullb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqdmullb_vs_handler VSA\n");
    

}

void vqdmullt_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqdmullt_vs_handler VSA\n");
    

}

void vqmovnb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqmovnb_vs_handler VSA\n");
    

}

void vqmovnt_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqmovnt_vs_handler VSA\n");
    

}

void vqmovunb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqmovunb_vs_handler VSA\n");
    

}

void vqmovunt_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqmovunt_vs_handler VSA\n");
    

}

void vqneg_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqneg_vs_handler VSA\n");
    

}

void vqrdmladhx_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqrdmladhx_vs_handler VSA\n");
    

}

void vqrdmladh_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqrdmladh_vs_handler VSA\n");
    

}

void vqrdmlah_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqrdmlah_vs_handler VSA\n");
    

}

void vqrdmlash_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqrdmlash_vs_handler VSA\n");
    

}

void vqrdmlsdhx_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqrdmlsdhx_vs_handler VSA\n");
    

}

void vqrdmlsdh_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqrdmlsdh_vs_handler VSA\n");
    

}

void vqrdmulh_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqrdmulh_vs_handler VSA\n");
    

}

void vqrshl_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqrshl_vs_handler VSA\n");
    

}

void vqrshrnb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqrshrnb_vs_handler VSA\n");
    

}

void vqrshrnt_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqrshrnt_vs_handler VSA\n");
    

}

void vqrshrunb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqrshrunb_vs_handler VSA\n");
    

}

void vqrshrunt_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqrshrunt_vs_handler VSA\n");
    

}

void vqshlu_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqshlu_vs_handler VSA\n");
    

}

void vqshl_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqshl_vs_handler VSA\n");
    

}

void vqshrnb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqshrnb_vs_handler VSA\n");
    

}

void vqshrnt_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqshrnt_vs_handler VSA\n");
    

}

void vqshrunb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqshrunb_vs_handler VSA\n");
    

}

void vqshrunt_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqshrunt_vs_handler VSA\n");
    

}

void vqsub_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqsub_vs_handler VSA\n");
    

}

void vrev16_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vrev16_vs_handler VSA\n");
    

}

void vrev32_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vrev32_vs_handler VSA\n");
    

}

void vrev64_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vrev64_vs_handler VSA\n");
    

}

void vrhadd_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vrhadd_vs_handler VSA\n");
    

}

void vrinta_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vrinta_vs_handler VSA\n");
    

}

void vrintm_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vrintm_vs_handler VSA\n");
    

}

void vrintn_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vrintn_vs_handler VSA\n");
    

}

void vrintp_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vrintp_vs_handler VSA\n");
    

}

void vrintx_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vrintx_vs_handler VSA\n");
    

}

void vrintz_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vrintz_vs_handler VSA\n");
    

}

void vrmlaldavha_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vrmlaldavha_vs_handler VSA\n");
    

}

void vrmlaldavhax_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vrmlaldavhax_vs_handler VSA\n");
    

}

void vrmlaldavh_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vrmlaldavh_vs_handler VSA\n");
    

}

void vrmlaldavhx_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vrmlaldavhx_vs_handler VSA\n");
    

}

void vrmlsldavha_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vrmlsldavha_vs_handler VSA\n");
    

}

void vrmlsldavhax_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vrmlsldavhax_vs_handler VSA\n");
    

}

void vrmlsldavh_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vrmlsldavh_vs_handler VSA\n");
    

}

void vrmlsldavhx_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vrmlsldavhx_vs_handler VSA\n");
    

}

void vrmulh_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vrmulh_vs_handler VSA\n");
    

}

void vrshl_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vrshl_vs_handler VSA\n");
    

}

void vrshrnb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vrshrnb_vs_handler VSA\n");
    

}

void vrshrnt_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vrshrnt_vs_handler VSA\n");
    

}

void vrshr_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vrshr_vs_handler VSA\n");
    

}

void vsbc_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vsbc_vs_handler VSA\n");
    

}

void vsbci_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vsbci_vs_handler VSA\n");
    

}

void vshlc_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vshlc_vs_handler VSA\n");
    

}

void vshllb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vshllb_vs_handler VSA\n");
    

}

void vshllt_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vshllt_vs_handler VSA\n");
    

}

void vshl_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vshl_vs_handler VSA\n");
    

}

void vshrnb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vshrnb_vs_handler VSA\n");
    

}

void vshrnt_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vshrnt_vs_handler VSA\n");
    

}

void vshr_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vshr_vs_handler VSA\n");
    

}

void vsli_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vsli_vs_handler VSA\n");
    

}

void vsri_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vsri_vs_handler VSA\n");
    

}

void vst20_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vst20_vs_handler VSA\n");
    

}

void vst21_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vst21_vs_handler VSA\n");
    

}

void vst40_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vst40_vs_handler VSA\n");
    

}

void vst41_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vst41_vs_handler VSA\n");
    

}

void vst42_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vst42_vs_handler VSA\n");
    

}

void vst43_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vst43_vs_handler VSA\n");
    

}

void vstrb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vstrb_vs_handler VSA\n");
    

}

void vstrd_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vstrd_vs_handler VSA\n");
    

}

void vstrh_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vstrh_vs_handler VSA\n");
    

}

void vstrw_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vstrw_vs_handler VSA\n");
    

}

void vsub_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vsub_vs_handler VSA\n");
    

}

void wlstp_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill wlstp_vs_handler VSA\n");
    

}

void mvn_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill mvn_vs_handler VSA\n");
    

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
    LOG(stdout, "Please fill pkhbt_vs_handler VSA\n");
    

}

void pkhtb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill pkhtb_vs_handler VSA\n");
    

}

void pldw_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill pldw_vs_handler VSA\n");
    

}

void pld_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill pld_vs_handler VSA\n");
    

}

void pli_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill pli_vs_handler VSA\n");
    

}

void qadd_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill qadd_vs_handler VSA\n");
    

}

void qadd16_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill qadd16_vs_handler VSA\n");
    

}

void qadd8_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill qadd8_vs_handler VSA\n");
    

}

void qasx_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill qasx_vs_handler VSA\n");
    

}

void qdadd_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill qdadd_vs_handler VSA\n");
    

}

void qdsub_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill qdsub_vs_handler VSA\n");
    

}

void qsax_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill qsax_vs_handler VSA\n");
    

}

void qsub_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill qsub_vs_handler VSA\n");
    

}

void qsub16_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill qsub16_vs_handler VSA\n");
    

}

void qsub8_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill qsub8_vs_handler VSA\n");
    

}

void rbit_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill rbit_vs_handler VSA\n");
    

}

void rev_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill rev_vs_handler VSA\n");
    

}

void rev16_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill rev16_vs_handler VSA\n");
    

}

void revsh_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill revsh_vs_handler VSA\n");
    

}

void rfeda_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill rfeda_vs_handler VSA\n");
    

}

void rfedb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill rfedb_vs_handler VSA\n");
    

}

void rfeia_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill rfeia_vs_handler VSA\n");
    

}

void rfeib_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill rfeib_vs_handler VSA\n");
    

}

void rsb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill rsb_vs_handler VSA\n");
    

}

void rsc_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill rsc_vs_handler VSA\n");
    

}

void sadd16_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill sadd16_vs_handler VSA\n");
    

}

void sadd8_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill sadd8_vs_handler VSA\n");
    

}

void sasx_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill sasx_vs_handler VSA\n");
    

}

void sb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill sb_vs_handler VSA\n");
    

}

void sbc_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill sbc_vs_handler VSA\n");
    

}

void sbfx_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill sbfx_vs_handler VSA\n");
    

}

void sdiv_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill sdiv_vs_handler VSA\n");
    

}

void sel_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill sel_vs_handler VSA\n");
    

}

void setend_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill setend_vs_handler VSA\n");
    

}

void setpan_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill setpan_vs_handler VSA\n");
    

}

void sha1c_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill sha1c_vs_handler VSA\n");
    

}

void sha1h_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill sha1h_vs_handler VSA\n");
    

}

void sha1m_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill sha1m_vs_handler VSA\n");
    

}

void sha1p_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill sha1p_vs_handler VSA\n");
    

}

void sha1su0_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill sha1su0_vs_handler VSA\n");
    

}

void sha1su1_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill sha1su1_vs_handler VSA\n");
    

}

void sha256h_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill sha256h_vs_handler VSA\n");
    

}

void sha256h2_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill sha256h2_vs_handler VSA\n");
    

}

void sha256su0_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill sha256su0_vs_handler VSA\n");
    

}

void sha256su1_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill sha256su1_vs_handler VSA\n");
    

}

void shadd16_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill shadd16_vs_handler VSA\n");
    

}

void shadd8_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill shadd8_vs_handler VSA\n");
    

}

void shasx_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill shasx_vs_handler VSA\n");
    

}

void shsax_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill shsax_vs_handler VSA\n");
    

}

void shsub16_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill shsub16_vs_handler VSA\n");
    

}

void shsub8_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill shsub8_vs_handler VSA\n");
    

}

void smc_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill smc_vs_handler VSA\n");
    

}

void smlabb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill smlabb_vs_handler VSA\n");
    

}

void smlabt_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill smlabt_vs_handler VSA\n");
    

}

void smlad_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill smlad_vs_handler VSA\n");
    

}

void smladx_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill smladx_vs_handler VSA\n");
    

}

void smlal_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill smlal_vs_handler VSA\n");
    

}

void smlalbb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill smlalbb_vs_handler VSA\n");
    

}

void smlalbt_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill smlalbt_vs_handler VSA\n");
    

}

void smlald_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill smlald_vs_handler VSA\n");
    

}

void smlaldx_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill smlaldx_vs_handler VSA\n");
    

}

void smlaltb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill smlaltb_vs_handler VSA\n");
    

}

void smlaltt_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill smlaltt_vs_handler VSA\n");
    

}

void smlatb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill smlatb_vs_handler VSA\n");
    

}

void smlatt_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill smlatt_vs_handler VSA\n");
    

}

void smlawb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill smlawb_vs_handler VSA\n");
    

}

void smlawt_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill smlawt_vs_handler VSA\n");
    

}

void smlsd_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill smlsd_vs_handler VSA\n");
    

}

void smlsdx_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill smlsdx_vs_handler VSA\n");
    

}

void smlsld_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill smlsld_vs_handler VSA\n");
    

}

void smlsldx_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill smlsldx_vs_handler VSA\n");
    

}

void smmla_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill smmla_vs_handler VSA\n");
    

}

void smmlar_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill smmlar_vs_handler VSA\n");
    

}

void smmls_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill smmls_vs_handler VSA\n");
    

}

void smmlsr_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill smmlsr_vs_handler VSA\n");
    

}

void smmul_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill smmul_vs_handler VSA\n");
    

}

void smmulr_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill smmulr_vs_handler VSA\n");
    

}

void smuad_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill smuad_vs_handler VSA\n");
    

}

void smuadx_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill smuadx_vs_handler VSA\n");
    

}

void smulbb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill smulbb_vs_handler VSA\n");
    

}

void smulbt_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill smulbt_vs_handler VSA\n");
    

}

void smull_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill smull_vs_handler VSA\n");
    

}

void smultb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill smultb_vs_handler VSA\n");
    

}

void smultt_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill smultt_vs_handler VSA\n");
    

}

void smulwb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill smulwb_vs_handler VSA\n");
    

}

void smulwt_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill smulwt_vs_handler VSA\n");
    

}

void smusd_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill smusd_vs_handler VSA\n");
    

}

void smusdx_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill smusdx_vs_handler VSA\n");
    

}

void srsda_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill srsda_vs_handler VSA\n");
    

}

void srsdb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill srsdb_vs_handler VSA\n");
    

}

void srsia_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill srsia_vs_handler VSA\n");
    

}

void srsib_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill srsib_vs_handler VSA\n");
    

}

void ssat_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill ssat_vs_handler VSA\n");
    

}

void ssat16_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill ssat16_vs_handler VSA\n");
    

}

void ssax_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill ssax_vs_handler VSA\n");
    

}

void ssub16_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill ssub16_vs_handler VSA\n");
    

}

void ssub8_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill ssub8_vs_handler VSA\n");
    

}

void stc2l_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill stc2l_vs_handler VSA\n");
    

}

void stc2_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill stc2_vs_handler VSA\n");
    

}

void stcl_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill stcl_vs_handler VSA\n");
    

}

void stc_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill stc_vs_handler VSA\n");
    

}

void stl_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill stl_vs_handler VSA\n");
    

}

void stlb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill stlb_vs_handler VSA\n");
    

}

void stlex_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill stlex_vs_handler VSA\n");
    

}

void stlexb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill stlexb_vs_handler VSA\n");
    

}

void stlexd_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill stlexd_vs_handler VSA\n");
    

}

void stlexh_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill stlexh_vs_handler VSA\n");
    

}

void stlh_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill stlh_vs_handler VSA\n");
    

}

void stmda_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill stmda_vs_handler VSA\n");
    

}

void stmdb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill stmdb_vs_handler VSA\n");
    

}

void stm_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill stm_vs_handler VSA\n");
    

}

void stmib_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill stmib_vs_handler VSA\n");
    

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
    LOG(stdout, "Please fill strd_vs_handler VSA\n");
    

}

void strex_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill strex_vs_handler VSA\n");
    

}

void strexb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill strexb_vs_handler VSA\n");
    

}

void strexd_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill strexd_vs_handler VSA\n");
    

}

void strexh_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill strexh_vs_handler VSA\n");
    

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
    LOG(stdout, "Please fill strht_vs_handler VSA\n");
    

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
    LOG(stdout, "Please fill svc_vs_handler VSA\n");
    

}

void swp_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill swp_vs_handler VSA\n");
    

}

void swpb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill swpb_vs_handler VSA\n");
    

}

void sxtab_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill sxtab_vs_handler VSA\n");
    

}

void sxtab16_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill sxtab16_vs_handler VSA\n");
    

}

void sxtah_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill sxtah_vs_handler VSA\n");
    

}

void sxtb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill sxtb_vs_handler VSA\n");
    

}

void sxtb16_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill sxtb16_vs_handler VSA\n");
    

}

void sxth_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill sxth_vs_handler VSA\n");
    

}

void teq_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill teq_vs_handler VSA\n");
    

}

void trap_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill trap_vs_handler VSA\n");
    

}

void tsb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill tsb_vs_handler VSA\n");
    

}

void tst_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill tst_vs_handler VSA\n");
    

}

void uadd16_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill uadd16_vs_handler VSA\n");
    

}

void uadd8_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill uadd8_vs_handler VSA\n");
    

}

void uasx_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill uasx_vs_handler VSA\n");
    

}

void ubfx_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill ubfx_vs_handler VSA\n");
    

}

void udf_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill udf_vs_handler VSA\n");
    

}

void udiv_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill udiv_vs_handler VSA\n");
    

}

void uhadd16_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill uhadd16_vs_handler VSA\n");
    

}

void uhadd8_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill uhadd8_vs_handler VSA\n");
    

}

void uhasx_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill uhasx_vs_handler VSA\n");
    

}

void uhsax_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill uhsax_vs_handler VSA\n");
    

}

void uhsub16_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill uhsub16_vs_handler VSA\n");
    

}

void uhsub8_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill uhsub8_vs_handler VSA\n");
    

}

void umaal_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill umaal_vs_handler VSA\n");
    

}

void umlal_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill umlal_vs_handler VSA\n");
    

}

void umull_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill umull_vs_handler VSA\n");
    

}

void uqadd16_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill uqadd16_vs_handler VSA\n");
    

}

void uqadd8_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill uqadd8_vs_handler VSA\n");
    

}

void uqasx_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill uqasx_vs_handler VSA\n");
    

}

void uqsax_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill uqsax_vs_handler VSA\n");
    

}

void uqsub16_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill uqsub16_vs_handler VSA\n");
    

}

void uqsub8_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill uqsub8_vs_handler VSA\n");
    

}

void usad8_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill usad8_vs_handler VSA\n");
    

}

void usada8_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill usada8_vs_handler VSA\n");
    

}

void usat_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill usat_vs_handler VSA\n");
    

}

void usat16_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill usat16_vs_handler VSA\n");
    

}

void usax_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill usax_vs_handler VSA\n");
    

}

void usub16_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill usub16_vs_handler VSA\n");
    

}

void usub8_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill usub8_vs_handler VSA\n");
    

}

void uxtab_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill uxtab_vs_handler VSA\n");
    

}

void uxtab16_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill uxtab16_vs_handler VSA\n");
    

}

void uxtah_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill uxtah_vs_handler VSA\n");
    

}

void uxtb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill uxtb_vs_handler VSA\n");
    

}

void uxtb16_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill uxtb16_vs_handler VSA\n");
    

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
    LOG(stdout, "Please fill vabal_vs_handler VSA\n");
    

}

void vaba_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vaba_vs_handler VSA\n");
    

}

void vabdl_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vabdl_vs_handler VSA\n");
    

}

void vacge_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vacge_vs_handler VSA\n");
    

}

void vacgt_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vacgt_vs_handler VSA\n");
    

}

void vaddhn_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vaddhn_vs_handler VSA\n");
    

}

void vaddl_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vaddl_vs_handler VSA\n");
    

}

void vaddw_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vaddw_vs_handler VSA\n");
    

}

void vfmab_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vfmab_vs_handler VSA\n");
    

}

void vfmat_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vfmat_vs_handler VSA\n");
    

}

void vbif_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vbif_vs_handler VSA\n");
    

}

void vbit_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vbit_vs_handler VSA\n");
    

}

void vbsl_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vbsl_vs_handler VSA\n");
    

}

void vceq_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vceq_vs_handler VSA\n");
    

}

void vcge_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vcge_vs_handler VSA\n");
    

}

void vcgt_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vcgt_vs_handler VSA\n");
    

}

void vcle_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vcle_vs_handler VSA\n");
    

}

void vclt_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vclt_vs_handler VSA\n");
    

}

void vcmpe_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vcmpe_vs_handler VSA\n");
    

}

void vcnt_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vcnt_vs_handler VSA\n");
    

}

void vdiv_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vdiv_vs_handler VSA\n");
    

}

void vext_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vext_vs_handler VSA\n");
    

}

void vfmal_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vfmal_vs_handler VSA\n");
    

}

void vfmsl_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vfmsl_vs_handler VSA\n");
    

}

void vfnma_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vfnma_vs_handler VSA\n");
    

}

void vfnms_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vfnms_vs_handler VSA\n");
    

}

void vins_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vins_vs_handler VSA\n");
    

}

void vjcvt_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vjcvt_vs_handler VSA\n");
    

}

void vldmdb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vldmdb_vs_handler VSA\n");
    

}

void vldmia_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vldmia_vs_handler VSA\n");
    

}

void vldr_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vldr_vs_handler VSA\n");
    

}

void vlldm_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vlldm_vs_handler VSA\n");
    

}

void vlstm_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vlstm_vs_handler VSA\n");
    

}

void vmlal_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmlal_vs_handler VSA\n");
    

}

void vmls_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmls_vs_handler VSA\n");
    

}

void vmlsl_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmlsl_vs_handler VSA\n");
    

}

void vmmla_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmmla_vs_handler VSA\n");
    

}

void vmovx_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmovx_vs_handler VSA\n");
    

}

void vmovl_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmovl_vs_handler VSA\n");
    

}

void vmovn_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmovn_vs_handler VSA\n");
    

}

void vmsr_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmsr_vs_handler VSA\n");
    

}

void vmull_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vmull_vs_handler VSA\n");
    

}

void vnmla_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vnmla_vs_handler VSA\n");
    

}

void vnmls_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vnmls_vs_handler VSA\n");
    

}

void vnmul_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vnmul_vs_handler VSA\n");
    

}

void vpadal_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vpadal_vs_handler VSA\n");
    

}

void vpaddl_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vpaddl_vs_handler VSA\n");
    

}

void vpadd_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vpadd_vs_handler VSA\n");
    

}

void vpmax_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vpmax_vs_handler VSA\n");
    

}

void vpmin_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vpmin_vs_handler VSA\n");
    

}

void vqdmlal_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqdmlal_vs_handler VSA\n");
    

}

void vqdmlsl_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqdmlsl_vs_handler VSA\n");
    

}

void vqdmull_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqdmull_vs_handler VSA\n");
    

}

void vqmovun_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqmovun_vs_handler VSA\n");
    

}

void vqmovn_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqmovn_vs_handler VSA\n");
    

}

void vqrdmlsh_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqrdmlsh_vs_handler VSA\n");
    

}

void vqrshrn_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqrshrn_vs_handler VSA\n");
    

}

void vqrshrun_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqrshrun_vs_handler VSA\n");
    

}

void vqshrn_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqshrn_vs_handler VSA\n");
    

}

void vqshrun_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vqshrun_vs_handler VSA\n");
    

}

void vraddhn_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vraddhn_vs_handler VSA\n");
    

}

void vrecpe_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vrecpe_vs_handler VSA\n");
    

}

void vrecps_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vrecps_vs_handler VSA\n");
    

}

void vrintr_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vrintr_vs_handler VSA\n");
    

}

void vrshrn_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vrshrn_vs_handler VSA\n");
    

}

void vrsqrte_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vrsqrte_vs_handler VSA\n");
    

}

void vrsqrts_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vrsqrts_vs_handler VSA\n");
    

}

void vrsra_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vrsra_vs_handler VSA\n");
    

}

void vrsubhn_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vrsubhn_vs_handler VSA\n");
    

}

void vscclrm_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vscclrm_vs_handler VSA\n");
    

}

void vsdot_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vsdot_vs_handler VSA\n");
    

}

void vseleq_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vseleq_vs_handler VSA\n");
    

}

void vselge_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vselge_vs_handler VSA\n");
    

}

void vselgt_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vselgt_vs_handler VSA\n");
    

}

void vselvs_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vselvs_vs_handler VSA\n");
    

}

void vshll_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vshll_vs_handler VSA\n");
    

}

void vshrn_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vshrn_vs_handler VSA\n");
    

}

void vsmmla_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vsmmla_vs_handler VSA\n");
    

}

void vsqrt_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vsqrt_vs_handler VSA\n");
    

}

void vsra_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vsra_vs_handler VSA\n");
    

}

void vstmdb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vstmdb_vs_handler VSA\n");
    

}

void vstmia_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vstmia_vs_handler VSA\n");
    

}

void vstr_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vstr_vs_handler VSA\n");
    

}

void vsubhn_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vsubhn_vs_handler VSA\n");
    

}

void vsubl_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vsubl_vs_handler VSA\n");
    

}

void vsubw_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vsubw_vs_handler VSA\n");
    

}

void vsudot_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vsudot_vs_handler VSA\n");
    

}

void vswp_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vswp_vs_handler VSA\n");
    

}

void vtbl_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vtbl_vs_handler VSA\n");
    

}

void vtbx_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vtbx_vs_handler VSA\n");
    

}

void vcvtr_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vcvtr_vs_handler VSA\n");
    

}

void vtrn_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vtrn_vs_handler VSA\n");
    

}

void vtst_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vtst_vs_handler VSA\n");
    

}

void vudot_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vudot_vs_handler VSA\n");
    

}

void vummla_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vummla_vs_handler VSA\n");
    

}

void vusdot_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vusdot_vs_handler VSA\n");
    

}

void vusmmla_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vusmmla_vs_handler VSA\n");
    

}

void vuzp_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vuzp_vs_handler VSA\n");
    

}

void vzip_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vzip_vs_handler VSA\n");
    

}

void addw_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill addw_vs_handler VSA\n");
    

}

void aut_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill aut_vs_handler VSA\n");
    

}

void autg_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill autg_vs_handler VSA\n");
    

}

void bfl_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill bfl_vs_handler VSA\n");
    

}

void bflx_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill bflx_vs_handler VSA\n");
    

}

void bf_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill bf_vs_handler VSA\n");
    

}

void bfcsel_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill bfcsel_vs_handler VSA\n");
    

}

void bfx_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill bfx_vs_handler VSA\n");
    

}

void bti_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill bti_vs_handler VSA\n");
    

}

void bxaut_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill bxaut_vs_handler VSA\n");
    

}

void clrm_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill clrm_vs_handler VSA\n");
    

}

void csel_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill csel_vs_handler VSA\n");
    

}

void csinc_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill csinc_vs_handler VSA\n");
    

}

void csinv_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill csinv_vs_handler VSA\n");
    

}

void csneg_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill csneg_vs_handler VSA\n");
    

}

void dcps1_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill dcps1_vs_handler VSA\n");
    

}

void dcps2_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill dcps2_vs_handler VSA\n");
    

}

void dcps3_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill dcps3_vs_handler VSA\n");
    

}

void dls_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill dls_vs_handler VSA\n");
    

}

void le_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill le_vs_handler VSA\n");
    

}

void orn_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill orn_vs_handler VSA\n");
    

}

void pac_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill pac_vs_handler VSA\n");
    

}

void pacbti_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill pacbti_vs_handler VSA\n");
    

}

void pacg_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill pacg_vs_handler VSA\n");
    

}

void sg_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill sg_vs_handler VSA\n");
    

}

void subs_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill subs_vs_handler VSA\n");
    

}

void subw_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill subw_vs_handler VSA\n");
    

}

void tbb_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill tbb_vs_handler VSA\n");
    

}

void tbh_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill tbh_vs_handler VSA\n");
    

}

void tt_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill tt_vs_handler VSA\n");
    

}

void tta_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill tta_vs_handler VSA\n");
    

}

void ttat_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill ttat_vs_handler VSA\n");
    

}

void ttt_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill ttt_vs_handler VSA\n");
    

}

void wls_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill wls_vs_handler VSA\n");
    

}

void blxns_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill blxns_vs_handler VSA\n");
    

}

void bxns_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill bxns_vs_handler VSA\n");
    

}

void cbnz_vs_handler(re_list_t *instnode){
    // LOG(stdout, "Please fill cbnz_vs_handler VSA\n");
    

}

void cbz_vs_handler(re_list_t *instnode){
    // LOG(stdout, "Please fill cbz_vs_handler VSA\n");
    

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
    LOG(stdout, "Please fill brkdiv0_vs_handler VSA\n");
    

}

void vpop_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vpop_vs_handler VSA\n");
    

}

void vpush_vs_handler(re_list_t *instnode){
    LOG(stdout, "Please fill vpush_vs_handler VSA\n");
    

}
#endif
#endif
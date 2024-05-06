#include <stdio.h>
#include <stdarg.h>
// #include <libdis.h>
#include <capstone/capstone.h>
#include <malloc.h>
#include <assert.h>
#include <string.h>
#include "reverse_log.h"
#include "global.h"
#include "disassemble.h"
#include "insthandler_arm.h"
#include "access_memory.h"
#include "reverse_exe.h"

#ifdef FRCA
#include "bintrace.capnp.h"
#endif

#ifdef FRCA
void print_memac(re_list_t *instnode){
    if (instnode == NULL || instnode->node_type != InstNode){
        return;
    }
    inst_node_t* node =  CAST2_INST(instnode->node);
    struct Access* access;
    LOG(stdout, "acnum = %d\n",node->acnum);

    for (int i = 0; i < node->acnum; i++) {
        access = node->accesses[i];
        assert(access->type == MEM_READ_AFTER || access->type == MEM_WRITE);
        LOG(stdout, "%s %d bytes ( %#x ) at %#x, pc = %#x\n",
            access->type == MEM_READ_AFTER ? "Read" : "Write",
            access->size, access->value, access->address, access->pc);
    }
}

void print_parser_info(uint8_t ndst, uint8_t nsrc, arm_ops_parser* parser){
	uint8_t i;
    LOG(stdout, "DEBUG: %d dst operands, %d src operands\n", ndst, nsrc);
    for (i=0; i < parser->op_num; i++) {
		LOG(stdout, "DEBUG: %dth operand (%s) - ", 
			i+1, parser->op_usage[i] == op_src ? "src" : "dst");
		if (parser->op[i] != NULL) {
			print_operand(parser->op[i]);
		} else {
			LOG(stdout, "NULL");
		}
		LOG(stdout, "\n");
	}
}

#endif
void print_assembly(cs_insn *inst){
	LOG(stdout, "Current Instruction is %#lx : %s\t%s\n",
    inst->address, inst->mnemonic, inst->op_str);
}

void print_operand(cs_arm_op* opd){
	// char debugopd[MAX_OP_STRING];
	// x86_format_operand(&opd, debugopd, MAX_OP_STRING, intel_syntax);
    switch (opd->type)
    {
    case ARM_OP_REG:
        LOG(stdout, "reg %d (%s)", opd->reg, cs_reg_name(re_ds.handle, opd->reg));
        break;
    case ARM_OP_IMM:
        LOG(stdout, "imm %#lx", opd->imm);
        break;
    case ARM_OP_MEM:
		if (opd->mem.base) {
			LOG(stdout, "mem base(%s) index(%s) disp(%d) shift value(%d)", 
			cs_reg_name(re_ds.handle, opd->mem.base), 
			opd->mem.index == ARM_REG_INVALID ? "NONE" :  cs_reg_name(re_ds.handle, opd->mem.index), 
			opd->mem.disp, opd->shift.value);
		} else {
			LOG(stdout, "dummy mem op");
		}
        
    default:
        break;
    }
}
void print_sub_operand(cs_arm_op* opd, enum u_type type) {
    switch(type) {
        case Opd:
            print_operand(opd);
            break;
        case Base:
			if (opd->mem.base) {
            	LOG(stdout, "mem base(%s)", cs_reg_name(re_ds.handle, opd->mem.base));
			} else {
				LOG(stdout, "dummy mem base");
			}
			break;
        case Index:
			if (opd->mem.index) {
	            LOG(stdout, "mem index(%s)", cs_reg_name(re_ds.handle, opd->mem.index));
			} else {
				LOG(stdout, "dummy mem index");
			}
			break;
        default:
            LOG(stderr, "!!!ERROR: Unknown type %d\n",type);
            assert(0);
    }
}

void print_node_operand(re_list_t* node) {
	LOG(stdout,"[node id %d] ",node->id);
    if (node->node_type == UseNode) {
        print_sub_operand((CAST2_USE(node->node))->operand, ((use_node_t*)node->node)->usetype);
    } else if (node->node_type == DefNode) {
        print_operand((CAST2_DEF(node->node))->operand);
    }
}


// print all the registers for one instruction
void print_registers(coredata_t *coredata){
    LOG(stdout, "DEBUG: r0 - 0x%x\n", coredata->corereg.regs[ARM_R0]);
    LOG(stdout, "DEBUG: r1 - 0x%x\n", coredata->corereg.regs[ARM_R1]);
    LOG(stdout, "DEBUG: r2 - 0x%x\n", coredata->corereg.regs[ARM_R2]);
    LOG(stdout, "DEBUG: r3 - 0x%x\n", coredata->corereg.regs[ARM_R3]);
    LOG(stdout, "DEBUG: r4 - 0x%x\n", coredata->corereg.regs[ARM_R4]);
    LOG(stdout, "DEBUG: r5 - 0x%x\n", coredata->corereg.regs[ARM_R5]);
    LOG(stdout, "DEBUG: r6 - 0x%x\n", coredata->corereg.regs[ARM_R6]);
    LOG(stdout, "DEBUG: r7 - 0x%x\n", coredata->corereg.regs[ARM_R7]);
    LOG(stdout, "DEBUG: r8 - 0x%x\n", coredata->corereg.regs[ARM_R8]);
    LOG(stdout, "DEBUG: r9 - 0x%x\n", coredata->corereg.regs[ARM_R9]);
    LOG(stdout, "DEBUG: r10 - 0x%x\n", coredata->corereg.regs[ARM_R10]);
    LOG(stdout, "DEBUG: r11 - 0x%x\n", coredata->corereg.regs[ARM_R11]);
    LOG(stdout, "DEBUG: r12 - 0x%x\n", coredata->corereg.regs[ARM_R12]);
    LOG(stdout, "DEBUG: lr - 0x%x\n", coredata->corereg.regs[ARM_LR]);
    LOG(stdout, "DEBUG: pc - 0x%x\n", coredata->corereg.regs[ARM_PC]);
    LOG(stdout, "DEBUG: sp - 0x%x\n", coredata->corereg.regs[ARM_SP]);
    LOG(stdout, "\n");
}



void print_operand_info(uint8_t ndst, uint8_t nsrc, cs_arm_op** dst, cs_arm_op** src){
    uint8_t i;
    LOG(stdout, "DEBUG: %d dst operands, %d src operands\n", ndst, nsrc);
    for (i=0; i < ndst; i++) {
        LOG(stdout, "DEBUG: %dth dst operand - ", i+1);
        if (dst[i] != NULL) {
            print_operand(dst[i]);
        } else {
            LOG(stdout, "NULL");
        }
        LOG(stdout, "\n");
    }
    for (i=0; i < nsrc; i++) {
        LOG(stdout, "DEBUG: %dth src operand - ", i+1);
        if (src[i] != NULL) {
            print_operand(src[i]);
        } else {
            LOG(stdout, "NULL");
        }
        LOG(stdout, "\n");
    }
}


void print_all_operands(cs_insn *inst) {

	LOG(stdout, "LOG: All operands num: %d\n", inst->detail->arm.op_count);
	// LOG(stdout, "LOG: Explicit operands num: %d\n", inst->explicit_count);
	
	cs_insn *temp;

    for (int i =0 ;i < inst->detail->arm.op_count; i++) {
        LOG(stdout, "LOG: operand type is %d : ", inst->detail->arm.operands[i].type);
        print_operand(&inst->detail->arm.operands[i]);
        LOG(stdout, "\n");
    }
	// for (temp=inst->detail->arm.operands;temp != NULL; temp=temp->next) {
	// 	LOG(stdout, "LOG: operand type is %d\n", temp->op.type);
	// 	print_operand(temp->op);
	// 	LOG(stdout, "\n");
	// }
}


void print_value_of_node(valset_u val, arm_datatype datatype) {
	switch (datatype) {
		case op_byte:
			LOG(stdout, "%#x -> 0x%x (byte)", val.dword, val.byte);
			break;
		case op_word:
			LOG(stdout, "%#x -> 0x%x (word)",val.dword, val.word);
			break;
		case op_dword:
			LOG(stdout, "0x%lx (dword)", val.dword);
			break;
		case op_qword:
			LOG(stdout, "0x%lx 0x%lx (qword)",
				val.qword[0], val.qword[1]);
			break;
		// case op_dqword:
		// 	LOG(stdout, "0x%lx 0x%lx 0x%lx 0x%lx (dqword)",
		// 		val.dqword[0], val.dqword[1],
		// 		val.dqword[2], val.dqword[3]);
		// 	break;
		
		// case op_ssimd:
		// 	LOG(stdout, "0x%lx 0x%lx 0x%lx 0x%lx (dqword)",
        //                         val.dqword[0], val.dqword[1],
        //                         val.dqword[2], val.dqword[3]);
        //                 break;

		default:
			assert("No such datatype" && 0);
	}
}


void print_defnode(def_node_t *defnode){
#ifdef FRCA
	LOG(stdout, "LOG: Def Node (usage=%d) with opd ", defnode->usage);
#else
	LOG(stdout, "LOG: Def Node with opd ");
#endif
	print_operand(defnode->operand);
	LOG(stdout, "\n");
	switch (defnode->val_stat) {
	case Unknown:
		LOG(stdout, "LOG: Both values are unknown\n");
		break;
	case BeforeKnown:
		LOG(stdout, "LOG: Before value is known: ");
		print_value_of_node(defnode->beforeval, arm_get_datatype(defnode->inst));
		LOG(stdout, "\n");
		break;
	case AfterKnown:
		LOG(stdout, "LOG: After value is known: ");
		print_value_of_node(defnode->afterval, arm_get_datatype(defnode->inst));
		LOG(stdout, "\n");
		break;
	case 0x3:
		LOG(stdout, "LOG: Both values are known\n");
		LOG(stdout, "LOG: Before Value ");
		print_value_of_node(defnode->beforeval, arm_get_datatype(defnode->inst));
		LOG(stdout, "\n");
		LOG(stdout, "LOG: After  Value ");
		print_value_of_node(defnode->afterval, arm_get_datatype(defnode->inst));
		LOG(stdout, "\n");
		break;
	}

#ifdef VSA
#if defined (ALIAS_MODULE) && (ALIAS_MODULE == VSA_MODULE)
	if (!list_empty(&defnode->bef_valset.list)) {
		LOG(stdout, "Before Value Set of DefNode: \n");
		print_valset(&defnode->bef_valset);
	}

	if (!list_empty(&defnode->aft_valset.list)) {
		LOG(stdout, "After Value Set of DefNode: \n");
		print_valset(&defnode->aft_valset);
	}
#endif
#endif
	if (defnode->operand->type == ARM_OP_MEM){
		if (defnode->address != 0) {
			LOG(stdout, "LOG: address = 0x%x\n", defnode->address);
		} else {
			LOG(stdout, "LOG: address is unknown\n");
		}
#ifdef VSA
        if (defnode->true_addr) {
                    LOG(stdout, "LOG: truth address is 0x%x\n", defnode->true_addr);
                }
        #if defined (ALIAS_MODULE) && defined(DL_AST)
                LOG(stdout, "Region Type %d\n", defnode->dl_region);
        #endif
#endif
	}

#ifdef VSA
        #if defined (ALIAS_MODULE) && (ALIAS_MODULE == VSA_MODULE)
            if (!list_empty(&defnode->addr_valset.list)) {
                LOG(stdout, "Address Value Set of DefNode: \n");
                print_valset(&defnode->addr_valset);
            }
        #endif
#endif
}


void print_usenode(use_node_t *usenode){
#ifdef FRCA
	LOG(stdout, "LOG: Use Node (usage=%d) with ",usenode->usage);
#else
	LOG(stdout, "LOG: Use Node with ");
#endif
	switch (usenode->usetype) {
		case Opd:
			LOG(stdout, "Opd itself ");
			print_operand(usenode->operand);
			break;
		case Base:
			LOG(stdout, "Base Register %s",cs_reg_name(re_ds.handle, usenode->operand->mem.base));
			break;
		case Index:
			LOG(stdout, "Index Register %s", cs_reg_name(re_ds.handle, usenode->operand->mem.index));
			break;
	}
	LOG(stdout, "\n");
	if (usenode->val_known) {
		LOG(stdout, "LOG: Value is known\n");
		LOG(stdout, "LOG: Value ");
		switch (usenode->usetype) {
		case Opd:
			print_value_of_node(usenode->val, arm_get_datatype(usenode->inst));
			break;
		case Base:
			print_value_of_node(usenode->val, op_dword);
			break;
		case Index:
			print_value_of_node(usenode->val, op_dword);
			break;
		}
		LOG(stdout, "\n");
	} else {
		LOG(stdout, "LOG: Value is unknown\n");
	}

#ifdef VSA
#if defined (ALIAS_MODULE) && (ALIAS_MODULE == VSA_MODULE)
	if (!list_empty(&usenode->valset.list)) {
		LOG(stdout, "Value Set of UseNode: \n");
		print_valset(&usenode->valset);
	}
#endif
#endif
	if ((usenode->usetype == Opd)&&(usenode->operand->type == ARM_OP_MEM)){
		if (usenode->address != 0) {
			LOG(stdout, "LOG: Address = 0x%x\n", usenode->address);
		} else {
			LOG(stdout, "LOG: Address is unknown\n");
		}
#ifdef VSA
        if (usenode->true_addr) {
                    LOG(stdout, "LOG: truth address is 0x%x\n", usenode->true_addr);
                }
        #if defined (ALIAS_MODULE) && defined(DL_AST)
                LOG(stdout, "Region Type %d\n", usenode->dl_region);
        #endif
#endif
	}
#ifdef VSA
        #if defined (ALIAS_MODULE) && (ALIAS_MODULE == VSA_MODULE)
            if (!list_empty(&usenode->addr_valset.list)) {
                LOG(stdout, "Address Value Set of UseNode: \n");
                print_valset(&usenode->addr_valset);
            }
        #endif
#endif
}


void print_instnode(inst_node_t *instnode) {
    LOG(stdout, "LOG: Inst Node with index %d and function ID 0x%x\n", instnode->inst_index, instnode->funcid);
	LOG(stdout, "LOG: Inst forward index %d and address 0x%x\n", re_ds.instnum-1-instnode->inst_index, re_ds.instlist[instnode->inst_index].address);
	print_assembly(re_ds.instlist + instnode->inst_index);
}


void print_node(re_list_t *node){
	LOG(stdout, "LOG: Node ID is %d\n", node->id);
	switch (node->node_type) {
		case InstNode:
			print_instnode(CAST2_INST(node->node));
			break;
		case UseNode:
			print_usenode(CAST2_USE(node->node));
			break;
		case DefNode:
			print_defnode(CAST2_DEF(node->node));
			break;
		default:
			assert(0);
			break;
	}
}


// only print def list
void print_deflist(re_list_t *re_deflist) {
	re_list_t *entry;
	def_node_t *defnode;
	LOG(stdout, "=================================================\n");
	LOG(stdout, "Item of deflist:\n");
	list_for_each_entry_reverse(entry, &re_deflist->deflist, deflist){
		LOG(stdout, "LOG: Node ID is %d\n", entry->id);
		defnode = CAST2_DEF(entry->node);
		print_defnode(defnode);
	}
    LOG(stdout, "=================================================\n");
}


// only print use list
void print_uselist(re_list_t *re_uselist) {
	re_list_t *entry;
	use_node_t *usenode;
	LOG(stdout, "=================================================\n");
	LOG(stdout, "Item of uselist:\n");
	list_for_each_entry_reverse(entry, &re_uselist->uselist, uselist){
		LOG(stdout, "LOG: Node ID is %d\n", entry->id);
		usenode = CAST2_USE(entry->node);
		print_usenode(usenode);
	}
    LOG(stdout, "=================================================\n");
}


// only print inst list
void print_instlist(re_list_t *re_instlist) {
	re_list_t *entry;
	inst_node_t *instnode;
	LOG(stdout, "=================================================\n");
	LOG(stdout, "Item of instlist:\n");
	list_for_each_entry_reverse(entry, &re_instlist->instlist, instlist){
		LOG(stdout, "LOG: Node ID is %d\n", entry->id);
		instnode = CAST2_INST(entry->node);
		print_instnode(instnode);
	}
    LOG(stdout, "=================================================\n");
}


// In general, re_umemlist should be &re_ds.head
// This linked list is a global list
void print_umemlist(re_list_t *re_umemlist) {
	re_list_t *entry, *inst;
    int num = 0;
	LOG(stdout, "=================================================\n");
	LOG(stdout, "Item of umemlist:\n");
	list_for_each_entry_reverse(entry, &re_umemlist->umemlist, umemlist){
		LOG(stdout, "LOG: Node ID is %d\n", entry->id);
        num++;
		if (entry->node_type == DefNode) {
			print_defnode(CAST2_DEF(entry->node));
		}
		if (entry->node_type == UseNode) {
			print_usenode(CAST2_USE(entry->node));
		}
		inst = find_inst_of_node(entry);
		if (inst) {
			print_instnode(CAST2_INST(inst->node));
		} else {
			assert(0);
		}
	}
    printf("Total number of umemlist is %d\n", num);
	LOG(stdout, "=================================================\n");

}


// heavy print function 
// print all the elements in the core list
void print_corelist(re_list_t *re_list) {
	re_list_t *entry;
	LOG(stdout, "~~~~~~~~~~~~~~~~~~~~~~Start of Core List~~~~~~~~~~~~~~~~~~~~~~\n");
	list_for_each_entry_reverse(entry, &re_list->list, list) {
		if (entry->node_type == InstNode) LOG(stdout, "\n");
		
		LOG(stdout, "=================================================\n");
		LOG(stdout, "LOG: Node ID is %d\n", entry->id);
		if (entry->node_type == InstNode) {
			print_instnode(CAST2_INST(entry->node));
		}
		if (entry->node_type == DefNode) {
			print_defnode(CAST2_DEF(entry->node));
		}
		if (entry->node_type == UseNode) {
			print_usenode(CAST2_USE(entry->node));
		}
	}
	LOG(stdout, "~~~~~~~~~~~~~~~~~~~~~~~End of Core List~~~~~~~~~~~~~~~~~~~~~~~\n");

}

#ifdef VSA
#if defined (ALIAS_MODULE) && (ALIAS_MODULE == VSA_MODULE)
void print_valsetlist(re_list_t *re_list) {
	re_list_t *entry;
	LOG(stdout, "~~~~~~~~~~~~~~~~~~~~~Start of Valset List~~~~~~~~~~~~~~~~~~~~~\n");
	list_for_each_entry(entry, &re_list->list, list) {
		
		LOG(stdout, "=================================================\n");
		LOG(stdout, "LOG: Node ID is %d\n", entry->id);
		if (entry->node_type == InstNode) {
			print_instnode(CAST2_INST(entry->node));
		}
		if (entry->node_type == DefNode) {
			print_defnode(CAST2_DEF(entry->node));
		}
		if (entry->node_type == UseNode) {
			print_usenode(CAST2_USE(entry->node));
		}
		if (entry->node_type == InstNode) LOG(stdout, "\n");
	}
	LOG(stdout, "~~~~~~~~~~~~~~~~~~~~~~End of Valset List~~~~~~~~~~~~~~~~~~~~~~\n");
}

void print_uvalset_list(re_list_t *re_list) {
	re_list_t *entry;
	cs_arm_op *opd;
	re_value_set *addr_valset;
	
	LOG(stdout, "~~~~~~~~~~~~~~~~~~~~~Start of Unknown Valset List~~~~~~~~~~~~~~~~~~~~~\n");
	list_for_each_entry_reverse(entry, &re_list->list, list) {
		if (entry->node_type == InstNode) continue;

		opd = GET_OPERAND(entry);
		if (opd->type == ARM_OP_MEM) {
			addr_valset = GET_ADDR_VALSET(entry);
			if (list_empty(&addr_valset->list)) {
				print_node(entry);
			}
		}
	}
	LOG(stdout, "~~~~~~~~~~~~~~~~~~~~~End of Unknown Valset List~~~~~~~~~~~~~~~~~~~~~\n");
}
#endif

void print_maxfuncid() {
	LOG(stdout, "=================================================\n");
	LOG(stdout, "Max Function ID is %d\n", re_ds.maxfuncid);
	LOG(stdout, "=================================================\n");
}

void print_func_info() {
	int i;

	for (i=0; i<=re_ds.maxfuncid; i++) {
		LOG(stdout, "Information for function %d:\n", i);
		if (re_ds.flist[i].returned) {
			LOG(stdout, "\tFunction Returned\n");
		} else {
			LOG(stdout, "\tFunction still Active\n");
		}
		LOG(stdout, "\tstart %d, end %d\n", re_ds.flist[i].start, re_ds.flist[i].end);
		LOG(stdout, "\tstack_start 0x%x, stack_end 0x%x\n", re_ds.flist[i].stack_start, re_ds.flist[i].stack_end);
		
	}
}

#if defined (ALIAS_MODULE) && (ALIAS_MODULE == VSA_MODULE)
char* convert_region_type(region_type type) {
	char *region_name = NULL;
	switch (type) {
	case REG_REGION:
		region_name = "Register Region";
		break;
	case GLOBAL_REGION:
		region_name = "Global Region";
		break;
	//case RO_REGION:
	//	region_name = "Read Only Region";
	//	break;
	case GS_REGION:
		region_name = "GS Region";
		break;
	case CONST_REGION:
		region_name = "Constant Region";
		break;
	case STACK_REGION:
		region_name = "Stack Region";
		break;
	case HEAP_REGION:
		region_name = "Heap Region";
		break;
	case OTHER_REGION:
		region_name = "Other Region";
		break;
	}
	assert(region_name);
	return region_name;
}

void print_one_region(re_region_t *entry) {
	LOG(stdout, "\tRegion ID is %d\n", entry->reg_id);
	LOG(stdout, "\tRegion Name is %s\n", convert_region_type(entry->type));
	LOG(stdout, "\tRegion SUBID is %d\n", entry->sub_id);
	if (entry->base_addr != 0) {
		LOG(stdout, "\tRegion Base Address is 0x%x\n", entry->base_addr);
	}

	if (entry->segment_id != -1) {
		LOG(stdout, "\tRegion Segment ID is %d\n",
			entry->segment_id);
		LOG(stdout, "\tRegion Low Address is 0x%x\n",
			re_ds.coredata->coremem[entry->segment_id].low);
		LOG(stdout, "\tRegion High Address is 0x%x\n",
			re_ds.coredata->coremem[entry->segment_id].high);
	}
}

void print_region_info(re_region_t *head) {
	re_region_t *entry;
	LOG(stdout, "~~~~~~~~~~~~~~~~~~Start of Current Region Info~~~~~~~~~~~~~~~~~~\n");

	list_for_each_entry(entry, &head->list, list) {
		print_one_region(entry);
	}

	LOG(stdout, "~~~~~~~~~~~~~~~~~~~End of Current Region Info~~~~~~~~~~~~~~~~~~~\n");
}

void print_strided_interval(re_si *vs) {
//	LOG(stdout, "\tValue Set bits = %d\n", vs->bits);
	if (si_is_full(vs)) {
		LOG(stdout, "\t(1[-inf, inf])");
#define ADDR_MIN 0x80000000
#define ADDR_MAX 0xc0000000
	} else if ((vs->lower_bound > ADDR_MIN) && (vs->upper_bound < ADDR_MAX)) {
		LOG(stdout, "\t(%ld[%lx, %lx])", vs->stride, vs->lower_bound, vs->upper_bound);
	} else {
		LOG(stdout, "\t(%ld[%ld, %ld])", vs->stride, vs->lower_bound, vs->upper_bound);
	}
}

void print_valset_entry(re_value_set *entry) {
	print_one_region(entry->region);
	//LOG(stdout, "\t%p\n", entry->region);
	print_strided_interval(&entry->si);
	LOG(stdout, "\n");
}

void print_valset(re_value_set *head) {
	re_value_set *entry;
	LOG(stdout, "~~~~~~~~~Start of Value Set Info~~~~~~~~~\n");

	list_for_each_entry(entry, &head->list, list) {
		print_valset_entry(entry);
	}

	LOG(stdout, "~~~~~~~~~~End of Value Set Info~~~~~~~~~~\n");
}
#endif
#endif
// only print all the operands of the current instruction 
void print_info_of_current_inst(re_list_t *inst){
	re_list_t *entry;
	LOG(stdout, "~~~~~~~~~~~~~~~~~~~Start of Current Inst Info~~~~~~~~~~~~~~~~~~~\n");
	LOG(stdout, "LOG: Node ID is %d\n", inst->id);
	print_instnode(inst->node);
	list_for_each_entry_reverse(entry, &inst->list, list) {
		LOG(stdout, "=================================================\n");
		if (entry == &re_ds.head) break;
		LOG(stdout, "LOG: Node ID is %d\n", entry->id);
		if (entry->node_type == InstNode) break;
		if (entry->node_type == DefNode) {
			print_defnode(CAST2_DEF(entry->node));
		}
		if (entry->node_type == UseNode) {
			print_usenode(CAST2_USE(entry->node));
		}
	}
	LOG(stdout, "~~~~~~~~~~~~~~~~~~~~End of Current Inst info~~~~~~~~~~~~~~~~~~~~\n");
}


// log all the instructions to one file called "instructions"
void log_instructions(cs_insn *instlist, unsigned instnum){
	FILE *file;
	if ((file=fopen("instructions", "w")) == NULL) {
		LOG(stderr, "ERROR: instructions file open error\n");
		assert(0);
	}
	int i;
	for (i=0;i<instnum;i++) {
		fprintf(file, "0x%08lx:\t%s\n", instlist[i].address, instlist[i].mnemonic);
	}
}

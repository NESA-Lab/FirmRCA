#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <capstone/capstone.h>
#include "global.h"
#include "disassemble.h"
#include "insthandler_arm.h"
#include "reverse_exe.h"
#include "re_stackpointer.h"
#include "analyze_result.h"


int *inst_tainted; 
int taintpair;
int branch;

static void taint_operand(int reg, size_t address){
	re_list_t node; 
	use_node_t use;
	re_list_t* prevdef = NULL; 
	int dtype;
	cs_arm_op * opd; 

    re_list_t srclist;
#ifdef FRCA
    re_list_t absolute;
#endif
    re_list_t* entry, *temp;
	re_list_t* base, *index; 
	re_list_t *defsrc[NOPD];
	int nuse, i; 

//add the new node to the main list 
	memset(&use, 0, sizeof(use_node_t));
	// support reg taint and address taint
	if (reg != 0) {
		opd = (cs_arm_op *)calloc(1, sizeof(cs_arm_op));	
		opd->type = ARM_OP_REG; 
		// opd->data.reg = *reg;
		opd->reg = reg;
		// opd->datatype = op_dword; 
	} else if (address != 0) {
		opd = (cs_arm_op *)calloc(1, sizeof(cs_arm_op));	
		opd->type = ARM_OP_MEM; 
		// opd->data.reg = *reg;
		use.address = address;
		// opd->datatype = op_dword;
	}
	use.operand = opd; 
	use.usetype = Opd;
	use.inst = re_ds.root;
	node.node_type = UseNode; 
	node.node = &use; 
	node.id = 0;
	
#if defined (ALIAS_MODULE) && (ALIAS_MODULE == VSA_MODULE)
	INIT_LIST_HEAD(&(use.valset.list));
	INIT_LIST_HEAD(&(use.addr_valset.list));
#endif
	list_add_tail(&node.list, &re_ds.head.list);

	INIT_LIST_HEAD(&srclist.uselist);	
	add_to_uselist(&node, &srclist);

	// This while-loop recursively taints use nodes
	while(!list_empty(&srclist.uselist)){


		list_for_each_entry_safe_reverse(entry, temp, &srclist.uselist, uselist){
			LOG(stdout, " ============= One pair of taint propagation\n");	

			if(entry != &node){
				print_instnode(find_inst_of_node(entry)->node);
				inst_tainted[CAST2_INST(find_inst_of_node(entry)->node)->inst_index] = 1;
				if(CAST2_INST(find_inst_of_node(entry)->node)->inst_index > get_root_cause_rev_idx()) {
					branch++;
					goto endbranch;
				}
			}
			
			taintpair++;

			print_usenode(entry->node);

			// find the previous write of the use address
			
#ifdef FRCA
			prevdef = find_prev_write_of_address(entry, &dtype);
			if(prevdef){
				LOG(stdout, "=> Found prev memory write as following\n");
				inst_tainted[CAST2_INST(find_inst_of_node(prevdef)->node)->inst_index] = 1;
				// if (prevdef->node_type == DefNode) {
				// 	LOG(stdout, "This is a def node.\n");
				// } else if (prevdef->node_type == UseNode) {
				// 	add_to_uselist(prevdef, &srclist);
				// 	LOG(stdout, "Add this node into srclist.\n");
				// }
				print_instnode(find_inst_of_node(prevdef)->node);
				// taint the previous definition
				LOG(stdout, "=> Found prevdef as following\n");

				print_instnode(find_inst_of_node(prevdef)->node);
				
				LOG(stdout, "=> Found its def node as following\n");
				print_defnode(prevdef->node);

				if(node_is_exp(prevdef, false)){
					base = NULL;
					index = NULL;
					get_element_of_exp(prevdef, &index, &base);
					if(base){
						LOG(stdout, "=> Found its base operand, add to srclist\n");
						add_to_uselist(base, &srclist);
					}
					if(index){
						LOG(stdout, "=> Found its index operand, add to srclist\n");
						add_to_uselist(index, &srclist);
					}
				}

				get_src_of_def(prevdef, defsrc, &nuse);

				for(i = 0; i < nuse; i++){
					if (CAST2_USE(defsrc[i]->node)->operand->type == ARM_OP_IMM) 
						inst_tainted[CAST2_INST(find_inst_of_node(prevdef)->node)->inst_index] = 1;
					if(CAST2_USE(defsrc[i]->node)->operand->type == ARM_OP_REG)  {
						LOG(stdout, "=> Found a register operand, add to srclist\n");
						add_to_uselist(defsrc[i], &srclist);
					}
					if(CAST2_USE(defsrc[i]->node)->operand->type == ARM_OP_MEM){
						LOG(stdout, "=> Found a memory operand, add to srclist\n");
						add_to_uselist(defsrc[i], &srclist);

						base = NULL;
						index = NULL;

						get_element_of_exp(defsrc[i], &index, &base);
						if(base) {
							LOG(stdout, "=> Found its base operand, add to srclist\n");
							add_to_uselist(base, &srclist);
						}
						if(index) {
							LOG(stdout, "=> Found its index operand, add to srclist\n");
							add_to_uselist(index, &srclist);
						}
					}
				}
			} 
#endif

			prevdef = find_prev_def_of_use(entry, &dtype);

			// taint the previous definition
			if(prevdef){
				LOG(stdout, "=> Found prevdef as following\n");

				print_instnode(find_inst_of_node(prevdef)->node);
				
				print_defnode(prevdef->node);

				if(node_is_exp(prevdef, false)){
					base = NULL;
					index = NULL;
					get_element_of_exp(prevdef, &index, &base);
					if(base){
						LOG(stdout, "=> Found its base operand, add to srclist\n");
						add_to_uselist(base, &srclist);
					}
					if(index){
						LOG(stdout, "=> Found its index operand, add to srclist\n");
						add_to_uselist(index, &srclist);
					}
				}

				get_src_of_def(prevdef, defsrc, &nuse);

				for(i = 0; i < nuse; i++){
#ifdef FRCA
// NOTE: the original POMP and POMP++ code do not taint the instruction with the immediate operand 
					if (CAST2_USE(defsrc[i]->node)->operand->type == ARM_OP_IMM) 
						inst_tainted[CAST2_INST(find_inst_of_node(prevdef)->node)->inst_index] = 1;
#endif
					if(CAST2_USE(defsrc[i]->node)->operand->type == ARM_OP_REG)  {
						LOG(stdout, "=> Found a register operand, add to srclist\n");
						add_to_uselist(defsrc[i], &srclist);
					}
					if(CAST2_USE(defsrc[i]->node)->operand->type == ARM_OP_MEM){
						LOG(stdout, "=> Found a memory operand, add to srclist\n");
						add_to_uselist(defsrc[i], &srclist);

						base = NULL;
						index = NULL;

						get_element_of_exp(defsrc[i], &index, &base);
						if(base) {
							LOG(stdout, "=> Found its base operand, add to srclist\n");
							add_to_uselist(base, &srclist);
						}
						if(index) {
							LOG(stdout, "=> Found its index operand, add to srclist\n");
							add_to_uselist(index, &srclist);
						}
					}
				}

				// For insn that accesses memory, address is useful
#ifdef FRCA
				if (CAST2_DEF(prevdef->node)->address != 0) {
					prevdef = find_prev_write_of_address(prevdef, &dtype);
					if(prevdef){
						inst_tainted[CAST2_INST(find_inst_of_node(prevdef)->node)->inst_index] = 1;
						// if (prevdef->node_type == DefNode) {
						// 	LOG(stdout, "This is a def node.\n");
						// } else if (prevdef->node_type == UseNode) {
						// 	add_to_uselist(prevdef, &srclist);
						// 	LOG(stdout, "Add this node into srclist.\n");
						// }
						// print_instnode(find_inst_of_node(prevdef)->node);
					} 
				}
#endif
			}		
			else{
				branch++;
			}

endbranch:

			list_del(&entry->uselist);
		
			LOG(stdout, " ============= Finish one pair of taint propagation\n");	
		}
	}
	list_del(&node.list);		
}
 
size_t set_taint_sink(int* index, int* base) {
	*index = 0;
	*base = 0;
	size_t memaddr = 0;
	switch (re_ds.root->id)
	{
		// for memory illegal read/write
		case ARM_INS_ADR:
		case ARM_INS_LDR:
		case ARM_INS_LDRB:
		case ARM_INS_LDRSB:
		case ARM_INS_LDRH:
		case ARM_INS_LDRSH:
		case ARM_INS_LDRD:
		case ARM_INS_TBB:
		case ARM_INS_TBH:
		case ARM_INS_STR:
		case ARM_INS_STRB:
		case ARM_INS_STRH:
		case ARM_INS_STRD:
			*index = re_ds.root->detail->arm.operands[1].mem.index;
			*base = re_ds.root->detail->arm.operands[1].mem.base;
			break;
        case ARM_INS_STM:
        case ARM_INS_STMDA:
        case ARM_INS_STMDB:
        case ARM_INS_STMIB:
        case ARM_INS_LDM:
        case ARM_INS_LDMDA:
        case ARM_INS_LDMDB:
        case ARM_INS_LDMIB:
            // *index = re_ds.root->detail->arm.operands[0].reg;
			*base = re_ds.root->detail->arm.operands[0].reg;
			break;
		// for instruction illegal fetch
		case ARM_INS_BLX:
		case ARM_INS_BX:
			*base = re_ds.root->detail->arm.operands[0].reg;
			break;
		case ARM_INS_POP:
		// for pop instruction, the stack address should be tainted
			for (int i = 0; i < re_ds.root->detail->arm.op_count; i++) {
				if (re_ds.root->detail->arm.operands[i].type == ARM_OP_REG &&
					re_ds.root->detail->arm.operands[i].reg == ARM_REG_PC) {
				
					// *base = re_ds.root->detail->arm.operands[i].reg;
					memaddr = re_ds.coredata->corereg.regs[ARM_SP] - 4; // NOTE: -4 is correct only when pc is the final register to modify
					assert(i == re_ds.root->detail->arm.op_count - 1);
					break;
				}
			}
			break;
		default:
			break;
	}
	// base = re_ds.root->detail->arm.operands[1].mem.base ? re_ds.root->detail->arm.operands[1].mem.base : 0;
	// index = re_ds.root->detail->arm.operands[1].mem.index ? re_ds.root->detail->arm.operands[1].mem.index : 0;
	return memaddr;
}

#ifdef FRCA
bool absolute_address_data(inst_node_t* read_node, inst_node_t* write_node){
	// Check whether reads and writes use exactly the same address and data
	for (int ri = 0; ri < read_node->acnum; ri++) {
		for (int wi = 0; wi < write_node->acnum; wi++) {
			if (read_node->accesses[ri]->address == write_node->accesses[wi]->address &&
				read_node->accesses[ri]->value == write_node->accesses[wi]->value) {
				return true;
			}
		}
	}
	return false;
}

struct address_counter {
	uint32_t address;
	int count;
	struct address_counter* next;
};

void add_address_counter(struct address_counter* head, uint32_t address) {
	struct address_counter* p = head;
	while (p->next != NULL) {
		if (p->address == address) {
			p->count++;
			return;
		}
		p = p->next;
	}
	struct address_counter* new = (struct address_counter*)calloc(1,sizeof(struct address_counter));
	new->address = address;
	new->count = 1;
	p->next = new;
}

int get_address_counter(struct address_counter* head, uint32_t address) {
	struct address_counter* p = head;
	while (p->next != NULL) {
		if (p->address == address) {
			return p->count;
		}
		p = p->next;
	}
	return 0;
}

bool is_conditional_jump(cs_insn* insn) {
	switch (insn->id)
	{
		case ARM_INS_CBZ:
		case ARM_INS_CBNZ:
		case ARM_INS_TBB:
		case ARM_INS_TBH:
		case ARM_INS_IT:
			return true;
		default:
			return false;
	}
}

void taint_ranking(void) {
	// Ranking the tainted instructions heuristically
	re_list_t* entry;
	inst_node_t* inst_node;
	// initialize the score to 100
	for (int i = 0; i < re_ds.instnum; i++) {
		if (inst_tainted[i] == 1) {
			inst_tainted[i] = 100;
		}
	}

	// Default strategy
	// +: reading and writing the same memory
	#ifndef ABLATION2 
	inst_node_t* read_node = NULL;
	
	list_for_each_entry_reverse(entry, &re_ds.head.list, list) {
		if (entry->node_type == InstNode) {
			inst_node = CAST2_INST(entry->node);
			if (inst_tainted[inst_node->inst_index]) {
				// printf("%s\n",inst_node->inst->mnemonic);
				switch (check_mem_access(inst_node->inst))
				{
				case mem_read:
					if (NULL == read_node) {
						printf("better be 1 : acnum = %d\n",inst_node->acnum);
						read_node = inst_node;
					}
					break;
				case mem_write:
					if(NULL != read_node) {
						if (absolute_address_data(read_node, inst_node)) {
							inst_tainted[inst_node->inst_index] += 100;
							// make sure inst_tainted[index] not equal to 0 (0 means untainted)
							if (inst_tainted[inst_node->inst_index] == 0) {
								inst_tainted[inst_node->inst_index]++;
							}
							read_node = NULL;
						}
					}
					break;
				default:
					break;
				}
			}
		}
	}
	#endif
	
	// Ranking strategy 1, decrease the suspicious score of redundant loops.
	// -: a lot of redundant instructions
#ifndef ABLATION1
	struct address_counter* head = (struct address_counter*)calloc(1,sizeof(struct address_counter));
	list_for_each_entry_reverse(entry, &re_ds.head.list, list) {
		if (entry->node_type == InstNode) {
			inst_node = CAST2_INST(entry->node);
			if (inst_tainted[inst_node->inst_index]) {
				add_address_counter(head, inst_node->inst->address);
			}
		}
	}
	list_for_each_entry_reverse(entry, &re_ds.head.list, list) {
		if (entry->node_type == InstNode) {
			inst_node = CAST2_INST(entry->node);
			if (inst_tainted[inst_node->inst_index]) {
				inst_tainted[inst_node->inst_index] -= get_address_counter(head, inst_node->inst->address);
				// make sure inst_tainted[index] not equal to 0 (0 means untainted)
				if (inst_tainted[inst_node->inst_index] == 0) {
					inst_tainted[inst_node->inst_index]--;
				}
			}
		}
	}
#endif
	// TODO -: the middle ldr instructions of a sequence of ldr instructions

	// Ranking strategy 2, increase the suspicious score of conditional jumps
	// +: conditional jumps
// #ifndef ABLATION2 
// 	list_for_each_entry_reverse(entry, &re_ds.head.list, list) {
// 		if (entry->node_type == InstNode) {
// 			inst_node = CAST2_INST(entry->node);
// 			if (inst_tainted[inst_node->inst_index]) {
// 				if (is_conditional_jump(inst_node->inst)) {
// 					inst_tainted[inst_node->inst_index] += 20;
// 					// make sure inst_tainted[index] not equal to 0 (0 means untainted)
// 					if (inst_tainted[inst_node->inst_index] == 0) {
// 						inst_tainted[inst_node->inst_index]++;
// 					}
// 				}
// 			}
// 		}
// 	}
// #endif
}

#endif
static void taint_analysis(void){
	int index, base;
	uint32_t memaddr;
	int taintsize;
	int i; 

	index = 0;
	base = 0;

	if(!re_ds.root)
		return;
	LOG(stdout, "Start Taint Analysis.\n");
	// NOTE upgrade POMP and VSA 's simple taint method
	memaddr = set_taint_sink(&index, &base);

	if(base){
	
		LOG(stdout,"Base name is %s \n", cs_reg_name(re_ds.handle, base));

		taint_operand(base, 0);
	}

	if(index){
		LOG(stdout,"Index name is %s \n", cs_reg_name(re_ds.handle, index));
	
		taint_operand(index, 0);
	}

	// for memory addr tainting
	if (memaddr) {
		LOG(stdout, "Taint corrupted memory address %#x\n", memaddr);
		taint_operand(0, memaddr);
	}

#ifdef FRCA
	taint_ranking();
#endif
	taintsize = 0;
	
	for(i=0; i < re_ds.instnum; i++){
		taintsize += inst_tainted[i] ? 1 : 0;
	}	
	printf("======= The total number of tainted instruction is %d. These instruction are:\n", taintsize);

	for (i=0; i < re_ds.instnum; i++){
		if(inst_tainted[i]){
			// always output the tainting result
#ifdef FRCA
			printf("Current Instruction at %d with score %d is %#lx : %s\t%s\n",i,inst_tainted[i],
    			re_ds.instlist[i].address, re_ds.instlist[i].mnemonic, re_ds.instlist[i].op_str);
#else
            printf("Current Instruction at %d is %#lx : %s\t%s\n",i, re_ds.instlist[i].address,  re_ds.instlist[i].mnemonic,  re_ds.instlist[i].op_str);
#endif
			// print_assembly(&re_ds.instlist[i]);
		}
	}

	printf("======= The total number of branch is %d\n", branch);
	printf("======= The total number of taint pair is %d\n", taintpair);
}

void analyze_corelist(void){
//fist round of analysis using taint
	
	taintpair = 0;
	branch = 0;
	inst_tainted = malloc(re_ds.instnum * sizeof(int));
	memset(inst_tainted, 0, re_ds.instnum*sizeof(int));
	taint_analysis();
	free(inst_tainted);
}









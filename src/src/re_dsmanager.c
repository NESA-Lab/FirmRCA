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
#include "inst_opd.h"

#ifdef VSA
#include "syshandler.h"
#include "solver.h"
#include "bin_alias.h"
#include "analyze_result.h"
#endif
re_list_t * find_next_def_of_def(re_list_t *def, int *type) __attribute__ ((alias("find_next_def_of_use")));

re_list_t * find_prev_def_of_def(re_list_t *def, int *type) __attribute__ ((alias("find_prev_def_of_use")));

re_list_t * find_next_use_of_def(re_list_t *def, int *type) __attribute__ ((alias("find_next_use_of_use")));

re_list_t * find_prev_use_of_def(re_list_t *def, int *type) __attribute__ ((alias("find_prev_use_of_use")));


unsigned maxfuncid(void){

        unsigned id;
        re_list_t* entry;

        id = 0;
        list_for_each_entry(entry, &re_ds.head.list, list){
                if(entry->node_type != InstNode)
                        continue;
                id = CAST2_INST(entry->node)->funcid > id ? CAST2_INST(entry->node)->funcid : id;                     
        }
        return id;
}


re_list_t * lookfor_inst_nexttocall(re_list_t* instnode){

        re_list_t *entry;
        inst_node_t *inst, *curinst;
        cs_insn *arminst, *curarminst;
        //to deal with the cases of recurssion
        int recnum;

        recnum = 0;

        inst = CAST2_INST(instnode->node);
        arminst = &re_ds.instlist[inst->inst_index];

        list_for_each_entry(entry, &re_ds.head.list, list){
                if(entry->node_type != InstNode)
                        continue;

                curinst = CAST2_INST(entry->node);
                curarminst = &re_ds.instlist[curinst->inst_index];


                if(curarminst->address == arminst->address)
                        recnum++;

                //find the returned instruction and the recursive layer matches 
                if(arminst->address + arminst->size == curarminst->address){
                        if(!recnum)
                                return entry;
                        recnum--;
                }
        }

        return NULL;
}


void funcid_of_inst(re_list_t* instnode){

        re_list_t* entry, *previnstnode;
        inst_node_t* previnst;
        inst_node_t* inst;
        cs_insn *arminst;
        cs_insn *prevarminst;

        inst = CAST2_INST(instnode->node);

        if(list_empty(&re_ds.head.list)){
                inst->funcid = 0;
                goto adjust_boundary;
        }

        //find the last instruction 
        list_for_each_entry(entry, &re_ds.head.list, list){
                if(entry->node_type != InstNode)
                        continue;

                previnst = CAST2_INST(entry->node);
                break;
        }

        arminst = &re_ds.instlist[inst->inst_index];
        prevarminst = &re_ds.instlist[previnst->inst_index];

        //determine the function id based on the instruction type

        switch(get_insn_type(re_ds.handle, arminst)){
                //if this is return, as we are looking at the trace reversely, 
                //then a new function start
                case CS_GRP_RET:
                        inst->funcid = maxfuncid() + 1;
                        break;
                case CS_GRP_CALL:

                        previnstnode = lookfor_inst_nexttocall(instnode);
                        if(!previnstnode){
                                inst->funcid = maxfuncid() + 1;
                                // print_instnode(inst);
                                //assert(0);
                                break;
                        }

                        previnst = CAST2_INST(lookfor_inst_nexttocall(instnode)->node);
                        inst->funcid = previnst->funcid;
                        break;
                // case insn_callcc:
                //         assert(0);
                //         break;

                //not special, simply classify it to the previous instruction
                default:
                        inst->funcid = previnst->funcid;
                        break;
        }
adjust_boundary:

	// adjust_func_boundary(instnode);
	return;
}

#ifdef VSA
static int adjust_val_offset(re_list_t* entry, int type){

	int regid;
//use node 
	if(entry->node_type == UseNode){

		if(CAST2_USE(entry->node)->usetype == Opd && CAST2_USE(entry->node)->operand->type == ARM_OP_REG)
				regid = CAST2_USE(entry->node)->operand->reg;

			if(CAST2_USE(entry->node)->usetype == Base)
				regid = CAST2_USE(entry->node)->operand->mem.base;
			if(CAST2_USE(entry->node)->usetype == Index)
				regid = CAST2_USE(entry->node)->operand->mem.index;
	}
	
	if(entry->node_type == DefNode){
		if(CAST2_DEF(entry->node)->operand->type  == ARM_OP_REG)
				regid = CAST2_DEF(entry->node)->operand->reg;
	}

	// note note this
	// if(type == SUB && (regid == get_ah_id() || regid == get_bh_id() || regid == get_ch_id() || regid == get_dh_id()))
	// 	return 1; 

	return 0;
}
#endif
//get the value for a new use whose address is known 
//the use must be an expression
//if the use is a register, assignment to it will occur in add_new_use
static bool assign_use_mem_val(re_list_t* exp, valset_u * rv, re_list_t* uselist){
#ifdef VERBOSE
	LOG(stdout, "assign_use_mem_val: address = %#x, operand = ",
		CAST2_USE(exp->node)->address);
	print_node_operand(exp);
	LOG(stdout, "\n");
#endif

//basic logic
//get the value for the use byte by byte 
//for each byte, there are four different ways
//1. Check next def  
//2. Check next use
//3. Check prev def
//4. Check prev use
//attention, must take care of the unknown memory write between any memory accesses

	int dtype; 
	size_t memsize;
	unsigned index;  
	valset_u tv; 
	unsigned oriaddr;
	cs_arm_op tmpopd; 
	cs_arm_op *oriopd;	
	use_node_t* use;
	re_list_t *nextdef, *nextuse, *prevdef, *prevuse; 

	assert(exp->node_type == UseNode);

	use = CAST2_USE(exp->node);
	memsize = translate_datatype_to_byte(use->inst);
	oriaddr = use->address;

	oriopd = use->operand; 
	memcpy(&tmpopd, use->operand, sizeof(cs_arm_op));		

//process the destination byte by byte; 
	for(index = 0; index < memsize; index++){
#ifdef VERBOSE
	LOG(stdout, "assign_use_mem_val: index %d in memsize %d\n", index, memsize);
#endif
////////very important here!
		re_ds.alias_offset = index;
//////// 


//get the next define for one byte and restore the contexts
		use->operand = &tmpopd; 
		use->address = oriaddr + index; 
		// use->operand->datatype = op_byte; 
		nextdef = find_next_def_of_use(exp, &dtype);
		use->address = oriaddr; 
		use->operand = oriopd; 

	// the base for alias check is the exp
	// so the address offset for check is the index here		

		if(nextdef && !(CAST2_DEF(nextdef->node)->val_stat & BeforeKnown)){
#ifdef VERBOSE
	LOG(stdout, "assign_use_mem_val: goto nextuse (case 1).\n");
#endif				
			goto nextuse;
}
		if(obstacle_between_two_targets(&re_ds.head, nextdef, exp)){
#ifdef VERBOSE
	LOG(stdout, "assign_use_mem_val: goto nextuse (case 2).\n");
#endif				
			goto nextuse;  
}
		//get one byte from core dump
		if(!nextdef){

			//get one byte for the current address
			
			use->operand = &tmpopd; 
			use->address = oriaddr + index; 
			// use->operand->datatype = op_byte; 
						
			if (get_value_from_coredump(exp, &tv) == BAD_ADDRESS) {
				use->address = oriaddr; 
				use->operand = oriopd;
				// assert_address(); // note: only the crash site will trigger this assert, but that is ok.
				LOG(stderr,"BAD_ADDRESS at assign_use_mem_val\n");
			}

			//assign the byte to the corrsponding location 
			memcpy(((void*)rv) + index, &tv.byte, 1);
			use->address = oriaddr; 
			use->operand = oriopd;
			
			//one byte has been resolved; continue with the next byte
			continue; 
		}

//get the value for the current byte from the next define
		
		if(true){	
//take care of the address difference between the next define and the target
			int offset = index + oriaddr - CAST2_DEF(nextdef->node)->address; 
			void * copyaddr = ((void*)&CAST2_DEF(nextdef->node)->beforeval) + offset; 
			memcpy(((void*)rv) + index, copyaddr, 1);
			continue;
		}

nextuse:				
		re_ds.alias_offset = index;

		use->operand = &tmpopd; 
		
		use->address = oriaddr + index; 
		// use->operand->datatype = op_byte; 
		nextuse = find_next_use_of_use(exp, &dtype);
		use->address = oriaddr; 
		use->operand = oriopd; 

		if(!nextuse){
#ifdef VERBOSE
	LOG(stdout, "assign_use_mem_val: goto prevdef (case 1).\n");
#endif	
			goto prevdef;
}
		if(nextdef && node1_add_before_node2(nextuse, nextdef)){
#ifdef VERBOSE
	LOG(stdout, "assign_use_mem_val: goto prevdef (case 2).\n");
#endif	
			goto prevdef; 
			}
		if(!CAST2_USE(nextuse->node)->val_known){
#ifdef VERBOSE
	LOG(stdout, "assign_use_mem_val: goto prevdef (case 3).\n");
#endif	
			goto prevdef; 
}
		if(obstacle_between_two_targets(&re_ds.head, nextuse, exp)){
#ifdef VERBOSE
	LOG(stdout, "assign_use_mem_val: goto prevdef (case 4).\n");
#endif	
			goto prevdef;  
}
		if(true){
			int offset = index + oriaddr - CAST2_USE(nextuse->node)->address;	
                        void * copyaddr = ((void*)&CAST2_USE(nextuse->node)->val) + offset;
                        memcpy(((void*)rv) + index, copyaddr, 1);
			continue;
                }

prevdef:

	//now the previous define or use is the base for alias check
	//as we only get one byte, no need to add any offset for alias  
		re_ds.alias_offset = 0;
		
		use->operand = &tmpopd; 
		use->address = oriaddr + index; 
		// use->operand->datatype = op_byte; 
		prevdef = find_prev_def_of_use(exp, &dtype);
		use->address = oriaddr; 
		use->operand = oriopd; 

		//there is no previous define; then try to find the previous use
		if(!prevdef){
#ifdef VERBOSE
	LOG(stdout, "assign_use_mem_val: goto prevuse (case 1).\n");
#endif	
			goto prevuse; }

		if(!(CAST2_DEF(prevdef->node)->val_stat & AfterKnown)){
#ifdef VERBOSE
	LOG(stdout, "assign_use_mem_val: goto prevuse (case 2).\n");
#endif	
			goto prevuse; }

		if(obstacle_between_two_targets(&re_ds.head,exp, prevdef)){
#ifdef VERBOSE
	LOG(stdout, "assign_use_mem_val: goto prevuse (case 3).\n");
#endif	
			goto prevuse;  }

		if(true){
			int offset = index + oriaddr - CAST2_DEF(prevdef->node)->address;
			void * copyaddr = ((void*)&CAST2_DEF(prevdef->node)->afterval) + offset; 
			memcpy(((void*)rv) + index, copyaddr, 1);
			continue;
		}

prevuse:		
		re_ds.alias_offset = 0;
		
		use->operand = &tmpopd; 
		use->address = oriaddr + index; 
		// use->operand->datatype = op_byte; 
		prevuse = find_prev_use_of_use(exp, &dtype);
		use->address = oriaddr; 
		use->operand = oriopd; 


		if(!prevuse){
#ifdef VERBOSE
	LOG(stdout, "assign_use_mem_val: goto out (case 1).\n");
#endif			
			goto out;
}
		if(prevdef && node1_add_before_node2(prevdef, prevuse)){
#ifdef VERBOSE
	LOG(stdout, "assign_use_mem_val: goto out (case 2).\n");
#endif	
			goto out;
		 }
		if(!CAST2_USE(prevuse->node)->val_known){
#ifdef VERBOSE
	LOG(stdout, "assign_use_mem_val: goto out (case 3).\n");
#endif				
			goto out; 	
		}
		if(obstacle_between_two_targets(&re_ds.head, exp, prevuse)){
#ifdef VERBOSE
	LOG(stdout, "assign_use_mem_val: goto out (case 4).\n");
#endif				
			goto out;  
}
		if(true){
			int offset = index + oriaddr - CAST2_USE(prevuse->node)->address;
                        void * copyaddr = ((void*)&CAST2_USE(prevuse->node)->val) + offset;
                        memcpy(((void*)rv) + index, copyaddr, 1);
			continue;
                }
out:
#ifdef VERBOSE
	LOG(stdout, "assign_use_mem_val false.\n");
#endif
		return false; 
	}
#ifdef VERBOSE
	LOG(stdout, "assign_use_mem_val true.\n");
#endif

	re_ds.alias_offset = 0;
	return true; 
}


static bool assign_def_before_mem_val(re_list_t* exp, valset_u * rv, re_list_t* uselist){
#ifdef VERBOSE
	LOG(stdout, "assign_def_before_mem_val: address = %#x, operand = ",
		CAST2_DEF(exp->node)->address);
	print_node_operand(exp);
	LOG(stdout, "\n");
#endif
	int dtype; 
	size_t memsize;
	unsigned index;  
	valset_u tv; 
	unsigned oriaddr;
	cs_arm_op tmpopd; 
	cs_arm_op *oriopd;	
	def_node_t* def;
	re_list_t *nextdef, *nextuse, *prevdef, *prevuse; 

	assert(exp->node_type == DefNode);

	def = CAST2_DEF(exp->node);
	memsize = translate_datatype_to_byte(def->inst);
	oriaddr = def->address;

	oriopd = def->operand; 
	memcpy(&tmpopd, def->operand, sizeof(cs_arm_op));		
	def->operand = &tmpopd; 

//process the destination byte by byte; 
	for(index = 0; index < memsize; index++){
#ifdef VERBOSE
	LOG(stdout, "assign_def_before_mem_val: index %d in memsize %d\n", index, memsize);
#endif
////////very important here!
		re_ds.alias_offset = 0;
//////// 
		def->operand = &tmpopd; 
		def->address = oriaddr + index; 
		// def->operand->datatype = op_byte; 
		prevdef = find_prev_def_of_def(exp, &dtype);
		def->address = oriaddr; 
		def->operand = oriopd; 

		if(!prevdef){
#ifdef VERBOSE
	LOG(stdout, "assign_def_before_mem_val: goto prevuse (case 1).\n");
#endif			
			goto prevuse; 
}
		if(!(CAST2_DEF(prevdef->node)->val_stat & AfterKnown)){
#ifdef VERBOSE
	LOG(stdout, "assign_def_before_mem_val: goto prevuse (case 2).\n");
#endif	
			goto prevuse;
			}

		if(obstacle_between_two_targets(&re_ds.head, exp, prevdef)){
#ifdef VERBOSE
	LOG(stdout, "assign_def_before_mem_val: goto prevuse (case 3).\n");
#endif	
			goto prevuse;  
	}

		if(true){
			int offset = index + oriaddr - CAST2_DEF(prevdef->node)->address;
			void * copyaddr = ((void*)&CAST2_DEF(prevdef->node)->afterval) + offset; 
			memcpy(((void*)rv) + index, copyaddr, 1);
			continue;
		}

prevuse:		

		re_ds.alias_offset = 0;

		def->operand = &tmpopd; 
		def->address = oriaddr + index; 
		// def->operand->datatype = op_byte; 
		prevuse = find_prev_use_of_def(exp, &dtype);
		def->address = oriaddr; 
		def->operand = oriopd; 

		if(!prevuse){
#ifdef VERBOSE
	LOG(stdout, "assign_def_before_mem_val: goto out (case 1).\n");
#endif	
			goto out;}

		if(prevdef && node1_add_before_node2(prevdef, prevuse)){
#ifdef VERBOSE
	LOG(stdout, "assign_def_before_mem_val: goto out (case 2).\n");
#endif
			goto out; 
}
		if(!CAST2_USE(prevuse->node)->val_known){
#ifdef VERBOSE
	LOG(stdout, "assign_def_before_mem_val: goto out (case 3).\n");
#endif
			goto out; 
}
		if(obstacle_between_two_targets(&re_ds.head, exp, prevuse)){
#ifdef VERBOSE
	LOG(stdout, "assign_def_before_mem_val: goto out (case 4).\n");
#endif
			goto out;  
}
		if(true){
			int offset = index + oriaddr - CAST2_USE(prevuse->node)->address;
			void * copyaddr = ((void*)&CAST2_USE(prevuse->node)->val) + offset;
			memcpy(((void*)rv) + index, copyaddr, 1);
			continue;
		}
out:
#ifdef VERBOSE
	LOG(stdout, "assign_def_before_mem_val false.\n");
#endif
		return false; 
	}
#ifdef VERBOSE
	LOG(stdout, "assign_def_before_mem_val true.\n");
#endif

	re_ds.alias_offset = 0;
	return true; 
}

static bool assign_def_after_mem_val(re_list_t* exp, valset_u * rv, re_list_t* uselist){
#ifdef VERBOSE
	LOG(stdout, "assign_def_after_mem_val: address = %#x, operand = ",
		CAST2_DEF(exp->node)->address);
	print_node_operand(exp);
	LOG(stdout, "\n");
#endif
	int dtype; 
	size_t memsize;
	unsigned index;  
	valset_u tv; 
	unsigned oriaddr;
	cs_arm_op tmpopd; 
	cs_arm_op *oriopd;	
	def_node_t* def;
	re_list_t *nextdef, *nextuse, *prevdef, *prevuse; 

	assert(exp->node_type == DefNode);

	def = CAST2_DEF(exp->node);
	memsize = translate_datatype_to_byte(def->inst);
	oriaddr = def->address;

	oriopd = def->operand; 
	memcpy(&tmpopd, def->operand, sizeof(cs_arm_op));		
	def->operand = &tmpopd; 

//process the destination byte by byte; 
	for(index = 0; index < memsize; index++){
#ifdef VERBOSE
	LOG(stdout, "assign_def_after_mem_val: index %d in memsize %d\n", index, memsize);
#endif
////////very important here!
		re_ds.alias_offset = index;
//////// 
		def->operand = &tmpopd; 

		def->address = oriaddr + index; 
		// def->operand->datatype = op_byte; 
		nextdef = find_next_def_of_def(exp, &dtype);
		def->address = oriaddr; 
		def->operand = oriopd; 
	

		if(nextdef && !(CAST2_DEF(nextdef->node)->val_stat & BeforeKnown)) {
#ifdef VERBOSE
	LOG(stdout, "assign_def_after_mem_val: goto nextuse (case 1).\n");
#endif
			goto nextuse;
		}				

	
		if(obstacle_between_two_targets(&re_ds.head, nextdef, exp)){
#ifdef VERBOSE
	LOG(stdout, "assign_def_after_mem_val: goto nextuse (case 2).\n");
#endif
			goto nextuse;  }

		//get one byte from core dump
		if(!nextdef){

			def->operand = &tmpopd; 
			def->address = oriaddr + index; 
			// def->operand->datatype = op_byte; 
						
			if (get_value_from_coredump(exp, &tv) == BAD_ADDRESS) {
				def->address = oriaddr; 
				def->operand = oriopd;
				assert_address();
			}

			memcpy(((void*)rv) + index,&tv.byte, 1);
			def->address = oriaddr; 
			def->operand = oriopd;

			continue; 
		}

		if(true){
			int offset = index + oriaddr - CAST2_DEF(nextdef->node)->address; 
			void * copyaddr = ((void*)&CAST2_DEF(nextdef->node)->beforeval) + offset; 
			memcpy(((void*)rv) + index, copyaddr, 1);
			continue;
		}

nextuse:	
		re_ds.alias_offset = index;
			
		def->operand = &tmpopd; 
		def->address = oriaddr + index; 
		// def->operand->datatype = op_byte; 
		nextuse = find_next_use_of_def(exp, &dtype);
		def->address = oriaddr; 
		def->operand = oriopd; 

		if(!nextuse){
#ifdef VERBOSE
	LOG(stdout, "assign_def_after_mem_val: goto out (case 1).\n");
#endif
			goto out;
		}
		if(nextdef && node1_add_before_node2(nextuse, nextdef)){
#ifdef VERBOSE
	LOG(stdout, "assign_def_after_mem_val: goto out (case 2).\n");
#endif
			goto out; 
}
		if(!CAST2_USE(nextuse->node)->val_known){
#ifdef VERBOSE
	LOG(stdout, "assign_def_after_mem_val: goto out (case 3).\n");
#endif
			goto out; 	
		}
		if(obstacle_between_two_targets(&re_ds.head, nextuse, exp)){
#ifdef VERBOSE
	LOG(stdout, "assign_def_after_mem_val: goto out (case 4).\n");
#endif
			goto out;  
		}
		if(true){
			int offset = index + oriaddr - CAST2_USE(nextuse->node)->address;	
			void * copyaddr = ((void*)&CAST2_USE(nextuse->node)->val) + offset;
			memcpy(((void*)rv) + index, copyaddr, 1);
			continue;
                }
out:
#ifdef VERBOSE
	LOG(stdout, "assign_def_after_mem_val false.\n");
#endif
		return false; 
	}
#ifdef VERBOSE
	LOG(stdout, "assign_def_after_mem_val true.\n");
#endif

	re_ds.alias_offset = 0;
	return true; 
}


bool assign_mem_val(re_list_t* exp, valset_u * rv, re_list_t* uselist){
	
	if(exp->node_type == UseNode)
		return assign_use_mem_val(exp, rv, uselist);

	return false; 
}

re_list_t * get_main_instnode() {
	re_list_t *entry;
	
	list_for_each_entry(entry, &re_ds.head.list, list) {
		if (entry->node_type == InstNode){
			return entry;
		}
	}

	return NULL;
}

#ifdef VSA
void add_to_memlist(re_list_t *entry) {
        list_add_tail(&entry->memlist, &re_ds.head.memlist);
}
#endif
//add new use to the main link; checked
#ifdef FRCA
re_list_t * add_new_use(cs_arm_op * opd, cs_insn* insn, arm_op_usage usage, enum u_type type, re_list_t * re_uselist){
#else
re_list_t * add_new_use(cs_arm_op * opd, enum u_type type, cs_insn* insn){
#endif
	re_list_t * newnode;
	re_list_t * nextdef;
	use_node_t * newuse; 
	int alias_type;

	newnode = (re_list_t *)malloc(sizeof(re_list_t ));
	if(!newnode){
		return NULL; 
	}

	newnode->id = re_ds.current_id; 
	re_ds.current_id++;	

	newuse = (use_node_t*)malloc(sizeof(use_node_t));	
	if(!newuse){
		free(newnode);
		return NULL;
	}

	memset(newuse, 0, sizeof(use_node_t));

#ifdef VSA
#if defined (ALIAS_MODULE) && (ALIAS_MODULE == VSA_MODULE)
	INIT_LIST_HEAD(&(newuse->valset.list));
	INIT_LIST_HEAD(&(newuse->addr_valset.list));
#endif
#endif
	newuse->usetype = type;
	newuse->inst = insn;
	newuse->operand = opd; 
#ifdef FRCA
	newuse->usage = usage;
#endif
	newnode->node_type = UseNode;
	newnode->node = (void*)newuse;

#ifdef VERBOSE
	LOG(stdout, "add_new_use: [");
	print_sub_operand(opd, type);
#ifdef FRCA
	LOG(stdout, "] at id %d, usage=%d\n", newnode->id,usage);
#else
	LOG(stdout, "] at id %d\n", newnode->id);
#endif
#endif

#ifdef VSA
	#ifdef WITH_SOLVER
		//if we have no solver system, we do not add any constraints
		CAST2_USE(newnode->node)->constraint = NULL;
	#endif
#endif
	//insert new node into main list
	list_add(&newnode->list, &re_ds.head.list);

#ifdef VSA
	// insert new node into memory list
        if ((type == Opd) && opd->type == ARM_OP_MEM) {
                add_to_memlist(newnode);
        }
#endif
	//the use is an immediate value; 
	// op_immediate = 2,       /* Immediate Value */
	if(opd->type == ARM_OP_IMM){
		get_immediate_from_opd(opd, &newuse->val);
		newuse->val_known = true;
#ifdef VSA
#ifdef WITH_SOLVER
	CAST2_USE(newnode->node)->addresscst = NULL;
	CAST2_USE(newnode->node)->constant = false;
	adjust_use_constraint(newnode); 
#endif
#endif
		return newnode; 
	}

	// note : PC is a special case, no need to add in the use-def chain
	if(type == Base && opd->type == ARM_OP_MEM && opd->mem.base == ARM_REG_PC){
		newuse->val_known = true;
		newuse->val.dword = insn->address + insn->size;
		return newnode; 
	}

	// try memac
#ifdef MEMAC
	if (assign_memac_value(newnode)){
		add_to_uselist(newnode, re_uselist);
	}
#endif

	//check the next define
	nextdef = find_next_def_of_use(newnode, &alias_type);

	//check if the use has been killed before
	if(!nextdef){

		if (ok_to_get_value(newnode)) {
			//set up value for the use here!
			if (get_value_from_coredump(newnode, &newuse->val) == BAD_ADDRESS) {
				// assert_address(); // note: only the crash site will trigger this assert, but that is ok.
				memset(&newuse->val, 0, sizeof(valset_u));
			}
			newuse->val_known = true;
		}
	}
	else{
		//VSA: if this is really necessary?
		 if( (alias_type == EXACT || alias_type == SUPER) &&
			CAST2_DEF(nextdef->node)->val_stat & BeforeKnown){

			assign_use_value(newnode, CAST2_DEF(nextdef->node)->beforeval);
		}
	}

	return newnode; 
}

#ifdef FRCA
re_list_t * add_new_define(cs_arm_op * opd, cs_insn* insn, arm_op_usage usage, bool do_memac, re_list_t *re_deflist){
#else
re_list_t * add_new_define(cs_arm_op * opd, cs_insn* insn){
#endif

	re_list_t * newnode;
	re_list_t * nextdef;
	def_node_t * newdef; 
	int type;

	newnode = (re_list_t *)malloc(sizeof(re_list_t ));
	if(!newnode){
		return NULL; 
	}
	
	newnode->id = re_ds.current_id; 
	re_ds.current_id++;	

	newdef = (def_node_t*)malloc(sizeof(def_node_t));	
	if(!newdef){
		free(newnode);
		return NULL;
	}

	memset(newdef, 0, sizeof(def_node_t));

#ifdef VSA
#if defined (ALIAS_MODULE) && (ALIAS_MODULE == VSA_MODULE)
	INIT_LIST_HEAD(&(newdef->bef_valset.list));
	INIT_LIST_HEAD(&(newdef->aft_valset.list));
	INIT_LIST_HEAD(&(newdef->addr_valset.list));
#endif
#endif
	newdef->operand = opd; 
	newdef->inst = insn;
#ifdef FRCA
	newdef->usage = usage;
#endif
	newnode->node_type = DefNode;
	newnode->node = (void*)newdef;

#ifdef VERBOSE
	LOG(stdout, "add_new_define [");
	print_operand(opd);
#ifdef FRCA
	LOG(stdout, "] at id %d, usage=%d, do_memac = %s\n", newnode->id, usage, do_memac ? "true" : "false");
#else
	LOG(stdout, "] at id %d\n", newnode->id);
#endif
#endif
#ifdef VSA
#ifdef WITH_SOLVER
// init the before and after constraints
	CAST2_DEF(newnode->node)->beforecst = NULL;
	CAST2_DEF(newnode->node)->aftercst = NULL;
#endif
#endif
	//insert new node into main list
	list_add(&newnode->list, &re_ds.head.list);

#ifdef VSA
	// insert new node into memory list
	if (opd->type == ARM_OP_MEM) {
			add_to_memlist(newnode);
	}
#endif
	// try memac
#ifdef MEMAC
	if (do_memac){
		if (assign_memac_value(newnode)) {
			add_to_deflist(newnode, re_deflist);
		}
	}
#endif

	nextdef = find_next_def_of_def(newnode, &type);

	//check if the use has been killed before
	if(!nextdef){
		if (ok_to_get_value(newnode)) {
			//set up value for the define here!
			//assign_def_after_value(newnode, get_value_from_coredump(newnode));
			if (get_value_from_coredump(newnode, &newdef->afterval) == BAD_ADDRESS) {
				// assert_address(); // note: only the crash site will trigger this assert, but that is ok.
				memset(&newdef->afterval, 0, sizeof(valset_u));
			}
			newdef->val_stat |= AfterKnown; 
		} 
	}
	else{
		if((type == EXACT || type == SUPER) &&	
			CAST2_DEF(nextdef->node)->val_stat & BeforeKnown){
				assign_def_after_value(newnode, CAST2_DEF(nextdef->node)->beforeval);
		}
	}

#ifdef VSA
#ifdef WITH_SOLVER
	CAST2_DEF(newnode->node)->addresscst = NULL;	
	CAST2_DEF(newnode->node)->beforeconst = false;	
	CAST2_DEF(newnode->node)->afterconst = false;	
	adjust_def_constraint(newnode);		
#endif
#endif

	return newnode; 
}

re_list_t * add_new_inst(unsigned index){

	re_list_t * newnode; 
	inst_node_t * newinst;  

	newnode = (re_list_t *)malloc(sizeof(re_list_t ));

	if(!newnode){
		return NULL; 
	}
	
	newnode->id = re_ds.current_id;
	re_ds.current_id++;	

	newinst = (inst_node_t*)malloc(sizeof(inst_node_t));	

	if(!newinst){
		free(newnode);
		return NULL;
	}

	newinst->inst_index = index; 
#ifdef VSA
#ifdef WITH_SOLVER
	newinst->constraint = NULL;
#endif
#endif
#ifdef FRCA
	newinst->acnum = 0;
	newinst->curac = 0;
#endif
	newinst->inst = re_ds.instlist + index;
#ifdef VERBOSE
	LOG(stdout, "add_new_inst %s %s, Xaddress = %#x\n",
	re_ds.instlist[index].mnemonic,re_ds.instlist[index].op_str,
	re_ds.instlist[index].address);

#endif
#ifdef FRCA
	// CRITAL: if not the same, it means capstone made a mistake in disassembling
	if (re_ds.instlist[index].address != re_ds.accesslist[re_ds.memac_count].pc) {
		LOG(stdout,"ERROR!!!!! Xaddress not the same: re_ds.instlist[index].address=%#x, \
		re_ds.accesslist[re_ds.memac_count].pc=%#x\n",
		re_ds.instlist[index].address,re_ds.accesslist[re_ds.memac_count].pc);
	}
	// IMPORTANT: 0 means exactly this instruction ITSELF
	while(re_ds.accesslist[re_ds.memac_count].size != 0) {
		newinst->accesses[newinst->acnum] = re_ds.accesslist + re_ds.memac_count;
#ifdef VERBOSE
	LOG(stdout, "add_new_inst memac_count = %d, instnode.access[%d].%caddress = %#x, data = %#x, pc = %#x\n",
		re_ds.memac_count,
		newinst->acnum,
		newinst->accesses[newinst->acnum]->type == MEM_WRITE ? 'W' : 'R',
		newinst->accesses[newinst->acnum]->address,
		newinst->accesses[newinst->acnum]->value,
		newinst->accesses[newinst->acnum]->pc);

#endif
		newinst->acnum++;
		re_ds.memac_count++;
	}

	// switch to next instruction
	re_ds.memac_count++;
#endif
	newnode->node_type = InstNode;
	newnode->node = (void*)newinst;

	funcid_of_inst(newnode);
	//insert new node into main list
	list_add(&newnode->list, &re_ds.head.list);

	return newnode;
}

void assign_def_before_value(re_list_t * def, valset_u val){

	memcpy( &(CAST2_DEF(def->node)->beforeval), 
		&val, sizeof(val));   
	
	CAST2_DEF(def->node)->val_stat |= BeforeKnown;  
#ifdef VERBOSE
	LOG(stdout, "assign_def_before_value %#lx to [", val.dword);
	print_operand((CAST2_DEF(def->node)->operand));
	LOG(stdout, "], def node id %d\n", def->id);
#endif

#ifdef VSA
	if(re_ds.rec_count == 0 && re_ds.oplog_list.log_num > 0)
		correctness_check(find_inst_of_node(def));	
#endif
}

void assign_def_after_value(re_list_t * def, valset_u val){

	memcpy(&(CAST2_DEF(def->node)->afterval), 
		&val, sizeof(val));   

	CAST2_DEF(def->node)->val_stat |= AfterKnown; 
#ifdef VERBOSE
	LOG(stdout, "assign_def_after_value %#lx to [", val.dword);
	print_operand((CAST2_DEF(def->node)->operand)); 
	LOG(stdout, "], def node id %d\n", def->id);
#endif

#ifdef VSA
	if(re_ds.rec_count == 0 && re_ds.oplog_list.log_num > 0)
		correctness_check(find_inst_of_node(def));	
#endif
}

void assign_use_value(re_list_t *use, valset_u val) {
	memcpy( &(CAST2_USE(use->node)->val), 
		&val, sizeof(val));   

	CAST2_USE(use->node)->val_known = true;  
#ifdef VERBOSE
	LOG(stdout, "assign_use_value %#lx to [", val.dword);
	print_node_operand(use); 
	LOG(stdout, "], use node id %d\n", use->id);
#endif

#ifdef VSA
	if(re_ds.rec_count == 0 && re_ds.oplog_list.log_num > 0)
		correctness_check(find_inst_of_node(use));	
#endif
}

#ifdef FRCA
bool check_multiple_ldst(cs_insn *inst) {
	if (inst->id == ARM_INS_LDM || inst->id == ARM_INS_STM) {
		return 1; // IA mode
	} else if (inst->id == ARM_INS_LDMDB || inst->id == ARM_INS_STMDB) {
		return -1; // DB mode
	}
	return 0;
}
bool assign_memac_value(re_list_t *unode){
	re_list_t* re_node;
	inst_node_t* instnode;
	valset_u val;
	unsigned short target_idx = 0;
	bool memac_value = true;
	bool do_assign = true;
	int check_ldst;
	if (unode->node_type == InstNode){
		return false;
	}
#ifdef VERBOSE
	LOG(stdout, "assign_memac_value: ");
	print_node_operand(unode);
	LOG(stdout, "\n");
#endif
	//find the instnode of this node in instlist (closest smaller node ID)
	re_node = get_main_instnode();
	if (!re_node) {
		return false;
	}
	instnode = CAST2_INST(re_node->node);

	if (instnode->acnum == 0) {
		return false;
	}
	check_ldst = check_multiple_ldst(instnode->inst);
	if (unode->node_type == UseNode) {
		use_node_t* usenode = CAST2_USE(unode->node);
		if (Opd == usenode->usetype){ // Apply to the whole operand
			instnode->curac++;
			target_idx = instnode->acnum - (instnode->curac & 0xff);
			// Some special instructions 
			if (0 != check_ldst) {
				if (usenode->operand->reg == instnode->inst->detail->arm.operands[0].reg){
					// instnode->acnum - 1 is the initial value of src[0]
					val.dword = instnode->accesses[instnode->acnum-1]->address; 
					instnode->curac--; // address usage not effect value usage
					memac_value = false;
				}
			}
			// } else if (-1 == check_ldst) {
			// 	if (usenode->operand->reg == instnode->inst->detail->arm.operands[0].reg){
			// 		// in DB mode, use the last operand's address
			// 		val.dword = instnode->accesses[0]->address; 
			// 		instnode->curac--; // address usage not effect value usage
			// 		memac_value = false;
			// 	}
			// }
			if (memac_value) {
				val.dword = instnode->accesses[target_idx]->value;
			}

			if (usenode->address){
				if(usenode->address != instnode->accesses[target_idx]->address) {
					LOG(stdout,"ERROR!!!!! usenode->address (%#x) != instnode->accesses[0]->address (%#x)\n",
						usenode->address, instnode->accesses[target_idx]->address);
				}
			}
			usenode->address = instnode->accesses[target_idx]->address;
			if (usenode->val_known) {
				if (usenode->val.dword != val.dword) {
					LOG(stdout,"ERROR!!!!! usenode->val.dword (%#lx) != val.dword (%#lx)\n",
						usenode->val.dword, val.dword);
				}
			} else {
				assign_use_value(unode, val);
				return true;
			}
		} else if (Base == usenode->usetype || Index == usenode->usetype) { // Apply to base and index node
			// When analyzing base/index, the defnode has been analyzed before
			target_idx = instnode->acnum - ((instnode->curac >> 8) & 0xff);
			if (target_idx >= instnode->acnum) {
				// Some instructions do not have "defnode", such as tbb
				return false;
			}
			// val.dword = instnode->accesses[target_idx]->value;
			// LOG(stdout, "target_idx = %d\n", target_idx);
			// for (int ii = 0; ii < instnode->acnum; ii++)
			// {
			// 	LOG(stdout, "Access[%d].address = %#x, Access[%d].value = %#x\n", ii, instnode->accesses[ii]->address,ii, instnode->accesses[ii]->value);
			// }
			// No not handle some special instructions 
			if (0 == check_ldst) {
				val.dword = instnode->accesses[target_idx]->address;
				// calculate the value according to the Base and Index
				enum expreg_status status = get_expreg_status(usenode->operand->mem);
				if (Base_Reg == status)
				{
					// resolve for offset operands like [r0, #4]
 					// LOG(stdout, "old val.dword = %#x, disp = %d, scale = %d\n", val.dword, usenode->operand->mem.disp, usenode->operand->mem.scale);
					val.dword = val.dword - usenode->operand->mem.disp;

				}
				else if (Base_Index_Reg == status)
				{
					// TODO currently do not handle shift operands like [r0, r1, lsl #2]
					do_assign = false;
				}
				if (usenode->val_known) {
					if (usenode->val.dword != val.dword) {
						LOG(stdout,"ERROR!!!!! usenode->val.dword (%#lx) != val.dword (%#lx)\n",
							usenode->val.dword, val.dword);
						}
				} else {
					if (do_assign){
						assign_use_value(unode, val);
						return true;
					}
				}
			}
			
		}
	}
	
	if (unode->node_type == DefNode) {
		def_node_t* defnode = CAST2_DEF(unode->node);
		if (defnode->operand->type == ARM_OP_MEM ||
			defnode->operand->type == ARM_OP_REG){
			instnode->curac += 0x100;
			target_idx = instnode->acnum - ((instnode->curac >> 8) & 0xff);
			if (0 != check_ldst) {
				if (defnode->operand->reg == instnode->inst->detail->arm.operands[0].reg){
					// 0 is the index of dst[0]
					val.dword = instnode->accesses[0]->address; 
					instnode->curac -= 0x100; // address usage not effect value usage
					memac_value = false;
				}
			}
			// } else if (-1 == check_ldst) {
			// 	if (defnode->operand->reg == instnode->inst->detail->arm.operands[0].reg){
			// 		// in DB mode, use the last operand's address
			// 		val.dword = instnode->accesses[instnode->acnum-1]->address; 
			// 		instnode->curac -= 0x100; // address usage not effect value usage
			// 		memac_value = false;
			// 	}
			// }

			// memcpy(&val, &instnode->accesses[target_idx]->value, sizeof(val));
			if (memac_value) {
				val.dword = instnode->accesses[target_idx]->value;
			}
			if (defnode->address){
				if(defnode->address != instnode->accesses[target_idx]->address) {
					LOG(stdout,"ERROR!!!!! defnode->address (%#x) != instnode->accesses[0]->address (%#x)\n",
						defnode->address, instnode->accesses[target_idx]->address);
				}
			}
			defnode->address = instnode->accesses[target_idx]->address;
			assign_def_after_value(unode, val);
			return true;
		}
	}
	return false;
}
#endif
int compare_def_def(re_list_t *first, re_list_t *second) {
	def_node_t *firstd = (def_node_t*) first->node;
	def_node_t *secondd = (def_node_t*) second->node;	

	if(firstd->operand->type != secondd->operand->type) {
		return 0;
	}

	// op_register = 1,        /* CPU register */
	if(firstd->operand->type == ARM_OP_REG) {
		// if (exact_same_regs(firstd->operand->reg, secondd->operand->reg)) {
		// 	return EXACT;
		// }
		if (firstd->operand->reg == secondd->operand->reg) {
			return EXACT;
		}

		// if (reg1_alias_reg2(firstd->operand->data.reg, secondd->operand->data.reg)) {
		// 	return SUB; 
		// }

		// if (reg1_alias_reg2(secondd->operand->data.reg, firstd->operand->data.reg)) {
		// 	return SUPER; 
		// }

		// if (same_alias(firstd->operand->data.reg, secondd->operand->data.reg)) {

		// 	if (firstd->operand->data.reg.size == secondd->operand->data.reg.size) {
		// 		return 0;
		// 	}

		// 	if (firstd->operand->data.reg.size > secondd->operand->data.reg.size) {
		// 		return SUPER;
		// 	}

		// 	return SUB;
		// }
	}

	// op_expression = 6,      /* Address expression (scale/index/base/disp) */
	if(firstd->operand->type == ARM_OP_MEM){
		if(firstd->address == 0 || secondd->address == 0){			
			return 0;
		}

		size_t size2 = translate_datatype_to_byte(secondd->inst);
		size_t size1 = translate_datatype_to_byte(firstd->inst);
		if exact_same_mem(firstd->address, size1, secondd->address, size2) {
			return EXACT;
		}
		if subset_mem(firstd->address, size1, secondd->address, size2) {
			return SUB;
		}
		if superset_mem(firstd->address, size1, secondd->address, size2) {
			return SUPER;
		}
		if ( overlap_mem(firstd->address, size1, secondd->address, size2) ||
		     overlap_mem(secondd->address, size2, firstd->address, size1) ) {
			return OVERLAP;
		}
		
	}
	// op_offset = 7,          /* Offset relative to a register */
	// if (firstd->operand->type == op_offset) {
	// 	if (op_with_gs_seg(firstd->operand) && op_with_gs_seg(secondd->operand)) {
	// 		if (firstd->operand->data.offset != secondd->operand->data.offset) {
	// 			return 0;
	// 		} else {
	// 			return EXACT;
	// 		}
	// 	}
	// 	assert(0);
	// }
	return 0;		
}

int compare_def_use(re_list_t *first, re_list_t *second) {
	def_node_t *firstd = (def_node_t *)first->node;
	use_node_t *secondu = (use_node_t*)second->node; 

	size_t size1, size2;

	// arm 4 bytes
	size1 = translate_datatype_to_byte(firstd->inst);
	size2 = translate_datatype_to_byte(secondu->inst);

	switch(secondu->usetype){
		case Opd:

			if(firstd->operand->type != secondu->operand->type){
				return 0;
			}
			// op_register
			if(firstd->operand->type == ARM_OP_REG){
				// if (exact_same_regs(firstd->operand->data.reg, secondu->operand->data.reg)) {
				// 	return EXACT;
				// }
				if (firstd->operand->reg == secondu->operand->reg) {
					return EXACT;
				}	
				// if (reg1_alias_reg2(firstd->operand->data.reg, secondu->operand->data.reg)) {
				// 	return SUB; 
				// }
				// if (reg1_alias_reg2(secondu->operand->data.reg, firstd->operand->data.reg)) {
				// 	return SUPER; 
				// }
				// if (same_alias(firstd->operand->data.reg, secondu->operand->data.reg)) {

				// 	if (firstd->operand->data.reg.size == secondu->operand->data.reg.size) {
				// 		return 0;
				// 	}

				// 	if (firstd->operand->data.reg.size > secondu->operand->data.reg.size) {
				// 		return SUPER;
				// 	}

				// 	return SUB;					
				// }
			}
			// op_expression
			if(firstd->operand->type == ARM_OP_MEM){

				if(firstd->address == 0 || secondu->address == 0)	
					return 0;
#ifdef CMP_LOG
				LOG(stdout, "In compare_def_use: first address = %#x and size = %d, second address = %#x and size = %d\n", 
				firstd->address, size1, secondu->address, size2);
#endif
				if exact_same_mem(firstd->address, size1, secondu->address, size2) {
					return EXACT;
				}
				if subset_mem(firstd->address, size1, secondu->address, size2) {
					return SUB;
				}
				if superset_mem(firstd->address, size1, secondu->address, size2) {
					return SUPER;
				}
				if ( overlap_mem(firstd->address, size1, secondu->address, size2) ||
						overlap_mem(secondu->address, size2, firstd->address, size1) ) {
					return OVERLAP;
				}

			}	
			// if (firstd->operand->type == op_offset) {
			// 	if (op_with_gs_seg(firstd->operand) && op_with_gs_seg(secondu->operand)) {
			// 		if (firstd->operand->data.offset != secondu->operand->data.offset) {
			// 			return 0;
			// 		} else {
			// 			return EXACT;
			// 		}
			// 	}
			// 	assert(0);
			// }
			break;

		case Base:
			if(firstd->operand->type != ARM_OP_REG){
					return 0;
			}

			// Base is always 32 bit register in x86
			if (firstd->operand->reg == secondu->operand->mem.base) {
				return EXACT;
			}
			// if (exact_same_regs(firstd->operand->data.reg, secondu->operand->data.expression.base)) {
			// 	return EXACT;

			// }
			// if (reg1_alias_reg2(firstd->operand->data.reg, secondu->operand->data.expression.base)) {
			// 	return SUB;
			// }
			break;

		case Index:
			
			if(firstd->operand->type != ARM_OP_REG)
				return 0;

			// Base is always 32 bit register in x86
			if (firstd->operand->reg == secondu->operand->mem.index) {
				return EXACT;
			}
			// if (exact_same_regs(firstd->operand->data.reg, secondu->operand->data.expression.index)) {
			// 	return EXACT;
			// }
			// if (reg1_alias_reg2(firstd->operand->data.reg, secondu->operand->data.expression.index)) {
			// 	return SUB;
			// }
			break;

		default:
			
			break;
	}	
	return 0;
}


int compare_use_use(re_list_t *first, re_list_t *second) {
		
	use_node_t *firstu, *secondu;
	int type1, type2; 
	unsigned addr1, addr2, offset1, offset2; 
	size_t size1, size2;
	int reg1, reg2; 

	firstu = (use_node_t *)first->node;
	secondu = (use_node_t*)second->node; 

//process the first use
//use is an opd, then it could be anything
//use it as it is
	if(firstu->usetype == Opd){
				
		switch(firstu->operand->type){
			
			case ARM_OP_MEM:
				type1 = 0; 
				addr1 = firstu->address;
				size1 = translate_datatype_to_byte(firstu->inst);
				break;

			case ARM_OP_REG:
				type1 = 1; 
				reg1 = firstu->operand->reg;
				break;
				
			// case op_offset:
					
			// 	if(op_with_gs_seg(firstu->operand)){
			// 		type1 = 2; 
			// 		offset1 = firstu->operand->data.offset; 
			// 	}
			// 	else
			// 		type1 = 3;

			// 	break;

			case ARM_OP_IMM: 
				return 0;

			default: 
				assert(0);	
		}		
	}
	
	if(firstu->usetype == Base){
		type1 = 1; 
		reg1 = firstu->operand->mem.base;
	}

	if(firstu->usetype == Index){
		type1 = 1; 
		reg1 = firstu->operand->mem.index;
	}


	if(secondu->usetype == Opd){
				
		switch(secondu->operand->type){
			
			case ARM_OP_MEM:
				type2 = 0; 
				addr2 = secondu->address;
				size2 = translate_datatype_to_byte(secondu->inst);
				break;

			case ARM_OP_REG:
				type2 = 1; 
				reg2 = secondu->operand->reg;
				break;
				
			// case op_offset: 
			// 	if(op_with_gs_seg(secondu->operand)){
			// 		type2 = 2; 
			// 		offset2 =  secondu->operand->data.offset; 
			// 	}else
			// 		type2 = 3;
			// 	break;

			default: 
				assert(0);	

		}		
	}
	
	if(secondu->usetype == Base){
		type2 = 1; 
		reg2 = secondu->operand->mem.base;
	}

	if(secondu->usetype == Index){
		type2 = 1; 
		reg2 = secondu->operand->mem.index;
	}
	
	if(type1 != type2)
		return 0;

	switch(type1){

		case 0:
			if(!addr1 || !addr2)
				return 0;

			if exact_same_mem(addr1, size1, addr2, size2) 
				return EXACT;

			if subset_mem(addr1, size1, addr2, size2)
				return SUB;

			if superset_mem(addr1, size1, addr2, size2)			
				return SUPER;

			if (overlap_mem(addr1, size1, addr2, size2) || overlap_mem(addr2, size2, addr1, size1) )
				return OVERLAP;

			return 0;

		case 1:
			assert(reg1 && reg2);

			// if (exact_same_regs((*reg1), (*reg2))) {
			// 	return EXACT;
			// }

			if (reg1 == reg2){
				return EXACT;
			}

			// if (reg1_alias_reg2((*reg1), (*reg2))) {
			// 	return SUB; 
			// }

			// if (reg1_alias_reg2((*reg2), (*reg1))) {
			// 	return SUPER; 
			// }

			// if (same_alias((*reg1), (*reg2))) {

			// 	if ((*reg1).size == (*reg2).size) {
			// 		return 0;
			// 	}

			// 	if ((*reg1).size > (*reg2).size) {
			// 		return SUPER;
			// 	}

			// 	return SUB;					
			// }
			break;

		case 2:
			return offset1 == offset2 ? EXACT : 0;

		case 3:
			return 0;

		default:
			assert(0);
	}
		
	return 0;
}


int compare_two_targets(re_list_t* first, re_list_t * second){

	int type; 
#ifdef CMP_LOG
	LOG(stdout, "compare two targets, first node id %d, second node id %d\n",first->id, second->id);
#endif

	if(first->node_type == DefNode && second ->node_type == DefNode){
		type = compare_def_def(first, second);
#ifdef CMP_LOG
		LOG(stdout, "compare first def[");
		// print_sub_operand(CAST2_DEF(first->node)->operand, ((def_node_t*)first->node)->usetype);
		print_operand(CAST2_DEF(first->node)->operand);
		LOG(stdout, "] and second def[");
		// print_sub_operand(CAST2_DEF(second->node)->operand, ((def_node_t*)second->node)->usetype);
		print_operand(CAST2_DEF(second->node)->operand);
		LOG(stdout, "]. Result: %d\n",type);
#endif
		return type;
	}	

	if(first->node_type == DefNode && second ->node_type == UseNode){
		type = compare_def_use(first, second);
#ifdef CMP_LOG
		LOG(stdout, "compare first def[");
		// print_sub_operand((CAST2_DEF(first->node)->operand), ((def_node_t*)first->node)->usetype);
		print_operand((CAST2_DEF(first->node)->operand));
		LOG(stdout, "] and second use[");
		print_sub_operand((CAST2_USE(second->node)->operand), ((use_node_t*)second->node)->usetype);
		LOG(stdout, "]. Result: %d\n",type);
#endif
		return type;
	}	

	if(first->node_type == UseNode && second ->node_type == DefNode){
		
		type = compare_def_use(second, first);
#ifdef CMP_LOG
		LOG(stdout, "compare first use[");
		print_sub_operand((CAST2_USE(first->node)->operand), ((use_node_t*)first->node)->usetype);
		LOG(stdout, "] and second def[");
		print_operand((CAST2_DEF(second->node)->operand));
		LOG(stdout, "]. Result: %d\n",type);
#endif
		switch(type){

			case 0:
			     return 0;

			case EXACT:
			case OVERLAP:
				return type; 

			case SUB: 
				return SUPER;

			case SUPER:
				return SUB;		
							
			default: 
				assert(0);
		}



	}	

	if(first->node_type == UseNode && second ->node_type == UseNode){
		type = compare_use_use(first, second);
#ifdef CMP_LOG
		LOG(stdout, "compare first use[");
		print_sub_operand((CAST2_USE(first->node)->operand), ((use_node_t*)first->node)->usetype);
		LOG(stdout, "] and second use[");
		print_sub_operand((CAST2_USE(second->node)->operand), ((use_node_t*)second->node)->usetype);
		LOG(stdout, "]. Result: %d\n",type);
#endif
		return type;
	}	
	return 0;
}


bool ok_to_get_value(re_list_t *entry) {
	def_node_t *defnode = NULL;
	use_node_t *usenode = NULL;
	if (entry->node_type == DefNode) {
		defnode = CAST2_DEF(entry->node);
		// op_expression = 6,      /* Address expression (scale/index/base/disp) */
		return (!((defnode->operand->type == ARM_OP_MEM) && 
			(defnode->address == 0)));
	}
	if (entry->node_type == UseNode) {

		usenode = CAST2_USE(entry->node);
		if (usenode->usetype != Opd) {
			return true;
		}
		// op_expression = 6,      /* Address expression (scale/index/base/disp) */
		return (!((usenode->operand->type == ARM_OP_MEM) && 
			(usenode->address == 0)));
	}
}

re_list_t * find_next_use_of_use(re_list_t* use, int *type){
#ifdef VERBOSE
	LOG(stdout, "In find_next_use_of_use: use ");
	print_node_operand(use);
	LOG(stdout,"\n");
#endif
	re_list_t *entry;

	list_for_each_entry(entry, &use->list, list) {
	
		if (entry == &re_ds.head) break;
		if (entry->node_type != UseNode)
			continue;
		
		*type = compare_two_targets(entry, use);
#ifdef VERBOSE
		switch(*type){
			case EXACT:
				LOG(stdout,"In find_next_use_of_use [EXACT]: next use ");
				print_node_operand(entry);
				LOG(stdout, " of use ");
				print_node_operand(use);
				LOG(stdout,"\n");
				break;
			case SUPER:
				LOG(stdout,"In find_next_use_of_use [SUPER]: next use ");
				print_node_operand(entry);
				LOG(stdout, " of use ");
				print_node_operand(use);
				LOG(stdout,"\n");
				break;
			case SUB:
				LOG(stdout,"In find_next_use_of_use [SUB]: next use ");
				print_node_operand(entry);
				LOG(stdout, " of use ");
				print_node_operand(use);
				LOG(stdout,"\n");
				break;
			case OVERLAP:
				LOG(stdout,"In find_next_use_of_use [OVERLAP]: next use ");
				print_node_operand(entry);
				LOG(stdout, " of use ");
				print_node_operand(use);
				LOG(stdout,"\n");
				break;
			default:
				assert("find_next_use_of_use type error");
		}
#endif
		if (*type) {
			return entry;
		}
	}
	return NULL;
}

re_list_t * find_next_def_of_use(re_list_t* use, int *type){

#ifdef VERBOSE
	LOG(stdout, "In find_next_def_of_use: use ");
	print_node_operand(use);
	LOG(stdout,"\n");
#endif

	re_list_t *entry;

	list_for_each_entry(entry, &use->list, list) {
	
		if (entry == &re_ds.head) break;
		if (entry->node_type != DefNode)
			continue;
		
		*type = compare_two_targets(entry, use);
#ifdef VERBOSE
		switch(*type){
			case EXACT:
				LOG(stdout,"In find_next_def_of_use [EXACT]: next def ");
				print_node_operand(entry);
				LOG(stdout, " of use ");
				print_node_operand(use);
				LOG(stdout,"\n");
				break;
			case SUPER:
				LOG(stdout,"In find_next_def_of_use [SUPER]: next def ");
				print_node_operand(entry);
				LOG(stdout, " of use ");
				print_node_operand(use);
				LOG(stdout,"\n");
				break;
			case SUB:
				LOG(stdout,"In find_next_def_of_use [SUB]: next def ");
				print_node_operand(entry);
				LOG(stdout, " of use ");
				print_node_operand(use);
				LOG(stdout,"\n");
				break;
			case OVERLAP:
				LOG(stdout,"In find_next_def_of_use [OVERLAP]: next def ");
				print_node_operand(entry);
				LOG(stdout, " of use ");
				print_node_operand(use);
				LOG(stdout,"\n");
				break;
			default:
				assert("find_next_def_of_use type error");
		}
#endif
		if (*type) {
			return entry;
		}
	}
	return NULL;
}

re_list_t * find_prev_use_of_use(re_list_t* use, int *type){
#ifdef VERBOSE
	LOG(stdout, "In find_prev_use_of_use: use ");
	print_node_operand(use);
	LOG(stdout,"\n");
#endif
	re_list_t *entry;

	list_for_each_entry_reverse(entry, &use->list, list) {
		if (entry == &re_ds.head) break;
		if (entry->node_type != UseNode)
			continue;

		*type = compare_two_targets(entry, use);
#ifdef VERBOSE
		switch(*type){
			case EXACT:
				LOG(stdout,"In find_prev_use_of_use [EXACT]: prev use ");
				print_node_operand(entry);
				LOG(stdout, " of use ");
				print_node_operand(use);
				LOG(stdout,"\n");
				break;
			case SUPER:
				LOG(stdout,"In find_prev_use_of_use [SUPER]: prev use ");
				print_node_operand(entry);
				LOG(stdout, " of use ");
				print_node_operand(use);
				LOG(stdout,"\n");
				break;
			case SUB:
				LOG(stdout,"In find_prev_use_of_use [SUB]: prev use ");
				print_node_operand(entry);
				LOG(stdout, " of use ");
				print_node_operand(use);
				LOG(stdout,"\n");
				break;
			case OVERLAP:
				LOG(stdout,"In find_prev_use_of_use [OVERLAP]: prev use ");
				print_node_operand(entry);
				LOG(stdout, " of use ");
				print_node_operand(use);
				LOG(stdout,"\n");
				break;
			default:
				assert("find_prev_use_of_use type error");
		}
		
#endif
		if (*type) return entry;
	}
	return NULL;
}

#ifdef FRCA
re_list_t * find_prev_write_of_address(re_list_t* node, int *type){
#ifdef VERBOSE
	LOG(stdout, "In find_prev_write_of_address node");
	print_node_operand(node);
	LOG(stdout,"\n");
#endif
	re_list_t *entry = NULL;
	re_list_t *temp_inst = NULL;
	int diff, acnum;
	bool flag = false;
	unsigned address1, address2;
	*type = 0;
	if ( node->node_type == UseNode) {
		address2 = CAST2_USE(node->node)->address;
	} else if (node->node_type == DefNode) {
		address2 = CAST2_DEF(node->node)->address;
	}
	list_for_each_entry_reverse(entry, &node->list, list) {
		// LOG(stdout, "In find_prev_write_of_address: entry ");
		// print_node_operand(entry);
		// LOG(stdout,"\n");
		// printf("%d\n",entry->node_type);
		if (entry == &re_ds.head) break;
		if (entry->node_type == InstNode) {
			temp_inst = entry;
			continue;
		}
		if (temp_inst) {
			acnum = CAST2_INST(temp_inst->node)->acnum;
			if (acnum == 0) {
				continue;
			}
			// if (CAST2_INST(temp_inst->node)->accesses[acnum-1]->type != MEM_WRITE) {
			// 	continue;
			// }
		}
		// LOG(stdout,"temp checker2\n");
		if (entry->node_type != DefNode || CAST2_DEF(entry->node)->operand->type != ARM_OP_MEM) {
			continue;
		}
		address1 = CAST2_DEF(entry->node)->address;
		// LOG(stdout,"temp checker3 flag=%d\n",flag);
		if (address1 && address2) {
			diff = address1 > address2 ? address1 - address2 : address2 - address1;
			if (diff == 0){
				*type = EXACT;
			} 
			// else if (diff < 4){
			// 	*type = OVERLAP;
			// }
			else {
				*type = 0;
			}
		}
		
#ifdef VERBOSE
		switch(*type){
			case EXACT:
				LOG(stdout,"In find_prev_write_of_address [EXACT]: next def ");
				print_node_operand(entry);
				LOG(stdout, " of ");
				print_node_operand(node);
				LOG(stdout,"\n");
				break;
			case SUPER:
				LOG(stdout,"In find_prev_write_of_address [SUPER]: next def ");
				print_node_operand(entry);
				LOG(stdout, " of ");
				print_node_operand(node);
				LOG(stdout,"\n");
				break;
			case SUB:
				LOG(stdout,"In find_prev_write_of_address [SUB]: next def ");
				print_node_operand(entry);
				LOG(stdout, " of ");
				print_node_operand(node);
				LOG(stdout,"\n");
				break;
			case OVERLAP:
				LOG(stdout,"In find_prev_write_of_address [OVERLAP]: next def ");
				print_node_operand(entry);
				LOG(stdout, " of ");
				print_node_operand(node);
				LOG(stdout,"\n");
				break;
			default:
				assert("find_prev_write_of_address type error");
		}
#endif
		if (*type) {
			LOG(stdout, "In find_prev_write_of_address: address1 = %#x, address2 = %#x\n", address1, address2);
			return entry;
		} 
	}
	return NULL;
}

#endif
re_list_t * find_prev_def_of_use(re_list_t* use, int *type){
#ifdef VERBOSE
	LOG(stdout, "In find_prev_def_of_use: use ");
	print_node_operand(use);
	LOG(stdout,"\n");
#endif
	re_list_t *entry;

	list_for_each_entry_reverse(entry, &use->list, list) {
		if (entry == &re_ds.head) break;
		if (entry->node_type != DefNode)
			continue;

		*type = compare_two_targets(entry, use);
#ifdef VERBOSE
		switch(*type){
			case EXACT:
				LOG(stdout,"In find_prev_def_of_use [EXACT]: next def ");
				print_node_operand(entry);
				LOG(stdout, " of use ");
				print_node_operand(use);
				LOG(stdout,"\n");
				break;
			case SUPER:
				LOG(stdout,"In find_prev_def_of_use [SUPER]: next def ");
				print_node_operand(entry);
				LOG(stdout, " of use ");
				print_node_operand(use);
				LOG(stdout,"\n");
				break;
			case SUB:
				LOG(stdout,"In find_prev_def_of_use [SUB]: next def ");
				print_node_operand(entry);
				LOG(stdout, " of use ");
				print_node_operand(use);
				LOG(stdout,"\n");
				break;
			case OVERLAP:
				LOG(stdout,"In find_prev_def_of_use [OVERLAP]: next def ");
				print_node_operand(entry);
				LOG(stdout, " of use ");
				print_node_operand(use);
				LOG(stdout,"\n");
				break;
			default:
				assert("find_prev_def_of_use type error");
		}
#endif
		if (*type) return entry;
	}
	return NULL;
}

re_list_t * find_inst_of_node(re_list_t *node) {
	re_list_t *entry;
	list_for_each_entry(entry, &node->list, list) {
		if (entry == &re_ds.head) break;
		if (entry->node_type == InstNode) 
			return entry;
	}
	return NULL;
}

bool check_node_in_list(re_list_t *node, re_list_t *list) {
	re_list_t *temp;
	switch (node->node_type) {
	case InstNode:
		list_for_each_entry(temp, &list->instlist, instlist) {
			if (temp == node) {
				return true;
			}
		}
		break;
	case UseNode:
		list_for_each_entry(temp, &list->uselist, uselist) {
			if (temp == node) {
				return true;
			}
		}
		break;
	case DefNode:
		list_for_each_entry(temp, &list->deflist, deflist) {
			if (temp == node) {
				return true;
			}
		}
		break;
	}
	return false;
}


void re_resolve(re_list_t *re_deflist, re_list_t *re_uselist, re_list_t *re_instlist) {


	while(RE_RES(re_deflist, re_uselist, re_instlist)){

		LOG(stdout, "Start of one iteration of resolving\n");

		if (!(list_empty(&re_uselist->uselist))) {
			// only affect deflist one time
			LOG(stdout, "RE_RESOLVE: Start of USE\n");
			resolve_use(re_deflist, re_uselist, re_instlist);
			LOG(stdout, "RE_RESOLVE: End of USE\n");
		}
		
		if (!(list_empty(&re_deflist->deflist))) {
			// affect deflist and instlist one time
			LOG(stdout, "RE_RESOLVE: Start of DEF\n");
			resolve_define(re_deflist, re_uselist, re_instlist);
			LOG(stdout, "RE_RESOLVE: End of DEF\n");
		}

		if (!(list_empty(&re_instlist->instlist))) {
			// affect deflist and uselist one time
			LOG(stdout, "RE_RESOLVE: Start of INST\n");
			resolve_inst(re_deflist, re_uselist, re_instlist);
			LOG(stdout, "RE_RESOLVE: End of INST\n");

		}

	}
}

void resolve_heuristics(re_list_t* instnode, re_list_t *re_deflist, re_list_t *re_uselist, re_list_t *re_instlist){
	
	int index; 
	cs_insn * inst; 	

	inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index; 
	
	index = insttype_to_index(inst->id);

	if(index >= 0){
		post_resolve_heuristics[index](instnode, re_deflist, re_uselist, re_instlist);
	}

}


void resolve_use(re_list_t *re_deflist, re_list_t *re_uselist, re_list_t *re_instlist){
	int type;
	re_list_t *entry, *temp;
	re_list_t *nextdef, *nextuse, *prevdef, *prevuse, *inst;
	valset_u vt; 
	int offset; 
#ifdef VSA
	int valoffset;
#endif
	list_for_each_entry_safe_reverse(entry, temp, &re_uselist->uselist, uselist){

		assert(CAST2_USE(entry->node)->val_known);
#ifdef VSA
#ifdef WITH_SOLVER
		adjust_use_constraint(entry);
#endif
#endif

		//deal with lea instruction in particular; 
		if(node_is_exp(entry, true) && !ok_to_check_alias(entry))
			goto out; 

		if(inst = find_inst_of_node(entry)){
			if (!check_inst_resolution(inst))
				add_to_instlist(inst, re_instlist);
		}

		assert(inst);

//be careful if the nextdef and entry have different addresses
		nextdef = find_next_def_of_use(entry, &type);

		//no nextdef, goto nextuse
		if(!nextdef)
			goto nextuse; 

		//nextdef has a super size
		if(type != EXACT && type !=SUB)
			goto nextuse;

//nextdef is an expression 
//then we need to exclude any possible unknown memory write inbetween
// FirmRCA note: seems a bug here?
		// if(node_is_exp(entry, true)){
		if(node_is_exp(nextdef, false)){

			int memsize; 
			int index; 

			//get size of the nextdef
			memsize = translate_datatype_to_byte(CAST2_DEF(nextdef->node)->inst);

			//check unknown memory write between each overlap byte
			for(index = 0; index < memsize; index++){

				//in this case, the alias check is based on entry; 
				//set up the offset for alias check 
				re_ds.alias_offset = CAST2_DEF(nextdef->node)->address- CAST2_USE(entry->node)->address + index; 

				if(obstacle_between_two_targets(&re_ds.head, nextdef, entry))
					goto nextuse;
			}

			//considering about the offset between two addresses; 
			offset = CAST2_DEF(nextdef->node)->address - CAST2_USE(entry->node)->address; 
			memcpy(&vt, ((void*)&CAST2_USE(entry->node)->val) + offset, sizeof(valset_u) - offset);

		}else{
			//still have a problem here
			memcpy(&vt, (void*)&CAST2_USE(entry->node)->val, sizeof(valset_u));
		}

		if(!(CAST2_DEF(nextdef->node)->val_stat & BeforeKnown)){
			assign_def_before_value(nextdef, vt);
			add_to_deflist(nextdef, re_deflist);
		}else
			assert_val(nextdef, vt, true);

		//assign to the next use
nextuse:
		nextuse = find_next_use_of_use(entry, &type);

		if(!nextuse)
			goto prevdef; 

		//between the next use, there is a define	
		if(nextdef && node1_add_before_node2(nextuse, nextdef))
			goto prevdef; 

		if(type != EXACT && type != SUB)
			goto prevdef;

// FirmRCA note: seems a bug here?
		// if(node_is_exp(entry, true)){
		if(node_is_exp(nextuse, true)){

			int memsize; 
			int index; 

			//get size of the next def
			memsize = translate_datatype_to_byte(CAST2_USE(nextuse->node)->inst);

			//check unknown memory write between each overlap byte
			for(index = 0; index < memsize; index++){

				//set up the offset for alias check 
				re_ds.alias_offset = CAST2_USE(nextuse->node)->address- CAST2_USE(entry->node)->address + index; 

				if(obstacle_between_two_targets(&re_ds.head, nextuse, entry))
					goto prevdef;

			}

			offset = CAST2_USE(nextuse->node)->address - CAST2_USE(entry->node)->address; 
			memcpy(&vt, ((void*)&CAST2_USE(entry->node)->val) + offset, sizeof(valset_u) - offset);

		}else{
			//still have a problem here
			memcpy(&vt, (void*)&CAST2_USE(entry->node)->val, sizeof(valset_u));
		}

		//assign the value to the next use
		if(!(CAST2_USE(nextuse->node)->val_known)){
			assign_use_value(nextuse, vt);
			add_to_uselist(nextuse, re_uselist);

		}else{ assert_val(nextuse, vt,false); }

		//assign to the previous define 
prevdef:
		prevdef = find_prev_def_of_use(entry, &type);

		if(!prevdef)
			goto prevuse; 

		if(type != EXACT && type != SUB)
			goto prevuse;

// FirmRCA note: seems a bug here?
		// if(node_is_exp(entry, true)){
		if(node_is_exp(prevdef, false)){

			int memsize; 
			int index; 

			//get size of the next def
			memsize = translate_datatype_to_byte(CAST2_DEF(prevdef->node)->inst);
			//check unknown memory write between each overlap byte
			for(index = 0; index < memsize; index++){

				//set up the offset for alias check 
				re_ds.alias_offset = index; 

//at this time, the base for alias check is the previous define 
				if(obstacle_between_two_targets(&re_ds.head, entry, prevdef))
					goto prevuse;
			}

			offset = CAST2_DEF(prevdef->node)->address - CAST2_USE(entry->node)->address; 
			memcpy(&vt, ((void*)&CAST2_USE(entry->node)->val) + offset, sizeof(valset_u) - offset);
		}else{
			//still have a problem here
			memcpy(&vt, (void*)&CAST2_USE(entry->node)->val, sizeof(valset_u));
		}

		if(!(CAST2_DEF(prevdef->node)->val_stat & AfterKnown)){
			assign_def_after_value(prevdef, vt);
			add_to_deflist(prevdef, re_deflist);

		}else{assert_val(prevdef, vt, false); }

		//assign to the previous use
prevuse:
		prevuse = find_prev_use_of_use(entry, &type);

		if(!prevuse)
			goto out; 

		if(prevdef && node1_add_before_node2(prevdef, prevuse))
			goto out; 

		if(type != EXACT && type != SUB)
			goto out;

// FirmRCA note: seems a bug here?
		// if(node_is_exp(entry, true)){
		if(node_is_exp(prevuse, true)){

			int memsize; 
			int index; 

			//get size of the next def
			memsize = translate_datatype_to_byte(CAST2_USE(prevuse->node)->inst);
			//check unknown memory write between each overlap byte
			for(index = 0; index < memsize; index++){

				//set up the offset for alias check 
				re_ds.alias_offset = index; 

				if(obstacle_between_two_targets(&re_ds.head, entry, prevuse))
					goto out;
			}

			offset = CAST2_USE(prevuse->node)->address - CAST2_USE(entry->node)->address; 
			memcpy(&vt, ((void*)&CAST2_USE(entry->node)->val) + offset, sizeof(valset_u) - offset);
		}else{
			//still have a problem here
			memcpy(&vt, (void*)&CAST2_USE(entry->node)->val, sizeof(valset_u));
		}
		if(!(CAST2_USE(prevuse->node)->val_known)){
			assign_use_value(prevuse, vt);
			add_to_uselist(prevuse, re_uselist);

		}else{assert_val(prevuse, vt, false);}
out:
		list_del(&entry->uselist);
	}
}

void resolve_define(re_list_t *re_deflist, re_list_t *re_uselist, re_list_t *re_instlist){
	int type;
	re_list_t *entry, *temp;
	re_list_t *nextdef, *nextuse, *prevdef, *prevuse, *inst;
	valset_u vt; 
	int offset; 
#ifdef VSA
	int valoffset;
#endif
	list_for_each_entry_safe_reverse(entry, temp, &re_deflist->deflist, deflist){

		assert(CAST2_DEF(entry->node)->val_stat & BeforeKnown
			|| CAST2_DEF(entry->node)->val_stat & AfterKnown);

#ifdef VSA
		//we do not real with eip here, as we know every eip value
		if(CAST2_DEF(entry->node)->operand->type == ARM_OP_REG 
			&& CAST2_DEF(entry->node)->operand->reg == ARM_REG_PC)
			goto out;  

#ifdef WITH_SOLVER
		adjust_def_constraint(entry);
#endif
#endif
		if(inst = find_inst_of_node(entry)){
			if (!check_inst_resolution(inst))
				add_to_instlist(inst, re_instlist);
		}

		assert(inst);

		if( !(CAST2_DEF(entry->node)->val_stat & AfterKnown) )
			goto prevdef; 

		nextdef = find_next_def_of_def(entry, &type);

		if(!nextdef)
			goto nextuse; 

		//nextdef has a super size
		if(type != EXACT && type !=SUB)
			goto nextuse;

		//nextdef is an expression 
		// FirmRCA note: seems a bug here?
		// if(node_is_exp(entry, false)){
		if(node_is_exp(nextdef, false)){

			int memsize; 
			int index; 

			//get size of the next def
			memsize = translate_datatype_to_byte(CAST2_DEF(nextdef->node)->inst);
			//check unknown memory write between each overlap byte
			for(index = 0; index < memsize; index++){

				//set up the offset for alias check 
				re_ds.alias_offset = CAST2_DEF(nextdef->node)->address- CAST2_DEF(entry->node)->address + index; 

				if(obstacle_between_two_targets(&re_ds.head, nextdef, entry))
					goto nextuse;
			}

			//considering about the offset between two addresses; 
			offset = CAST2_DEF(nextdef->node)->address - CAST2_DEF(entry->node)->address; 
			memcpy(&vt, ((void*)&CAST2_DEF(entry->node)->afterval) + offset, sizeof(valset_u) - offset);

		}else{

			//still have a problem here
			memcpy(&vt, (void*)&CAST2_DEF(entry->node)->afterval, sizeof(valset_u));
		}


		if(!(CAST2_DEF(nextdef->node)->val_stat & BeforeKnown)){
			assign_def_before_value(nextdef, vt);
			add_to_deflist(nextdef, re_deflist);

		}else{assert_val(nextdef, vt, true); }

//assign to the next use
nextuse:
		nextuse = find_next_use_of_def(entry, &type);

		if(!nextuse)
			goto prevdef; 
	
		//between the next use, there is a define	
		if(nextdef && node1_add_before_node2(nextuse, nextdef))
			goto prevdef; 

		//there is unknown memory write between the current use 
		//and the next use

		if(type != EXACT && type !=SUB)
			goto prevdef;

		//nextdef is an expression 
		// FirmRCA note: seems a bug here?
		// if(node_is_exp(entry, false)){
		if(node_is_exp(nextuse, true)){

			int memsize; 
			int index; 

			//get size of the next def
			memsize = translate_datatype_to_byte(CAST2_USE(nextuse->node)->inst);

			//check unknown memory write between each overlap byte
			for(index = 0; index < memsize; index++){

				//set up the offset for alias check 
				re_ds.alias_offset = CAST2_USE(nextuse->node)->address- CAST2_DEF(entry->node)->address + index; 

				if(obstacle_between_two_targets(&re_ds.head, nextuse, entry))
					goto prevdef;
			}

			//considering about the offset between two addresses; 
			offset = CAST2_USE(nextuse->node)->address - CAST2_DEF(entry->node)->address; 
			memcpy(&vt, ((void*)&CAST2_DEF(entry->node)->afterval) + offset, sizeof(valset_u) - offset);

		}else{

			//still have a problem here
			memcpy(&vt, (void*)&CAST2_DEF(entry->node)->afterval, sizeof(valset_u));
		}

		//assign the value to the next use
			if(!(CAST2_USE(nextuse->node)->val_known)){
				assign_use_value(nextuse, vt);
				add_to_uselist(nextuse, re_uselist);
			}else{assert_val(nextuse, vt,false);}

//assign to the previous define 
prevdef:
		if( !(CAST2_DEF(entry->node)->val_stat & BeforeKnown) )
			goto out; 

		prevdef = find_prev_def_of_def(entry, &type);

		if(!prevdef)
			goto prevuse; 


		if(type != EXACT && type !=SUB)
			goto prevuse;

		//nextdef is an expression 
		// FirmRCA note: seems a bug here?
		// if(node_is_exp(entry, false)){
		if(node_is_exp(prevdef, false)){

			int memsize; 
			int index; 

			//get size of the next def
			memsize = translate_datatype_to_byte(CAST2_DEF(prevdef->node)->inst);
			//check unknown memory write between each overlap byte
			for(index = 0; index < memsize; index++){

				//set up the offset for alias check 
				re_ds.alias_offset =  index; 

				if(obstacle_between_two_targets(&re_ds.head, entry, prevdef))
					goto prevuse;
			}

			//considering about the offset between two addresses; 
			offset = CAST2_DEF(prevdef->node)->address - CAST2_DEF(entry->node)->address; 
			memcpy(&vt, ((void*)&CAST2_DEF(entry->node)->beforeval) + offset, sizeof(valset_u) - offset);

		}else{

			//still have a problem here
			memcpy(&vt, (void*)&CAST2_DEF(entry->node)->beforeval, sizeof(valset_u));
#ifdef VSA
			valoffset = adjust_val_offset(prevdef, type);
			memcpy(&vt, ((void*)(&vt)) + valoffset, sizeof(valset_u) - valoffset);
#endif
		}

			if(!(CAST2_DEF(prevdef->node)->val_stat & AfterKnown)){
				assign_def_after_value(prevdef, vt);
				add_to_deflist(prevdef, re_deflist);

			}else{assert_val(prevdef, vt, false); }

//assign to the previous use
prevuse:
		prevuse = find_prev_use_of_def(entry, &type);

		if(!prevuse)
			goto out; 
		
		if(prevdef && node1_add_before_node2(prevdef, prevuse))
			goto out; 

		if(type != EXACT && type !=SUB)
			goto out;

		//nextdef is an expression
		// FirmRCA note: seems a bug here? 
		// if(node_is_exp(entry, false)){
		if(node_is_exp(prevuse, true)){

			int memsize; 
			int index; 

			//get size of the next def
			memsize = translate_datatype_to_byte(CAST2_USE(prevuse->node)->inst);
			//check unknown memory write between each overlap byte
			for(index = 0; index < memsize; index++){

				//set up the offset for alias check 
				re_ds.alias_offset =  index; 

				if(obstacle_between_two_targets(&re_ds.head, entry, prevuse))
					goto out;
			}

			//considering about the offset between two addresses; 
			offset = CAST2_USE(prevuse->node)->address - CAST2_DEF(entry->node)->address; 
			memcpy(&vt, ((void*)&CAST2_DEF(entry->node)->beforeval) + offset, sizeof(valset_u) - offset);

		}else{

			//still have a problem here
			memcpy(&vt, (void*)&CAST2_DEF(entry->node)->beforeval, sizeof(valset_u));
		}

			if(!(CAST2_USE(prevuse->node)->val_known)){
				assign_use_value(prevuse,vt);
				add_to_uselist(prevuse, re_uselist);

			}else{assert_val(prevuse, vt, false); }

out:
		list_del(&entry->deflist);
	}
}

#if 0
void resolve_define(re_list_t *re_deflist, re_list_t *re_uselist, re_list_t *re_instlist) {

	re_list_t *entry, *temp, *def, *use, *inst;
	def_node_t *dnode;
	int type;

	list_for_each_entry_safe_reverse(entry, temp, &re_deflist->deflist, deflist){
		// directly add corresponding inst entry into instlist
		inst = find_inst_of_node(entry);
		if (inst) {

			if (!check_inst_resolution (inst)) {
				add_to_instlist(inst, re_instlist);
			}
		} 

		dnode = (def_node_t *)entry->node;
		// only care about next define to avoid duplicate node
		if (dnode->val_stat & AfterKnown) {

			def_after_pollute_use(entry, re_instlist);

			def = find_next_def_of_def(entry, &type);


			if (def && (type == EXACT || type == SUB)){ 
				if(!(CAST2_DEF(def->node)->val_stat & BeforeKnown)) {
					assign_def_before_value(def, dnode->afterval);
					//if (!check_node_in_list(def, re_deflist)) {
					//	list_add(&def->deflist, &re_deflist->deflist);
					//}
					add_to_deflist(def, re_deflist);
				}else{
					assert_val(def, dnode->afterval, true);
				}
			}
		}

		if (dnode->val_stat & BeforeKnown) {

			// set value of all use node by beforevalue of current define
			def_before_pollute_use(entry,re_instlist);

			def = find_prev_def_of_def(entry, &type);

			if(def && node_is_exp(entry, false) && check_next_unknown_write(&re_ds.head, entry, def)){

				re_list_t* tempinst; 

				goto out;

				//assert(0);	
			}

			if(def &&  (type == EXACT || type == SUB)){ 
				if(!(CAST2_DEF(def->node)->val_stat & AfterKnown) ){
					assign_def_after_value(def, dnode->beforeval);
					//if(!check_node_in_list(def, re_deflist)){
					//	list_add(&def->deflist, &re_deflist->deflist);
					//}
					add_to_deflist(def, re_deflist);
				}else{
					assert_val(def, dnode->beforeval, false);
				}
			}

		}
out:
		list_del(&entry->deflist);
	}
}
#endif

int insttype_to_index(arm_insn type){

	int index; 
	for(index = 0; index < ninst; index++){
		
		if(opcode_index_tab[index].type == type){
			return index; 
		}
	}

	return -1;
}

#ifdef VSA
static bool use_after_def(re_list_t *use, int regid, re_list_t *def[], int ndef){

	int defindex;
	cs_insn* arminst; 
	re_list_t* inst;

	inst = find_inst_of_node(use);
	arminst = &re_ds.instlist[CAST2_INST(inst->node)->inst_index];

	if(get_insn_type(re_ds.handle, arminst) == CS_GRP_RET) // expression leave
		return true;

	for(defindex = 0; defindex < ndef; defindex++){
		//this defines a register and its ID matches the register for use
		if(CAST2_DEF(def[defindex]->node)->operand->type == ARM_OP_REG && CAST2_DEF(def[defindex]->node)->operand->reg == regid){
			//this use has been redefined, so we cannot check
			if(use->id < def[defindex]->id)
				return true;
		}	
	}
	return false; 
}

void correctness_check(re_list_t * instnode){
	return;
	inst_node_t *inst; 
	re_list_t *use[NOPD], *def[NOPD];
	operand_val_t *regvals; 
	use_node_t * tempuse; 
	def_node_t * tempdef;

	size_t nuse, ndef; 
	int i,j, regindex; 

	//get the operands log from re_ds	
	inst = (inst_node_t*)(instnode->node); 
	regvals = &re_ds.oplog_list.opval_list[inst->inst_index];

	// not check system call
	// if (!strcmp(re_ds.instlist[inst->inst_index].mnemonic, "sysenter"))
	// 	return;

	if(regvals -> regnum == 0)
		return; 
	
	obtain_inst_elements(instnode, use, def, &nuse, &ndef);

	//check every use	
	//we can only check the values of registers
	for(i = 0; i < nuse; i++ ){

		tempuse = CAST2_USE(use[i]->node);		

		if(!tempuse->val_known)
			continue; 

		if(tempuse->usetype == Base ){
			for(regindex = 0; regindex < regvals->regnum; regindex++){

				//if this use has been redefined, we do not consider about it
				if(use_after_def(use[i], tempuse->operand->mem.base, def, ndef))
					continue; 

				//for debug use
				if(tempuse->operand->mem.base == get_esp_id()){
					if(tempuse->val.dword == regvals->regs[regindex].val.dword || tempuse->val.dword == regvals->regs[regindex].val.dword - 0x4)
						continue;
				}				
				//end debugging use;


				if(tempuse->operand->mem.base == regvals->regs[regindex].reg_num)
					assert_val(use[i], regvals->regs[regindex].val, false);
			}			
		}	
	
		if(tempuse->usetype == Index){
			for(regindex = 0; regindex < regvals->regnum; regindex++){
	
				//if this use has been redefined, we do not consider about it
				if(use_after_def(use[i], tempuse->operand->mem.index, def, ndef))
					continue; 


                                if(tempuse->operand->mem.index == regvals->regs[regindex].reg_num)
                                        assert_val(use[i], regvals->regs[regindex].val, false);
                        }
		}

		if(tempuse->usetype == Opd && tempuse->operand->type == ARM_OP_REG){

			for(regindex = 0; regindex < regvals->regnum; regindex++){
				
				//if this use has been redefined, we do not consider about it
				if(use_after_def(use[i], tempuse->operand->reg, def, ndef))
					continue; 

                                if(tempuse->operand->reg == regvals->regs[regindex].reg_num)
                                        assert_val(use[i], regvals->regs[regindex].val, false);
                        }
		}
	}
	
	//check before value of def
	for(j = 0; j < ndef; j++){
		tempdef = CAST2_DEF(def[j]->node);

		if(tempdef->operand->type == ARM_OP_REG && (tempdef->val_stat & BeforeKnown)){
			for(regindex = 0; regindex < regvals->regnum; regindex++){
				if(use_after_def(def[j], tempdef->operand->reg, def, ndef))
					continue; 			

                                if(tempdef->operand->reg == regvals->regs[regindex].reg_num)
                                        assert_val(def[j], regvals->regs[regindex].val, true);
			}
		}
	}
}	

#ifdef FIX_OPTM

void fix_optimization(re_list_t* inst){
	
	re_list_t *dst[NOPD], *src[NOPD];
        int nuse, ndef;
        int it;
        def_node_t *def;
        use_node_t *use;
	re_list_t re_deflist, re_uselist, re_instlist;  	

	INIT_LIST_HEAD(&re_deflist.deflist);
	INIT_LIST_HEAD(&re_uselist.uselist);
	INIT_LIST_HEAD(&re_instlist.instlist);	

        //get the operands of the instruciton   
        obtain_inst_operand(inst, src, dst, &nuse, &ndef);		

	for(it = 0; it < nuse; it++){
		if(CAST2_USE(src[it]->node)->val_known)
			add_to_uselist(src[it], &re_uselist);
	}

	for(it = 0; it < ndef; it++){
		if(CAST2_DEF(dst[it]->node)->val_stat & AfterKnown)
			add_to_deflist(dst[it], &re_deflist);
	}

	re_resolve(&re_deflist, &re_uselist, &re_instlist);
}
	

#endif





#endif
void resolve_inst(re_list_t *re_deflist, re_list_t *re_uselist, re_list_t *re_instlist) {
/* list_for_each_entry (instlist)
 * 	Search all the operands of each instruction
 * 	justify whether those known operands meet the requirement of constraints
 *	According to instruction semantics, resolve define/use  and add them to the corresponding list
 */
	int index; 
	cs_insn * inst; 	
	re_list_t *entry, *temp;

	list_for_each_entry_safe_reverse(entry, temp, &re_instlist->instlist, instlist){

		inst = re_ds.instlist + CAST2_INST(entry->node)->inst_index; 
		index = insttype_to_index(inst->id);
		
		if(index >= 0){
			inst_resolver[index](entry, re_deflist, re_uselist);
		}
		else{
			assert(0);
		}

		list_del(&entry->instlist);
#ifdef VSA
		if(re_ds.rec_count == 0 && re_ds.oplog_list.log_num > 0)
			correctness_check(entry);
#endif
	}
}


int check_inst_resolution(re_list_t* inst){

	re_list_t *entry;

	list_for_each_entry_reverse(entry, &inst->list, list) {

		if (entry == &re_ds.head) return 1;	

		if(entry->node_type == InstNode) return 1; 

		if (entry->node_type == DefNode){
			if(CAST2_DEF(entry->node)->val_stat != (BeforeKnown | AfterKnown))
				return 0;
		}

		if(entry->node_type == UseNode){
			if(!CAST2_USE(entry->node)->val_known)
				return 0;

			if(!CAST2_USE(entry->node)->address)
				return 0;
		}
	}
	return 1;
}

/*
bool unknown_expression(re_list_t * exp){


	re_list_t *index, *base, *entry; 
	x86_op_t* opd;
	unsigned baseaddr, indexaddr;

	index = NULL;
	base = NULL;
	baseaddr = 0; 
	indexaddr = 0;

	opd = (exp->node_type == DefNode ? 
			CAST2_DEF(exp->node)->operand : CAST2_USE(exp->node)->operand);

	list_for_each_entry_reverse(entry, &exp->list, list){
		if(entry == &re_ds.head || entry->node_type != UseNode)
			break;
		if(CAST2_USE(entry->node)->operand != opd)
			break;		

		if(CAST2_USE(entry->node)->usetype == Base)
			base = entry;
		if(CAST2_USE(entry->node)->usetype == Index)
			index = entry;
	}

	if(base && !CAST2_USE(base->node)->val_known){
		return true;
	}




	if(index && ! CAST2_USE(index->node)->val_known){
		return true;	
	}

	if(exp->node_type == DefNode){

		CAST2_DEF(exp->node)->address = baseaddr + indexaddr * opd->data.expression.scale + (int)(opd->data.expression.disp * opd->data.expression.disp_size);
		print_defnode(exp->node);

	}

	if(exp->node_type == UseNode){
		CAST2_USE(exp->node)->address = baseaddr + indexaddr * opd->data.expression.scale + (int)(opd->data.expression.disp * opd->data.expression.disp_size);
	}	
	
	return false;
}
*/

// note Important function, resolve the expression address. Sometimes update register value
void res_expression(re_list_t * exp, re_list_t *uselist){

	re_list_t *index, *base, *entry; 
	cs_arm_op* opd;
	unsigned baseaddr, indexaddr;

	index = NULL;
	base = NULL;
	baseaddr = 0; 
	indexaddr = 0;
	
	opd = (exp->node_type == DefNode ? CAST2_DEF(exp->node)->operand : CAST2_USE(exp->node)->operand);

	get_element_of_exp(exp, &index, &base);
	
	enum addrstat stat = exp_addr_status(base, index);
#ifdef VERBOSE
	LOG(stdout, "re_dsmanager.c/res_expression for [");
	if (exp->node_type == DefNode){
		print_operand(opd);
	} else {
		print_sub_operand(opd, ((use_node_t *)exp->node)->usetype);
	}
	LOG(stdout, "], status = %d, ", stat);
#endif
	switch (exp_addr_status(base, index)) {
		case KBaseKIndex:
			if (base){
				baseaddr = CAST2_USE(base->node)->val.dword;
			}

			if (index) {
				indexaddr = CAST2_USE(index->node)->val.dword;
			}
			break;

		case UBase:
		case UIndex:

			if(exp->node_type == DefNode) {
				add_to_umemlist(exp);
			}
			return;

		case KBaseUIndex:
			if (exp->node_type == DefNode) {
				if (!CAST2_DEF(exp->node)->address){
					add_to_umemlist(exp);
				} else {
					baseaddr = CAST2_USE(base->node)->val.dword;
					unsigned temp = CAST2_DEF(exp->node)->address - baseaddr -
							(int)(opd->mem.disp);
					indexaddr = temp/(opd->mem.scale); // TODO ? scale ?
					valset_u vt;
					vt.dword = indexaddr;
					assign_use_value(index, vt);
					add_to_uselist(index, uselist);
				}
			}
			return;
			break;
		case UBaseKIndex:
			if (exp->node_type == DefNode) {
				if (!CAST2_DEF(exp->node)->address) {
					add_to_umemlist(exp);
				} else {
					indexaddr = CAST2_USE(index->node)->val.dword;
					baseaddr = CAST2_DEF(exp->node)->address -
						indexaddr * opd->mem.scale -
						(int)(opd->mem.disp);
					valset_u vt;
					vt.dword = baseaddr;
					assign_use_value(base, vt);
					add_to_uselist(base, uselist);
				}
			}
			return;
			break;
		case UBaseUIndex:
			if((exp->node_type == DefNode) && (!CAST2_DEF(exp->node)->address)){
				add_to_umemlist(exp);
			}
			return;
			break;
		case NBaseNIndex:
			break;
		default:
			assert(0);
			break;
	}
#ifdef VERBOSE
	LOG(stdout, "baseaddr = %x, indexaddr = %x\n", baseaddr, indexaddr);
#endif
	// note calculate address of def node and use node for expression
	if(exp->node_type == DefNode){
		re_list_t *nextdef; 
		int type;
		valset_u rv;
		// https://github.com/capstone-engine/capstone/issues/246 LSL is the only shift way in memory
		assert(opd->shift.type == ARM_SFT_LSL || opd->shift.type == ARM_SFT_INVALID);

		CAST2_DEF(exp->node)->address = baseaddr + 
		(indexaddr << opd->shift.value) +  
		(int)(opd->mem.disp);
		// note TODO what if self-modifying register usage? ldr r0, [r1, #4]!
		// note what does scale do?

		// if (op_with_gs_seg(CAST2_DEF(exp->node)->operand)) {
		// 	CAST2_DEF(exp->node)->address += re_ds.coredata->corereg.gs_base;
		// }

		remove_from_umemlist(exp);



		if(assign_def_before_mem_val(exp, &rv, uselist)){
			if(!(CAST2_DEF(exp->node)->val_stat & BeforeKnown)){
				assign_def_before_value(exp, rv);
			}else{
				assert_val(exp, rv, true);
			}
		}

		if(assign_def_after_mem_val(exp, &rv, uselist)){
			if(!(CAST2_DEF(exp->node)->val_stat & AfterKnown)){
				assign_def_after_value(exp, rv);
			}else{
				assert_val(exp, rv, false);
			}
		}

	}

	if(exp->node_type == UseNode){
		re_list_t *nextdef;	
		int type;
		valset_u rv;
		assert(opd->shift.type == ARM_SFT_LSL || opd->shift.type == ARM_SFT_INVALID); // note support typedef enum arm_shifter: lsl
		CAST2_USE(exp->node)->address = baseaddr + 
		(indexaddr << opd->shift.value) + 
		(int)(opd->mem.disp);
		// note TODO what if self-modifying register usage? ldr r0, [r1, #4]!
		// note what does scale do? 

		// if (op_with_gs_seg(CAST2_USE(exp->node)->operand)) {
		// 	CAST2_USE(exp->node)->address += re_ds.coredata->corereg.gs_base;
		// }

		//take care of lea instruction particularly
		if(!ok_to_check_alias(exp))
			return; 

		if(assign_use_mem_val(exp, &rv, uselist)){
			if(!CAST2_USE(exp->node)->val_known){
				assign_use_value(exp, rv);
			}else{
				assert_val(exp, rv, false);
			}
		}
	}	
}

bool node_is_exp(re_list_t* node, bool use){
	if(use)
		return CAST2_USE(node->node)->usetype == Opd && CAST2_USE(node->node)->operand->type == ARM_OP_MEM ? 1 : 0;

	return CAST2_DEF(node->node)->operand->type == ARM_OP_MEM ? 1 : 0;
}


bool address_is_known(re_list_t *node) {
	switch (node->node_type) {
		case UseNode:
			return CAST2_USE(node->node)->address != 0 ? true : false;
			break;
		case DefNode:
			return CAST2_DEF(node->node)->address != 0 ? true : false;
			break;
		default:
			assert(0);
			break;
	}
}

//find all the operands use after a def node
void get_src_of_def(re_list_t* def, re_list_t **use, int *nuse){

	re_list_t * entry;
	*nuse = 0;
#ifdef VERBOSE
	LOG(stdout, "get_src_of_def start: def node[");
	print_node_operand(def);
	LOG(stdout, "]\n");
#endif
	list_for_each_entry_reverse(entry, &def->list, list){
#ifdef VERBOSE
		LOG(stdout, "get_src_of_def: entry node[");
		print_node_operand(entry);
		LOG(stdout, "]\n");
#endif
#ifdef FRCA
		switch (entry->node_type)
		{
			case UseNode:
				if(CAST2_USE(entry->node)->usetype == Opd){
					use[(*nuse)++] = entry; 
				}
				break;
			case DefNode:
				if (CAST2_DEF(entry->node)->usage != op_writeback) {
					return;
				}
				break;
			case InstNode:
				return;
			default:
				return;
		}
#else		
		if(entry->node_type != UseNode)
			return; 

		if(CAST2_USE(entry->node)->usetype == Opd){
			use[(*nuse)++] = entry; 
		}
#endif
	}
}

//only to get the operands of an instruction
void obtain_inst_elements(re_list_t* inst, re_list_t **use, re_list_t **def, int *nuse, int *ndef){
		
	bool tak, addr, tak1, addr1;
	re_list_t* entry;

	*nuse = 0;
	*ndef = 0;

	list_for_each_entry_reverse(entry, &inst->list, list){
		if(entry == &re_ds.head) break;
		if(entry->node_type == InstNode) break;

		if(entry->node_type == UseNode){
			use[(*nuse)++] = entry;
		}
		
		if(entry->node_type == DefNode){
			def[(*ndef)++] = entry;
		}
	}
}

//only to get the operands of an instruction
void obtain_inst_operand(re_list_t* inst, re_list_t **use, re_list_t **def, int *nuse, int *ndef){
		
	bool tak, addr, tak1, addr1;
	re_list_t* entry;

	*nuse = 0;
	*ndef = 0;

	list_for_each_entry_reverse(entry, &inst->list, list){
		if(entry == &re_ds.head) break;
		if(entry->node_type == InstNode) break;

		if(entry->node_type == UseNode){
			if(CAST2_USE(entry->node)->usetype == Opd)
				use[(*nuse)++] = entry;
		}
		
		if(entry->node_type == DefNode){
			def[(*ndef)++] = entry;
		}
	}
}

void traverse_inst_operand(re_list_t* inst, re_list_t **use, re_list_t **def, re_list_t* uselist, re_list_t* deflist, int *nuse, int *ndef){
		
	bool tak, addr, tak1, addr1;
	unsigned int address = 0;
	re_list_t* entry;
#ifdef FRCA
	re_list_t* writeback_node = NULL;
#endif
	valset_u vt;
	*nuse = 0;
	*ndef = 0;
	
	list_for_each_entry_reverse(entry, &inst->list, list){
		if(entry == &re_ds.head) break;
		if(entry->node_type == InstNode) {
			break;
		}
		if(entry->node_type == UseNode){
			if(node_is_exp(entry, true)){ 
				tak = CAST2_USE(entry->node)->val_known;
				addr = CAST2_USE(entry->node)->address;
				assert (address == 0);
				address = CAST2_USE(entry->node)->address;

#ifdef VERBOSE
				LOG(stdout, "traverse_inst_operand: use node[");
				print_sub_operand(CAST2_USE(entry->node)->operand, ((use_node_t*)entry->node)->usetype);
				LOG(stdout, "] is an expression with value%sknown, address %#x\n",
						tak ? " " : " un", addr);
#endif				
				if(!tak || !addr){
					res_expression(entry, uselist);
					tak1 = CAST2_USE(entry->node)->val_known;
#ifdef POMP
					if(tak != tak1)
					add_to_uselist(entry, uselist);
#else
					addr1 = CAST2_USE(entry->node)->address; // VSA
					if( (tak != tak1 || addr != addr1) && addr1 && tak1) // VSA
						add_to_uselist(entry, uselist);
#endif
				}
			}
			if(CAST2_USE(entry->node)->usetype == Opd) {
				use[(*nuse)++] = entry;
			} 
		}
		
		if(entry->node_type == DefNode){
			if(node_is_exp(entry, false)){

				tak = CAST2_DEF(entry->node)->val_stat & AfterKnown;
				addr = CAST2_DEF(entry->node)->address;
#ifdef FRCA
				assert (address == 0);
				address = CAST2_DEF(entry->node)->address;
#endif
#ifdef VERBOSE
				LOG(stdout, "traverse_inst_operand: def node is an expression with AfterKnown %s, addr %#x\n",
						tak ? "true" : "false", addr);
#endif
				if(!tak || !addr){

					res_expression(entry, uselist);

					tak1 = CAST2_DEF(entry->node)->val_stat & AfterKnown;
#ifdef POMP
					if(tak!=tak1){
						//list_add(&entry->deflist, &deflist->deflist);
						add_to_deflist(entry, deflist);
					}
#else
					addr1 = CAST2_DEF(entry->node)->address; // VSA
					// if(tak!=tak1){
					if( (tak != tak1 || addr != addr1) && addr1 && tak1) { // VSA
						//list_add(&entry->deflist, &deflist->deflist);
						add_to_deflist(entry, deflist);
					}	
#endif
				}

			}
#ifdef FRCA
			if (CAST2_DEF(entry->node)->usage == op_writeback) {
				// writeback node should be resolved here, no need to turn to resolver
				writeback_node = entry;
			} 
#endif
			def[(*ndef)++] = entry;
		}
	}
#ifdef FRCA
	// just resolve after value here.
	// before value could be resolved in the instruction resolver
	if (writeback_node && (!CAST2_DEF(entry->node)->val_stat & AfterKnown)) {
		if (address){
			vt.dword = address;
			assign_def_after_value(writeback_node, vt);		
		}
	}
#endif
//if the unknown umem list is empty, should we do some clean up here?

}
#ifdef FRCA
void split_expression_to_use(cs_arm_op *opd, cs_insn *insn, arm_op_usage usage, re_list_t* re_uselist){
	// bool writeback = insn->detail->writeback;
	// TODO: since writeback has been regarded as a def node when leaving insn
	// It seems that we don't need to consider writeback here
	switch (get_expreg_status(opd->mem)) {
		case No_Reg:
			break;
		case Base_Reg:
			add_new_use(opd, insn, usage, Base, re_uselist);
			break;
		case Index_Reg:
			add_new_use(opd, insn, usage, Index, re_uselist);	
			break;
		case Base_Index_Reg:
			add_new_use(opd, insn, usage, Base, re_uselist);	
			add_new_use(opd, insn, usage, Index, re_uselist);	
			break;
	}
}
#else
void split_expression_to_use(cs_arm_op* opd, cs_insn *insn){
#ifdef WITH_SOLVER
	re_list_t * exp; 
	valset_u tempval;
	Z3_ast baseast, indexast, scaleast, dispast; 

	exp = list_first_entry(&re_ds.head.list, re_list_t, list);
#endif
	if (opd->type == ARM_OP_MEM) {
		switch (get_expreg_status(opd->mem)) {
			case No_Reg:
				break;
			case Base_Reg:
				add_new_use(opd, Base, insn);
				break;
			case Index_Reg:
				add_new_use(opd, Index, insn);	
				break;
			case Base_Index_Reg:
				add_new_use(opd, Base, insn);	
				add_new_use(opd, Index, insn);	
				break;
		}
	}

#ifdef WITH_SOLVER

	if(base)
		baseast = CAST2_USE(base->node)->constraint;
	else{
		tempval.dword = 0;
		baseast = val_to_bv(tempval, sizeof(unsigned));
	}
	
	if(index){
		indexast = CAST2_USE(index->node)->constraint; 
	}else{
		tempval.dword = 0;
		indexast = val_to_bv(tempval, sizeof(unsigned));
	}

	tempval.dword = opd->data.expression.scale;
	scaleast = val_to_bv(tempval, sizeof(unsigned));

	tempval.dword = opd->data.expression.disp;
	dispast = val_to_bv(tempval, sizeof(unsigned));

	if(exp->node_type == UseNode){
		CAST2_USE(exp->node)->addresscst = Z3_mk_bvadd(re_ds.zctx, Z3_mk_bvadd(re_ds.zctx, baseast, Z3_mk_bvmul(re_ds.zctx, indexast, scaleast)), dispast);
	}else{
		CAST2_DEF(exp->node)->addresscst = Z3_mk_bvadd(re_ds.zctx, Z3_mk_bvadd(re_ds.zctx, baseast, Z3_mk_bvmul(re_ds.zctx, indexast, scaleast)), dispast);
	}
	
#endif
}
#endif


bool node1_add_before_node2(re_list_t *node1, re_list_t* node2){
	return node1->id < node2->id ? true : false;
}


void destroy_corelist() {
	delete_corelist(&re_ds.head);
}


void add_to_deflist(re_list_t *entry, re_list_t *listhead) {
       if (!check_node_in_list(entry, listhead))
               list_add(&entry->deflist, &listhead->deflist);
}


void add_to_uselist(re_list_t *entry, re_list_t *listhead) {
       if (!check_node_in_list(entry, listhead))
               list_add(&entry->uselist, &listhead->uselist);
}


void add_to_instlist(re_list_t *entry, re_list_t *listhead) {
       if (!check_node_in_list(entry, listhead))
               list_add(&entry->instlist, &listhead->instlist);
}


void add_to_instlist_tail(re_list_t *entry, re_list_t *listhead) {
       if (!check_node_in_list(entry, listhead))
               list_add_tail(&entry->instlist, &listhead->instlist);
}


void remove_from_deflist(re_list_t *entry, re_list_t *listhead) {
       if (check_node_in_list(entry, listhead)) {
               list_del(&entry->deflist);
       }
}


void remove_from_uselist(re_list_t *entry, re_list_t *listhead) {
       if (check_node_in_list(entry, listhead)) {
               list_del(&entry->uselist);
       }
}


void remove_from_instlist(re_list_t *entry, re_list_t *listhead) {
       if (check_node_in_list(entry, listhead)) {
               list_del(&entry->instlist);
       }
}

void zero_valset(valset_u *vt) {
	memset(vt, 0, sizeof(valset_u));
}

void one_valset(valset_u *vt) {
	memset(vt, 0xff, sizeof(valset_u));
}

void clean_valset(valset_u *vt, arm_datatype datatype, bool sign) {
	unsigned char tchar;
	unsigned short tshort;
	unsigned long tlong;
	switch (datatype) {
		case op_byte:
			tchar = vt->byte;
			if (sign) {
				one_valset(vt);
			} else {
				zero_valset(vt);
			}
			vt->byte = tchar;
			break;
		case op_word:
			tshort = vt->word;
			if (sign) {
				one_valset(vt);
			} else {
				zero_valset(vt);
			}
			vt->word = tshort;
			break;
		case op_dword:
			tlong = vt->dword;
			if (sign) {
				one_valset(vt);
			} else {
				zero_valset(vt);
			}
			vt->dword = tlong;
			break;
		// case op_dqword:
		// 	break;
		default:
			assert(0);
			break;
	}
}


bool sign_of_valset(valset_u *vt, arm_datatype datatype) {
	bool sign;
	
	switch (datatype) {
		case op_byte:
			sign = vt->byte & (1 << (BYTE_SIZE - 1));
			break;
		case op_word:
			sign = vt->word & (1 << (WORD_SIZE - 1));
			break;
		case op_dword:
			sign = vt->dword & (1 << (DWORD_SIZE - 1));
			break;
		default:
			LOG(stdout, "%d\n", datatype);
			assert(0);
			break;
	}
	return sign;
}


void sign_extend_valset(valset_u *vt, arm_datatype datatype) {
	bool sign;

	sign = sign_of_valset(vt, datatype);

	clean_valset(vt, datatype, sign);
}


re_list_t * get_entry_by_id(unsigned id) {
	re_list_t *entry;

	list_for_each_entry_reverse(entry, &re_ds.head.list, list) {
		if (entry->id == id) {
			return entry;
		}
	}
	return NULL;
}


re_list_t *get_entry_by_inst_id(unsigned inst_index) {
	re_list_t *entry;

	list_for_each_entry_reverse(entry, &re_ds.head.list, list) {
		if ((entry->node_type == InstNode) && 
			(CAST2_INST(entry->node)->inst_index == inst_index)) {
			return entry;
		}
	}
	return NULL;
}

#ifdef VSA
bool get_esp_value_from_inst(re_list_t *inst, unsigned long *esp_min, unsigned long *esp_max) {
	
	re_list_t *entry;
	bool is_known = 0;
	cs_arm_op *opd;

	*esp_max = 0;
	*esp_min = ULONG_MAX;

	list_for_each_entry_reverse(entry, &inst->list, list) {
		if (entry == &re_ds.head) break;
		if (entry->node_type == InstNode) break;

		opd = GET_OPERAND(entry);

		if (entry->node_type == DefNode) {
			if (!x86_opd_is_esp(CAST2_DEF(entry->node)->operand))
				continue;
			if (CAST2_DEF(entry->node)->val_stat & BeforeKnown) {
				is_known = 1;
				if (*esp_min > CAST2_DEF(entry->node)->beforeval.dword) {
					*esp_min = CAST2_DEF(entry->node)->beforeval.dword;
				}
				if (*esp_max < CAST2_DEF(entry->node)->beforeval.dword) {
					*esp_max = CAST2_DEF(entry->node)->beforeval.dword;
				}
			}
			if (CAST2_DEF(entry->node)->val_stat & AfterKnown) {
				is_known = 1;
				if (*esp_min > CAST2_DEF(entry->node)->afterval.dword) {
					*esp_min = CAST2_DEF(entry->node)->afterval.dword;
				}
				if (*esp_max < CAST2_DEF(entry->node)->afterval.dword) {
					*esp_max = CAST2_DEF(entry->node)->afterval.dword;
				}
			}
		}
		if (entry->node_type == UseNode) {
			bool flag = 0;
			// esp use operand
			if ((CAST2_USE(entry->node)->usetype == Opd) &&
			    (x86_opd_is_esp(opd))) {
				flag = 1;
			}
			// [esp] esp only could reside in Base Register
			if ((CAST2_USE(entry->node)->usetype == Base) &&
			   (x86_base_is_esp(opd))) {
				flag = 1;
			}
			assert(!(CAST2_USE(entry->node)->usetype == Index &&
				 x86_index_is_esp(opd)));
			if (flag && CAST2_USE(entry->node)->val_known) {
				is_known = 1;
				if (*esp_min > CAST2_USE(entry->node)->val.dword) {
					*esp_min = CAST2_USE(entry->node)->val.dword;
				}
				if (*esp_max < CAST2_USE(entry->node)->val.dword) {
					*esp_max = CAST2_USE(entry->node)->val.dword;
				}
			}
		}	
	}
	return is_known;
}

// make sure that your function has return value
re_list_t * find_return_value(re_list_t *ret_inst) {
	re_list_t *entry, *result = NULL;
	cs_arm_op *opd;
	list_for_each_entry_reverse(entry, &ret_inst->list, list) {
		if (entry == &re_ds.head) break;
		if (entry->node_type == InstNode) continue;

		opd = GET_OPERAND(entry);
		// if (x86_opd_is_eax(opd)) {
		if (opd->type == ARM_OP_REG && opd->reg == ARM_REG_R0) {
			result = entry;
			break;
		}
	}
	assert(result && result->node_type == DefNode);
	return result;
}

// if the current instruction is the last one, result is NULL
re_list_t *find_next_instruction(re_list_t *instnode) {
	re_list_t *result = NULL;
	re_list_t *entry;
	list_for_each_entry(entry, &instnode->list, list) {
		if (entry == &re_ds.head) break;
		if (entry->node_type == InstNode) {
			result = entry;
			break;
		}
	}
	return result;
}

// re_list_t *find_first_jcc(re_list_t *instnode) {
// 	re_list_t *result = NULL;
// 	re_list_t *entry;
// 	int inst_index;
// 	list_for_each_entry(entry, &instnode->list, list) {
// 		if (entry == &re_ds.head) break;
// 		if (entry->node_type != InstNode) continue;
// 		inst_index = CAST2_INST(entry->node)->inst_index;
// 		if (re_ds.instlist[inst_index].type == insn_jcc) {
// 			result = entry;
// 			break;
// 		}	
// 	}
// 	return result;
// }

#if defined (ALIAS_MODULE) && (ALIAS_MODULE == VSA_MODULE)
bool infer_valset_from_entry(re_list_t *entry) {
	// Stack Region:
	// one side: check 
	// two side: according to RE, calculate region and offset, and directly add them
	// Heap Region:
	// first : check
	// second : calculate base address of heap region
	// third : according to RE, calculate region and offset, and directly add them
	// ...

	cs_arm_op *opd;

	opd = GET_OPERAND(entry);

	if (entry->node_type == DefNode) {
		// Before and After Value Set are already known
		if (!valset_is_empty(&CAST2_DEF(entry->node)->bef_valset) &&
		    !valset_is_empty(&CAST2_DEF(entry->node)->aft_valset) &&
		    !valset_is_empty(&CAST2_DEF(entry->node)->addr_valset))
			return false;

		// Before and After Value from RE is not known
		if ((CAST2_DEF(entry->node)->val_stat == Unknown) &&
		    (CAST2_DEF(entry->node)->address == 0))
			return false;

		// Only infer register with machine word size
		if (true) { // NOTE note to verify: less than 4 bytes modification
		// if (opd->datatype == op_dword) {
			// only infer value from Reverse Execution here
			if ((CAST2_DEF(entry->node)->val_stat & BeforeKnown) &&
			    (valset_is_empty(&CAST2_DEF(entry->node)->bef_valset))) {
				set_valset_from_address(&CAST2_DEF(entry->node)->bef_valset, 
					CAST2_DEF(entry->node)->beforeval.dword);
			}
			if ((CAST2_DEF(entry->node)->val_stat & AfterKnown) &&
		    	    (valset_is_empty(&CAST2_DEF(entry->node)->aft_valset))) {
				set_valset_from_address(&CAST2_DEF(entry->node)->aft_valset, 
					CAST2_DEF(entry->node)->afterval.dword);
			}
		}

		if (opd->type == ARM_OP_MEM) {
			// infer address from Reverse Execution
			if (!valset_is_empty(&CAST2_DEF(entry->node)->addr_valset))
				return false;

			if ((CAST2_DEF(entry->node)->address) &&
		            (valset_is_empty(&CAST2_DEF(entry->node)->addr_valset))) {
				set_valset_from_address(&CAST2_DEF(entry->node)->addr_valset,
					CAST2_DEF(entry->node)->address);
			}
		} else if (opd->type == ARM_OP_REG) {
		}
	} else if (entry->node_type == UseNode) {

		// Value Set are already known
		if (!valset_is_empty(&CAST2_USE(entry->node)->valset) &&
		    !valset_is_empty(&CAST2_USE(entry->node)->addr_valset))
			return false;

		// Value from RE is not known
		if ((!CAST2_USE(entry->node)->val_known) && 
		    (!CAST2_USE(entry->node)->address))
			return false;

		// Only infer register with machine word size
		if (true) { // NOTE note to verify: less than 4 bytes modification
		// if (opd->datatype == op_dword) {
			if ((CAST2_USE(entry->node)->val_known) &&
			    (valset_is_empty(&CAST2_USE(entry->node)->valset))) {
				// only infer value from Reverse Execution here
				set_valset_from_address(&CAST2_USE(entry->node)->valset, 
					CAST2_USE(entry->node)->val.dword);
			}
		}

		if ((opd->type == ARM_OP_MEM) ||
		    (CAST2_USE(entry->node)->usetype == Opd)) {
			// infer address from Reverse Execution
		    	if ((CAST2_USE(entry->node)->address) &&
			    (valset_is_empty(&CAST2_USE(entry->node)->addr_valset))) {
				set_valset_from_address(&CAST2_USE(entry->node)->addr_valset,
					CAST2_USE(entry->node)->address);
			}
		}
	}
	return true;
}

// infer concrete region and offset information from result of Reverse Execution
unsigned long infer_valset_from_re() {
	unsigned long infer_num = 0;
	re_list_t *entry;

	LOG(stdout, "\nInfer Value Set From Reverse Execution\n");

	list_for_each_entry(entry, &re_ds.head.list, list) {
		if (entry->node_type == InstNode) continue;

		LOG(stdout, "Start analyzing one operand\n");
		// infer value and address of memory access from RE
		//print_node(entry);
		if (infer_valset_from_entry(entry)) {
			infer_num++;
		}	
		LOG(stdout, "Finish analyzing one operand\n\n");
	}
	return infer_num;
}
#endif

void re_statistics() {
	long entry_num = 0;
	long mem_num = 0, reg_num = 0;
	long mem_use_num = 0, reg_use_num = 0;
	long mem_def_num = 0, reg_def_num = 0;
	long mem_addr_num = 0; // only for memory access
	long reg_useval_num = 0, reg_defbef_num = 0, reg_defaft_num = 0;
	long mem_useval_num = 0, mem_defbef_num = 0, mem_defaft_num = 0;

	re_list_t *entry;

#if defined (ALIAS_MODULE) && (ALIAS_MODULE == VSA_MODULE)
	re_value_set *addr_valset;
#endif

	cs_arm_op *opd;
	list_for_each_entry_reverse(entry, &re_ds.head.list, list) {
		if (entry->node_type == InstNode) continue;

		entry_num++;

		opd = GET_OPERAND(entry);

#if defined (ALIAS_MODULE) && (ALIAS_MODULE == VSA_MODULE)
		addr_valset = GET_ADDR_VALSET(entry);
#endif

		if (entry->node_type == DefNode) {
			if (opd->type == ARM_OP_MEM) {
				mem_def_num++;
				mem_num++;

				if (CAST2_DEF(entry->node)->address) {
					mem_addr_num++;

#if defined (ALIAS_MODULE) && (ALIAS_MODULE == VSA_MODULE)
					if (valset_is_empty(addr_valset)) {
						LOG(stdout, "warning: no value set\n");
						print_node(entry);
					}
#endif
				} else {
					LOG(stdout, "unknown address warning\n");
					print_node(entry);
				} 

				if (CAST2_DEF(entry->node)->val_stat & BeforeKnown) {
					mem_defbef_num++;
				}

				if (CAST2_DEF(entry->node)->val_stat & AfterKnown) {
					mem_defaft_num++;
				}
			} else if (opd->type == ARM_OP_REG) {
				reg_def_num++;
				reg_num++;

				if (CAST2_DEF(entry->node)->val_stat & BeforeKnown) {
					reg_defbef_num++;
				}

				if (CAST2_DEF(entry->node)->val_stat & AfterKnown) {
					reg_defaft_num++;
				}
			} else {
				LOG(stderr, "Define other type : %d\n", opd->type);
			}
		}

		if (entry->node_type == UseNode) {
			if ((CAST2_USE(entry->node)->usetype == Opd) &&
			    (opd->type == ARM_OP_MEM)) {
				mem_use_num++;
				mem_num++;
				if (CAST2_USE(entry->node)->address) {
					mem_addr_num++;
#if defined (ALIAS_MODULE) && (ALIAS_MODULE == VSA_MODULE)
					if (valset_is_empty(addr_valset)) {
						LOG(stdout, "warning: no value set\n");
						print_node(entry);
					}
#endif
				} else {
					LOG(stdout, "unknown address warning\n");
					print_node(entry);
				}
				if (CAST2_USE(entry->node)->val_known) {
					mem_useval_num++;
				}
			} else if ((CAST2_USE(entry->node)->usetype == Opd) &&
				   (opd->type == ARM_OP_REG)) {
				reg_use_num++;
				reg_num++;
				if (CAST2_USE(entry->node)->val_known) {
					reg_useval_num++;
				}
			} else if (CAST2_USE(entry->node)->usetype != Opd) {
				reg_use_num++;
				reg_num++;
				if (CAST2_USE(entry->node)->val_known) {
					reg_useval_num++;
				}
			} else if (opd->type == ARM_OP_IMM) {
			} else {
				LOG(stderr, "Use other type : %d\n", opd->type);
			}
		}
	}
	LOG(stdout, "~~~~~~~~~~~~~~~~~~~~~Result of Reverse Execution~~~~~~~~~~~~~~~~~~~~~\n");
	LOG(stdout, "Total Entry Num is %ld\n", entry_num);
	LOG(stdout, "Total Memory Num is %ld\n", mem_num);
	//LOG(stdout, "Total Register Num is %ld\n", reg_num);
	LOG(stdout, "Total Address Known Num is %ld\n", mem_addr_num);
	LOG(stdout, "Address Known Average is %f\n", ((float)mem_addr_num)/mem_num);
	LOG(stdout, "\n");
	LOG(stdout, "Total Use Node Num is %ld\n", reg_use_num + mem_use_num);
	LOG(stdout, "Total Value Known of Reg Use Node Num is %ld\n", reg_useval_num);
	LOG(stdout, "Total Reg Use Node Num is %ld\n", reg_use_num);
	LOG(stdout, "Total Value Known of Mem Use Node Num is %ld\n", mem_useval_num);
	LOG(stdout, "Total Mem Use Node Num is %ld\n", mem_use_num);
	LOG(stdout, "\n");
	LOG(stdout, "Total Define Node Num is %ld\n", reg_def_num + mem_def_num);
	LOG(stdout, "Total Before Value Known of Reg Define Node Num is %ld\n", reg_defbef_num);
	LOG(stdout, "Total After Value Known of Reg Define Node Num is %ld\n", reg_defaft_num);
	LOG(stdout, "Total Reg Define Node Num is %ld\n", reg_def_num);
	LOG(stdout, "Total Before Value Known of Mem Define Node Num is %ld\n", mem_defbef_num);
	LOG(stdout, "Total After Value Known of Mem Define Node Num is %ld\n", mem_defaft_num);
	LOG(stdout, "Total Mem Define Node Num is %ld\n", mem_def_num);
	LOG(stdout, "\n");
	LOG(stdout, "Value Known of Use Node Average is %f\n",
			((float)(reg_useval_num + mem_useval_num))/(reg_use_num + mem_use_num));
	LOG(stdout, "BeforeValue Known of Define Node Average is %f\n",
			((float)(reg_defbef_num + mem_defbef_num))/(reg_def_num + mem_def_num));
	LOG(stdout, "AfterValue Known of Define Node Average is %f\n",
			((float)(reg_defaft_num + mem_defaft_num))/(reg_def_num + mem_def_num));
	LOG(stdout, "\n");
}

// After the second round of reverse execution
// always do this round of RE
void one_round_of_re(){
	re_list_t *entry;
	re_list_t re_deflist, re_uselist, re_instlist;

	re_ds.resolving = true;	
	list_for_each_entry_reverse(entry, &re_ds.head.list, list) {

		if (entry->node_type != InstNode) continue;

		re_ds.curinstid = entry->id; 

		INIT_LIST_HEAD(&re_deflist.deflist);
		INIT_LIST_HEAD(&re_uselist.uselist);
		INIT_LIST_HEAD(&re_instlist.instlist);	

		add_to_instlist(entry, &re_instlist);
		re_resolve(&re_deflist, &re_uselist, &re_instlist);

		resolve_heuristics(entry, &re_deflist, &re_uselist, &re_instlist);
		re_resolve(&re_deflist, &re_uselist, &re_instlist);
		//print_info_of_current_inst(entry);
	}
}
#endif
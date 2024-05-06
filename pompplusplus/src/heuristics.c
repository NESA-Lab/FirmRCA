#include <capstone/capstone.h>
#include "heuristics.h"
#include "insthandler_arm.h"

int get_ebp_id(){
	return ARM_REG_R11;
}

int get_esp_id(){
	return ARM_REG_SP;
}

int get_insn_type(csh handle, cs_insn* insn) {
	cs_regs regs_read, regs_write;
	uint8_t regs_read_count, regs_write_count;

	// function return: pop {pc}; bx lr; 
	cs_regs_access(handle, insn, regs_read, &regs_read_count, regs_write, &regs_write_count);
	if (insn->id == ARM_INS_POP) {
		for (int i = 0; i < insn->detail->arm.op_count; i++) {
			if (insn->detail->arm.operands[i].type == ARM_OP_REG && insn->detail->arm.operands[i].reg == ARM_REG_PC) {
				return CS_GRP_RET;
			}
		}
	}
	if (insn->id == ARM_INS_BX) {
		for (int i = 0; i < regs_read_count; i++) {
			if (regs_read[i] == ARM_REG_LR) {
				return CS_GRP_RET;
			}
		}
	}

	// function call: CS_GRP_CALL
	if (insn->id == ARM_INS_BL || insn->id == ARM_INS_BLX) {
		return CS_GRP_CALL;
	}

	return 0;
}

static void adjust_func_level_reverse(cs_insn* arminst, int * func_level){

		cs_group_type type = get_insn_type(re_ds.handle, arminst);
		switch(type){

			case CS_GRP_RET:
				//going back to a returned child function
				(*func_level)--;
				break;
			case CS_GRP_CALL:
				//going out  from the child function
				(*func_level)++;
				break;
			// case insn_callcc:
			// 	assert(0);
			// 	break;
			default: 
				break;
		}
}

//heuristics for recovering ebp 
//the basic idea is that: searching use and def of ebp in the same function 
//if there is no in-function def between two accesses of ebp, assume they are equal???!!!
static bool is_ebp_known(re_list_t * ebp, bool before){

	use_node_t * use; 
	def_node_t * def; 

	if(ebp->node_type == DefNode){

		def = CAST2_DEF(ebp->node);
		if(def->operand->type == ARM_OP_REG && def->operand->reg == get_ebp_id()){
			if(before)
				return def->val_stat & BeforeKnown ? true : false; 
			else
					
				return def->val_stat & AfterKnown ? true : false; 
		}else{
			return false; 
		}
	}

	if(ebp->node_type == UseNode){
		
		use = CAST2_USE(ebp->node);
		
		if(use->operand->type == ARM_OP_REG){
			return use->operand->reg == get_ebp_id() && use->val_known ? true : false;
		}else{

			if(use->usetype == Base){
				return use->operand->mem.base == get_ebp_id() && use->val_known ? true : false;

			}

			if(use->usetype == Index){
				return use->operand->mem.index == get_ebp_id() && use->val_known ? true : false;
			}
		}
	}

	return false; 
}
static bool is_ebp_unknown(re_list_t * ebp, bool before){

	use_node_t * use; 
	def_node_t * def; 

	if(ebp->node_type == DefNode){

		def = CAST2_DEF(ebp->node);
		if(def->operand->type == ARM_OP_REG && def->operand->reg == get_ebp_id()){

			if(before)
				return !(def->val_stat & BeforeKnown) ? true : false; 
			else
					
				return !(def->val_stat & AfterKnown) ? true : false; 
		}else{
			return false; 
		}
	}

	if(ebp->node_type == UseNode){
		
		use = CAST2_USE(ebp->node);
		
		if(use->operand->type == ARM_OP_REG){
			return use->operand->reg == get_ebp_id() && !use->val_known ? true : false;
		}else{

			if(use->usetype == Base){
				return use->operand->mem.base == get_ebp_id() && !use->val_known ? true : false;

			}

			if(use->usetype == Index){
				return use->operand->mem.index == get_ebp_id() && !use->val_known ? true : false;
			}
		}
	}

	return false; 
}

re_list_t * get_next_ebp(re_list_t * ebpuse){
			
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	int func_level;
	re_list_t *entry; 
	re_list_t *prevebp;
	int i; 
	cs_insn *arminst;


	func_level = 0;
	
	list_for_each_entry(entry, &ebpuse->list, list){

		if(entry->node_type != InstNode)
			continue;

		arminst = &re_ds.instlist[CAST2_INST(entry->node)->inst_index]; 

		//the current function has returned; 
		if(func_level < 0)
			return NULL;

		if(func_level == 0) {

			obtain_inst_elements(entry, src, dst, &nuse, &ndef);	

			for(i = 0; i < nuse; i ++){
				if(is_ebp_known(src[i], false))			
					return src[i];
			}		

			for(i = 0; i < ndef; i ++){
				if(is_ebp_known(dst[i], true))			
					return dst[i];

				if(is_ebp_unknown(dst[i], true))
					if(node1_add_before_node2(dst[i], ebpuse))
						return NULL;
			}	
		}
		adjust_func_level_reverse(arminst, &func_level);
	}
	return NULL;
}


//only care about use with unknown ebp 
void infer_ebp_value(re_list_t *ebpinst, re_list_t * uselist){

	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	int i; 
	re_list_t *prevebp, *nextebp;
	valset_u vt;


	obtain_inst_elements(ebpinst, src, dst, &nuse, &ndef);	

	for(i = 0; i < nuse; i++){

		if(is_ebp_unknown(src[i], false)){

			nextebp = get_next_ebp(src[i]);
		
			if(!nextebp)
				continue;

			if(nextebp->node_type == UseNode){
				memcpy(&vt, &CAST2_USE(nextebp->node)->val, sizeof(valset_u));		
				assign_use_value(src[i], vt);
				add_to_uselist(src[i], uselist);	

			}else{
				memcpy(&vt, &CAST2_DEF(nextebp->node)->beforeval, sizeof(valset_u));		
				assign_use_value(src[i], vt);
				add_to_uselist(src[i], uselist);	
			}

		}
	}
}

//heuristics for searching address based on value
//this heuristic still has logic problems, as we do not 
//consider about define after this node
//FIX ME LATER!!!

void val2addr_heuristics(re_list_t* uselist){

	re_list_t *entry;

	list_for_each_entry(entry, &re_ds.head.list, list){

		if(entry->node_type == InstNode)
			continue;

		infer_address_from_value(uselist, entry);
	}	
}


void infer_address_from_value(re_list_t* uselist, re_list_t* node){

	int dtype;
	unsigned address;
	valset_u vt;
	re_list_t* nextdef;
	re_list_t *index, *base;  
	use_node_t *use; 

//an expression of use
	if(node->node_type == UseNode && node_is_exp(node, true)){
		use = CAST2_USE(node->node);

//value is known but address is unknown
		if(use->val_known && !use->address && !check_next_unknown_write(&re_ds.head, NULL, node))

	{

//there exists only one copy of the value in the memory
			address = search_address_of_value(use->val, use->inst);		

//the address can be inferred by the corresponding value
//assign the address to the corresponding index or base
			if(address){
//assign the address to the index plus base
				get_element_of_exp(node, &index, &base);

				LOG(stdout, "The displacement is %x\n", use->operand->mem.disp);

				switch(exp_addr_status(base, index)){
					case KBaseKIndex:
						return; 

					case UBaseUIndex:
						return; 

					case UBase: 
						vt.dword = address - use->operand->mem.disp;	
						assign_use_value(base, vt);
						add_to_uselist(base, uselist);
						break;

					case UBaseKIndex:
						vt.dword = address - use->operand->mem.disp - CAST2_USE(index->node)->val.dword * use->operand->mem.scale;	

						assign_use_value(base, vt);
						add_to_uselist(base, uselist);

					default: 
						return;
						//assert(0);
						break;								
				}
			}
		}
	}

	if(node->node_type == DefNode && node_is_exp(node, false)){
		if( (CAST2_DEF(node->node)->val_stat & AfterKnown) && !CAST2_DEF(node->node)->address){

			if(!check_next_unknown_write(&re_ds.head, NULL, node)){
			address = search_address_of_value(
			CAST2_DEF(node->node)->afterval, 
			CAST2_DEF(node->node)->inst);		
			LOG(stdout, "The address found is %x\n", address);
			}


		}

	}
}

//in the reverse execution, return increases the function level,
//calll decreases the function level
static void adjust_func_level(cs_insn* inst, int * func_level){

		cs_group_type type = get_insn_type(re_ds.handle, inst);
		switch(type){

			case CS_GRP_RET:
				//going back to a returned child function
				(*func_level)++;
				break;

			case CS_GRP_CALL:
				//going out  from the child function
				(*func_level)--;
				break;

			// case insn_callcc:
				
			// 	assert(0);
			// 	break;

			default: 
				break;
		}
}

//in the normal execution, call increase the function level 
//return decrease the function level 

static bool check_operation_esp_ebp(re_list_t* inst, cs_insn* arminst, re_list_t **storeesp){
		
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	int i;
	def_node_t *def;
	use_node_t *use; 


	//get the operands of the instruciton	
	obtain_inst_operand(inst, src, dst, &nuse, &ndef);	

	for(i = 0; i < ndef; i++){

		def = CAST2_DEF(dst[i]->node);
		//it is trying to define the ebp
		if(def->operand->type == ARM_OP_REG && def->operand->reg == get_ebp_id()){

			//now only the following instructions will be accepted
			switch(arminst->id){

				case ARM_INS_MOV:
				case ARM_INS_MOVS:
				case ARM_INS_MOVT:
				case ARM_INS_MOVW:

					//check if the source is ebp  
					use = CAST2_USE(src[0]->node);
					//the esp has not been stored, but the ebp is polluted


					//mov ebp, esp
					//there are multiple defines? maybe we should ignore the first one
					if(*storeesp){
						if(use->operand->type == ARM_OP_REG && use->operand->reg == get_esp_id()){
							print_instnode(inst->node);
							assert(0);
							return false;
						}
					}

					//ebp is redefined before esp is stored into it
					if(!*storeesp){	
						if(use->operand->type != ARM_OP_REG || use->operand->reg != get_esp_id()){
							print_instnode(inst->node);
							assert(0);
							return false;
						}
						*storeesp = src[0];
					}

					break;

				default:
					print_instnode(inst->node);
					assert(0);				
			}			
		}	
	}
	
	return true; 
}
#ifdef POMP
re_list_t* find_paired_esp_store(re_list_t * espdef){

//traverse the core list to find instructions in the current function 
//and find move from esp to ebp
	int func_level;
	re_list_t *entry; 
	cs_insn * arminst; 
	re_list_t *espstore; 

	func_level = 0;

//must be initialized here
	espstore = NULL;

	list_for_each_entry_reverse(entry, &espdef->list, list){

		if(entry->node_type != InstNode)
			continue;

		//get the instruction in x86 format	
		arminst = &re_ds.instlist[CAST2_INST(entry->node)->inst_index]; 

		//adjust the function level of the current instruction
		//based on call and return instruction
		//must be processed before any other operations
		adjust_func_level(arminst, &func_level);


		//only care about instruction in the current function
		if(func_level == 0) {
//			print_assembly(x86inst);
			if(!check_operation_esp_ebp(entry, arminst, &espstore)){
				return NULL;
			}
		}

		if(func_level < 0)
			return espstore; 
	}	
}

static int pollute_esp(re_list_t *inst, re_list_t *deflist, re_list_t  *uselist, re_list_t *instlist, valset_u *vt){
			
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	int i; 
	int index; 

	cs_insn * arminst; 
	re_list_t tdeflist; 
	re_list_t tuselist; 
	re_list_t tinstlist; 


	INIT_LIST_HEAD(&tdeflist.deflist);
	INIT_LIST_HEAD(&tuselist.uselist);
	INIT_LIST_HEAD(&tinstlist.instlist);

	arminst = &re_ds.instlist[CAST2_INST(inst->node)->inst_index]; 

	//get the operands of the instruciton	
	obtain_inst_operand(inst, src, dst, &nuse, &ndef);	


	LOG(stdout, "The before value of esp is %lx\n", vt->dword);
	for(i = ndef - 1; i >= 0; i--){

		//the next define of esp 
		if(CAST2_DEF(dst[i]->node)->operand->type == ARM_OP_REG && CAST2_DEF(dst[i]->node)->operand->reg == get_esp_id()){
		
			//the before value of esp is known 
			if(CAST2_DEF(dst[i]->node)->val_stat & BeforeKnown){

				//compare the after value of the previous define 
				//and the before value of the next define
				assert_val(dst[i], *vt, true);

			}else{
				//if the before value of the next define is unknown
				assign_def_before_value(dst[i], *vt);		
				add_to_deflist(dst[i], &tdeflist);

				re_resolve(&tdeflist, &tuselist, &tinstlist);	

				index = insttype_to_index(arminst->id);
				inst_resolver[index](inst, &tdeflist, &tuselist);

				//are you sure you want it to be added into define list? 
				//any possibility of endless loop
			}
		
			//if the aftervalue of the esp define is known, which means the define 
			//of esp is not cut off	
			
			if(CAST2_DEF(dst[i]->node)->val_stat & AfterKnown){
				
				//if this is a call, then the return of the child function will adjust the esp
				if(get_insn_type(re_ds.handle, arminst) == CS_GRP_CALL){
					memcpy(vt, &CAST2_DEF(dst[i]->node)->beforeval, sizeof(valset_u));
				}
				else{
					memcpy(vt, &CAST2_DEF(dst[i]->node)->afterval, sizeof(valset_u));
				}

				LOG(stdout, "The after value of esp is %lx\n", vt->dword);
			}
			else
				return -1; 
		}
	}
	return 0;
}

static int pollute_esp_in_current_function(re_list_t* storeesp, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){

//traverse the core list to find instructions in the current function 
//and find move from esp to ebp
	int func_level;
	re_list_t *entry; 
	re_list_t *inst;
	cs_insn * arminst; 
	re_list_t *espstore; 

	func_level = 0;
	valset_u vt;

//must be initialized here
//the traverse must be in the normal order 
//as now the store of esp is newly added into the core list

	memcpy(&vt, &CAST2_USE(storeesp->node)->val, sizeof(valset_u));


	list_for_each_entry(entry, &storeesp->list, list){

		if(entry->node_type != InstNode)
			continue;


		//the current function has returned; 
		if(func_level < 0)
			return 0; 

		//get the instruction in x86 format	
		arminst = &re_ds.instlist[CAST2_INST(entry->node)->inst_index]; 

		//only care about instruction in the current function
		if(func_level == 0) {

			print_assembly(arminst);
			switch (pollute_esp(entry, deflist, uselist, instlist, &vt)){
				case -1:
					return 0; // the propagation of esp cannot be continued 

				case 0:
					break;
				case 1:

					break;
				default:
					assert(0);
			}

		}
	//need to take care of the time to adjust the function level 	
	//the pollution is conducted in the normal order, 
	//so the adjustment will be performed after the instruction has been processed	
		adjust_func_level_reverse(arminst, &func_level);
	}	
}
#else
re_list_t* find_paired_esp_store(re_list_t * espdef){
//traverse the core list to find instructions in the current function 
//and find move from esp to ebp
	re_list_t *entry; 
	cs_insn * arminst; 
	re_list_t *espstore; 
	re_list_t *leaveinst; 

//must be initialized here
	espstore = NULL;
	leaveinst = find_inst_of_node(espdef);

	list_for_each_entry_reverse(entry, &espdef->list, list){

		if(entry->node_type != InstNode)
			continue;

		arminst = &re_ds.instlist[CAST2_INST(entry->node)->inst_index]; 

		//check if in the same function
		if(CAST2_INST(leaveinst->node)->funcid == CAST2_INST(entry->node)->funcid){

			if(!check_operation_esp_ebp(entry, arminst, &espstore))
				return NULL;

			if(espstore)
				return espstore;

		}else{
			//if this is a call and next instruction is in the target function,,,
			//we should terminate the searching here
			//this must be a parent function
			if(CAST2_INST(entry->node)->funcid < CAST2_INST(leaveinst->node)->funcid)
				return espstore; 
		}						
	}	
}

static int pollute_esp(re_list_t *inst, re_list_t *deflist, re_list_t  *uselist, re_list_t *instlist, valset_u *vt){

	re_list_t* previnst;
	re_list_t* entry;
	use_node_t* tempuse; 
	def_node_t* tempdef;
	def_node_t* calldef;
	cs_insn * arminst; 
	unsigned index; 

	arminst = &re_ds.instlist[CAST2_INST(inst->node)->inst_index]; 

	//find the previous instruction
	list_for_each_entry_reverse(previnst,&inst->list,list){
		if(previnst->node_type == InstNode)
			break;
	}

	//deal with the operands between 	
	list_for_each_entry(entry, &previnst->list, list){

		if(entry->node_type == UseNode){

			tempuse = CAST2_USE(entry->node);
			//directly use esp as operand		
			if(tempuse->operand->type == ARM_OP_REG && tempuse->operand->reg == get_esp_id()){
				// temporarily fix "ret 0x14"
				//if (entry->id == 431 || entry->id == 14723 || entry->id == 16978) {
				//if (entry->id == 1044 || entry->id == 4533 || entry->id == 7856) {
				//if (entry->id == 1157) {
				//	vt->dword += 0x14;
				//}
				assign_use_value(entry, *vt);
				add_to_uselist(entry, uselist);		
			}

			if(tempuse->operand->type == ARM_OP_MEM && tempuse->usetype == Base && tempuse->operand->mem.base == get_esp_id()){
                                assign_use_value(entry, *vt);  
				add_to_uselist(entry, uselist);      
                        }

			if(tempuse->operand->type == ARM_OP_MEM && tempuse->usetype == Index && tempuse->operand->mem.index == get_esp_id()){
                                assign_use_value(entry, *vt);   
			 	add_to_uselist(entry, uselist);     
                        }
		}	

		if(entry->node_type == DefNode){

			tempdef = CAST2_DEF(entry->node);

			if(tempdef->operand->type == ARM_OP_REG && tempdef->operand->reg == get_esp_id()){

				if(tempdef->val_stat & BeforeKnown){
					assert_val(entry, *vt, true);
				}else{
					//if the before value of the next define is unknown
					assign_def_before_value(entry, *vt);		
					add_to_deflist(entry, deflist);
				}

				if(get_insn_type(re_ds.handle, arminst) == CS_GRP_CALL)
					calldef = tempdef;

				index = insttype_to_index(arminst->id);
				inst_resolver[index](inst, deflist, uselist);

				if(tempdef->val_stat & AfterKnown){
					memcpy(vt, &tempdef->afterval, sizeof(valset_u));
				}
				else return -1; 
			}
		}

		if(entry->node_type == InstNode)
			break;
	}

//if this is a call instruction, we need to take care of it carefully
	if(get_insn_type(re_ds.handle, arminst) == CS_GRP_CALL)
		memcpy(vt, &calldef->beforeval, sizeof(valset_u));

	return 0;
}

//recover the same register across funcation calls
//example: frame pointer!
static re_list_t* intra_procedure_register_recovery(re_list_t* regnode, int regid){

	re_list_t* entry;
	unsigned funcid;
	unsigned curfuncid;

	funcid = CAST2_INST(find_inst_of_node(regnode)->node)->funcid; 

//forward finding
	list_for_each_entry(entry, &regnode->list, list){

		if(entry->node_type == InstNode)
			continue;

		curfuncid = CAST2_INST(find_inst_of_node(entry)->node)->funcid;

		if(entry->node_type == DefNode){

			//out of the current function scope
			if(curfuncid < funcid)
				break;
			//inside child functions
			if(curfuncid > funcid)
				continue;

			//not define a regiser
			if(CAST2_DEF(entry->node)->operand->type != ARM_OP_REG)
				continue;
			//not the expected register
			if(CAST2_DEF(entry->node)->operand->reg != regid)
				continue;
			//found it 
			if(CAST2_DEF(entry->node)->val_stat & BeforeKnown)
				return entry;
			else
				return NULL;
		}

		if(entry->node_type == UseNode){

                        //out of the current function scope
                        if(curfuncid < funcid)
                                break;
                        //inside child functions
                        if(curfuncid > funcid)
                                continue;
                        //not use a regiser
                        if(CAST2_USE(entry->node)->operand->type != ARM_OP_REG 
				&& CAST2_USE(entry->node)->usetype == Opd)
                                continue;
                        //not the expected register
                        if(CAST2_USE(entry->node)->operand->type == ARM_OP_REG && CAST2_USE(entry->node)->operand->reg != regid)
                                continue;

			 if(CAST2_USE(entry->node)->operand->type == ARM_OP_MEM && CAST2_USE(entry->node)->usetype == Base && CAST2_USE(entry->node)->operand->mem.base != regid)
				continue;
			
			 if(CAST2_USE(entry->node)->operand->type == ARM_OP_MEM && CAST2_USE(entry->node)->usetype == Index && CAST2_USE(entry->node)->operand->mem.index != regid)
				continue;

			if(!CAST2_USE(entry->node)->val_known)
				continue;

                        //found it
			return entry;
                }
	}
	return NULL;
}
#ifdef VSA
static int recover_frame_pointer(re_list_t* instnode, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
        int nuse, ndef;
        int i;
	unsigned index;
	re_list_t *dst[NOPD], *src[NOPD];
	re_list_t *refer; 
	cs_insn *arminst;
	
	//get all the lements of the instruction
	arminst = &re_ds.instlist[CAST2_INST(instnode->node)->inst_index];
        obtain_inst_elements(instnode, src, dst, &nuse, &ndef);

	//check the use
        for(i = 0; i < nuse; i++){
		//assume the frame pointer is ebp, but of course needs to check
                if(is_ebp_unknown(src[i], false)){
			refer = intra_procedure_register_recovery(src[i], get_ebp_id());	
			if(!refer || refer->node_type == DefNode){
				continue;
			}
			//get previous use whose value is known
			assign_use_value(src[i], CAST2_USE(refer->node)->val);
			add_to_uselist(src[i], uselist);
			index = insttype_to_index(arminst->id);
			inst_resolver[index](instnode, deflist, uselist);
			correctness_check(instnode);
                }
        }
}
#endif
static int pollute_esp_in_current_function(re_list_t* storeesp, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){

//traverse the core list to find instructions in the current function 
//and find move from esp to ebp
	re_list_t *entry; 
	re_list_t *inst;
	re_list_t *espstore; 
	valset_u vt;

//must be initialized here
//the traverse must be in the normal order 
//as now the store of esp is newly added into the core list
	inst = find_inst_of_node(storeesp);
	memcpy(&vt, &CAST2_USE(storeesp->node)->val, sizeof(valset_u));

	list_for_each_entry(entry, &storeesp->list, list){

		if (entry == &re_ds.head) break;

		if(entry->node_type != InstNode)
			continue;

		//has went out of the current function
		if(CAST2_INST(entry->node)->funcid < CAST2_INST(inst->node)->funcid)
			return 0;

		//only care about instruction in the current function
		if(CAST2_INST(entry->node)->funcid == CAST2_INST(inst->node)->funcid) {
			switch (pollute_esp(entry, deflist, uselist, instlist, &vt)){
				case -1:
					return 0; // the propagation of esp cannot be continued 
				case 0:
				case 1:
					break;
				default:
					assert(0);
			}
		}
	}	
}
#endif

int jmp_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}

int jcc_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;

}

int call_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}

int callcc_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}

int return_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}

int add_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    // NOTE FirmRCA didn't need this
#ifdef VSA
	recover_frame_pointer(inst, deflist, uselist, instlist);
#endif
    return 0;
}


int sub_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}

int mul_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}


int div_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}


int inc_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}

int dec_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}

int shl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}

int shr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}

int rol_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}


int ror_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}

int and_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}


int or_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
    // NOTE FirmRCA didn't need this 
#ifdef VSA
	recover_frame_pointer(inst, deflist, uselist, instlist);
#endif
	return 0;
}


int xor_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}


int not_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}

int neg_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}

int push_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}

int pop_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}

int pushregs_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}

int popregs_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}

int pushflags_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}

int popflags_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}


int enter_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}



int leave_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	re_list_t *storeesp; 	
#ifdef POMP
	traverse_inst_operand(inst, src, dst, uselist, deflist, &nuse, &ndef);	
	print_defnode(dst[2]->node);
#else
	obtain_inst_operand(inst, src, dst, &nuse, &ndef);
#endif
	assert(nuse == 2 && ndef == 3);

//first heuristic
//if the esp cannot be recovered by previous operations, then using heuristics to do it here. 

	if( CAST2_DEF(dst[2]->node)->val_stat & BeforeKnown)
		return 0;	

	if(!(CAST2_DEF(dst[2]->node)->val_stat & AfterKnown))
		return 0;	

//logic
//1. determine if the operations on ebp and esp is paird
//2. get the value of the current esp
//3. assign to it and then add to the deflist and uselist 
//
//storeesp is a source operand in mov and the 
//target is esp
	 storeesp = find_paired_esp_store(dst[2]);

	if(storeesp){
		//recover the value of esp with the value stored in ebp 
		assign_use_value(storeesp, CAST2_DEF(dst[2]->node)->afterval);		
		add_to_uselist(storeesp, uselist);
		pollute_esp_in_current_function(storeesp, deflist, uselist, instlist);
	}
	return 0;
}

int test_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}

int cmp_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}

int lea_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	
	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	re_list_t *storeesp;
	valset_u vt = {0};
	re_list_t *index, *base, *nextebp;
	int it; 
	int type;

#ifdef POMP
	traverse_inst_operand(inst, src, dst, uselist, deflist, &nuse, &ndef);	
	assert(nuse == 1 && ndef == 1);
	print_defnode(dst[0]->node);
#else
	//we do not do it here for now
	//the code for infer_ebp_value is old version
	//infer_ebp_value(inst, uselist);
	obtain_inst_elements(inst, src, dst, &nuse, &ndef);	
	assert((nuse == 0 || nuse == 1 || nuse == 2) && ndef == 1);
#endif
//first heuristic
//if the esp cannot be recovered by previous operations, then using heuristics to do it here. 
	//print_defnode(dst[0]->node);
	if (CAST2_DEF(dst[0]->node)->operand->type == ARM_OP_REG 
		&& CAST2_DEF(dst[0]->node)->operand->reg != get_esp_id()) {
		return 0;
	}

//if the before value of the esp is known, 
//we do not bother
//but removing this check may still help a lot
//we will see later
	if(CAST2_DEF(dst[0]->node)->val_stat & BeforeKnown)
		return 0;	

	if (!(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown))
		return 0;	

//logic
//1. determine if the operations on ebp and esp is paird
//2. get the value of the current esp
//3. assign to it and then add to the deflist and uselist 
//

#ifdef POMP
	get_element_of_exp(src[0], &index, &base);
	assert(index == NULL);
#else
//here we deal with lea esp, [ebp+offset]
	base = NULL; 
	index = NULL;

	for(it = 0; it < nuse; it++){
		if(CAST2_USE(src[it]->node)->usetype == Base)
			base = src[it];

		if(CAST2_USE(src[it]->node)->usetype == Index)
			index = src[it];
	}

	//not in the form of [ebp+offset]
	if(index) return 0;	

	//not in the form of [ebp+offset]
	if(CAST2_USE(base->node)->operand->mem.base != get_ebp_id())
		return 0;	

	//ebp is unknown
	if(!CAST2_USE(base->node)->val_known) return 0;
#endif
	//storeesp is a source operand in mov and the 
	//target is esp
	storeesp = find_paired_esp_store(dst[0]);

	if(storeesp){
		//recover the value of esp with the value stored in ebp 
		assign_use_value(storeesp, CAST2_USE(base->node)->val);		
		add_to_uselist(storeesp, uselist);
		pollute_esp_in_current_function(storeesp, deflist, uselist, instlist);
	}
	return 0;
}


static bool process_other_mov_inst_heuristic(re_list_t *instnode, re_list_t *deflist, re_list_t *uselist, re_list_t * instlist) {

	cs_insn *inst;
	
	inst= re_ds.instlist + CAST2_INST(instnode->node)->inst_index;

	if (strcmp(inst->mnemonic, "lea") == 0) {
		lea_post_res(instnode, deflist, uselist, instlist);
		return true;
	}
	return false;
}


int mov_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	process_other_mov_inst_heuristic(inst, deflist, uselist, instlist);
#ifdef VSA
	recover_frame_pointer(inst, deflist, uselist, instlist); // NOTE FirmRCA didn't need this
#endif
	return 0;
}


int movcc_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}

int xchg_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}

int xchgcc_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}

int strcmp_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}

int strload_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}

int strmov_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}

int strstore_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}

int translate_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}

int bittest_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}


int bitset_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}

int bitclear_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}


int nop_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}


int szconv_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}


int unknown_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}


int clear_dir_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}

int sys_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}


int in_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}

int out_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}

int int_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}

int cpuid_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}

#ifdef VSA
int fpu_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist){
	return 0;
}
#endif

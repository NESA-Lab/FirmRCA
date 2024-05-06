#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include "access_memory.h"
#include "elf_core.h"
#include "elf_binary.h"
#include "insthandler_arm.h"
#include "disassemble.h"
#include "thread_selection.h"
#include "inst_data.h"

#ifdef MEMAC
#include "bintrace.capnp.h"
#endif

#include "arm_define.h"
#include "reverse_log.h"
#include "global.h"

#ifdef VSA
#define REGINFODEM ":"
#define LOG_MAX_SIZE 256
#define REGDEM ";"
#define INFODEM ":"
static void process_log_line(char* line, operand_val_t * oplog){

	char *str1, *str2, *saveptr1, *saveptr2; 
	char *token, *regid, *regval;
	char *endptr;  
	int regcount; 

	int vallen; 
	int i, j;
	
	for(regcount = 0, str1 = line; ;regcount++, str1 = NULL){
		token = strtok_r(str1, REGDEM, &saveptr1);
		if(token == NULL)
			break; 	
			
		regid = strtok_r(token, INFODEM, &saveptr2);
		assert(regid != NULL);
		regval = strtok_r(NULL, INFODEM, &saveptr2);
		assert(regval != NULL);

		//process the id and the value 
		oplog->regs[regcount].reg_num = strtol(regid, &endptr, 10);

		//conver the string to value
		//as the length of the string is varying, 
		//we use iterations instead of strtol 
		
		if(regval[strlen(regval)-1] == '\n')
			regval[strlen(regval)-1] = 0;
		
		for(i = strlen(regval) - 2, j = 0; i >=2; i -= 2, j++){
			char temp[5];
			temp[0] = '0';
			temp[1] = 'x';
			temp[4] = '\0';
			memcpy(&temp[2], &regval[i], 2);
			((char*)&oplog->regs[regcount].val)[j] = (char)strtol(temp, &endptr, 16);
		}
	}
	oplog->regnum = regcount;
}
static void load_line_dlregion(char *line, dlregion_list_t *dlregion) {

        int opcount;
        char *str, *saveptr, *token, *endptr;

        for (opcount = 0, str = line; ;opcount++, str = NULL) {
                token = strtok_r(str, REGINFODEM, &saveptr);
                if (token == NULL) break;
                //printf("%d: %s ", opcount, token);
                dlregion->dlreg_list[opcount] = (unsigned long)strtoll(token, &endptr, 10);
        }

	assert(opcount <= 2);
        dlregion->dlreg_num = opcount;
}

// load region_DL file into dlregionlist data structure
int load_dlregion(char *dlregion_file, dlregion_list_t *dlregionlist){
        char line[LINE_SIZE];
        FILE *file;
        char *start, *end, *saveptr, *token;
        int i;
        if ((file = fopen(dlregion_file, "r")) == NULL){
                LOG(stderr, "ERROR: dlregion file open error\n");
                return -1;
        }

        i = 0;
        while (fgets(line, sizeof(line), file) != NULL) {
                load_line_dlregion(line, dlregionlist + i);
                i++;
        }

        return 0;
}
unsigned long count_linenum_ptlog(char *filename){
	char line[256];
	FILE *file;
	if ((file = fopen(filename, "r")) == NULL) {
		LOG(stderr, "ERROR: open error\n");
		return -1;
	}
	unsigned long linenum = 0;
	while (fgets(line, sizeof line, file) != NULL) {
		if ((strncmp(line, "[disabled]", 10) == 0)) continue;
		if ((strncmp(line, "[enabled]", 9) == 0)) continue;
		if ((strncmp(line, "[resumed]", 9) == 0)) continue;
		linenum++;
	}

	LOG(stdout, "RESULT: Valid Address Number - 0x%lx\n", linenum);
	return linenum;
}

unsigned long gcd(unsigned long a, unsigned long b) {
	int tmp;
	while(b != 0) {
		tmp = b;
		b = a % b;
		a = tmp;
	}
	return a;
}


//count the number of instructions that have valid data logging
unsigned long count_linenum(char * filename){
	char line[256];
	FILE *file;
	unsigned long linenum;

	if ((file = fopen(filename, "r")) == NULL) {
		LOG(stderr, "ERROR: cannot open file %s\n",filename);
		return -1;
	}

	linenum = 0;
	while(fgets(line, sizeof(line), file) != NULL){
		if (linenum >= get_max_rev_ins_num()){
			break;
		}
		linenum++;
	}

	LOG(stdout, "RESULT: Valid Address Number - 0x%lx\n", linenum);
	return linenum;
}
#endif

unsigned long countvalidaddress(char *filename){
    char line[80];
    FILE *file;
    if ((file = fopen(filename, "r")) == NULL) {
        LOG(stderr, "ERROR: open error\n");
        return -1;
    }
    unsigned long linenum = 0;
    while (fgets(line, sizeof line, file) != NULL) {
        if (linenum >= get_max_rev_ins_num()){
            break;
        }
        if ((strncmp(line, "[disabled]", 10) == 0)) continue;
        if ((strncmp(line, "[enabled]", 9) == 0)) continue;
        if ((strncmp(line, "[resumed]", 9) == 0)) continue;
        linenum++;
    }

    LOG(stdout, "RESULT: Valid Address Number - 0x%ld\n", linenum);
    return linenum;
}


// Parse memory dump and registers
coredata_t * load_coredump(const char* core_path){

	coredata_t * coredata = NULL;	

    FILE* file = fopen(core_path, "r");
    if (file == NULL){
    	LOG(stderr, "Error When Open ELF core file: %s\n", strerror(errno));
    	return NULL;
    }

    coredata = (coredata_t*)malloc(sizeof(coredata_t));

    if (coredata == NULL){
    	LOG(stderr, "Error When Memory Allocation\n");
        fclose(file);
        return NULL;
    }	

    memset(coredata, 0, sizeof(coredata_t));
    LOG(stdout, "STATE: Parsing Core File: %s\n", core_path);

    uint32_t base_address = 0;
	uint32_t current_address = 0;
	uint32_t prev_address = 0;
    uint8_t *current_data = NULL;
    size_t current_size = 0;

    uint8_t byte_count, record_type;
    uint32_t offset;
    uint8_t byte;
	uint32_t linear_address;

    char line[512];
	const char* reg_names[] = {
		"zero","r0","r1","r2","r3","r4","r5","r6","r7",
		"r8","r9","r10","r11","r12","lr","pc","sp","xpsr"
	};

    while (fgets(line, sizeof(line), file)) {
        if (line[0] == ':') {
            // Parse the hex record
            sscanf(line + 1, "%2hhx%4hx%2hhx", &byte_count, &offset, &record_type);
			offset &= 0xFFFF;
            // Data record
            if (record_type == 0) {
                // Calculate the data size
				current_address = base_address + offset;
				if (prev_address == 0 || (prev_address + byte_count < current_address)){
					// Not continuous memory
					current_size = 0;
					coredata->memsegnum++;
					coredata->coremem = (memseg_t*)realloc(coredata->coremem, coredata->memsegnum * sizeof(memseg_t));
					coredata->coremem[coredata->memsegnum - 1].low = current_address;
                    current_data = NULL;
				}
				prev_address = current_address;
                if (current_data) {
                    current_data = (uint8_t *)realloc(current_data, current_size + byte_count);
                } else {
                    current_data = (uint8_t *)malloc(byte_count);
                }
                for (size_t i = 0; i < byte_count; i++) {
                    sscanf(line + 9 + i * 2, "%2hhx", &byte);
                    current_data[current_size + i] = byte;
                }
                current_size += byte_count;
				coredata->coremem[coredata->memsegnum - 1].data = current_data;
				coredata->coremem[coredata->memsegnum - 1].high = coredata->coremem[coredata->memsegnum - 1].low + current_size ;
            }
            // End of file record
            else if (record_type == 1) {
                // ....
            }
            // Extended segment address record
            else if (record_type == 2) {
                // ...
                LOG(stderr, "Record type %d is not supported.\n", record_type);
            }
            // Start segment address record
            else if (record_type == 3) {
                // ...
                LOG(stderr, "Record type %d is not supported.\n", record_type);
            }
            // Extended linear address record
            else if (record_type == 4) {
                // Extract 32-bit linear address from data
                sscanf(line + 9, "%4hx", &linear_address);
                base_address = linear_address << 16;
            }
            // Start linear address record
            else if (record_type == 5) {
                // ...
                LOG(stderr, "Record type %d is not supported.\n", record_type);
            }
        }
		else {
			for (int i = 0; i < 18; i++) {
				if (strncmp(line, reg_names[i], strlen(reg_names[i])) == 0) {
					sscanf(line + strlen(reg_names[i]) + 1, "%x", &coredata->corereg.regs[i]);
					break;
				}
			}
		}
	}
    fclose(file);

	return coredata;
}

#ifdef MEMAC
int load_trace_mem(elf_binary_info * binary_info, char *trace_file, size_t* instnum, cs_insn** instlist, struct Access** accesslist){

    size_t tmpinst, tmpac;
    FILE *file;
    uint32_t address;
    cs_insn *instlist_tmp;
    struct Access *accesslist_tmp;

    struct capn ctx;
    TraceEvent_ptr pevent;
    struct TraceEvent event;
    struct Instruction instruction;

    // count the number of executed instructions
    if ((file = fopen(trace_file, "rb" )) == NULL){
        LOG(stderr, "ERROR: trace file open error\n");
        return -1;
    }

    tmpinst = 0; 	
    tmpac = 0;

    while (0==capn_init_fp(&ctx, file, 0)) {
        pevent.p = capn_getp(capn_root(&ctx), 0, 0);
        read_TraceEvent(&event, pevent);
        switch (event.which)
        {
        case TraceEvent_instruction:
            tmpinst++;
            break;
        case TraceEvent_access:
            tmpac++;
            break;
        }
    }

    *instnum = tmpinst;

    // fill instlist
    instlist_tmp = (cs_insn*)malloc(tmpinst * sizeof(cs_insn));

    // use NULL as padding
    accesslist_tmp = (struct Access*)malloc((tmpac+tmpinst) * sizeof(struct Access)); 
    
    if (!instlist_tmp || !accesslist_tmp){
        LOG(stderr, "ERROR: instlist/accesslist malloc error\n");
        return false;
    }
    memset(accesslist_tmp, 0, (tmpac+tmpinst) * sizeof(struct Access));
    memset(instlist_tmp, 0, tmpinst * sizeof(cs_insn));

    // int ttt = tmpac + tmpinst;

    // reset file pointer and fill the list
    fseek(file, 0, SEEK_SET);

    while (0==capn_init_fp(&ctx, file, 0)) {

        pevent.p = capn_getp(capn_root(&ctx), 0, 0);
        read_TraceEvent(&event, pevent);

        switch (event.which)
        {
            case TraceEvent_instruction:
                tmpinst--;
                read_Instruction(&instruction, event.instruction);
                instlist_tmp[tmpinst] = binary_info->instlist[binary_info->lookuptable[(instruction.pc - binary_info->start_address)>>1]];
                accesslist_tmp[tmpac+tmpinst].pc = instruction.pc; 
                break;
            case TraceEvent_access:
                tmpac--;
                read_Access(&accesslist_tmp[tmpac+tmpinst], event.access);
                break;
        }
    }
	fclose(file);

    *instlist = instlist_tmp;
    *accesslist = accesslist_tmp;

    // for (int i = 0; i < ttt; i++) {
    //     if (accesslist_tmp[i].size == 0) {
    //         LOG(stdout, "i = %d, empty\n", i);
    //     } else {
    //         LOG(stdout, "i = %d, %s %d bytes at %#x\n",
    //         i, accesslist_tmp[i].type == MEM_READ_AFTER ? "read" : "write",
    //         accesslist_tmp[i].size, accesslist_tmp[i].address);
    //     }
    // }
    return 0;
}
#else 
unsigned long load_trace(elf_binary_info * binary_info, char *trace_file, cs_insn *instlist){

    char line[ADDRESS_SIZE + 2];
    int offset = 0;
    char inst_buf[INST_LEN];
    unsigned long i;
    FILE *file;
    cs_insn inst;
    uint32_t address;

    if ((file = fopen(trace_file, "r" )) == NULL){
        LOG(stderr, "ERROR: trace file open error\n");
        return -1;
    }

    i = 0; 	

    while (fgets(line, sizeof(line), file) != NULL) {
        // need to check the result of strtoll instead of strncmp
        if (i >= get_max_rev_ins_num()){
            break;
        }
        if (strncmp(line, "[disabled]", 10) == 0) continue;
        if (strncmp(line, "[enabled]", 9) == 0) continue;
        if (strncmp(line, "[resumed]", 9) == 0) continue;

        // strtol return unsigned long.
        // So if input is bigger than 0x80000000, it will return 0x7fffffff
        address = (uint32_t)strtoll(line, NULL, 16);
        // LOG(stdout, "Processing 0x%08x...\n", address);
        // LOG(stdout,"1. address = %x\n", address);
        // LOG(stdout,"2. binary_info->start_address = %x\n", binary_info->start_address);
        // LOG(stdout,"3. lookuptable[%x]\n", (address - binary_info->start_address)>>1);
        // LOG(stdout,"4. instlist[%x]\n", binary_info->lookuptable[(address - binary_info->start_address)>>1]);
        // LOG(stdout,"5. instlist[%x].address = %x\n", binary_info->lookuptable[(address - binary_info->start_address)>>1], binary_info->instlist[binary_info->lookuptable[(address - binary_info->start_address)>>1]].address);
        instlist[i++] = binary_info->instlist[binary_info->lookuptable[(address - binary_info->start_address)>>1]];

    }

	fclose(file);
    return i;
}
#endif

#ifdef VSA
unsigned long load_log(char* log_path, operand_val_t *oploglist){

	unsigned index;
	char log_buf[LOG_MAX_SIZE];

	FILE* file; 


	if((file = fopen(log_path, "r")) == NULL){
		LOG(stderr, "ERROR: Cannot open file for log data\n");
		return -1;
	}

	index = 0;


	memset(log_buf, 0, LOG_MAX_SIZE);
	while(fgets(log_buf, sizeof(log_buf), file) != 0){
		if (index >= get_max_rev_ins_num()){
			break;
		}
		if(strncmp(log_buf, "noreg", 5) == 0){
			oploglist[index].regnum = 0;
			memset(oploglist[index].regs, 0, sizeof(oploglist[index].regs));
		}else{
			//process this line to get the tokens
			process_log_line(log_buf, &oploglist[index]);
		}

		index++;
		memset(log_buf, 0, LOG_MAX_SIZE);
	}
}
#endif



void destroy_instlist(cs_insn * instlist){
	if(instlist)
		free(instlist);
	instlist = NULL;
}

static char *useless_inst[] = {
	"prefetcht0",
	"lfence"
};

#define NUINST (sizeof(useless_inst)/sizeof(char *))

bool verify_useless_inst(cs_insn *inst) {
	int i;

	if (!inst) {
		return false;
	}

	for (i = 0; i < NUINST; i++) {
		if (strcmp(inst->mnemonic, useless_inst[i]) == 0)
			return true;
	}
        return false;
}

// destroy elf_binary_info structure
int destroy_bin_info(elf_binary_info * bin_info){
	// if (bin_info && bin_info->binary_info_set){
	// 	destroy_binary_set(bin_info);
	// }
	if (bin_info->instlist) {
		free(bin_info->instlist);
	}
	if (bin_info->lookuptable) {
		free(bin_info->lookuptable);
	} 
	if (bin_info){
		free(bin_info);
		bin_info = NULL;
	}
	return 0;
}


#ifdef VSA
void destroy_dlregionlist(dlregion_list_t *dlregionlist) {
        if (dlregionlist) {
                free(dlregionlist);
        	dlregionlist = NULL;
        }
}

int get_segment_from_addr(unsigned address) {
	int seg_id = -1, index;
	for (index = 0; index < re_ds.coredata->memsegnum; index++) {
		if ((address>=re_ds.coredata->coremem[index].low) &&
		    (address<re_ds.coredata->coremem[index].high)) {
			seg_id = index;
			break;
		}
	} 
	return seg_id;
}

#endif
// process all the binary files mapped by the core file,
// including the binary and the dynamic libraries
int count_bin_file_num(core_nt_file_info nt_file_info){
	int num = 0;
	int i = 0;
	char *prev_name, *next_name;
	prev_name = basename(nt_file_info.file_info[0].name);

	if (strlen(prev_name) > 0) num++;
	for (i=1; i< nt_file_info.nt_file_num; i++){
		next_name = basename(nt_file_info.file_info[i].name);
		if (!strlen(next_name)) continue;
		if (!strcmp(prev_name, next_name)){		
			continue;
        } else {
			num++;
			prev_name = next_name;
		}		
	}
	LOG(stdout, "DEBUG: The number of different binary files is %d\n", num);
	return num; 
}

// parse binary
elf_binary_info* parse_binary(const char* bin_path, uint32_t start_address){
	
	LOG(stdout, "STATE: Process Binary Files Mapped into Address Space\n");

	csh handle;
	cs_insn* insn;
	size_t count;

	elf_binary_info * binary_info = NULL;

	FILE* file = fopen(bin_path, "rb");

	if (file == NULL){
		LOG(stderr, "Error When Open ELF core file: %s\n", strerror(errno));
		return NULL;
	}

	fseek(file, 0, SEEK_END);
	size_t filesize = ftell(file);
	fseek(file, 0, SEEK_SET);

	uint8_t* buffer = (uint8_t*)malloc(filesize);

	if (buffer == NULL){
		LOG(stderr, "Error When Memory Allocation\n");
		fclose(file);
		return NULL;
	}

	size_t bytes_read = fread(buffer, 1, filesize, file);
	if (bytes_read != filesize){
		LOG(stderr, "Error When Reading ELF core file: %s\n", strerror(errno));
		fclose(file);
		free(buffer);
		return NULL;
	}
	
	if (cs_open(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS, &handle) != CS_ERR_OK){
		LOG(stderr, "ERROR: Failed to initialize engine!\n");
		return NULL;
	}

	// use capstone to disasm the binary file
	cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	binary_info = (elf_binary_info*)malloc(sizeof(elf_binary_info));

	if (binary_info == NULL){
		LOG(stderr, "Error When Memory Allocation binary_info\n");
		fclose(file);
		free(buffer);
		return NULL;
	}

	// use capstone to disasm the binary file
	size_t j;
	uint32_t offset;
	count = cs_disasm(handle, buffer, filesize, start_address, 0, &insn);
	if (count > 0) {
		LOG(stdout, "DEBUG: The number of instructions is %d\n", count);
		binary_info->instlist = insn;
		binary_info->lookuptable = (uint32_t*)malloc(count * 2 * sizeof(uint32_t));
		for (j = 0; j < count; j++) {
			if (insn[j].address & 1) {
				LOG(stderr, "ERROR: instruction address is not aligned\n");
			}
			// Bugfix: it seems that capstone will wrongly disassemble some instructions (pop)
            if (insn[j].id == ARM_INS_POP) {
                // although sp(r13) read, just ignore it.
                for (int op_idx = 0; op_idx <= insn[j].detail->arm.op_count; op_idx++) {
                    // LOG(stdout, "%s %s op[%d](%s) access = %d\n",
                    // insn[j].mnemonic, insn[j].op_str, op_idx, 
                    // cs_reg_name(handle, insn[j].detail->arm.operands[op_idx].reg),
                    // insn[j].detail->arm.operands[op_idx].access);
                    if (insn[j].detail->arm.operands[op_idx].access & CS_AC_READ) {
                        insn[j].detail->arm.operands[op_idx].access = CS_AC_WRITE;
                    }
                }
            }
			// Bugfix: it seems that capstone will wrongly disassemble negative disp 
			if (strstr(insn[j].op_str, "#-")) {
				insn[j].detail->arm.operands[1].mem.disp = -insn[j].detail->arm.operands[1].mem.disp;
			}

			offset = (insn[j].address - start_address) >> 1; // Trick: instructions are even aligned
			binary_info->lookuptable[offset] = j;
			// LOG(stdout,"lookuptable[%d ((%#x - %#x) >> 1)] = %dth instruction in instlist\n", offset, insn[j].address, start_address,j);
			// usage: binary_info->instlist[binary_info->lookuptable[(address - start_address)>>2]]
		}
		// cs_free(insn, count);
	} else {
		LOG(stderr, "ERROR: Failed to disassemble given code!\n");
	}

	fclose(file);
	free(buffer);

	binary_info->start_address = start_address;
	re_ds.handle = handle;
	return binary_info;
}


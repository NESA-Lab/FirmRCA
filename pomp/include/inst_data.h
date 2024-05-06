#ifndef __INST_DATA__
#define __INST_DATA__

#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <assert.h>
#include <capstone/capstone.h>
#include "global.h"
#include "bintrace.capnp.h"

typedef struct memseg_struct{
	unsigned low;
	unsigned high;
	void * data;
}memseg_t; 

typedef struct corereg_struct{
	int32_t regs[18];
}corereg_t;


typedef struct coredata_struct{
	size_t memsegnum; 
	memseg_t * coremem; 
	corereg_t corereg;
}coredata_t;

unsigned long load_trace(elf_binary_info * binary_info, char *trace_file, cs_insn *instlist);

#ifdef MEMAC
int load_trace_mem(elf_binary_info * binary_info, char *trace_file, size_t* instnum, cs_insn **instlist, struct Access **accesslist);
#endif

coredata_t * load_coredump(const char* core_path);

bool verify_useless_inst(cs_insn *inst);

void destroy_instlist(cs_insn * instlist);

#endif


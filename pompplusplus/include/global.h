#ifndef __GLOBAL__
#define __GLOBAL__

// #include <libdis.h>
#include <capstone/capstone.h>

#include "elf_core.h"
#include "elf_binary.h"
extern char *core_path;
extern char *bin_path;
extern char *inst_path;
extern int max_rev_ins_num;
extern int root_cause_rev_idx;

void set_core_path(char *path);
char * get_core_path(void);

void set_bin_path(char *path);
char * get_bin_path(void);

void set_inst_path(char *path);
char * get_inst_path(void);

void set_bin_info(elf_binary_info *binaryinfo);
elf_binary_info *get_bin_info(void);

void set_memac_path(char *path);
char * get_memac_path(void);

void set_max_rev_ins_num(int num);
int get_max_rev_ins_num(void);

void set_root_cause_rev_idx(int idx);
int get_root_cause_rev_idx(void);

unsigned long countvalidaddress(char *filename);

// typedef struct input_struct {
// 	char *case_path;
// 	char *core_path;	// coredump
// 	char *inst_path; 	// instruction address
// 	char *libs_path;   	// library 
// 	char *log_path;	// register status
// 	char *xmm_path;		// xmm registers
// 	// DL input data
// 	char *bin_path;   	// binary representation
// 	//char *memop_path;	// memory operands
// 	char *region_path;   	// region for memory operands
// 	// DL input data
// #if defined (ALIAS_MODULE) && (ALIAS_MODULE == VSA_MODULE)
// 	// VSA input data
// 	char *heu_path;		// vsa heuristic
// #endif
// } input_st;

// extern input_st input_data;

// void set_input_data(char *path);
// void clean_input_data(input_st input_data);

// char * get_core_path(void);
// char * get_inst_path(void);
// char * get_libs_path(void);
char * get_log_path(void);
// char * get_xmm_path(void);

// char * get_bin_path(void);
// //char * get_memop_path(void);
// char * get_region_path(void);

#if defined (ALIAS_MODULE) && (ALIAS_MODULE == VSA_MODULE)
char * get_heu_path(void);
#endif

// unsigned long count_linenum(char *filename);
// unsigned long count_linenum_ptlog(char *filename);
// unsigned long gcd(unsigned long a, unsigned long b);
#endif

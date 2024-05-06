#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <assert.h>
#include <capstone/capstone.h>
#include <sys/time.h>
#include <time.h>
#include "reverse_instructions.h"
#include "reverse_log.h"
#include "global.h"
#include "reverse_exe.h"
#include "inst_data.h"
#include "re_runtime.h"
#include "bjtime.h"
#ifdef VSA
#include "bin_alias.h"
#include "solver.h"
#endif

re_t re_ds; 

int main(int argc, char *argv[]){
	setvbuf(stdout, 0, 2, 0);
	setvbuf(stderr, 0, 2, 0);
#ifdef VSA
#if !defined (ALIAS_MODULE)
	LOG(stderr, "Please set Alias Module as : \n"
		    "ALIAS_MODULE=0          means No Alias \n"
		    "ALIAS_MODULE=1          means POMP \n"
		    "ALIAS_MODULE=1 + DL_AST means POMP+DL \n"
		    "ALIAS_MODULE=2          means VSA  \n"
		    "ALIAS_MODULE=2 + DL_AST means VSA+DL \n"
		    "ALIAS_MODULE=2 + HT_AST means VSA+POMP \n"
		    "ALIAS_MODULE=2 + DL_AST + HT_AST means VSA+DL+POMP \n"
		    "ALIAS_MODULE=9          means GT+POMP \n");
	return 0;
#endif
#endif
    size_t instnum;
	int result; 
	int temp_int;
	unsigned int start_address;

#ifdef VSA
    size_t lognum, dlregionnum;
    operand_val_t *oploglist;
#endif
	elf_binary_info *binary_info;
	coredata_t * coredata; 
	cs_insn * rawinstlist;
#ifndef POMP
	struct Access *accesslist; 
#endif
    time_t now = time(NULL);
    struct tm *p =localtime(&now);
    mytime_t BJT = {
        .year=p->tm_year+1900,
        .month=p->tm_mon+1,
        .day=p->tm_mday,
        .hours=p->tm_hour,
        .minutes=p->tm_min,
        .seconds=p->tm_sec

    };
    UTCToBeijing(&BJT);
    printf("Current Time:%04d-%02d-%02d %02d:%02d:%02d\n",  BJT.year,BJT.month,BJT.day,BJT.hours,BJT.minutes,BJT.seconds); 

	

	// if (argc != 5){
	// 	LOG(stderr, "Help: %s coredump binary_path instruction_file\n", argv[0]);
	// 	LOG(stderr, "      You must make sure that binary file,all the library files are in the directory defined by binary_path\n");
	// 	exit(1);
	// }

//pre-processing
	set_core_path(argv[1]); // (state-out.txt)
	set_bin_path(argv[2]);  // (firmware.bin)
	set_inst_path(argv[3]); // (instlist.reverse)
	set_memac_path(argv[4]); // (memac.bin)

#ifdef FRCA
	sscanf(argv[5],"%x",&start_address);
	sscanf(argv[6],"%d",&temp_int);
	set_max_rev_ins_num(temp_int);
	sscanf(argv[7],"%d",&temp_int);
	set_root_cause_rev_idx(temp_int);
#endif

#ifdef VSA
	set_log_path(argv[5]); // (loglist.reverse)
	sscanf(argv[6],"%x",&start_address);
	sscanf(argv[7],"%d",&temp_int); //max_rev_ins_num
	set_max_rev_ins_num(temp_int);  
	sscanf(argv[8],"%d",&temp_int); //root_cause_rev_idx
	set_root_cause_rev_idx(temp_int);
#endif

#ifdef POMP
	sscanf(argv[5],"%x",&start_address);
	sscanf(argv[6],"%d",&temp_int); //max_rev_ins_num
	set_max_rev_ins_num(temp_int);  
	sscanf(argv[7],"%d",&temp_int); //root_cause_rev_idx
	set_root_cause_rev_idx(temp_int);
#endif

	// initialize the runtime
	init_runtime();

	printf("max_rev_ins_num: %d\n", get_max_rev_ins_num());
	printf("root_cause_rev_idx: %d\n", get_root_cause_rev_idx());
//load data from core dump, including registers and memory 
	coredata = load_coredump(get_core_path());
	if (!coredata) {
		LOG(stderr,"ERROR: Cannot load data from core dump");
		exit(1); 
	}
	

//parse binaries (*.bin)
	binary_info = parse_binary(get_bin_path(), start_address); 
	if (!binary_info) {
		LOG(stderr,"ERROR: The binary file is not parsed correctly");
		exit(1); 
   	} 

#ifdef MEMAC

	if (load_trace_mem(binary_info, get_memac_path(), &instnum, &rawinstlist, &accesslist) != 0) {
		LOG(stderr, "ERROR: error in loading all the instructions\n");
		assert(0);
	}
#else
	//load all the instructions in a reversed manner
	instnum = countvalidaddress(get_inst_path());
	if(instnum <= 0){
		LOG(stderr, "ERROR: read file error when counting linenum\n");
		exit(1);
	}
    LOG(stdout,"RESULT: load %d instnum from %s\n", instnum, get_inst_path());
	rawinstlist = (cs_insn*)malloc(instnum * sizeof(cs_insn));

	if (!rawinstlist){
		LOG(stderr, "ERROR: malloc error in main\n");
		exit(1);
	}
	memset(rawinstlist, 0, instnum * sizeof(cs_insn));
	result = load_trace(binary_info, get_inst_path(), rawinstlist);
	if (result < 0) {
		LOG(stderr, "ERROR: error in loading all the instructions\n");
		assert(0);
	}

#endif

	print_registers(coredata);

#ifdef LOG_INSTRUCTIONS
	log_instructions(rawinstlist, instnum);
	return 0;
#endif

#ifdef VSA
	lognum = count_linenum(get_log_path());
	LOG(stdout,"RESULT: load %d lognum from %s\n", lognum, get_log_path());
	if (lognum <= 0) {
		LOG(stderr, "Warning: There is no valid log\n");
		lognum = 0;
		oploglist = NULL;
	} else {
		oploglist = (operand_val_t*)malloc(lognum * sizeof(operand_val_t));
		if (!oploglist) {
			LOG(stderr, "ERROR: malloc error\n");
			exit(1);
		}
		
		result = load_log(get_log_path(), oploglist);
		if (result < 0) {
			LOG(stderr, "ERROR: error when loading the data logs\n");
			exit(1);
		}
		LOG(stdout,"inst num = %d, log num = %d\n", instnum, lognum);
		assert(instnum == lognum);
	}
#endif
//main function of reverse exectuion
#ifdef POMP
    INIT_RE(re_ds, instnum, rawinstlist, coredata);
#else
	INIT_RE(re_ds, instnum, rawinstlist, coredata, accesslist);
#endif
#ifdef VSA
	re_ds.oplog_list.log_num = lognum;
	re_ds.oplog_list.opval_list = oploglist;
    memset(re_ds.flist, 0, MAXFUNC * sizeof(func_info_t));
#endif
	re_ds.root =&(rawinstlist[0]);

	re_ds.instnum = instnum > get_max_rev_ins_num() ? get_max_rev_ins_num() : instnum;

	LOG(stdout, "Start reverse execution with crash site: ");
	print_assembly(re_ds.root);

	clock_t start_time, end_time;
	start_time = clock();
	reverse_instructions();
	end_time = clock();
	printf("Finish reverse execution using %f seconds.\n", (double)(end_time - start_time) / CLOCKS_PER_SEC);

//do some cleanup here
	destroy_instlist(rawinstlist);
	destroy_bin_info(binary_info);
}

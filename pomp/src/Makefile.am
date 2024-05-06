handlers_FILES = handler_arm.c
bin_PROGRAMS = reversenolog reverselog

# baseline | reverse-baseline-nolog-noassert.elf | experiment
reversenolog_CFLAGS= -DPOMP -DNDEBUG -I ../include 
reversenolog_LDADD = -lcapstone
reversenolog_CPPFLAGS = -msse4.1
reversenolog_SOURCES = access_memory.c alias_manager.c disassemble.c heuristics.c global.c inst_handle_resolve.c process_input.c re_dsmanager.c re_insttable_arm.c re_mem_alias.c re_opdvalue.c reverse_log.c analyze_result.c reverse_execution.c reverse_instructions.c re_runtime.c $(handlers_FILES)

# baseline | reverse-baseline-log-noassert.elf | debug 
reverselog_CFLAGS=  -DPOMP -DNDEBUG -DENABLE_LOG -DVERBOSE -I ../include 
reverselog_LDADD = -lcapstone
reverselog_CPPFLAGS = -msse4.1
reverselog_SOURCES = access_memory.c alias_manager.c disassemble.c heuristics.c global.c inst_handle_resolve.c process_input.c re_dsmanager.c re_insttable_arm.c re_mem_alias.c re_opdvalue.c reverse_log.c analyze_result.c reverse_execution.c reverse_instructions.c  re_runtime.c $(handlers_FILES) 


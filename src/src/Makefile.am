AUTOMAKE_OPTIONS = -Wno-error

handlers_FILES  = handler_arm.c
bin_PROGRAMS    = reversenolog reverselog ablation1 ablation2 ablation3
#bin_PROGRAMS    = reverselog
capnproto_FILES = bintrace.capnp.c

# capnp    | reverse-capnproto-nolog-noassert.elf | experiment
reversenolog_CFLAGS   = -DFRCA -DNDEBUG -DMEMAC -I ../include -Wl,-rpath=../lib -L../lib
reversenolog_LDADD    = -lcapstone -lcapnproto
reversenolog_CPPFLAGS = -msse4.1
reversenolog_SOURCES  = access_memory.c alias_manager.c  disassemble.c heuristics.c global.c inst_handle_resolve.c process_input.c re_dsmanager.c re_insttable_arm.c re_mem_alias.c re_opdvalue.c reverse_log.c analyze_result.c reverse_execution.c reverse_instructions.c re_runtime.c $(handlers_FILES) $(capnproto_FILES)

# capnp    | reverse-capnproto-log-noassert.elf | debug
reverselog_CFLAGS   = -DFRCA -DNDEBUG -DENABLE_LOG -DVERBOSE -DMEMAC -I ../include -Wl,-rpath=../lib -L../lib
reverselog_LDADD    = -lcapstone -lcapnproto
reverselog_CPPFLAGS = -msse4.1
reverselog_SOURCES  = access_memory.c alias_manager.c  disassemble.c heuristics.c global.c inst_handle_resolve.c process_input.c re_dsmanager.c re_insttable_arm.c re_mem_alias.c re_opdvalue.c reverse_log.c analyze_result.c reverse_execution.c reverse_instructions.c re_runtime.c $(handlers_FILES) $(capnproto_FILES)

# capnp    |  ablation study 1: no redundant loops ranking
ablation1_CFLAGS    = -DFRCA -DNDEBUG -DMEMAC -DABLATION1 -I ../include -Wl,-rpath=../lib -L../lib
ablation1_LDADD     = -lcapstone -lcapnproto
ablation1_CPPFLAGS  = -msse4.1
ablation1_SOURCES   = access_memory.c alias_manager.c  disassemble.c heuristics.c global.c inst_handle_resolve.c process_input.c re_dsmanager.c re_insttable_arm.c re_mem_alias.c re_opdvalue.c reverse_log.c analyze_result.c reverse_execution.c reverse_instructions.c re_runtime.c $(handlers_FILES) $(capnproto_FILES)

# capnp    | ablation study 2: no conditional jumps ranking
ablation2_CFLAGS    = -DFRCA -DNDEBUG -DMEMAC -DABLATION2 -I ../include -Wl,-rpath=../lib -L../lib
ablation2_LDADD     = -lcapstone -lcapnproto
ablation2_CPPFLAGS  = -msse4.1
ablation2_SOURCES   = access_memory.c alias_manager.c  disassemble.c heuristics.c global.c inst_handle_resolve.c process_input.c re_dsmanager.c re_insttable_arm.c re_mem_alias.c re_opdvalue.c reverse_log.c analyze_result.c reverse_execution.c reverse_instructions.c re_runtime.c $(handlers_FILES) $(capnproto_FILES)

# capnp    | ablation study 3: no heuristic rankings
ablation3_CFLAGS    = -DFRCA -DNDEBUG -DMEMAC -DABLATION1 -DABLATION2 -I ../include -Wl,-rpath=../lib -L../lib
ablation3_LDADD     = -lcapstone -lcapnproto
ablation3_CPPFLAGS  = -msse4.1
ablation3_SOURCES   = access_memory.c alias_manager.c  disassemble.c heuristics.c global.c inst_handle_resolve.c process_input.c re_dsmanager.c re_insttable_arm.c re_mem_alias.c re_opdvalue.c reverse_log.c analyze_result.c reverse_execution.c reverse_instructions.c re_runtime.c $(handlers_FILES) $(capnproto_FILES)
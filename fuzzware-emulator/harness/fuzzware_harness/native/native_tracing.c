#include "native_tracing.h"

// 0. Constants
#define DEFAULT_INITIAL_MMIO_ACCESS_CONTEXT_TRACE_SET_CAPACITY 0x10000
#define DEFAULT_INITIAL_PC_TRACE_SET_CAPACITY 0x10000

// 1. Static (after initialization) configs
char *bbl_set_trace_path = NULL;
char *bbl_hash_path = NULL;
char *mmio_set_trace_path = NULL;

// 3. Dynamic State (required for state restore)
struct TraceState trace_state = {
    .bb_hash_base = 0,
    .bb_hash = 0,
    .kh_basic_block_set = NULL,
    .kh_scratch_basic_block_set = NULL,
    .kh_mmio_access_context_set_reads = NULL,
    .kh_scratch_mmio_access_context_set_reads = NULL,
    .kh_mmio_access_context_set_writes = NULL,
    .kh_scratch_mmio_access_context_set_writes = NULL
};

static uint64_t dw_sdbm_hash(uint64_t state, uint32_t value)
{
    return value + (state << 6) + (state << 16) - state;
}

void hook_block_trace_set(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    int kh_res;

    if(kh_get(32, trace_state.kh_basic_block_set, address) == kh_end(trace_state.kh_basic_block_set)) {
        kh_put(32, trace_state.kh_scratch_basic_block_set, address, &kh_res);
    }
}

void hook_block_trace_hash_bbs(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    trace_state.bb_hash = dw_sdbm_hash(trace_state.bb_hash, address);
}

#define ENCODE_MMIO_ACCESS_CONTEXT(PC, ADDR) (((uint64_t)(PC))<<32 | (uint64_t)(ADDR))
#define DECODE_MMIO_ACCESS_CONTEXT_PC(ENCODED_VAL) ((uint32_t)((ENCODED_VAL) >> 32))
#define DECODE_MMIO_ACCESS_CONTEXT_ADDR(ENCODED_VAL) ((uint32_t)((ENCODED_VAL) & 0xffffffff))

void hook_mem_trace_mmio_access(uc_engine *uc, uc_mem_type type,
                      uint64_t addr, int size, int64_t value, void *user_data) {
    uint32_t pc;
    int kh_res;
    uint64_t context;
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    context = ENCODE_MMIO_ACCESS_CONTEXT(pc, addr);

    if(type == UC_MEM_WRITE) {

        if( kh_get(64, trace_state.kh_mmio_access_context_set_writes, context)
                == kh_end(trace_state.kh_mmio_access_context_set_writes)) {
            kh_put(64, trace_state.kh_scratch_mmio_access_context_set_writes, context, &kh_res);
        }
    } else {

        if( kh_get(64, trace_state.kh_mmio_access_context_set_reads, context)
                == kh_end(trace_state.kh_mmio_access_context_set_reads)) {
            kh_put(64, trace_state.kh_scratch_mmio_access_context_set_reads, context, &kh_res);
        }
    }
}

void exit_hook_write_trace_sets(int status, int sig)
{
    FILE *f;

    if(bbl_set_trace_path) {
        f = fopen(bbl_set_trace_path, "w");

        uint32_t bbl_addr;
        kh_foreach_key(trace_state.kh_basic_block_set, bbl_addr, {
            fprintf(f, "%x\n", bbl_addr);
        });
        kh_foreach_key(trace_state.kh_scratch_basic_block_set, bbl_addr, {
            fprintf(f, "%x\n", bbl_addr);
        });

        fflush(f);
        fclose(f);
    }

    if(bbl_hash_path) {
        f = fopen(bbl_hash_path, "w");
        fprintf(f, "%016lx\n", trace_state.bb_hash);

        fflush(f);
        fclose(f);
    }

    if(mmio_set_trace_path) {
        f = fopen(mmio_set_trace_path, "w");

        uint64_t access_context;
        kh_foreach_key(trace_state.kh_mmio_access_context_set_reads, access_context, {
            fprintf(f, "%x %x r\n", DECODE_MMIO_ACCESS_CONTEXT_PC(access_context), DECODE_MMIO_ACCESS_CONTEXT_ADDR(access_context));
        });
        kh_foreach_key(trace_state.kh_scratch_mmio_access_context_set_reads, access_context, {
            fprintf(f, "%x %x r\n", DECODE_MMIO_ACCESS_CONTEXT_PC(access_context), DECODE_MMIO_ACCESS_CONTEXT_ADDR(access_context));
        });

        kh_foreach_key(trace_state.kh_mmio_access_context_set_writes, access_context, {
            fprintf(f, "%x %x w\n", DECODE_MMIO_ACCESS_CONTEXT_PC(access_context), DECODE_MMIO_ACCESS_CONTEXT_ADDR(access_context));
        });
        kh_foreach_key(trace_state.kh_scratch_mmio_access_context_set_writes, access_context, {
            fprintf(f, "%x %x w\n", DECODE_MMIO_ACCESS_CONTEXT_PC(access_context), DECODE_MMIO_ACCESS_CONTEXT_ADDR(access_context));
        });

        fflush(f);
        fclose(f);
    }
}

void *tracing_take_snapshot(uc_engine *uc) {
    int kh_res;

    if(trace_state.kh_basic_block_set) {
        // Copy all entries from scratch set to base set and erase scratch
        uint32_t bbl_addr;

        kh_foreach_key(trace_state.kh_scratch_basic_block_set, bbl_addr, {
            kh_put(32, trace_state.kh_basic_block_set, bbl_addr, &kh_res);
        });
        kh_clear(32, trace_state.kh_scratch_basic_block_set);
    }

    if(bbl_hash_path) {
        trace_state.bb_hash_base = trace_state.bb_hash;
    }

    if(trace_state.kh_mmio_access_context_set_reads && trace_state.kh_mmio_access_context_set_writes) {
        // Copy all entries from scratch set to base set and erase scratch
        uint64_t context;

        kh_foreach_key(trace_state.kh_scratch_mmio_access_context_set_reads, context, {
            kh_put(64, trace_state.kh_mmio_access_context_set_reads, context, &kh_res);
        });
        kh_clear(64, trace_state.kh_scratch_mmio_access_context_set_reads);

        kh_foreach_key(trace_state.kh_scratch_mmio_access_context_set_writes, context, {
            kh_put(64, trace_state.kh_mmio_access_context_set_writes, context, &kh_res);
        });
        kh_clear(64, trace_state.kh_scratch_mmio_access_context_set_writes);
    }

    return NULL;
}

void tracing_restore_snapshot(uc_engine *uc, void *snapshot) {
    // Restoring is just emptying the scratch buffer
    if(trace_state.kh_basic_block_set) {
        kh_clear(32, trace_state.kh_scratch_basic_block_set);
    }

    if(trace_state.kh_mmio_access_context_set_reads) {
        kh_clear(64, trace_state.kh_scratch_mmio_access_context_set_reads);
    }

    if(trace_state.kh_mmio_access_context_set_writes) {
        kh_clear(64, trace_state.kh_scratch_mmio_access_context_set_writes);
    }

    if(bbl_hash_path) {
        trace_state.bb_hash = trace_state.bb_hash_base;
    }
}

void tracing_discard_snapshot(uc_engine *uc, void *snapshot) {
    // NOP, as we did not allocate anything.
    // At the same time, be aware that we can only hold one snapshot at a time
}

uc_err init_tracing(uc_engine *uc, char *p_bbl_set_trace_path, char *p_bbl_hash_path, char *p_mmio_set_trace_path, size_t num_mmio_ranges, uint64_t *mmio_starts, uint64_t *mmio_ends) {
    uc_hook tmp_hook;

    if (p_bbl_set_trace_path || p_bbl_hash_path || p_mmio_set_trace_path)
    {
        add_exit_hook(exit_hook_write_trace_sets);

        if (p_bbl_set_trace_path) {
            bbl_set_trace_path = strdup(p_bbl_set_trace_path);

            trace_state.kh_basic_block_set = kh_init(32);
            trace_state.kh_scratch_basic_block_set = kh_init(32);

            // Tracing basic blocks is done via a single block hook
            uc_hook_add(uc, &tmp_hook, UC_HOOK_BLOCK_UNCONDITIONAL, hook_block_trace_set, NULL, 1, 0);
        }

        if(p_bbl_hash_path) {
            bbl_hash_path = strdup(p_bbl_hash_path);

            printf("logging basic block hash to %s\n", bbl_hash_path);

            // Tracing basic blocks is done via a single block hook
            uc_hook_add(uc, &tmp_hook, UC_HOOK_BLOCK_UNCONDITIONAL, hook_block_trace_hash_bbs, NULL, 1, 0);
        }

        if(p_mmio_set_trace_path) {
            mmio_set_trace_path = strdup(p_mmio_set_trace_path);

            trace_state.kh_mmio_access_context_set_writes = kh_init(64);
            trace_state.kh_mmio_access_context_set_reads = kh_init(64);
            trace_state.kh_scratch_mmio_access_context_set_writes = kh_init(64);
            trace_state.kh_scratch_mmio_access_context_set_reads = kh_init(64);

            // For tracing MMIO, we need to register hooks for all MMIO regions
            for (int i = 0; i < num_mmio_ranges; ++i) {
                // We do not currently need writes for our purposes, otherwise, this would require | UC_HOOK_MEM_WRITE
                uc_hook_add(uc, &tmp_hook, UC_HOOK_MEM_READ_AFTER, hook_mem_trace_mmio_access, NULL, mmio_starts[i], mmio_ends[i]);
            }
        }

        subscribe_state_snapshotting(uc, tracing_take_snapshot, tracing_restore_snapshot, tracing_discard_snapshot);
    }
    return UC_ERR_OK;
}

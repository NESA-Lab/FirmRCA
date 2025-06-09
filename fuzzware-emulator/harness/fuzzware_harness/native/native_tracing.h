#ifndef FUZZWARE_NATIVE_TRACING
#define FUZZWARE_NATIVE_TRACING

#include <unicorn/unicorn.h>
#include <string.h>

#include "native_hooks.h"
#include "state_snapshotting.h"

#include "khash.h"

KHASH_SET_INIT_INT64(64);
KHASH_SET_INIT_INT(32);

/*
 * To support snapshotting, keep one base set around as well as
 * one scratch set. We store all contexts already collected upon
 * taking a snapshot in the base sets, and add to the scratch set
 * when running from a snapshot. Restoring the snapshot then means
 * only wiping the scratch set.
 *
 * Note that nested snapshotting (which we are currently not using)
 * is not supported by this.
 */
struct TraceState {
    uint64_t bb_hash_base;
    uint64_t bb_hash;
    khash_t(32) *kh_basic_block_set;
    khash_t(64) *kh_mmio_access_context_set_writes;
    khash_t(64) *kh_mmio_access_context_set_reads;
    khash_t(32) *kh_scratch_basic_block_set;
    khash_t(64) *kh_scratch_mmio_access_context_set_writes;
    khash_t(64) *kh_scratch_mmio_access_context_set_reads;
};

uc_err init_tracing(uc_engine *uc, char *p_bbl_set_trace_path, char *p_bbl_hash_path, char *p_mmio_set_trace_path, size_t num_mmio_ranges, uint64_t *mmio_starts, uint64_t *mmio_ends);

#endif
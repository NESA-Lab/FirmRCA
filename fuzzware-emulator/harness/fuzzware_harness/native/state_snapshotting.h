/*
    API to save and restore harness-based state of the emulation
*/

#ifndef FUZZWARE_STATE_RESTORE
#define FUZZWARE_STATE_RESTORE
#include "unicorn/unicorn.h"

#define INITIAL_NUM_STATE_SOURCES 8

typedef void *(*snapshot_take_handler_t)(uc_engine *uc);
typedef void (*snapshot_restore_handler_t)(uc_engine *uc, void *state);
typedef void (*snapshot_discard_handler_t)(uc_engine *uc, void *state);

struct snapshot_t {
    void *state;
    snapshot_take_handler_t take_handler;
    snapshot_restore_handler_t restore_handler;
    snapshot_discard_handler_t discard_handler;
};

struct snapshotting_state_t {
    int num_allocated;
    int num_used;
    struct snapshot_t *snapshots;
};

void subscribe_state_snapshotting(uc_engine *uc, snapshot_take_handler_t take_handler, snapshot_restore_handler_t restore_handler, snapshot_discard_handler_t discard_handler);
void trigger_snapshotting(uc_engine *uc);
void trigger_restore(uc_engine *uc);

#endif
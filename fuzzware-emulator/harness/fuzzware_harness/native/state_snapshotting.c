#include "state_snapshotting.h"
#include "native_hooks.h"

static struct snapshotting_state_t state = {
    .num_allocated = 0,
    .num_used = 0
};

void subscribe_state_snapshotting(uc_engine *uc, snapshot_take_handler_t take_handler, snapshot_restore_handler_t restore_handler, snapshot_discard_handler_t discard_handler) {
    #ifdef DEBUG_STATE_SNAPSHOTTING
    puts("[subscribe_state_snapshotting]"); fflush(stdout);
    #endif

    if(state.num_allocated == 0) {
        state.snapshots = calloc(INITIAL_NUM_STATE_SOURCES, sizeof(*state.snapshots));
        state.num_allocated = INITIAL_NUM_STATE_SOURCES;
    } else if(state.num_used == state.num_allocated) {
        state.num_allocated = 2 * state.num_allocated;
        state.snapshots = realloc(state.snapshots, state.num_allocated * sizeof(*state.snapshots));
    }
    struct snapshot_t *snapshot = &state.snapshots[state.num_used++];

    snapshot->state = NULL;
    snapshot->take_handler = take_handler;
    snapshot->restore_handler = restore_handler;
    snapshot->discard_handler = discard_handler;
}

#define INITIAL_NUM_STATE_SOURCES 8

void trigger_snapshotting(uc_engine *uc) {
    #ifdef DEBUG_STATE_SNAPSHOTTING
    puts("[trigger_snapshotting]"); fflush(stdout);
    #endif

    for(int i = 0; i < state.num_used; ++i) {
        struct snapshot_t *snapshot = &state.snapshots[i];
        snapshot->state = snapshot->take_handler(uc);
    }
}

void trigger_restore(uc_engine *uc) {
    #ifdef DEBUG_STATE_SNAPSHOTTING
    puts("[trigger_restore]"); fflush(stdout);
    #endif
    for(int i = 0; i < state.num_used; ++i) {
        struct snapshot_t *snapshot = &state.snapshots[i];
        snapshot->restore_handler(uc, snapshot->state);
    }
}

void trigger_teardown(uc_engine *uc) {
    #ifdef DEBUG_STATE_SNAPSHOTTING
    puts("[trigger_teardown]"); fflush(stdout);
    #endif
    for(int i = 0; i < state.num_used; ++i) {
        struct snapshot_t *snapshot = &state.snapshots[i];
        snapshot->discard_handler(uc, snapshot->state);
    }
}
#include "uc_snapshot.h"
#include "state_snapshotting.h"
#include <string.h>

/*
 * Snapshotting of the unicorn engine state (registers and memory).
 *
 * To restore the register context, we use Unicorn's uc_context_alloc
 * and uc_context_save APIs.
 *
 * To restore memory, we take a copy on write / incremental approach:
 * 1. Setup:
 * - Initially, snapshot all memory range contents (we exclude MMIO
 *  for performance reasons).
 * - We set all writable memory regions to readonly, while noting the
 *  regions which have originally been writable.
 * 2. Run-time behavior:
 * - We intercept writes to readonly memory, and mark them for memory
 *  restoration. We then set the memory region writable.
 * 3. Restoration
 * - We restore the regions which have previously been written to during
 * any one of the previous runs.
 *
 * This keeps the number of restored pages small as long the emulated code
 * keeps writing to the same, small set of pages (for example, a few pages of
 * stack memory as well as the global data section and possibly heap memory).
 *
 * This way we save tracking dirty pages each run. The trade-off here is
 * that we always restore all pages which have been written to in any one
 * of the previous runs. Once firmware starts writing to a lot of pages in memory,
 * we will restore pages which may not have been written to in the current run.
 *
 * A growing corpus of to-restore pages can result from firmware corruptions / crashes,
 * which might start writing to random pages due to accidental ROP gadgets.
 *
 */

// 0. Constants
uint64_t ignored_state_restore_mem_addresses[] = {
    // Ret mask
    0xfffff000,
    // Sysregs
    0xe0000000
};

// 3. Dynamic State (required for state restore)
struct NativeHooksState native_hooks_state = {
    .curr_exit_at_hit_num = 0
};

void add_staterestore_region(struct NativeHooksState * result, uint8_t *contents, uint64_t guest_addr, int cursor, uint64_t region_size, int prev_is_nullpage) {
    #ifdef DEBUG_STATE_RESTORE
    printf("Adding %s region at 0x%08lx with size 0x%lx\n", prev_is_nullpage ? "null" : "content", guest_addr, region_size);
    #endif

    if(prev_is_nullpage) {
        // only registering null region
        ++result->num_nullregions;
        result->nullregion_sizes = realloc(result->nullregion_sizes, result->num_nullregions*sizeof(*result->nullregion_sizes));
        result->nullregion_starts = realloc(result->nullregion_starts, result->num_nullregions*sizeof(*result->nullregion_starts));
        result->nullregion_sizes[result->num_nullregions-1] = region_size;
        result->nullregion_starts[result->num_nullregions-1] = guest_addr;
    } else {
        // need to register actual contents region
        ++result->num_content_regions;
        result->content_sizes = realloc(result->content_sizes, result->num_content_regions * sizeof(*result->content_sizes));
        result->content_guest_addrs = realloc(result->content_guest_addrs, result->num_content_regions * sizeof(*result->content_guest_addrs));
        result->contents_ptrs = realloc(result->contents_ptrs, result->num_content_regions * sizeof(*result->contents_ptrs));
        result->content_sizes[result->num_content_regions-1] = region_size;
        result->content_guest_addrs[result->num_content_regions-1] = guest_addr;
        result->contents_ptrs[result->num_content_regions-1] = malloc(region_size);
        memcpy(result->contents_ptrs[result->num_content_regions-1], contents, region_size);
    }
}

bool activate_page_staterestore(struct NativeHooksState * s, uint64_t guest_addr) {
    /**
     * Activate restoration for a given page in memory.
     *
     * @return true, if region was successfully added. False, if page was already being restored or it does not exist in the state.
     **/
    uint64_t region_start, region_end, region_offset;
    bool is_first, is_last;

    // Page alignment
    guest_addr = guest_addr & ~(PAGE_SIZE-1);

    #ifdef DEBUG_STATE_RESTORE
    printf("[activate_page_staterestore] guest_addr=%lx\n", guest_addr); fflush(stdout);
    #endif

    // memory content regions
    for(int i=0; i < s->num_content_regions; ++i) {
        region_start = s->content_guest_addrs[i];
        region_end = s->content_guest_addrs[i] + s->content_sizes[i];
        region_offset = guest_addr - region_start;
        if(guest_addr >= region_start
            && guest_addr < region_end
        ) {
            is_first = region_offset == 0;
            is_last = guest_addr+PAGE_SIZE == region_end;

            #ifdef DEBUG_STATE_RESTORE
            printf("[activate_page_staterestore] region found: 0x%lx-0x%lx -> offset: 0x%lx [is_first=%d, is_last=%d]\n", region_start, region_end, region_offset, is_first, is_last); fflush(stdout);
            #endif

            // Found, see if we can add the page to an existing region
            // TODO: merge restore regions if a hole within a region is filled
            for(int j=0; j < s->num_restore_content_regions; ++j) {
                // Overlap?
                if(guest_addr >= s->restore_content_guest_addrs[j] && guest_addr < s->restore_content_guest_addrs[j]+s->restore_content_sizes[j]) {
                    #ifdef DEBUG_STATE_RESTORE
                    puts("[activate_page_staterestore] [-] overlapping with existing..."); fflush(stdout);
                    #endif
                    return false;
                }

                if((!is_first) && (s->restore_content_guest_addrs[j] + s->restore_content_sizes[j] == guest_addr)) {
                    #ifdef DEBUG_STATE_RESTORE
                    puts("[activate_page_staterestore] append to existing");
                    fflush(stdout);
                    #endif
                    // New page directly after already restored region
                    s->restore_content_sizes[j] += PAGE_SIZE;
                    return true;
                }

                if((!is_last) && guest_addr+PAGE_SIZE == s->restore_content_guest_addrs[j]) {
                    #ifdef DEBUG_STATE_RESTORE
                    puts("[activate_page_staterestore] prepending to existing"); fflush(stdout);
                    #endif
                    // New page directly before already restored region
                    s->restore_content_guest_addrs[j] -= PAGE_SIZE;
                    s->restore_contents_ptrs[j] -= PAGE_SIZE;
                    s->restore_content_sizes[j] += PAGE_SIZE;
                    return true;
                }
            }

            #ifdef DEBUG_STATE_RESTORE
            puts("[activate_page_staterestore] adding new region");
            fflush(stdout);
            #endif

            // No concatenation possible, create new subregion
            ++s->num_restore_content_regions;
            s->restore_content_guest_addrs = realloc(s->restore_content_guest_addrs, s->num_restore_content_regions*sizeof(*s->restore_content_guest_addrs));
            s->restore_contents_ptrs = realloc(s->restore_contents_ptrs, s->num_restore_content_regions*sizeof(*s->restore_contents_ptrs));
            s->restore_content_sizes = realloc(s->restore_content_sizes, s->num_restore_content_regions*sizeof(*s->restore_content_sizes));

            s->restore_content_guest_addrs[s->num_restore_content_regions-1] = guest_addr;
            s->restore_contents_ptrs[s->num_restore_content_regions-1] = s->contents_ptrs[i]+region_offset;
            s->restore_content_sizes[s->num_restore_content_regions-1] = PAGE_SIZE;

            return true;
        }
    }

    // null regions
    for(int i=0; i < s->num_nullregions; ++i) {
        region_start = s->nullregion_starts[i];
        region_end = s->nullregion_starts[i] + s->nullregion_sizes[i];
        region_offset = region_start - guest_addr;
        if(guest_addr >= region_start
            && guest_addr < region_end
        ) {
            is_first = region_offset == 0;
            is_last = guest_addr+PAGE_SIZE == region_end;

            // Found, see if we can add the page to an existing region
            // TODO: merge restore regions if a hole within a region is filled
            for(int j=0; j < s->num_restore_nullregions; ++j) {
                // Overlap?
                if(guest_addr >= s->restore_nullregion_starts[j] && guest_addr < s->restore_nullregion_starts[j]+s->restore_nullregion_sizes[j]) {
                    #ifdef DEBUG_STATE_RESTORE
                    puts("[activate_page_staterestore] [-] overlapping with existing..."); fflush(stdout);
                    #endif
                    return false;
                }

                if(!is_first && (s->restore_nullregion_starts[j] + s->restore_nullregion_sizes[j] == guest_addr)) {
                    #ifdef DEBUG_STATE_RESTORE
                    puts("[activate_page_staterestore] append to existing"); fflush(stdout);
                    #endif
                    // New page directly after already restored region
                    s->restore_nullregion_sizes[j] += PAGE_SIZE;
                    return true;
                }

                if(!is_last && guest_addr+PAGE_SIZE == s->restore_nullregion_starts[j]) {
                    #ifdef DEBUG_STATE_RESTORE
                    puts("[activate_page_staterestore] prepending to existing"); fflush(stdout);
                    #endif
                    // New page directly before already restored region
                    s->restore_nullregion_starts[j] -= PAGE_SIZE;
                    s->restore_nullregion_sizes[j] += PAGE_SIZE;
                    return true;
                }
            }

            #ifdef DEBUG_STATE_RESTORE
            puts("[activate_page_staterestore] adding new region");
            fflush(stdout);
            #endif
            // No concatenation possible, create new subregion
            ++s->num_restore_nullregions;
            s->restore_nullregion_starts = realloc(s->restore_nullregion_starts, s->num_restore_nullregions*sizeof(*s->restore_nullregion_starts));
            s->restore_nullregion_sizes = realloc(s->restore_nullregion_sizes, s->num_restore_nullregions*sizeof(*s->restore_nullregion_sizes));

            s->restore_nullregion_starts[s->num_restore_nullregions-1] = guest_addr;
            s->restore_nullregion_sizes[s->num_restore_nullregions-1] = PAGE_SIZE;

            return true;
        }
    }

    return false;
}

bool hook_invalid_write_on_demand_page_restore_handle(uc_engine *uc, uc_mem_type type,
    uint64_t address, int size, int64_t value, void *user_data) {
    uint64_t aligned = address & (~(PAGE_SIZE-1));
    uint32_t old_perms = 0;

    #ifdef DEBUG_STATE_RESTORE
    printf("[hook_invalid_write_on_demand_page_restore_handle] addr: 0x%lx, aligned: 0x%lx\n", address, aligned);
    fflush(stdout);
    #endif

    struct NativeHooksState *restore_state = (struct NativeHooksState *) user_data;
    bool res = activate_page_staterestore(restore_state, aligned);
    if(res) {
        for(int i = 0; i < restore_state->num_orig_regions; ++i) {
            if(aligned >= restore_state->orig_regions[i].begin && aligned <= restore_state->orig_regions[i].end) {
                old_perms = restore_state->orig_regions[i].perms;
                #ifdef DEBUG_STATE_RESTORE
                printf("[hook_invalid_write_on_demand_page_restore_handle] [+] found previous perms: %d\n", old_perms); fflush(stdout);
                #endif
                break;
            }
        }

        if(old_perms & UC_PROT_WRITE) {
            int res;
            if((res = uc_mem_protect(uc, aligned, PAGE_SIZE, old_perms)) != UC_ERR_OK) {
                printf("[ERROR] uc_mem_protect failed for aligned=%08lx, perms=%x (err code: %d, msg: %s)\n", aligned, old_perms, res, uc_strerror(res)); fflush(stdout);
                exit(-1);
            }
            if (uc_mem_write(uc, address, &value, size) != UC_ERR_OK) {
                printf("[ERROR] uc_mem_write failed while trying to add page %#010lx. Write addr: %#010lx, size: %d, value: %08lx\n", aligned, address, size, value);
                exit(-1);
            }

            #ifdef DEBUG_STATE_RESTORE
            puts("[hook_invalid_write_on_demand_page_restore_handle] successfully handled");
            fflush(stdout);
            #endif
            // Successfully handled
            return true;
        }
    }

    // Could not handle
    return false;
}

void *native_hooks_take_snapshot(uc_engine *uc) {
    size_t size = sizeof(native_hooks_state);
    uint32_t permissions;
    uint32_t num_regions;

    uc_mem_region *regions;
    // Set up all null pointers in initial state
    struct NativeHooksState *result = calloc(1, size);
    result->curr_exit_at_hit_num = native_hooks_state.curr_exit_at_hit_num;

    // memcpy(result, native_hooks_state.curr_exit_at_hit_num, size);
    uc_context_alloc(uc, &result->uc_saved_context);
    uc_context_save(uc, result->uc_saved_context);

    uc_mem_regions(uc, &regions, &num_regions);
    result->num_orig_regions = num_regions;
    result->orig_regions = regions;

    result->num_nullregions = result->num_content_regions = 0;
    result->nullregion_starts = result->nullregion_sizes = result->content_guest_addrs = result->content_sizes = NULL;
    result->contents_ptrs = NULL;

    // Copy all memory contents of writeable regions
    for(int i=0; i < num_regions; ++i) {
        size = regions[i].end - regions[i].begin + 1;
        permissions = regions[i].perms;

        // Only writeable regions get restored
        if(!(permissions & UC_PROT_WRITE)) {
            size = 0;
        }

        // Do not restore MMIO-based regions
        #ifdef DEBUG_STATE_RESTORE
        printf("[STATE SNAPSHOTTING] Checking mapped address 0x%lx\n", regions[i].begin); fflush(stdout);
        #endif
        for(int j=0; size && j < num_mmio_regions; ++j) {
            #ifdef DEBUG_STATE_RESTORE
            printf("[STATE SNAPSHOTTING] Comparing against MMIO address 0x%lx\n", mmio_region_starts[j]); fflush(stdout);
            #endif

            if(regions[i].begin == mmio_region_starts[j]) {
                #ifdef DEBUG_STATE_RESTORE
                printf("[STATE SNAPSHOTTING] Ignoring address 0x%lx\n", mmio_region_starts[j]); fflush(stdout);
                #endif

                size = 0;
            }
        }

        for(int j=0; size && j < sizeof(ignored_state_restore_mem_addresses)/sizeof(*ignored_state_restore_mem_addresses); ++j) {
            #ifdef DEBUG_STATE_RESTORE
            printf("[STATE SNAPSHOTTING] Comparing against MMIO address 0x%lx\n", ignored_state_restore_mem_addresses[j]); fflush(stdout);
            #endif

            if(regions[i].begin == ignored_state_restore_mem_addresses[j]) {
                #ifdef DEBUG_STATE_RESTORE
                printf("[STATE SNAPSHOTTING] Ignoring address 0x%lx\n", ignored_state_restore_mem_addresses[j]); fflush(stdout);
                #endif

                size = 0;
                break;
            }
        }

        if(size) {
            int k;
            int num_adjacent_regions = 1;
            int cursor = 0;
            int is_nullpage = -1, prev_is_nullpage = -1;
            uint8_t *contents = malloc(size);
            uc_mem_read(uc, regions[i].begin, contents, size);

            for(cursor = 0; cursor < size; cursor += PAGE_SIZE) {
                is_nullpage = 1;
                for(k=0; k < PAGE_SIZE; ++k) {
                    if(contents[cursor+k] != 0) {
                        is_nullpage = 0;
                        break;
                    }
                }

                #ifdef DEBUG_STATE_RESTORE
                if(is_nullpage) {
                    printf("nullpage at 0x%08lx\n", regions[i].begin+cursor);
                } else {
                    printf("content page at 0x%08lx\n", regions[i].begin+cursor);
                }
                #endif

                if(prev_is_nullpage != -1) {
                    if(prev_is_nullpage == is_nullpage) {
                        ++num_adjacent_regions;
                    } else {
                        uint64_t region_size = num_adjacent_regions * PAGE_SIZE;
                        uint64_t guest_addr = regions[i].begin + cursor - region_size;
                        add_staterestore_region(result, contents + cursor - region_size, guest_addr, cursor, region_size, prev_is_nullpage);

                        num_adjacent_regions = 1;
                    }
                }
                prev_is_nullpage = is_nullpage;
            }
            uint64_t region_size = num_adjacent_regions * PAGE_SIZE;
            uint64_t guest_addr = regions[i].begin + cursor - region_size;
            add_staterestore_region(result, contents + cursor - region_size, guest_addr, cursor, region_size, prev_is_nullpage);
            free(contents);

            // Make region non-writeable so we can detect changes in the on-demand page restore hook
            uint32_t new_perms = permissions & (~UC_PROT_WRITE);
            #ifdef DEBUG_STATE_RESTORE
            printf("Setting new perms %x (prev: %x) for 0x%lx, size: 0x%lx\n", new_perms, permissions, regions[i].begin, size);
            #endif
            if(uc_mem_protect(uc, regions[i].begin, size, new_perms) == UC_ERR_ARG) {
                puts("ERROR: uc_mem_protect failed"); fflush(stdout);
                exit(1);
            }
        }
    }

    // Setup on-demand memory restore ranges
    result->num_restore_content_regions = 0;
    result->num_restore_nullregions = 0;

    // Register mem protect handler for on-demand registration
    if(uc_hook_add(uc, &result->on_demand_pages_handle, UC_HOOK_MEM_WRITE_PROT, hook_invalid_write_on_demand_page_restore_handle, result, 1, 0) != UC_ERR_OK) {
        puts("[ERROR] Could not add on-demand page restore hook"); fflush(stdout);
        exit(-1);
    }

    return result;
}

void native_hooks_restore_snapshot(uc_engine *uc, void *snapshot) {
    struct NativeHooksState *snapshot_state = (struct NativeHooksState *) snapshot;

    uc_context_restore(uc, snapshot_state->uc_saved_context);
    native_hooks_state.curr_exit_at_hit_num = snapshot_state->curr_exit_at_hit_num;

    // memory restore
    for(int i=0; i < snapshot_state->num_restore_content_regions; ++i) {
        #ifdef DEBUG_STATE_RESTORE
        printf("[] restoring 0x%lx bytes to 0x%lx\n", snapshot_state->restore_content_sizes[i], snapshot_state->restore_content_guest_addrs[i]);
        #endif
        uc_mem_write(uc, snapshot_state->restore_content_guest_addrs[i], snapshot_state->restore_contents_ptrs[i], snapshot_state->restore_content_sizes[i]);
    }

    // nullpages
    for(int i=0; i < snapshot_state->num_restore_nullregions; ++i) {
        #ifdef DEBUG_STATE_RESTORE
        printf("[] memsetting 0x%lx bytes at 0x%lx\n", snapshot_state->restore_nullregion_starts[i], snapshot_state->restore_nullregion_sizes[i]);
        #endif
        uc_mem_set(uc, snapshot_state->restore_nullregion_starts[i], 0, snapshot_state->restore_nullregion_sizes[i]);
    }
}

void native_hooks_discard_snapshot(uc_engine *uc, void *snapshot) {
    struct NativeHooksState *snapshot_state = (struct NativeHooksState *) snapshot;
    uc_free(snapshot_state->uc_saved_context);

    for(int i=0; i < snapshot_state->num_content_regions; ++i) {
        free(snapshot_state->contents_ptrs[i]);
    }

    uc_hook_del(uc, snapshot_state->on_demand_pages_handle);

    uc_free(snapshot_state->orig_regions);

    free(snapshot);
}

void init_uc_state_snapshotting(uc_engine *uc) {
    subscribe_state_snapshotting(uc, native_hooks_take_snapshot, native_hooks_restore_snapshot, native_hooks_discard_snapshot);
}
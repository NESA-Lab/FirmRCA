/* Low level unicorn hooks for fuzzing */

/* Porting Considerations
- Memory handlers currently assume shared endianness between host and emulated target (uc_mem_write)
- ARM thumb instruction set
- System peripherals written for Cortex-M3
*/

#include "native_hooks.h"
#include "util.h"
#include "timer.h"
#include "core_peripherals/cortexm_nvic.h"
#include "interrupt_triggers.h"
#include "state_snapshotting.h"
#include "uc_snapshot.h"

#include <unicorn/unicorn.h>

#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <sys/time.h>
#include <signal.h>
#include <errno.h>
#include <sys/shm.h>
#include <sys/wait.h>

// 0. Constants
// ~10 MB of preallocated fuzzing buffer size
#define PREALLOCED_FUZZ_BUF_SIZE 10000000
#define MMIO_HOOK_PC_ALL_ACCESS_SITES (0xffffffffuL)
#define DEFAULT_MAX_EXIT_HOOKS 32
#define MMIO_START_UNINIT (0xffffffffffffffffLL)
#define MAX_MMIO_CALLBACKS 4096
#define MAX_IGNORED_ADDRESSES 4096
#define FREAD_NMAX_CHUNKS 5

// AFL-related constants
// 65k bitmap size
#define MAP_SIZE_POW2       16
#define MAP_SIZE            (1 << MAP_SIZE_POW2)
#define FORKSRV_FD          198
#define SHM_ENV_VAR         "__AFL_SHM_ID"
// AFL++ compatibility constants
#define SHM_FUZZ_ENV_VAR "__AFL_SHM_FUZZ_ID"
#define FS_OPT_SHDMEM_FUZZ 0x01000000
#define FS_OPT_ENABLED 0x80000001

#define CPUID_ADDR 0xE000ED00
const int CPUID_CORTEX_M4=0x410fc240;
const int CPUID_CORTEX_M3=0x410fc230;

uc_err mem_errors[] = {
    UC_ERR_READ_UNMAPPED,
    UC_ERR_READ_PROT,
    UC_ERR_READ_UNALIGNED,
    UC_ERR_WRITE_UNMAPPED,
    UC_ERR_WRITE_PROT,
    UC_ERR_WRITE_UNALIGNED,
    UC_ERR_FETCH_UNMAPPED,
    UC_ERR_FETCH_PROT,
    UC_ERR_FETCH_UNALIGNED,
};

// 1. Static (after initialization) configs
int do_print_exit_info = 0;

uc_hook invalid_mem_hook_handle = 0;
uc_hook hook_block_cond_py_handlers_handle;
uc_cb_hookcode_t py_hle_handler_hook = (uc_cb_hookcode_t)0;
int num_handlers = 0;
uint64_t *bb_handler_locs = 0;
uint32_t fuzz_consumption_timer_id;
uint64_t fuzz_consumption_timeout;
uint32_t instr_limit_timer_id;
void *py_default_mmio_user_data = NULL;
uint32_t num_mmio_regions = 0;
uint64_t *mmio_region_starts = 0;
uint64_t *mmio_region_ends = 0;
int num_mmio_callbacks = 0;
struct mmio_callback *mmio_callbacks[MAX_MMIO_CALLBACKS];
char *input_path = NULL;
uint32_t num_ignored_addresses = 0;
uint64_t ignored_addresses[MAX_IGNORED_ADDRESSES];
uint32_t ignored_address_pcs[MAX_IGNORED_ADDRESSES];
uint32_t exit_at_hit_limit = 1;

uint32_t do_fuzz = 0;

uint64_t instr_limit = 0;

// 2. Transient variables (not required to be included in state restore)
// Housekeeping information for tracing MMIO accesses
unsigned long latest_mmio_fuzz_access_index = 0;
unsigned long latest_mmio_fuzz_access_size = 0;
uint32_t num_exit_hooks = 0;
exit_hook_t exit_hooks[DEFAULT_MAX_EXIT_HOOKS] = {NULL};

uint32_t is_discovery_child = 0;
static int pipe_to_parent[2] = {-1};

uint8_t *fuzz = NULL;
bool input_mode_SHM = false;
long fuzz_size = 0;
long fuzz_cursor = 0;

// 3. Dynamic State (required for state restore)
uint32_t input_already_given = 0;
int duplicate_exit = false;
uc_err custom_exit_reason = UC_ERR_OK;

// Fuzzer coverage bitmap
uint8_t coverage_bitmap[MAP_SIZE];

static void determine_input_mode() {
    char *id_str;
    int shm_id;
    int tmp;

    id_str = getenv(SHM_FUZZ_ENV_VAR);
    if (id_str) {
        shm_id = atoi(id_str);
        fuzz = shmat(shm_id, NULL, 0);
        if (!fuzz || fuzz == (void *)-1) {
            perror("[!] could not access fuzzing shared memory");
            exit(1);
        }

        // AFL++ detected. Read its status value
        if(read(FORKSRV_FD, &tmp, 4) != 4) {
            perror("[!] did not receive AFL++ status value");
            exit(1);
        }

        input_mode_SHM = true;
    }
}


void do_exit(uc_engine *uc, uc_err err) {
    if(do_print_exit_info) {
        fflush(stdout);
    }

    if(!duplicate_exit) {
        custom_exit_reason = err;
        duplicate_exit = true;
        uc_emu_stop(uc);
    }
}

void hook_block_debug(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    uint32_t lr;
    uc_reg_read(uc, UC_ARM_REG_LR, &lr);

    printf("Basic Block: addr= 0x%016lx (lr=0x%x)\n", address, lr);
    fflush(stdout);
}

void hook_debug_mem_access(uc_engine *uc, uc_mem_type type,
        uint64_t address, int size, int64_t value, void *user_data) {
    uint32_t pc, sp;
    uc_reg_read(uc, UC_ARM_REG_SP, &sp);
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);

    int64_t sp_offset = sp - address;
    if(sp_offset > -0x1000 && sp_offset < 0x2000) {
        if(type == UC_MEM_WRITE) {
            printf("        >>> Write: addr= 0x%08lx[SP:%c%04lx] size=%d data=0x%08lx (pc 0x%08x)\n", address, sp_offset >= 0 ? '+' : '-', sp_offset >= 0 ? sp_offset : -sp_offset, size, value, pc);
        } else {
            uint32_t read_value = 0;
            uc_mem_read(uc, address, &read_value, size);
            printf("        >>> Read: addr= 0x%08lx[SP:%c%04lx] size=%d data=0x%08x (pc 0x%08x)\n", address, sp_offset >= 0 ? '+' : '-', sp_offset >= 0 ? sp_offset : -sp_offset, size, read_value, pc);
        }
    } else {
        if(type == UC_MEM_WRITE) {
            printf("        >>> Write: addr= 0x%016lx size=%d data=0x%08lx (pc 0x%08x)\n", address, size, value, pc);
        } else {
            uint32_t read_value = 0;
            uc_mem_read(uc, address, &read_value, size);
            printf("        >>> Read: addr= 0x%016lx size=%d data=0x%08x (pc 0x%08x)\n", address, size, read_value, pc);
        }
    }
    fflush(stdout);
}

uc_err add_debug_hooks(uc_engine *uc) {
    uc_hook tmp;
    uc_err res = UC_ERR_OK;
    // Register unconditional hook for checking for handler presence
    res |= uc_hook_add(uc, &tmp, UC_HOOK_BLOCK_UNCONDITIONAL, hook_block_debug, NULL, 1, 0);
    res |= uc_hook_add(uc, &tmp, UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ, hook_debug_mem_access, 0, 1, 0);
    return res;
}

bool hook_debug_mem_invalid_access(uc_engine *uc, uc_mem_type type,
        uint64_t address, int size, int64_t value, void *user_data) {
    uint64_t pc = 0;
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    if(type == UC_MEM_WRITE_UNMAPPED || type == UC_MEM_WRITE_PROT) {
        printf("        >>> [ 0x%08lx ] INVALID Write: addr= 0x%016lx size=%d data=0x%016lx\n", pc, address, size, value);
    } else if (type == UC_MEM_READ_UNMAPPED || type == UC_MEM_READ_PROT){
        printf("        >>> [ 0x%08lx ] INVALID READ: addr= 0x%016lx size=%d data=0x%016lx\n", pc, address, size, value);
    } else if (type == UC_MEM_FETCH_UNMAPPED || type == UC_MEM_FETCH_PROT) {
        printf("        >>> [ 0x%08lx ] INVALID FETCH: addr= 0x%016lx\n", pc, address);
    }
    fflush(stdout);
    return false;
}

int uc_err_to_sig(uc_err error) {
    for (uint32_t i = 0; i < sizeof(mem_errors) / sizeof(*mem_errors); ++i) {
        if(error == mem_errors[i]) {
            return SIGSEGV;
        }
    }
    if(error == UC_ERR_INSN_INVALID) {
        return SIGILL;
    } else {
        return SIGABRT;
    }
}

void force_crash(uc_engine *uc, uc_err error)
{
    do_exit(uc, error);
}

void hook_block_exit_at(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    if(++native_hooks_state.curr_exit_at_hit_num == exit_at_hit_limit) {
        if(do_print_exit_info) {
            printf("Hit exit basic block address: %08lx, times: %d\n", address, native_hooks_state.curr_exit_at_hit_num); fflush(stdout);
        }
        do_exit(uc, UC_ERR_OK);
    }
}

void load_delayed_input(uc_engine *uc) {
    // Having spun up the fork server, we can now load the input file
    if(load_fuzz(input_path) != 0) {
        _exit(-1);
    }

    input_already_given = 1;
}

bool get_fuzz(uc_engine *uc, uint8_t *buf, uint32_t size) {
    /*
     * Consuming input is more complex here than one might expect.
     * The reason for this is that we support a prefix input as well
     * as detecting the number of basic blocks that we can execute
     * before consuming fuzzing input.
     *
     * a) The ordinary case is having input, consuming it, and progressing
     * the cursor as one would expect.
     * b) The second case makes the discovery child report the number of
     * translation blocks to run as part of the execution prefix as soon
     * as new fuzzing input would have to be consumed.
     * c) Once after a snapshot, we want to load the fuzzing input. We
     * do this in a delayed manner to support pre-loaded prefix inputs
     * (which are consumed as part of the execution prefix).
     * d) In case we have already loaded the dynamic input once, we
     * finally ran out of input to provide and conclude the run.
     */
    #ifdef DEBUG
    printf("[NATIVE FUZZ] Requiring %d fuzz bytes\n", size); fflush(stdout);
    #endif

    // Deal with copying over the (remaining) fuzzing bytes
    if(size && fuzz_cursor+size <= fuzz_size) {
        #ifdef DEBUG
        printf("[NATIVE FUZZ] Returning %d fuzz bytes\n", size); fflush(stdout);
        #endif
        memcpy(buf, &fuzz[fuzz_cursor], size);
        fuzz_cursor += size;

        // We are consuming fuzzing input, reset watchdog
        reload_timer(fuzz_consumption_timer_id);

        return 0;
    } else if(unlikely(is_discovery_child)) {
        // We are the discovery child, report the current tick count
        uint64_t ticks_so_far = get_global_ticker();
        if(write(pipe_to_parent[1], &ticks_so_far, sizeof(ticks_so_far)) != sizeof(ticks_so_far)) {
           puts("[Discovery Child] Error: could not write number of ticks to parent"); fflush(stdout);
        }
        _exit(0);
    } else if (!input_already_given) {
        // Load file-based input now
        load_delayed_input(uc);

        return get_fuzz(uc, buf, size);
    } else {
        if(do_print_exit_info) {
            puts("\n>>> Ran out of fuzz\n");
        }

        do_exit(uc, UC_ERR_OK);
        return 1;
    }
}

uint32_t fuzz_consumed() {
    return fuzz_cursor;
}

uint8_t *get_fuzz_ptr(uc_engine *uc, uint32_t size) {
    #ifdef DEBUG
    printf("[NATIVE FUZZ] Requiring %d fuzz bytes\n", size); fflush(stdout);
    #endif

    // Deal with handing out pointer to fuzzing bytes
    if(size && fuzz_cursor+size <= fuzz_size) {
        #ifdef DEBUG
        printf("[NATIVE FUZZ] Returning %d fuzz bytes\n", size); fflush(stdout);
        #endif
        uint8_t *res = &fuzz[fuzz_cursor];
        fuzz_cursor += size;

        // We are consuming fuzzing input, reset watchdog
        reload_timer(fuzz_consumption_timer_id);

        return res;
    } else if(unlikely(is_discovery_child)) {
        // We are the discovery child, report the current tick count
        uint64_t ticks_so_far = get_global_ticker();
        if(write(pipe_to_parent[1], &ticks_so_far, sizeof(ticks_so_far)) != sizeof(ticks_so_far)) {
           puts("[Discovery Child] Error: could not write number of ticks to parent"); fflush(stdout);
        }
        _exit(0);
    } else if (!input_already_given) {
        // Load file-based input now
        load_delayed_input(uc);

        return get_fuzz_ptr(uc, size);
    } else {
        if(do_print_exit_info) {
            puts("\n>>> Ran out of fuzz\n"); fflush(stdout);
        }

        do_exit(uc, UC_ERR_OK);
        return NULL;
    }
}

uint32_t get_latest_mmio_fuzz_access_index() {
    return latest_mmio_fuzz_access_index;
}

uint32_t get_latest_mmio_fuzz_access_size() {
    return latest_mmio_fuzz_access_size;
}

uint32_t fuzz_remaining() {
    return fuzz_size - fuzz_cursor;
}

void hook_mmio_access(uc_engine *uc, uc_mem_type type,
                      uint64_t addr, int size, int64_t value, void *user_data)
{
    uint32_t pc = 0;
    latest_mmio_fuzz_access_index = fuzz_cursor;

    uc_reg_read(uc, UC_ARM_REG_PC, &pc);

    // TODO: optimize this lookup
    for (int i = 0; i < num_ignored_addresses; ++i)
    {
        if(addr == ignored_addresses[i] && (ignored_address_pcs[i] == MMIO_HOOK_PC_ALL_ACCESS_SITES || ignored_address_pcs[i] == pc)) {
            #ifdef DEBUG
            printf("Hit passthrough address 0x%08lx - pc: 0x%08x - returning\n", addr, pc); fflush(stdout);
            #endif
            goto out;
        }
    }

    for (int i = 0; i < num_mmio_callbacks; ++i)
    {
        if (addr >= mmio_callbacks[i]->start && addr <= mmio_callbacks[i]->end &&
                (mmio_callbacks[i]->pc == MMIO_HOOK_PC_ALL_ACCESS_SITES || mmio_callbacks[i]->pc == pc))
        {
            if(mmio_callbacks[i]->user_data != NULL) {
                user_data = mmio_callbacks[i]->user_data;
            }

            mmio_callbacks[i]->callback(uc, type, addr, size, value, user_data);
            goto out;
        }
    }

    #ifdef DEBUG
    printf("Serving %d byte(s) fuzz for mmio access to 0x%08lx, pc: 0x%08x, rem bytes: %ld\n", size, addr, pc, fuzz_size-fuzz_cursor); fflush(stdout);
    #endif

    uint64_t val = 0;
    if(get_fuzz(uc, (uint8_t *)&val, size)) {
        return;
    }
    #ifdef DEBUG
    printf(", value: 0x%lx\n", val); fflush(stdout);
    #endif
    uc_mem_write(uc, addr, (uint8_t *)&val, size);

    out:

    latest_mmio_fuzz_access_size = fuzz_cursor - latest_mmio_fuzz_access_index;
    return;
}

void add_exit_hook(exit_hook_t hook) {
    if(num_exit_hooks == DEFAULT_MAX_EXIT_HOOKS) {
        perror("ERROR. add_exit_hook: Out of exit hook slots\n");
        exit(-1);
    }
    exit_hooks[num_exit_hooks++] = hook;
}

uc_err add_mmio_region(uc_engine *uc, uint64_t begin, uint64_t end) {
    if(!py_default_mmio_user_data) {
        perror("ERROR. add_mmio_region: py_default_mmio_user_data is NULL (did you not register handler first?)\n");
        return UC_ERR_EXCEPTION;
    }

    uc_hook tmp;
    printf("add_mmio_region called! hooking 0x%08lx - 0x%08lx\n", begin, end);
    return uc_hook_add(uc, &tmp, UC_HOOK_MEM_READ, hook_mmio_access, py_default_mmio_user_data, begin, end);
}

void hook_block_cond_py_handlers(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    uint64_t next_val;

    // Search for address in value list and invoke python handler if found
    for (int i = 0; i < num_handlers; ++i) {
        next_val = bb_handler_locs[i];
        if (next_val > address) {
            break;
        } else if(next_val == address) {
            py_hle_handler_hook(uc, address, size, user_data);
        }
    }
}

uc_err register_cond_py_handler_hook(uc_engine *uc, uc_cb_hookcode_t py_mmio_callback, uint64_t *addrs, int num_addrs, void *user_data) {
    py_hle_handler_hook = py_mmio_callback;
    num_handlers = num_addrs;

    bb_handler_locs = malloc(num_addrs * sizeof(uint64_t));
    if(!bb_handler_locs) {
        perror("allocating handler location struct failed\n");
        return -1;
    }

    memcpy(bb_handler_locs, addrs, num_addrs * sizeof(uint64_t));

    // shouldn't be many entries, just sort ascending this way
    for (int i = 0; i < num_addrs; i++)
	{
		for (int j = 0; j < num_addrs; j++)
		{
			if (bb_handler_locs[j] > bb_handler_locs[i])
			{
				uint64_t tmp = bb_handler_locs[i];
			    bb_handler_locs[i] = bb_handler_locs[j];
				bb_handler_locs[j] = tmp;
			}
		}
	}

    // Register unconditional hook for checking for handler presence
    return uc_hook_add(uc, &hook_block_cond_py_handlers_handle, UC_HOOK_BLOCK_UNCONDITIONAL, hook_block_cond_py_handlers, user_data, 1, 0);
}

uc_err remove_function_handler_hook_address(uc_engine *uc, uint64_t address) {
    for (int i = 0; i < num_handlers ; i++)	{
		if (bb_handler_locs[i] == address) {
            // Found the handler location, now move everything else to the front
            for(int j = i; j < num_handlers-1; ++j) {
                bb_handler_locs[j] = bb_handler_locs[j+1];
            }

            --num_handlers;
            // Now fully remove the (unconditional) hook if we can
            if(!num_handlers) {
                uc_hook_del(uc, hook_block_cond_py_handlers_handle);
            }
            return UC_ERR_OK;
        }
    }

    perror("[NATIVE ERROR] remove_function_handler_hook_address: could not find address to be removed\n");
    exit(-1);
}

uc_err register_py_handled_mmio_ranges(uc_engine *uc, uc_cb_hookmem_t py_mmio_callback, uint64_t *starts, uint64_t *ends, int num_ranges) {
    uint64_t start, end;

    if(py_default_mmio_user_data == NULL) {
        perror("ERROR. register_py_handled_mmio_ranges: python user data pointer not set up (did you forget to call init before?)\n");
        return UC_ERR_EXCEPTION;
    }

    for (int i = 0; i < num_ranges; ++i) {
        start = starts[i];
        end = ends[i];
        if(add_mmio_subregion_handler(uc, py_mmio_callback, start, end, MMIO_HOOK_PC_ALL_ACCESS_SITES, py_default_mmio_user_data) != UC_ERR_OK) {
            return UC_ERR_EXCEPTION;
        }
    }

    return UC_ERR_OK;
}

void linear_mmio_model_handler(uc_engine *uc, uc_mem_type type, uint64_t addr, int size, int64_t value, void *user_data) {
    struct linear_mmio_model_config *model_state = (struct linear_mmio_model_config *) user_data;

    model_state->val += model_state->step;

    #ifdef DEBUG
    uint32_t pc;
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    printf("[0x%08x] Native Linear MMIO handler: [0x%08lx] = [0x%x]\n", pc, addr, model_state->val); fflush(stdout);
    #endif

    uc_mem_write(uc, addr, &model_state->val, sizeof(model_state->val));
}

void constant_mmio_model_handler(uc_engine *uc, uc_mem_type type, uint64_t addr, int size, int64_t value, void *user_data) {
    struct constant_mmio_model_config *model_state = (struct constant_mmio_model_config *) user_data;
    uint64_t val = model_state->val;

    #ifdef DEBUG
    uint32_t pc;
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    printf("[0x%08x] Native Constant MMIO handler: [0x%08lx] = [0x%lx]\n", pc, addr, val); fflush(stdout);
    #endif

    // TODO: This assumes shared endianness between host and target
    uc_mem_write(uc, addr, &val, size);
}

void bitextract_mmio_model_handler(uc_engine *uc, uc_mem_type type, uint64_t addr, int size, int64_t value, void *user_data)
{
    struct bitextract_mmio_model_config *config = (struct bitextract_mmio_model_config *) user_data;
    uint64_t result_val = 0;
    uint64_t fuzzer_val = 0;

    // TODO: this currently assumes little endianness on both sides to be correct
    if(get_fuzz(uc, (uint8_t *)(&fuzzer_val), config->byte_size)) {
        return;
    }

    result_val = fuzzer_val << config->left_shift;
    uc_mem_write(uc, addr, &result_val, size);

    #ifdef DEBUG
    uint32_t pc;
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    printf("[0x%08x] Native Bitextract MMIO handler: [0x%08lx] = [0x%lx] from %d byte input: %lx\n", pc, addr, result_val, config->byte_size, fuzzer_val); fflush(stdout);
    #endif
}

void value_set_mmio_model_handler(uc_engine *uc, uc_mem_type type, uint64_t addr, int size, int64_t value, void *user_data) {
    struct value_set_mmio_model_config *config = (struct value_set_mmio_model_config *) user_data;

    uint64_t result_val;
    uint8_t fuzzer_val = 0;
    #ifdef DEBUG
    uint32_t pc;
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    #endif

    if(config->num_vals > 1) {
        if(get_fuzz(uc, (uint8_t *)&fuzzer_val, 1)) {
            return;
        }

        result_val = config->values[fuzzer_val % config->num_vals];
    } else {
        result_val = config->values[0];
    }

    #ifdef DEBUG
    printf("[0x%08x] Native Set MMIO handler: [0x%08lx] = [0x%lx] from input: %x [values: ", pc, addr, result_val, fuzzer_val);
    for (uint32_t i = 0; i < config->num_vals; ++i) {
        if(i) {
            printf(", ");
        }
        printf("%x", config->values[i]);
    }
    printf("]\n");
    fflush(stdout);
    #endif

    uc_mem_write(uc, addr, (uint8_t *)&result_val, size);
}

uc_err register_constant_mmio_models(uc_engine *uc, uint64_t *starts, uint64_t *ends, uint32_t *pcs, uint32_t *vals, int num_ranges) {
    struct constant_mmio_model_config *model_configs = calloc(num_ranges, sizeof(struct constant_mmio_model_config));

    for (int i = 0; i < num_ranges; ++i) {
        #ifdef DEBUG
        printf("Registering constant model for range: [%x] %lx - %lx with val: %x\n", pcs[i], starts[i], ends[i], vals[i]); fflush(stdout);
        #endif

        model_configs[i].val = vals[i];

        if(add_mmio_subregion_handler(uc, constant_mmio_model_handler, starts[i], ends[i], pcs[i], &model_configs[i]) != UC_ERR_OK) {
            return UC_ERR_EXCEPTION;
        }

    }

    return UC_ERR_OK;
}

uc_err register_linear_mmio_models(uc_engine *uc, uint64_t *starts, uint64_t *ends, uint32_t *pcs, uint32_t *init_vals, uint32_t *steps, int num_ranges) {
    // TODO: support cleanup, currently we just allocate, hand out pointers and forget about them
    struct linear_mmio_model_config *model_configs = calloc(num_ranges, sizeof(struct linear_mmio_model_config));

    for (int i = 0; i < num_ranges; ++i) {
        #ifdef DEBUG
        printf("Registering linear model for range: [%x] %lx - %lx with step: %x\n", pcs[i], starts[i], ends[i], steps[i]); fflush(stdout);
        #endif
        model_configs[i].val = init_vals[i];
        model_configs[i].step = steps[i];

        if(add_mmio_subregion_handler(uc, linear_mmio_model_handler, starts[i], ends[i], pcs[i], &model_configs[i]) != UC_ERR_OK) {
            return UC_ERR_EXCEPTION;
        }
    }

    return UC_ERR_OK;
}

uc_err register_bitextract_mmio_models(uc_engine *uc, uint64_t *starts, uint64_t *ends, uint32_t *pcs, uint8_t *byte_sizes, uint8_t *left_shifts, uint32_t *masks, int num_ranges) {
    struct bitextract_mmio_model_config *model_configs = calloc(num_ranges, sizeof(struct bitextract_mmio_model_config));

    for (int i = 0; i < num_ranges; ++i) {
        model_configs[i].mask = masks[i];
        model_configs[i].byte_size = byte_sizes[i];
        model_configs[i].left_shift = left_shifts[i];
        model_configs[i].mask_hamming_weight = 0;

        uint32_t mask = masks[i];
        while(mask) {
            if(mask & 1) {
                ++model_configs[i].mask_hamming_weight;
            }
            mask >>= 1;
        }

        #ifdef DEBUG
        printf("Registering bitextract model for range: [%x] %lx - %lx with size, left_shift: %d, %d. Mask: %08x, hw: %d\n", pcs[i], starts[i], ends[i], byte_sizes[i], left_shifts[i], masks[i], model_configs[i].mask_hamming_weight); fflush(stdout);
        #endif

        if(add_mmio_subregion_handler(uc, bitextract_mmio_model_handler, starts[i], ends[i], pcs[i], &model_configs[i]) != UC_ERR_OK) {
            return UC_ERR_EXCEPTION;
        }
    }

    return UC_ERR_OK;
}

uc_err register_value_set_mmio_models(uc_engine *uc, uint64_t *starts, uint64_t *ends, uint32_t *pcs, uint32_t *value_nums, uint32_t **value_lists, int num_ranges) {
    struct value_set_mmio_model_config *model_configs = calloc(num_ranges, sizeof(struct value_set_mmio_model_config));

    printf("Registering incoming Value Set models\n");

    for (int i = 0; i < num_ranges; ++i) {
        #ifdef DEBUG
        uint32_t pc;
        uc_reg_read(uc, UC_ARM_REG_PC, &pc);
        printf("Registering value set model: [%x] %lx - %lx with numvalues, value_set: %d, [", pcs[i], starts[i], ends[i], value_nums[i]);
        for (uint32_t j = 0; j < value_nums[i]; ++j) {
            if(j) {
                printf(", ");
            }
            printf("%x", value_lists[i][j]);
        }
        printf("]\n");
        fflush(stdout);
        #endif

        model_configs[i].num_vals = value_nums[i];
        model_configs[i].values = calloc(value_nums[i], sizeof(**value_lists));
        for (int j = 0; j < value_nums[i]; ++j) {
            model_configs[i].values[j] = value_lists[i][j];
        }

        if(add_mmio_subregion_handler(uc, value_set_mmio_model_handler, starts[i], ends[i], pcs[i], &model_configs[i]) != UC_ERR_OK) {
            return UC_ERR_EXCEPTION;
        }
    }

    return UC_ERR_OK;
}

uc_err set_ignored_mmio_addresses(uint64_t *addresses, uint32_t *pcs, int num_addresses) {
    assert(sizeof(*addresses) == sizeof(*ignored_addresses));
    assert(sizeof(*pcs) == sizeof(*ignored_address_pcs));

    if(num_addresses <= MAX_IGNORED_ADDRESSES) {
        #ifdef DEBUG
        for(int i = 0; i < num_addresses; ++i) {
            printf("Registering passthrough address: [%x] %lx\n", pcs[i], addresses[i]);
        }
        #endif
        memcpy(ignored_addresses, addresses, num_addresses * sizeof(*ignored_addresses));
        memcpy(ignored_address_pcs, pcs, num_addresses * sizeof(*ignored_address_pcs));
        num_ignored_addresses = num_addresses;
        return UC_ERR_OK;
    } else {
        printf("Too many ignored addresses to be registered");
        return UC_ERR_EXCEPTION;
    }
}

uc_err load_fuzz(const char *path) {
    FILE *fp;
    long leftover_size;

    if(input_mode_SHM) {
        // shm inputs: <size_u32> contents ...
        fuzz_size = (*(uint32_t *)fuzz) + sizeof(uint32_t);
        fuzz_cursor = sizeof(uint32_t);
        return 0;
    }

    leftover_size = fuzz_size - fuzz_cursor;

    if(leftover_size != 0) {
        perror("Got prefix input which is not fully consumed. Exiting...\n");
        exit(-1);
    }

    if(!(fp=fopen(path, "r"))) {
        perror("Opening file failed\n");
        return -1;
    }

    if(fseek(fp, 0L, SEEK_END)) {
        perror("fseek failed\n");
        return -1;
    }

    if((fuzz_size = ftell(fp)) < 0) {
        perror("ftell failed\n");
        return -1;
    }
    rewind(fp);

    #ifdef DEBUG
    printf("leftover_size = %ld, fuzz_size = %ld (path: %s)\n", leftover_size, fuzz_size, path);
    #endif

    if (fuzz_size > PREALLOCED_FUZZ_BUF_SIZE) {
        // As we may need to copy over leftover contents, keep ref

        if (!(fuzz = calloc(fuzz_size, 1)))
        {
            perror("Allocating fuzz buffer failed\n");
            return -1;
        }

        #ifdef DEBUG
        printf("Allocated new oversized fuzz buffer of size 0x%lx\n", fuzz_size);
        #endif
    }

    fuzz_cursor = 0;

    // Give reading the input multiple chunk tries
    size_t num_chunks, already_read = 0, last_read, to_be_read=fuzz_size;
    for(num_chunks=0; to_be_read && num_chunks<FREAD_NMAX_CHUNKS; ++num_chunks) {
        last_read = fread(&fuzz[already_read], 1, to_be_read, fp);
        to_be_read -= last_read;
        already_read += last_read;
    }
    fclose(fp);

    if(to_be_read) {
        perror("fread failed\n");
        return -1;
    }

    return 0;
}

static void *init_bitmap(uc_engine *uc) {
    // Use local backup bitmap to run without AFL
    void *bitmap = &coverage_bitmap[0];

    // Indicate to possible afl++ that we can use SHM fuzzing
    uint32_t tmp = FS_OPT_ENABLED | FS_OPT_SHDMEM_FUZZ;
    char *id_str;
    int shm_id;

    /* Tell AFL once that we are here  */
    id_str = getenv(SHM_ENV_VAR);
    if (id_str) {
        shm_id = atoi(id_str);
        bitmap = shmat(shm_id, NULL, 0);

        if (bitmap == (void *)-1) {
            // We allow this case so we can use the emulator in a forkserver-aware trace gen worker
            puts("[FORKSERVER SETUP] Could not map SHM, reverting to local buffer");
            bitmap = &coverage_bitmap[0];
        }

        if(write(FORKSRV_FD + 1, &tmp, 4) == 4) {
            do_fuzz = 1;
        } else {
            puts("[FORKSERVER SETUP] Got shared memory region, but no pipe. going for single input");
            do_fuzz = 0;
        }
    } else {
        puts("[FORKSERVER SETUP] It looks like we are not running under AFL, going for single input");
        do_fuzz = 0;
    }

    uc_fuzzer_init_cov(uc, bitmap, MAP_SIZE);

    return bitmap;
}

static inline int run_single(uc_engine *uc) {
    int status;
    uint64_t pc = 0;
    int sig = -1;

    uc_reg_read(uc, UC_ARM_REG_PC, &pc);

    status = uc_emu_start(uc, pc | 1, 0, 0, 0);

    if(custom_exit_reason != UC_ERR_OK) {
        status = custom_exit_reason;
    }

    if (status != UC_ERR_OK) {
        if(do_print_exit_info) {
            printf("Execution failed with error code: %d -> %s\n", status, uc_strerror(status));
            print_state(uc);
        }
        sig = uc_err_to_sig(status);
    }

    for (uint32_t i = 0; i < num_exit_hooks; ++i) {
        exit_hooks[i](status, sig);
    }

    return sig == -1 ? status : sig;
}

uc_err add_mmio_subregion_handler(uc_engine *uc, uc_cb_hookmem_t callback, uint64_t start, uint64_t end, uint32_t pc, void *user_data) {
    if(num_mmio_callbacks >= MAX_MMIO_CALLBACKS) {
        printf("ERROR add_mmio_subregion_handler: Maximum number of mmio callbacks exceeded\n");
        return -1;
    }

    if(!num_mmio_regions) {
        printf("ERROR add_mmio_subregion_handler: mmio start and end addresses not configured, yet\n");
        return UC_ERR_EXCEPTION;
    }

    int custom_region = 1;
    for (int i = 0; i < num_mmio_regions; ++i)
    {
        if (! (start < mmio_region_starts[i] || end > mmio_region_ends[i]))
        {
            custom_region = 0;
        }
    }

    if(custom_region) {
        printf("Attaching native listener to custom mmio subregion 0x%08lx-0x%08lx", start, end);
        add_mmio_region(uc, start, end);
    }

    struct mmio_callback *cb = calloc(1, sizeof(struct mmio_callback));
    cb->callback = callback;
    cb->start = start;
    cb->user_data = user_data;
    cb->end = end;
    cb->pc = pc;

    mmio_callbacks[num_mmio_callbacks++] = cb;

    return UC_ERR_OK;
}

void fuzz_consumption_timeout_cb(uc_engine *uc, uint32_t id, void *user_data) {
    if(do_print_exit_info) {
        printf("Fuzzing input not consumed for %ld basic blocks, exiting\n", fuzz_consumption_timeout);
    }
    do_exit(uc, UC_ERR_OK);
}

#ifdef DEBUG_INJECT_TIMER
void test_timeout_cb(uc_engine *uc, uint32_t id, void *user_data) {
    if(!is_discovery_child) {
        uint32_t pc;
        uc_reg_read(uc, UC_ARM_REG_PC, &pc);
        printf("Test timer triggered at pc 0x%08x\n", pc);
        fflush(NULL);
    }
}
#endif

void instr_limit_timeout_cb(uc_engine *uc, uint32_t id, void *user_data) {
    if(do_print_exit_info) {
        uint32_t pc;
        uc_reg_read(uc, UC_ARM_REG_PC, &pc);
        printf("Ran into instruction limit of %lu at 0x%08x - exiting\n", get_timer_reload_val(instr_limit_timer_id), pc);
    }
    do_exit(uc, UC_ERR_OK);
}

void *mmio_models_take_snapshot(uc_engine *uc) {
    size_t size = num_ignored_addresses * sizeof(uint32_t);
    uint32_t *passthrough_init_vals = malloc(size);

    for(int i = 0; i < num_ignored_addresses; ++i) {
        uc_mem_read(uc, ignored_addresses[i], &passthrough_init_vals[i], sizeof(*passthrough_init_vals));
    }

    return passthrough_init_vals;
}

void mmio_models_restore_snapshot(uc_engine *uc, void *snapshot) {
    uint32_t *passthrough_init_vals = (uint32_t *) snapshot;

    // Restore the initial passthrough MMIO values
    for(int i = 0; i < num_ignored_addresses; ++i) {
        uc_mem_write(uc, ignored_addresses[i], &passthrough_init_vals[i], sizeof(*passthrough_init_vals));
    }
}

void mmio_models_discard_snapshot(uc_engine *uc, void *snapshot) {
    free(snapshot);
}

uc_err init(uc_engine *uc, exit_hook_t p_exit_hook, int p_num_mmio_regions, uint64_t *p_mmio_starts, uint64_t *p_mmio_ends, void *p_py_default_mmio_user_data, uint32_t num_exit_at_bbls, uint64_t *exit_at_bbls, uint32_t p_exit_at_hit_limit, int p_do_print_exit_info, uint64_t p_fuzz_consumption_timeout, uint64_t p_instr_limit) {
    // TODO: assumes shared endianness
    uc_mem_write(uc, CPUID_ADDR, &CPUID_CORTEX_M4, sizeof(CPUID_CORTEX_M4));

    if(p_exit_hook) {
        add_exit_hook(p_exit_hook);
    }

    exit_at_hit_limit = p_exit_at_hit_limit;
    do_print_exit_info = p_do_print_exit_info;

    if(do_print_exit_info) {
        uc_hook_add(uc, &invalid_mem_hook_handle, UC_HOOK_MEM_WRITE_INVALID | UC_HOOK_MEM_READ_INVALID | UC_HOOK_MEM_FETCH_INVALID, hook_debug_mem_invalid_access, 0, 1, 0);
    }

    // Add fuzz consumption timeout as timer
    fuzz_consumption_timeout = p_fuzz_consumption_timeout;
    fuzz_consumption_timer_id = add_timer(fuzz_consumption_timeout, fuzz_consumption_timeout_cb, NULL, TIMER_IRQ_NOT_USED);
    if(fuzz_consumption_timeout) {
        start_timer(uc, fuzz_consumption_timer_id);
    }

    #ifdef DEBUG_INJECT_TIMER
    // debug timer to debug precise timing consistencies
    start_timer(uc,add_timer(DEBUG_TIMER_TIMEOUT, test_timeout_cb, NULL, TIMER_IRQ_NOT_USED));
    #endif

    instr_limit = p_instr_limit;
    instr_limit_timer_id = add_timer(instr_limit, instr_limit_timeout_cb, NULL, TIMER_IRQ_NOT_USED);
    if(instr_limit) {
        start_timer(uc, instr_limit_timer_id);
    }

    py_default_mmio_user_data = p_py_default_mmio_user_data;

    for (uint32_t i = 0; i < num_exit_at_bbls; ++i)
    {
        uint64_t tmp;
        uint64_t bbl_addr = exit_at_bbls[i] & (~1LL);
        if (uc_hook_add(uc, &tmp, UC_HOOK_BLOCK, hook_block_exit_at, 0, bbl_addr, bbl_addr) != UC_ERR_OK)
        {
            perror("Could not register exit-at block hook...\n");
            return -1;
        }
    }

    if(!(fuzz = calloc(PREALLOCED_FUZZ_BUF_SIZE, 1))) {
        perror("Allocating fuzz buffer failed\n");
        return -1;
    }

    // Register read hooks for mmio regions
    num_mmio_regions = p_num_mmio_regions;
    mmio_region_starts = calloc(num_mmio_regions, sizeof(*p_mmio_starts));
    mmio_region_ends = calloc(num_mmio_regions, sizeof(*p_mmio_ends));
    memcpy(mmio_region_starts, p_mmio_starts, num_mmio_regions * sizeof(*p_mmio_starts));
    memcpy(mmio_region_ends, p_mmio_ends, num_mmio_regions * sizeof(*p_mmio_ends));

    for (int i = 0; i < num_mmio_regions; ++i) {
        if(add_mmio_region(uc, mmio_region_starts[i], mmio_region_ends[i]) != UC_ERR_OK) {
            perror("[native init] could not register mmio region.\n");
            return UC_ERR_EXCEPTION;
        }
    }

    // Snapshotting
    init_interrupt_triggering(uc);

    init_uc_state_snapshotting(uc);

    subscribe_state_snapshotting(uc, mmio_models_take_snapshot, mmio_models_restore_snapshot, mmio_models_discard_snapshot);

    return UC_ERR_OK;
}

static void restore_snapshot(uc_engine *uc) {
    // Restore all subscribed snapshot parts
    trigger_restore(uc);

    // Also reset fuzzing input cursor and exit detection
    fuzz_cursor = fuzz_size;
    input_already_given = 0;
    duplicate_exit = false;
    custom_exit_reason = UC_ERR_OK;
}

uc_err emulate(uc_engine *uc, char *p_input_path, char *prefix_input_path) {
    uint64_t pc = 0;
    fflush(stdout);

    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    init_bitmap(uc);

    /*
     * Pre-execute deterministic part of target execution (the execution prefix)
     * Anything before consuming dynamic fuzzing input for the first time is deterministic.
     * This includes a potential prefix input which we will also consume during this stage
     * to effectively restore a snapshot (which the prefix input leads us to).
     */

    // Set input path for the fuzz reading handler to pick up on later
    input_path = p_input_path;
    // Pre-load prefix input
    if(prefix_input_path) {
        if(load_fuzz(prefix_input_path) != 0) {
            _exit(-1);
        }
    }

    /*
     * This part of executing the execution prefix is a bit tricky:
     * We cannot simply run up to the first MMIO access, as this will leave our
     * execution context in the middle of an MMIO access, which would leave unicorn
     * in a state which we cannot snapshot.
     * So instead, we fork and discover how much execution we have ahead of us before
     * running into the first fuzzing input-consuming MMIO access. We report this number
     * from the forked child to the parent via a pipe.
     */
    pid_t child_pid;
    uint64_t required_ticks = -1;
    if(pipe(pipe_to_parent)) {
        puts("[ERROR] Could not create pipe for discovery forking");
        exit(-1);
    }

    // For every run (and to keep consistency between single and fuzzing runs), find out how many basic blocks we can execute before hitting the first MMIO read
    child_pid = fork();
    if(child_pid) {
        // parent: wait for the discovery child to report back the number of tbs we need to execute
        if(read(pipe_to_parent[0], &required_ticks, sizeof(required_ticks)) != sizeof(required_ticks)) {
            puts("[ERROR] Could not retrieve the number of required ticks during discovery forking");
            exit(-1);
        }
        waitpid(child_pid, &child_pid, 0);

        close(pipe_to_parent[0]);
        close(pipe_to_parent[1]);

        printf("[DISCOVERY FORK PARENT] Got number of ticks to step: %ld\n", required_ticks);

        if(required_ticks > 2) {
            // Set up a timer that will make use stop after executing the prefix
            set_timer_reload_val(instr_limit_timer_id, required_ticks-2);

            // Execute the prefix
            if(uc_emu_start(uc, pc | 1, 0, 0, 0)) {
                puts("[ERROR] Could not execute the first some steps");
                exit(-1);
            }
        }
        puts("[+] Initial constant execution (including optional prefix input) done, starting input execution."); fflush(stdout);
    } else {
        // child: Run until we hit an input consumption
        is_discovery_child = 1;
        uc_err child_emu_status = uc_emu_start(uc, pc | 1, 0, 0, 0);

        // We do not expect to get here. The child should exit by itself in get_fuzz
        printf("[ERROR] Emulation stopped using just the prefix input (%d: %s)\n", child_emu_status, uc_strerror(child_emu_status));

        // Write wrong amount of data to notify parent of failure
        if(write(pipe_to_parent[1], emulate, 1) != 1) {
            puts("[Discovery Child] Error: Could not notify parent of failure..."); fflush(stdout);
        }
        _exit(-1);
    }

    // After consuming first part of input and executing the prefix, set input mode
    determine_input_mode();
    // Set the proper instruction limit (after using a fake one to execute exec prefix)
    set_timer_reload_val(instr_limit_timer_id, instr_limit);

    // Upon exiting emulation, Unicorn will trigger basic block hits.
    // This ticks off timers two times. This is an issue because this
    // makes timings slightly differ when splitting an input to an input prefix
    // and the remaining input file. Adjust for this offset here.
    // TODO: adjusting the timer has to be done when it is caused.
    // TODO: This seems to be the case when unicorn is stopped, but need to re-visit
    // adjust_timers_for_unicorn_exit();

    if(do_fuzz) {
        uc_fuzzer_reset_cov(uc, 1);
        uc_reg_read(uc, UC_ARM_REG_PC, &pc);
        trigger_snapshotting(uc);

        // AFL-compatible Forkserver loop
        child_pid = getpid();
        int count = 0;
        int tmp = 0;
        int sig;
        input_already_given = 0;
        duplicate_exit = false;
        for(;;) {
            ++count;

            /* Wait until we are allowed to run  */
            if(read(FORKSRV_FD, &tmp, 4) != 4) {
                if(count == 1) {
                    puts("[FORKSERVER MAIN LOOP] ERROR: Read from FORKSRV_FD to start new execution failed. Exiting");
                    exit(-1);
                } else {
                    puts("[FORKSERVER MAIN LOOP] Forkserver pipe now closed. Exiting");
                    exit(0);
                }
            }

            uc_fuzzer_reset_cov(uc, 0);

            /* Send AFL the child pid thus it can kill it on timeout   */
            if(write(FORKSRV_FD + 1, &child_pid, 4) != 4) {
                printf("[FORKSERVER MAIN LOOP] ERROR: Write to FORKSRV_FD+1 to send fake child PID failed. errno: %d. Description: '%s'. Count: %d\n", errno, strerror(errno), count); fflush(stdout);
                exit(-1);
            }

            sig = run_single(uc);

            if(write(FORKSRV_FD + 1, &sig, 4) != 4) {
                puts("[MAIN LOOP] Write to FORKSRV_FD+1 to send status failed");
                _exit(-1);
            }

            restore_snapshot(uc);
        }
    } else {
        puts("Running without a fork server");
        duplicate_exit = false;

        // Not running under fork server
        int sig = run_single(uc);

        if(do_print_exit_info) {
            if(sig) {
                // Crash occurred
                printf("Emulation crashed with signal %d\n", sig);
            } else {
                // Non-crashing exit (includes different timeouts)
                uint32_t pc;
                uc_reg_read(uc, UC_ARM_REG_PC, &pc);
                printf("Exited without crash at 0x%08x - If no other reason, we ran into one of the limits\n", pc);
            }
        }
    }

    return UC_ERR_OK;
}
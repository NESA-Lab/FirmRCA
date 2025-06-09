input_file_name = None
uc = None
regions = {}

# Make sure those match with what is specified in the native code
MMIO_HOOK_PC_ALL_ACCESS_SITES = 0xffffffff
MMIO_HOOK_MMIO_ALL_ADDRS = 0xffffffff
EXIT_AT_NONE = 0xffffffff

DEFAULT_NUM_NVIC_VECS = 256
NVIC_VTOR_NONE = 0xffffffff
NVIC_EXCEPT_MAGIC_RET_MASK = 0xfffffff0

SYSTICK_RELOAD_VAL_NONE = 0

DEFAULT_BASIC_BLOCK_LIMIT = 3000000        # 3kk
DEFAULT_MAX_INTERRUPTS = 3000              # 3k
DEFAULT_FUZZ_CONSUMPTION_TIMEOUT = 150000  # 150k
DEFAULT_TRACE_EVENT_LIMIT = 0              # No Limit
DEFAULT_MAX_NUM_DYN_ALLOC_MMIO_PAGES = 0

PAGE_SIZE = 0x1000

"""
#define IRQ_FUZZ_MODE_FIXED 0
#define IRQ_FUZZ_MODE_FUZZ_ENABLED_IRQ_INDEX 1
#define IRQ_FUZZ_MODE_ROUND_ROBIN 2
"""
FUZZ_MODES = ('fixed', 'fuzzed', 'round_robin')
TRIGGER_MODES = ('addr', 'every_nth_tick', 'fuzzed')

import ctypes
import os
import sys
import logging


from . import timer
from .exit import has_exit_hooks, invoke_exit_callbacks
from .globs import (DEFAULT_BASIC_BLOCK_LIMIT,
                    DEFAULT_FUZZ_CONSUMPTION_TIMEOUT, DEFAULT_MAX_INTERRUPTS,
                    FUZZ_MODES, TRIGGER_MODES)
from .mmio_models.wrapper import mmio_access_handler_wrapper_hook

logger = logging.getLogger("emulator")

""" native.py
Wrapper around the native library API functions.
"""

native_lib = None
mmio_cb_wrapper = None
timer_cb_wrapper = None
timer_cb_user_data = None

# just like unicorn does we need to keep references to ctype cb objects
obj_refs = []

uc_engine = ctypes.c_void_p
# Prototyping code taken from unicorn python bindings
def _load_lib(path):
    try:
        lib_file = os.path.join(path)
        dll = ctypes.cdll.LoadLibrary(lib_file)
        return dll
    except OSError as e:
        logger.error(f'FAILED to load {lib_file} {e}')
        return None

# setup all the function prototype
def _setup_prototype(lib, fname, restype, *argtypes):
    getattr(lib, fname).restype = restype
    getattr(lib, fname).argtypes = argtypes

EXIT_CB = ctypes.CFUNCTYPE(
    None, ctypes.c_int, ctypes.c_int
)

UC_HOOK_CODE_CB = ctypes.CFUNCTYPE(
    None, uc_engine, ctypes.c_uint64, ctypes.c_size_t, ctypes.c_void_p
)

UC_HOOK_MEM_ACCESS_CB = ctypes.CFUNCTYPE(
    None, uc_engine, ctypes.c_int,
    ctypes.c_uint64, ctypes.c_int, ctypes.c_int64, ctypes.c_void_p
)

UC_HOOK_INTR_CB = ctypes.CFUNCTYPE(
    None, uc_engine, ctypes.c_uint32, ctypes.c_void_p
)

mmio_user_data = None
def add_mmio_region(uc, start, end):
    global mmio_user_data
    if mmio_user_data is None:
        mmio_user_data = ctypes.cast(uc._callback_count, ctypes.c_void_p)
    assert native_lib.add_mmio_region(uc._uch, start, end, mmio_user_data)==0

def load_fuzz(file_path):
    assert native_lib.load_fuzz(file_path.encode())==0
    sys.stdout.flush()

def emulate(uc, fuzz_file_path, prefix_input_file_path=None):
    # uc_err emulate(uc_engine *uc, char *input_path, uint64_t instr_limit, char *prefix_input_path);

    if prefix_input_file_path:
        prefix_input_file_path = prefix_input_file_path.encode()
    else:
        # In case input path is an empty string, set it to None explicitly
        prefix_input_file_path = None

    native_lib.emulate(uc._uch, fuzz_file_path.encode(), prefix_input_file_path)

def get_fuzz(uc, size):
    ptr = (ctypes.c_char * size).from_address(native_lib.get_fuzz_ptr(uc, size))
    return ptr.raw

def fuzz_consumed():
    return native_lib.fuzz_consumed()

def fuzz_remaining():
    return native_lib.fuzz_remaining()

def get_latest_mmio_fuzz_access_size():
    return native_lib.get_latest_mmio_fuzz_access_size()

def get_latest_mmio_fuzz_access_index():
    return native_lib.get_latest_mmio_fuzz_access_index()

def register_cond_py_handler_hook(uc, handler_locs):
    if not handler_locs:
        logger.warning("no function handler hooks registered, skipping registration")
        return

    arr = (ctypes.c_int64 * len(handler_locs))(*handler_locs)

    # hack: In order to keep a uc reference around for the high level callback,
    # we sneak an additional callback into the uc object (as done in unicorn.py)
    from .user_hooks import func_hook_handler
    callback = func_hook_handler
    uc._callback_count += 1
    uc._callbacks[uc._callback_count] = (callback, None)
    cb = ctypes.cast(UC_HOOK_CODE_CB(uc._hookcode_cb), UC_HOOK_CODE_CB)
    user_data = ctypes.cast(uc._callback_count, ctypes.c_void_p)

    assert native_lib.register_cond_py_handler_hook(
        uc._uch, cb, arr, len(arr), user_data
    ) == 0
    obj_refs.append(cb)


def remove_function_handler_hook_address(uc, address):
    assert native_lib.remove_function_handler_hook_address(uc._uch, address) == 0


def _create_and_inject_c_callable_mem_hook(uc, py_fn):
    # hack: In order to keep a uc reference around for the high level callback,
    # we sneak an additional callback into the uc object (as done in unicorn.py)
    callback = py_fn
    uc._callback_count += 1
    uc._callbacks[uc._callback_count] = (callback, None)
    cb = ctypes.cast(UC_HOOK_MEM_ACCESS_CB(uc._hook_mem_access_cb), UC_HOOK_MEM_ACCESS_CB)
    user_data = ctypes.cast(uc._callback_count, ctypes.c_void_p)
    obj_refs.append(cb)
    return cb, user_data


def _create_and_inject_c_callable_central_timer_hook(uc, py_fn):
    callback = py_fn
    # hack: In order to keep a uc reference around for the high level callback,
    # we sneak an additional callback into the uc object (as done in unicorn.py)
    # even bigger hack: we re-use the prototype of interrupt callbacks for the fact of their function prototype
    # to create an alternative callback
    # from: cb(self, intno, data)
    # to  : cb(self, timer_id, data)
    uc._callback_count += 1
    uc._callbacks[uc._callback_count] = (callback, None)
    cb = ctypes.cast(UC_HOOK_INTR_CB(uc._hook_intr_cb), UC_HOOK_INTR_CB)
    user_data = ctypes.cast(uc._callback_count, ctypes.c_void_p)
    obj_refs.append(cb)
    return cb, user_data


def register_py_handled_mmio_ranges(uc, python_handled_range_starts, python_handled_range_ends):
    global mmio_cb_wrapper

    assert mmio_cb_wrapper is not None
    assert len(python_handled_range_starts) == len(python_handled_range_ends)

    starts_arr = (ctypes.c_int64 * len(python_handled_range_starts))(*python_handled_range_starts)
    ends_arr = (ctypes.c_int64 * len(python_handled_range_ends))(*python_handled_range_ends)

    assert native_lib.register_py_handled_mmio_ranges(uc._uch, mmio_cb_wrapper, starts_arr, ends_arr, len(python_handled_range_ends)) == 0

def register_linear_mmio_models(uc, starts, ends, pcs, init_vals, steps):
    assert len(starts) == len(ends) == len(init_vals) == len(steps)
    starts_arr = (ctypes.c_int64 * len(starts))(*starts)
    ends_arr = (ctypes.c_int64 * len(ends))(*ends)
    init_vals_arr = (ctypes.c_int32 * len(init_vals))(*init_vals)
    steps_arr = (ctypes.c_int32 * len(steps))(*steps)
    pcs_arr = (ctypes.c_int32 * len(pcs))(*pcs)

    assert native_lib.register_linear_mmio_models(uc._uch, starts_arr, ends_arr, pcs_arr, init_vals_arr, steps_arr, len(starts)) == 0

def register_constant_mmio_models(uc, starts, ends, pcs, vals):
    assert len(starts) == len(ends) == len(vals)==len(pcs)
    starts_arr = (ctypes.c_int64 * len(starts))(*starts)
    ends_arr = (ctypes.c_int64 * len(ends))(*ends)
    vals_arr = (ctypes.c_int32 * len(vals))(*vals)
    pcs_arr = (ctypes.c_int32 * len(pcs))(*pcs)

    assert native_lib.register_constant_mmio_models(uc._uch, starts_arr, ends_arr, pcs_arr, vals_arr, len(starts)) == 0

def register_bitextract_mmio_models(uc, starts, ends, pcs, byte_sizes, left_shifts, masks):
    assert len(starts) == len(ends) == len(byte_sizes) == len(left_shifts) == len(pcs)
    starts_arr = (ctypes.c_int64 * len(starts))(*starts)
    ends_arr = (ctypes.c_int64 * len(ends))(*ends)
    byte_sizes_arr = (ctypes.c_int8 * len(byte_sizes))(*byte_sizes)
    left_shifts_arr = (ctypes.c_int8 * len(left_shifts))(*left_shifts)
    masks_arr = (ctypes.c_int32 * len(masks))(*masks)
    pcs_arr = (ctypes.c_int32 * len(pcs))(*pcs)

    assert native_lib.register_bitextract_mmio_models(uc._uch, starts_arr, ends_arr, pcs_arr, byte_sizes_arr, left_shifts_arr, masks_arr, len(starts)) == 0

def register_value_set_mmio_models(uc, starts, ends, pcs, value_sets):
    assert len(starts) == len(ends) == len(value_sets) == len(value_sets) == len(pcs)
    starts_arr = (ctypes.c_int64 * len(starts))(*starts)
    ends_arr = (ctypes.c_int64 * len(ends))(*ends)
    pcs_arr = (ctypes.c_int32 * len(pcs))(*pcs)

    value_nums_arr = (ctypes.c_int32 * len(value_sets))(*[len(value_set) for value_set in value_sets])

    value_set_arrs = [(ctypes.c_int32 * len(value_set))(*value_set) for value_set in value_sets]
    value_sets_arr_ptrs = (ctypes.POINTER(ctypes.c_ulong) * len(value_set_arrs))(*[ctypes.cast(value_set_arr, ctypes.POINTER(ctypes.c_ulong)) for value_set_arr in value_set_arrs])

    assert native_lib.register_value_set_mmio_models(uc._uch, starts_arr, ends_arr, pcs_arr, value_nums_arr, value_sets_arr_ptrs, len(starts)) == 0

def set_ignored_mmio_addresses(addresses, pcs):
    addrs_arr = (ctypes.c_int64 * len(addresses))(*addresses)
    pcs_arr = (ctypes.c_uint32 * len(pcs))(*pcs)

    assert native_lib.set_ignored_mmio_addresses(
        addrs_arr, pcs_arr, len(addrs_arr)
    ) == 0

def init_nvic(uc, vtor, num_vecs, interrupt_limit=DEFAULT_MAX_INTERRUPTS, disabled_interrupts=()):
    global native_lib
    logger.debug("Calling init_nvic with vtor=0x{:08x}, num_vecs: {}".format(vtor, num_vecs))
    disabled_interrupts_arr = (ctypes.c_int32 * len(disabled_interrupts))(*disabled_interrupts)
    assert native_lib.init_nvic(uc._uch, vtor, num_vecs, interrupt_limit, len(disabled_interrupts), disabled_interrupts_arr) == 0

def init_native_tracing(uc, bbl_set_trace_path, bbl_hash_path, mmio_set_trace_path, mmio_ranges):
    global native_lib
    mmio_region_starts, mmio_region_ends = zip(*mmio_ranges)
    mmio_region_starts_arr = (ctypes.c_uint64 * len(mmio_region_starts))(*mmio_region_starts)
    mmio_region_ends_arr = (ctypes.c_uint64 * len(mmio_region_ends))(*mmio_region_ends)

    if not bbl_set_trace_path:
        bbl_set_trace_path = None
    else:
        bbl_set_trace_path = bbl_set_trace_path.encode()

    if not mmio_set_trace_path:
        mmio_set_trace_path = None
    else:
        mmio_set_trace_path = mmio_set_trace_path.encode()

    if not bbl_hash_path:
        bbl_hash_path = None
    else:
        bbl_hash_path = bbl_hash_path.encode()

    assert(native_lib.init_tracing(uc._uch, bbl_set_trace_path, bbl_hash_path, mmio_set_trace_path, len(mmio_ranges), mmio_region_starts_arr, mmio_region_ends_arr) == 0)

def nvic_set_pending(vec_num):
    global native_lib
    native_lib.nvic_set_pending(vec_num)

def init_timer_hook(uc, global_timer_scale):
    global native_lib
    global timer_cb_user_data
    global timer_cb_wrapper

    cb, user_data = _create_and_inject_c_callable_central_timer_hook(uc, timer.central_timer_hook)
    timer_cb_wrapper = cb
    timer_cb_user_data = user_data

    assert native_lib.init_timer_hook(uc._uch, global_timer_scale) == 0

def init_systick(uc, reload_val):
    global native_lib

    assert native_lib.init_systick(uc._uch, reload_val) == 0

IRQ_NOT_USED=0xffffffff
def add_timer(reload_val, callback=None, isr_num=IRQ_NOT_USED):
    global timer_cb_wrapper
    global timer_cb_user_data
    global native_lib

    assert timer_cb_wrapper is not None and timer_cb_user_data is not None
    # While technically allowed in the C code, invoking a callback and pending an interrupt at the same time is nothing we would like to support
    assert not (callback is not None and isr_num != IRQ_NOT_USED)

    passed_cb = timer_cb_wrapper if callback is not None else 0

    return native_lib.add_timer(reload_val, passed_cb, timer_cb_user_data, isr_num)


def is_running(timer_id):
    return native_lib.is_running(timer_id)


def get_global_ticker():
    global native_lib
    return native_lib.get_global_ticker()

def rem_timer(uc, timer_id):
    global native_lib
    assert native_lib.rem_timer(uc, timer_id) == 0

def reload_timer(timer_id):
    global native_lib
    assert native_lib.reload_timer(timer_id) == 0

def start_timer(uc, timer_id):
    global native_lib
    assert native_lib.start_timer(uc, timer_id) == 0

def stop_timer(uc, timer_id):
    global native_lib
    assert native_lib.stop_timer(uc, timer_id) == 0

# uc_hook add_interrupt_trigger(uc_engine *uc, uint64_t addr, uint32_t irq, uint32_t num_skips, uint32_t num_pends, uint32_t do_fuzz);
def add_interrupt_trigger(uc, addr, irq, num_skips, num_pends, fuzz_mode, trigger_mode, every_nth_tick):
    assert fuzz_mode < len(FUZZ_MODES) and trigger_mode < len(TRIGGER_MODES)
    assert native_lib.add_interrupt_trigger(uc._uch, addr, irq, num_skips, num_pends, fuzz_mode, trigger_mode, every_nth_tick) == 0

def register_native_debug_hooks(uc):
    assert(native_lib.add_debug_hooks(uc._uch) == 0)

def load_native_lib(native_lib_path):
    global native_lib

    native_lib = _load_lib(native_lib_path)

    assert  native_lib is not None

def do_exit(uc, status, sig=-1):
    global native_lib
    native_lib.do_exit(uc, status, sig)

def init(uc, mmio_regions, exit_at_bbls, exit_at_hit_num, do_print_exit_info, fuzz_consumption_timeout=DEFAULT_FUZZ_CONSUMPTION_TIMEOUT, instr_limit=DEFAULT_BASIC_BLOCK_LIMIT):
    global native_lib
    global mmio_cb_wrapper

    # GENERAL
    # uc_err init(                                     uc_engine *uc, exit_hook_t p_exit_hook, int p_num_mmio_regions, uint64_t *p_mmio_starts, uint64_t *p_mmio_ends, void *p_py_default_mmio_user_data, uint32_t num_exit_at_bbls, uint64_t *exit_at_bbls, uint32_t exit_at_hit_num, int p_do_print_exit_info, uint64_t fuzz_consumption_timeout, uint64_t p_instr_limit);
    _setup_prototype(native_lib, "init", ctypes.c_int, uc_engine,     ctypes.c_void_p,         ctypes.c_int,           ctypes.c_void_p,         ctypes.c_void_p,       ctypes.c_void_p,                   ctypes.c_uint,             ctypes.c_void_p,        ctypes.c_uint,            ctypes.c_uint,            ctypes.c_uint64,                   ctypes.c_uint64)
    # uc_err register_cond_py_handler_hook(uc_cb_hookcode_t py_callback, uint64_t *addrs, int num_addrs)
    _setup_prototype(native_lib, "register_cond_py_handler_hook", ctypes.c_int, uc_engine, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int)
    # uc_err remove_function_handler_hook_address(uc_engine * uc, uint64_t address);
    _setup_prototype(native_lib, "remove_function_handler_hook_address", ctypes.c_int, uc_engine, ctypes.c_uint64)
    # void do_exit(uc_engine *uc, int status, int sig);
    _setup_prototype(native_lib, "do_exit", ctypes.c_int, uc_engine, ctypes.c_int, ctypes.c_int)

    # FUZZING
    _setup_prototype(native_lib, "load_fuzz", ctypes.c_int, ctypes.c_char_p)
    # uint32_t fuzz_remaining();
    _setup_prototype(native_lib, "fuzz_remaining", ctypes.c_int)
    # uint64_t num_consumed_fuzz();
    _setup_prototype(native_lib, "fuzz_consumed", ctypes.c_uint32)

    # uint32_t get_latest_mmio_fuzz_access_size();
    _setup_prototype(native_lib, "get_latest_mmio_fuzz_access_size", ctypes.c_uint32)

    # uint32_t get_latest_mmio_fuzz_access_index();
    _setup_prototype(native_lib, "get_latest_mmio_fuzz_access_index", ctypes.c_uint32)

    # char *get_fuzz_ptr(uc_engine *uc, uint32_t size);
    _setup_prototype(native_lib, "get_fuzz_ptr", ctypes.c_void_p, uc_engine, ctypes.c_uint32)

    # uc_err add_mmio_region(uc_engine *uc, uint64_t begin, uint64_t end)
    _setup_prototype(native_lib, "add_mmio_region", ctypes.c_int, uc_engine, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p)
    # extern uc_err register_py_handled_mmio_ranges(uc_engine *uc, uc_cb_hookmem_t py_callback, uint64_t *starts, uint64_t *ends, int num_ranges);
    _setup_prototype(native_lib, "register_py_handled_mmio_ranges", ctypes.c_int, uc_engine, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int)
    # extern uc_err set_ignored_mmio_addresses(uint64_t *addresses, uint32_t *pcs, int num_addresses);
    _setup_prototype(native_lib, "set_ignored_mmio_addresses", ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int)
    # extern uc_err register_linear_mmio_models(uc_engine *uc, uint64_t *starts, uint64_t *ends, uint32_t *pcs, uint32_t *init_vals, uint32_t *steps, int num_ranges);
    _setup_prototype(native_lib, "register_linear_mmio_models", ctypes.c_int, uc_engine, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int)
    # extern uc_err register_constant_mmio_models(uc_engine *uc, uint64_t *starts, uint64_t *ends, uint32_t *pcs, uint32_t *vals, int num_ranges)
    _setup_prototype(native_lib, "register_constant_mmio_models", ctypes.c_int, uc_engine, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int)
    # extern uc_err register_bitextract_mmio_models(uc_engine *uc, uint64_t *starts, uint64_t *ends, uint32_t *pcs, uint8_t *byte_sizes, uint8_t *left_shifts, uint32_t * masks, int num_ranges);
    _setup_prototype(native_lib, "register_bitextract_mmio_models", ctypes.c_int, uc_engine, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int)
    # extern uc_err register_value_set_mmio_models(uc_engine *uc, uint64_t *starts, uint64_t *ends, uint32_t *pcs, uint32_t *value_nums, uint32_t **value_lists, int num_ranges);
    _setup_prototype(native_lib, "register_value_set_mmio_models", ctypes.c_int, uc_engine, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int)

    # NVIC
    # extern uc_err init_nvic(uc_engine *uc, uint32_t vtor, uint32_t num_irq, uint32_t interrupt_limit, uint32_t num_disabled_interrupts, uint32_t *disabled_interrupts);
    _setup_prototype(native_lib, "init_nvic", ctypes.c_int, uc_engine, ctypes.c_uint, ctypes.c_uint, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p)
    # extern void nvic_set_pending(int num)
    _setup_prototype(native_lib, "nvic_set_pending", ctypes.c_int, ctypes.c_int)

    # TRACING
    # uc_err init_tracing(uc_engine *uc, char *bbl_set_trace_path, char *mmio_set_trace_path, size_t num_mmio_ranges, uint64_t *mmio_starts, uint64_t *mmio_ends);
    _setup_prototype(native_lib, "init_tracing", ctypes.c_int, uc_engine, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p)

    # DEBUG
    # uc_err add_debug_hooks(uc_engine *uc)
    _setup_prototype(native_lib, "add_debug_hooks", ctypes.c_int, uc_engine)

    # TIMER
    # extern uint64_t get_global_ticker();
    _setup_prototype(native_lib, 'get_global_ticker', ctypes.c_int64)
    # extern uc_err init_timer_hook(uc_engine *uc, uint32_t global_timer_scale);
    _setup_prototype(native_lib, "init_timer_hook", ctypes.c_int, uc_engine, ctypes.c_uint)
    # extern uint32_t add_timer(int64_t reload_val, void *trigger_callback, uint32_t isr_num);
    _setup_prototype(native_lib, "add_timer", ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32)
    # extern uc_err rem_timer(uc_engine *uc, uint32_t id);
    _setup_prototype(native_lib, "rem_timer", ctypes.c_int, uc_engine, ctypes.c_uint32)
    # extern uc_err reload_timer(uint32_t id);
    _setup_prototype(native_lib, "reload_timer", ctypes.c_int, uc_engine, ctypes.c_uint32)
    # extern uc_err start_timer(uc_engine *uc, uint32_t id);
    _setup_prototype(native_lib, "start_timer", ctypes.c_int, uc_engine, ctypes.c_uint32)
    # extern uc_err stop_timer(uc_engine *uc, uint32_t id);
    _setup_prototype(native_lib, "stop_timer", ctypes.c_int, uc_engine, ctypes.c_uint32)

    # SYSTICK
    # extern uc_err init_systick(uc_engine *uc, uint32_t reload_val);
    _setup_prototype(native_lib, "init_systick", ctypes.c_int, uc_engine, ctypes.c_uint32)

    # INTERRUPT TRIGGERS
    # uc_hook add_interrupt_trigger(uc_engine *uc, uint64_t addr, uint32_t irq, uint32_t num_skips, uint32_t num_pends, uint32_t fuzz_mode, uint32_t trigger_mode, uint64_t every_nth_tick);
    _setup_prototype(native_lib, "add_interrupt_trigger", ctypes.c_int, uc_engine, ctypes.c_uint64, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint64)

    # Starting emulation
    # uc_err emulate(uc_engine *uc, char *input_path, char *prefix_input_path);
    _setup_prototype(native_lib, "emulate", ctypes.c_int, uc_engine, ctypes.c_char_p, ctypes.c_char_p)

    mmio_region_starts, mmio_region_ends = zip(*mmio_regions)
    mmio_region_starts_arr = (ctypes.c_int64 * len(mmio_region_starts))(*mmio_region_starts)
    mmio_region_ends_arr = (ctypes.c_int64 * len(mmio_region_ends))(*mmio_region_ends)

    mmio_cb_wrapper, user_data = _create_and_inject_c_callable_mem_hook(uc, mmio_access_handler_wrapper_hook)

    if has_exit_hooks():
        exit_cb = ctypes.cast(EXIT_CB(invoke_exit_callbacks), EXIT_CB)
        obj_refs.append(exit_cb)
    else:
        exit_cb = 0

    num_exit_at_bbls = len(exit_at_bbls)
    exit_at_bbls_arr = (ctypes.c_int64 * len(exit_at_bbls))(*exit_at_bbls)
    assert native_lib.init(uc._uch, exit_cb, len(mmio_regions), mmio_region_starts_arr, mmio_region_ends_arr, user_data, num_exit_at_bbls, exit_at_bbls_arr, exit_at_hit_num, do_print_exit_info, fuzz_consumption_timeout, instr_limit) == 0

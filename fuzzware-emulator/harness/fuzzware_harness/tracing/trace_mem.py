import logging
from unicorn import UC_HOOK_MEM_READ_AFTER, UC_HOOK_MEM_WRITE, UC_MEM_WRITE
from unicorn.arm_const import UC_ARM_REG_LR, UC_ARM_REG_PC

from .. import native
from ..exit import add_exit_hook
from .serialization import (dump_mmio_set_file, dump_mmio_trace_file,
                            dump_ram_line)
from .trace_ids import next_event_id

logger = logging.getLogger("emulator")

mmio_outfile = None
mmio_access_context_set_outfile = None
ram_outfile = None

mmio_events = []
mmio_access_contexts = set()
ram_events = []

def mem_hook_trace_mmio_access(uc, access, address, size, value, user_data):
    mmio_events.append((next_event_id(uc), uc.reg_read(UC_ARM_REG_PC), uc.reg_read(UC_ARM_REG_LR), "w" if access == UC_MEM_WRITE else "r", size, 0 if access == UC_MEM_WRITE else native.get_latest_mmio_fuzz_access_index(), 0 if access == UC_MEM_WRITE else native.get_latest_mmio_fuzz_access_size(), address, value))

def mem_hook_collect_mmio_access_context(uc, access, address, size, value, user_data):
    mmio_access_contexts.add((uc.reg_read(UC_ARM_REG_PC), address, "w" if access == UC_MEM_WRITE else "r"))

def mem_hook_trace_ram_access(uc, access, address, size, value, user_data):
    ram_events.append((next_event_id(uc), uc.reg_read(UC_ARM_REG_PC), uc.reg_read(UC_ARM_REG_LR), "w" if access == UC_MEM_WRITE else "r", size, address, value))

def exit_hook_dump_mmio_access_events(uc):
    dump_mmio_trace_file(mmio_events, mmio_outfile)

def dump_current_mmio_access_events(uc, outfile):
    dump_mmio_trace_file(mmio_events, outfile)

def exit_hook_dump_mmio_access_contexts(uc):
    dump_mmio_set_file(sorted(mmio_access_contexts, key=lambda x: x[0]), mmio_access_context_set_outfile)

def exit_hook_dump_ram_access_events(uc):
    _dump_ram_access_events(uc, ram_outfile, ram_events)

def dump_current_ram_access_events(uc, outfile):
    _dump_ram_access_events(uc, outfile, ram_events)

def _dump_ram_access_events(uc, outfile, events):
    last_mode, last_size, last_address, last_pc, last_lr = None, None, None, None, None
    values = []
    pl = ""
    for event_id, pc, lr, mode, size, address, value in events:
        if last_mode is not None:
            values.append(value)
            if not(address == last_address and mode == last_mode and size == last_size and pc == last_pc and lr == last_lr):
                # We got a new line, dump it
                line = dump_ram_line(event_id, pc, lr, mode, size, address, values)
                pl += line + "\n"
                values = []

        last_mode = mode
        last_size = size
        last_address = address
        last_pc = pc
        last_lr = lr

    with open(outfile, "w") as f:
        f.write(pl)

def register_mmio_access_handler(uc, start, end):
    global mmio_outfile, mmio_access_context_set_outfile

    if mmio_outfile is not None:
        uc.hook_add(UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ_AFTER, mem_hook_trace_mmio_access, None, start, end)

    if mmio_access_context_set_outfile is not None:
        uc.hook_add(UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ_AFTER, mem_hook_collect_mmio_access_context, None, start, end)

def register_ram_access_handler(uc, start, end):
    global ram_outfile

    if ram_outfile is not None:
        uc.hook_add(UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ_AFTER, mem_hook_trace_ram_access, None, start, end)

def init_mmio_tracing(uc, trace_file, set_file, ranges):
    global mmio_outfile, mmio_access_context_set_outfile

    if trace_file is not None:
        mmio_outfile = trace_file
        add_exit_hook(exit_hook_dump_mmio_access_events)

    if set_file is not None:
        mmio_access_context_set_outfile = set_file
        add_exit_hook(exit_hook_dump_mmio_access_contexts)

    for start, end in ranges:
        logger.info("Tracing mmio accesses from 0x{:08x} to 0x{:08x}".format(start, end))
        register_mmio_access_handler(uc, start, end)

#STACK_SIZE=0x1000
STACK_SIZE=0
def init_ram_tracing(uc, trace_file, config):
    global ram_outfile

    if trace_file is not None:
        ram_outfile = trace_file

        # trace everything but mmio
        for region_name in config['memory_map']:
            if 'mmio' in region_name.lower():
                continue

            start = config['memory_map'][region_name]['base_addr']
            end = start + config['memory_map'][region_name]['size']

            logger.info("Tracing ram accesses from 0x{:08x} to 0x{:08x}".format(start, end))
            register_ram_access_handler(uc, start, end)
        add_exit_hook(exit_hook_dump_ram_access_events)

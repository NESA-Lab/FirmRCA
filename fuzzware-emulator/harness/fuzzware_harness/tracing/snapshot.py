import logging
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4,
            UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_R8, UC_ARM_REG_R9,
            UC_ARM_REG_R10, UC_ARM_REG_R11, UC_ARM_REG_R12, UC_ARM_REG_LR, UC_ARM_REG_PC,
            UC_ARM_REG_SP, UC_ARM_REG_XPSR)
from unicorn.unicorn_const import UC_HOOK_MEM_READ, UC_HOOK_MEM_READ_AFTER
from ..exit import add_exit_hook
from .trace_bbs import dump_current_bb_trace

logger = logging.getLogger("emulator")

uc_reg_consts = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4,
            UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_R8, UC_ARM_REG_R9,
            UC_ARM_REG_R10, UC_ARM_REG_R11, UC_ARM_REG_R12, UC_ARM_REG_LR, UC_ARM_REG_PC,
            UC_ARM_REG_SP, UC_ARM_REG_XPSR]

NUM_BB_LINES_FOR_MMIO_ACCESS_STATE_TRACE = 50 * 1000

# HACK: because of qemu's current pc imprecisions we need to use both pre and post memory read hooks to get a good state dump
latest_regs = None

out_filename = None
mmio_states_out_dir = None
mmio_states_name_prefix = ""
def dump_state_exit_hook(uc):
    global out_filename
    regs, content_map = collect_state(uc)
    dump_state(out_filename, regs, content_map)

def collect_regs(uc):
    return {const: uc.reg_read(const) for const in uc_reg_consts}

def collect_state(uc):
    from .. import globs
    # Could do reg_read_batch here if that was exposed in bindings
    """
    r0 = uc.reg_read(UC_ARM_REG_R0)
    r1 = uc.reg_read(UC_ARM_REG_R1)
    r2 = uc.reg_read(UC_ARM_REG_R2)
    r3 = uc.reg_read(UC_ARM_REG_R3)
    r4 = uc.reg_read(UC_ARM_REG_R4)
    r5 = uc.reg_read(UC_ARM_REG_R5)
    r6 = uc.reg_read(UC_ARM_REG_R6)
    r7 = uc.reg_read(UC_ARM_REG_R7)
    r8 = uc.reg_read(UC_ARM_REG_R8)
    r9 = uc.reg_read(UC_ARM_REG_R9)
    r10 = uc.reg_read(UC_ARM_REG_R10)
    r11 = uc.reg_read(UC_ARM_REG_R11)
    r12 = uc.reg_read(UC_ARM_REG_R12)

    lr = uc.reg_read(UC_ARM_REG_LR)
    pc = uc.reg_read(UC_ARM_REG_PC)  # retaddr
    sp = uc.reg_read(UC_ARM_REG_SP)
    xpsr = uc.reg_read(UC_ARM_REG_XPSR)
    """
    regs = collect_regs(uc)

    total_size = 0
    content_chunks = {}
    empty_page = 0x1000 * b'\0'

    from .. import globs
    # collect memory pages that are non-zero
    #for begin, end, perms in uc.mem_regions():
    for name, (begin, size, _) in globs.regions.items():
        if name.lower().startswith("mmio"):
            logger.info("Skipping mmio region '{}': {:x}-{:x}".format(name, begin, begin+size))
            continue

        logger.info("looking at mapped region: 0x{:08x}-0x{:08x}".format(begin, begin+size))
        payload = uc.mem_read(begin, size)

        cursor = 0
        start = -1
        current_pl = b''
        while cursor < size:
            page = payload[cursor:cursor+0x1000]
            if page != empty_page:
                # if no region started, start one now
                if start == -1:
                    start = begin + cursor

                # add current page to region
                current_pl += page
            elif start != -1 or (cursor+0x1000 > size):
                # commit current adjacent region
                content_chunks[start] = current_pl
                total_size += len(current_pl)
                logger.debug("Adding memory region of len 0x{:x} at 0x{:08x}".format(len(current_pl), start))
                start = -1
                current_pl = b''

            cursor += 0x1000

        if current_pl != b'':
            logger.debug("Adding memory region of len 0x{:x} at 0x{:08x}".format(len(current_pl), start))
            content_chunks[start] = current_pl

    logger.debug("Recorded current state of (mem size 0x{:x})".format(total_size))

    return regs, content_chunks

def dump_state(filename, regs, content_chunks):
    from intelhex import IntelHex
    ih = IntelHex()

    for base_addr, contents in content_chunks.items():
        ih.puts(base_addr, contents)

    with open(filename, "w") as f:

        f.write(
"""r0=0x{:x}
r1=0x{:x}
r2=0x{:x}
r3=0x{:x}
r4=0x{:x}
r5=0x{:x}
r6=0x{:x}
r7=0x{:x}
r8=0x{:x}
r9=0x{:x}
r10=0x{:x}
r11=0x{:x}
r12=0x{:x}
lr=0x{:x}
pc=0x{:x}
sp=0x{:x}
xpsr=0x{:x}
""".format(*[regs[const] for const in uc_reg_consts]))
        logger.debug("Writing ihex dump now...")
        ih.write_hex_file(f)

def register_exit_state_dump_hook(state_dump_file):
    global out_filename

    if state_dump_file is not None:
        out_filename = state_dump_file
        add_exit_hook(dump_state_exit_hook)

dump_pc_address_pairs = set()
dump_count = 0
already_dumped_states = set()
def mem_hook_dump_state_after_mmio_read(uc, access, address, size, value, user_data):
    global dump_count
    global mmio_states_out_dir
    global mmio_states_name_prefix
    global latest_regs
    global dump_pc_address_pairs
    pc = uc.reg_read(UC_ARM_REG_PC)

    # Allow user to specify which MMIO states are of interest
    if dump_pc_address_pairs and (pc, address) not in dump_pc_address_pairs:
        return

    old_pc = latest_regs[UC_ARM_REG_PC]
    if pc != old_pc:
        logger.warning("Got unconsistency in mem read hook between 0x{:08x} (before) vs 0x{:08x} (after)".format(old_pc, pc))
        input("continue...?")

    if (pc, address) not in already_dumped_states:
        dump_count += 1
        logger.debug("Dumping state for MMIO access to 0x{:08x} from 0x{:08x}".format(address, pc))
        _, content_map = collect_state(uc)
        latest_regs[UC_ARM_REG_PC] = pc

        from .. import globs

        state_filename = "{}/{}mmio_access_state_pc_{:08x}_addr_{:08x}_{}".format(mmio_states_out_dir, mmio_states_name_prefix, pc, address, globs.input_file_name)
        logger.debug(f"Dumping to {state_filename}")
        dump_state(state_filename, latest_regs, content_map)

        bbtrace_filepath = "{}/{}mmio_access_bbtrace_pc_{:08x}_addr_{:08x}_{}".format(mmio_states_out_dir, mmio_states_name_prefix, pc, address, globs.input_file_name)
        dump_current_bb_trace(uc, bbtrace_filepath, num_latest_entries=NUM_BB_LINES_FOR_MMIO_ACCESS_STATE_TRACE)

        already_dumped_states.add((pc, address))

def mem_hook_record_regs_before_mmio_read(uc, access, address, size, value, user_data):
    global latest_regs
    pc = uc.reg_read(UC_ARM_REG_PC)
    # Allow user to specify which MMIO states are of interest
    if dump_pc_address_pairs and (pc, address) not in dump_pc_address_pairs:
        return

    latest_regs = collect_regs(uc)

def register_mmio_read_state_dump_handler(uc, start, end):
    # before: save state of registers
    uc.hook_add(UC_HOOK_MEM_READ, mem_hook_record_regs_before_mmio_read, None, start, end)
    # after: dump memory
    uc.hook_add(UC_HOOK_MEM_READ_AFTER, mem_hook_dump_state_after_mmio_read, None, start, end)

def init_mmio_read_state_dumping(uc, dump_base_filename, mmio_ranges, mmio_access_pc_address_config, name_prefix):
    global mmio_states_out_dir
    global mmio_states_name_prefix
    mmio_states_out_dir = dump_base_filename
    mmio_states_name_prefix = name_prefix

    if mmio_access_pc_address_config:
        logger.info(f"Parsing mmio access restriction config: {mmio_access_pc_address_config}")
        for token in mmio_access_pc_address_config.split(","):
            if not token:
                continue

            if ":" in token:
                pc_str, addr_str = token.split(":")
                dump_pc_address_pairs.add((int(pc_str, 16), int(addr_str, 16)))
            else:
                logger.warning(f"[MMIO State dumping] skipping malformed mmio access address token: {token}")

    for start, end in mmio_ranges:
        register_mmio_read_state_dump_handler(uc, start, end)

def init_state_snapshotting(uc, dump_filename, dump_mmio_states, mmio_ranges, mmio_access_pc_address_config="", mmio_state_name_prefix=""):
    if dump_mmio_states:
        # We need to dump all states before an MMIO access
        init_mmio_read_state_dumping(uc, dump_filename, mmio_ranges, mmio_access_pc_address_config, mmio_state_name_prefix)
    else:
        # We only want to dump the last state
        # dump_state_file = open(dump_filename, "w")
        register_exit_state_dump_hook(dump_filename)

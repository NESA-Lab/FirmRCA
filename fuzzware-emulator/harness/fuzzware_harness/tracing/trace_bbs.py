import logging
import os


from ..exit import add_exit_hook
from ..user_hooks import add_block_hook
from .serialization import dump_bbl_set_file, dump_bbl_trace_file
from .trace_ids import next_event_id

logger = logging.getLogger("emulator")

outfile = None
outfile_bb_set = None
auto_revisions = False
bb_addrs = []
bb_addr_set = set()
curr_cycle_len = 0
curr_cycle_offset = 0
MAX_CYCLE_LEN = 4
def collect_bb_set_addr(uc, address, size=None, user_data=None):
    bb_addr_set.add((address, ))

def collect_bb_event(uc, address, size=None, user_data=None):
    global curr_cycle_len
    global curr_cycle_offset
    found = False

    if curr_cycle_len != 0 and bb_addrs[-curr_cycle_len + curr_cycle_offset][1] == address:
        bb_addrs[-curr_cycle_len + curr_cycle_offset][2] += 1
        curr_cycle_offset = (curr_cycle_offset + 1) % curr_cycle_len
    else:
        curr_cycle_len = 0

        if bb_addrs:
            if bb_addrs and bb_addrs[-1][1]==address:
                bb_addrs[-1][2] += 1
                return

        if len(bb_addrs) >= 2*MAX_CYCLE_LEN:
            for prefix_len in range(MAX_CYCLE_LEN, 1, -1):
                if found:
                    break
                # Start of cycle fits
                if address == bb_addrs[-prefix_len][1] == bb_addrs[-2*prefix_len][1]:
                    found = True
                    for i in range(1, prefix_len):
                        if bb_addrs[-prefix_len + i][1] != bb_addrs[-2 * prefix_len + i][1]:
                            found = False
                            break

                    # We found a cycle. Tick up the counters and set the current cycle metadata
                    if found:
                        curr_cycle_len = prefix_len
                        curr_cycle_offset = 1
                        bb_addrs[-prefix_len][2] += 1
                        return

        bb_addrs.append([next_event_id(uc), address, 0])

def collect_bb_event_no_cyclic_compression(uc, address, size, user_data):
    if bb_addrs and bb_addrs[-1][1]==address:
        bb_addrs[-1][2] += 1
    else:
        bb_addrs.append([next_event_id(uc), address, 0])

def exit_hook_dump_bb_trace(uc):
    dump_current_bb_trace(uc)

def dump_current_bb_trace(uc, custom_outfile_path=None, num_latest_entries=0):
    global auto_revisions
    global outfile

    if custom_outfile_path is None:
        if auto_revisions:
            ind = 0
            used_outfile_path = outfile

            while os.path.isfile(used_outfile_path):
                used_outfile_path = "{}_{:06d}".format(outfile, ind)
                ind += 1
        else:
            used_outfile_path = outfile
    else:
        used_outfile_path = custom_outfile_path

    if num_latest_entries == 0 or len(bb_addrs) >= num_latest_entries:
        dump_bbl_trace_file(bb_addrs, used_outfile_path)
    else:
        dump_bbl_trace_file(bb_addrs[-num_latest_entries:], used_outfile_path)

    logger.info(f"Dumped bb trace access trace to {used_outfile_path}")

def dump_bb_set(uc):
    global outfile_bb_set, bb_addr_set
    dump_bbl_set_file(sorted(bb_addr_set, key=lambda x: x[0]), outfile_bb_set)

def register_handler(uc, trace_file, set_file, create_dynamic_filenames=False):
    global outfile, outfile_bb_set
    global auto_revisions

    auto_revisions = create_dynamic_filenames

    if trace_file is not None:
        add_block_hook(collect_bb_event)
        outfile = trace_file
        add_exit_hook(exit_hook_dump_bb_trace)

    if set_file is not None:
        add_block_hook(collect_bb_set_addr)
        outfile_bb_set = set_file
        add_exit_hook(dump_bb_set)

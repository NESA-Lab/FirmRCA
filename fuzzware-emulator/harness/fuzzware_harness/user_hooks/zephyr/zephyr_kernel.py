from unicorn import UcError


def dump_timeout(uc, timeout):
    cnt = 0
    print(f"Timeout @0x{timeout:08x}")
    curr_timeout = timeout # uc.mem.u32(timeout)
    while cnt < 10 and curr_timeout != 0 and (cnt == 0 or curr_timeout != timeout):
        try:
            next_timeout = uc.mem.u32(curr_timeout)
            prev_timeout = uc.mem.u32(curr_timeout+4)
        except UcError as e:
            print(f"\t <error fetching next: {e}")
            break

        print(f"\t0x{prev_timeout:08x} <- @0x{curr_timeout:08x} -> 0x{next_timeout:08x}")
        curr_timeout = next_timeout
        cnt += 1

    if cnt == 10:
        print("\t...")

timeout_depths = {}
def trace_remove_timeout(uc):
    global timeout_depths
    timeout = uc.regs.r0

    print(f"==== remove_timeout (called from 0x{uc.regs.lr:08x})====")
    dump_timeout(uc, timeout)
    print("========================")

    if timeout not in timeout_depths or timeout_depths[timeout] == 0:
        print("[CORRUPTION DETECTED")
        import os, sys
        sys.stdout.flush()
        os._exit(1)
    timeout_depths[timeout] -= 1

def trace_z_add_timeout(uc):
    global timeout_depths
    timeout = uc.regs.r0
    if timeout not in timeout_depths:
        timeout_depths[timeout] = 0
    timeout_depths[timeout] += 1

    print(f"==== z_add_timeout (called from 0x{uc.regs.lr:08x})====")
    dump_timeout(uc, timeout)
    print("=======================")

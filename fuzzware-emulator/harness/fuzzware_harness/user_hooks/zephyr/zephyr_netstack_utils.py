import os
from binascii import hexlify

from unicorn import UcError


def dump_net_buf_simple(uc, buf):
    length, size = uc.mem.u16(buf+4, 2)
    cursor, base = uc.mem.u32(buf), uc.mem.u32(buf+8)
    print(f"buf @0x{buf:08x} (len: 0x{length:x}, bufsize: 0x{size:x}, data_cursor: 0x{cursor:08x}, data_base: 0x{base:08x})")

    if length > 0:
        if cursor == 0:
            contents = "<ERR: NULL pointer>"
        else:
            try:
                contents = hexlify(uc.mem[cursor:cursor+length])
            except UcError as e:
                contents = "<error fetching>"
    else:
        contents = "<empty>"

    print(f"\tcontents: {contents}")

def dump_frag_list(uc, frag):
    print(f"Frag start @0x{frag:08x}")
    seen = set()
    while frag != 0:
        seen.add(frag)
        dump_frag(uc, frag)
        frag = uc.mem.u32(frag) # net_buf.frags first member
        if frag in seen:
            print(f"\tERROR: frag 0x{frag:08x} already seen")
            os._exit(1)
            break

def dump_frag(uc, frag):
    l = uc.mem.u16(frag+12)
    buf = uc.mem.u32(frag+8)
    if l > 0:
        if buf == 0:
            contents = "<ERR: NULL pointer>"
        else:
            try:
                contents = hexlify(uc.mem[buf:buf+l])
            except UcError as e:
                contents = "<error fetching>"
    else:
        contents = "<empty>"
    print(f"\tfrag @0x{frag:08x} ({l:x} bytes @0x{buf:08x}): {contents}")

def dump_net_pkt(uc, pkt):
    FRAG_OFF = 0x10
    frag = uc.mem.u32(pkt+FRAG_OFF)
    seen = set()
    print(f"Packet @0x{pkt:08x}")
    while frag != 0:
        dump_frag(uc, frag)
        seen.add(frag)
        frag = uc.mem.u32(frag) # net_buf.frags first member
        if frag in seen:
            print("<ERROR: cyclic frag in net pdt>")
            os._exit(1)
            break

def trace_net_icmpv6_input(uc):
    pkt = uc.regs.r0

    print("=== net_icmpv6_input ===")
    dump_net_pkt(uc, pkt)
    print("========================")

def trace_net_ipv6_input(uc):
    pkt = uc.regs.r0

    print("=== net_ipv6_input ===")
    dump_net_pkt(uc, pkt)
    print("========================")

def trace_net_recv_data(uc):
    pkt = uc.regs.r1

    print("==== net_recv_data ====")
    dump_net_pkt(uc, pkt)
    print("=======================")

def trace_net_buf_simple_pull(uc):
    buf, length = uc.regs.r0, uc.regs.r1

    print(f"=== net_buf_simple_pull (called from 0x{uc.regs.lr:08x}) ===")
    print(f"Pulling {length} bytes from the following buffer:")
    dump_net_buf_simple(uc, buf)
    print("===========================")

def trace_ieee802154_reassemble(uc):
    pkt = uc.regs.r0

    print("==== ieee802154_reassemble ====")
    dump_net_pkt(uc, pkt)
    print("=======================")

def trace_inline_ieee802154_reassemble(uc):
    pkt = uc.regs.r4

    print("==== fragment_move_back packet state ====")
    if pkt != 0:
        dump_net_pkt(uc, pkt)
    else:
        print("<NULL pkt>")
    print("=======================", flush=True)

def trace_inline_ieee802154_reassemble_dump_fraglist(uc):
    frag = uc.regs.r5

    print("==== within reassemble fragment ====")
    if frag != 0:
        dump_frag_list(uc, frag)
    else:
        print("<NULL frag start>")
    print("=======================", flush=True)

def trace_inline_ieee802154_reassemble_dump_fraglist_r3(uc):
    frag = uc.regs.r3

    print("==== reassemble_fragment current (r3) ====")
    if frag != 0:
        dump_frag_list(uc, frag)
    else:
        print("<NULL frag start>")
    print("=======================", flush=True)


def trace_net_6lo_uncompress(uc):
    pkt = uc.regs.r0

    print("==== net_6lo_uncompress ====")
    dump_net_pkt(uc, pkt)
    print("=======================")

def trace_memmove(uc):
    dst = uc.regs.r0
    src = uc.regs.r1
    length = uc.regs.r2

    print(f"==== memmove(0x{dst:08x}, 0x{src:08x}, 0x{length:x}) ====")

def trace_frag_offset_cmp(uc):
    curr_buf = uc.regs.lr
    curr_offset = uc.mem.u8(curr_buf+4) << 3
    frag_off = uc.regs.r0
    print(f"==== fragment_move_back comparing fragment_offset(frag): {frag_off} < {curr_offset} :")

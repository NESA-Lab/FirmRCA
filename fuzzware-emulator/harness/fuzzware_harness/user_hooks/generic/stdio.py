import sys
from string import digits

from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                               UC_ARM_REG_R3)

from ..fuzz import get_fuzz

def puts(uc):
    ptr = uc.reg_read(UC_ARM_REG_R0)
    if ptr == 0:
        print("puts(NULL)", flush=True)
        return

    msg = uc.mem_read(ptr, 256)
    #ptr += 1
    #while msg[-1] != b"\0":
    #    msg += uc.mem_read(ptr, 1)
    #    ptr += 1
    if b'\0' in msg:
        msg = msg[:msg.find(b'\0')]
    print(msg.decode())


def putchar(uc):
    c = uc.reg_read(UC_ARM_REG_R0)
    assert c < 256
    sys.stdout.write(chr(c))
    sys.stdout.flush()

def printf(uc):
    # for now just print out the fmt string
    ptr = uc.reg_read(UC_ARM_REG_R0)
    assert ptr != 0
    msg = uc.mem_read(ptr, 256)

    if b'\0' in msg:
        msg = msg[:msg.find(b'\0')]
    output = b''

    # just allow a limited number of arguments
    args = [uc.reg_read(UC_ARM_REG_R1), uc.reg_read(UC_ARM_REG_R2), uc.reg_read(UC_ARM_REG_R3)]
    args.reverse()

    prev_ind, cursor = 0, 0
    while args:
        cursor = msg.find(b"%", prev_ind)

        if cursor == -1:
            break

        output += msg[prev_ind:cursor]
        cursor += 1

        num_str = b""
        while msg[cursor] in digits.encode():
            num_str += msg[cursor]
            cursor += 1
        while msg[cursor] == ord('l'):
            cursor += 1

        if msg[cursor] == ord('s'):
            string_addr = args.pop()
            s = uc.mem_read(string_addr, 1)
            while s[-1] != ord("\0"):
                string_addr += 1
                s += uc.mem_read(string_addr, 1)
            output += s[:-1]
        elif msg[cursor] == ord('d'):
            val = args.pop()
            output += f"{val:d}".encode()
        elif msg[cursor] in (ord('x'), ord('p')):
            val = args.pop()
            output += f"{val:x}".encode()

        cursor += 1
        prev_ind = cursor

    output += msg[prev_ind:]
    sys.stdout.write(output.decode('latin1'))
    sys.stdout.flush()


def readline(uc):
    ptr = uc.reg_read(UC_ARM_REG_R0)
    l = uc.reg_read(UC_ARM_REG_R1)
    assert ptr != 0
    data = b''
    while len(data) < l:
        data += get_fuzz(uc, 1)
        if data.endswith(b'\n'):
            break
    uc.mem_write(ptr, data)
    uc.reg_write(UC_ARM_REG_R0, 0)
    # echo
    sys.stdout.write(data.decode('latin1'))
    sys.stdout.flush()

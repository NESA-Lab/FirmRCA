import struct
import types
import logging
from collections import defaultdict

import archinfo
import ipdb
import unicorn

from . import util

logger = logging.getLogger("emulator")
# SparklyUnicorn: A syntactic wrapper for working with Unicorn's objects that does not make my head hurt

class SparklyRegs():

    _uc = None

    def __init__(self, uc):
        self._uc = uc

    def __getattribute__(self, regname):
        myuc = object.__getattribute__(self, '_uc')
        for x in dir(unicorn.arm_const):
            if x.endswith('REG_' + regname.upper()):
                return myuc.reg_read(getattr(unicorn.arm_const, x))
        return object.__getattribute__(self, regname)

    def get_all(self):
        out = {}
        myuc = object.__getattribute__(self, '_uc')
        for reg in myuc.arch.register_list:
            if not reg.artificial:
                n = reg.name
                if "d" not in n:
                    try:
                        val = getattr(self, reg.name)
                        out[n] = val
                    except AttributeError:
                        pass
        return out


    def __setattr__(self, regname, val):
        if regname == "_uc":
            object.__setattr__(self, regname, val)
        myuc = object.__getattribute__(self, '_uc')
        for x in dir(unicorn.arm_const):
            if x.endswith('_' + regname.upper()):
                return myuc.reg_write(getattr(unicorn.arm_const, x), val)
        return object.__getattribute__(self, regname)

    def __repr__(self):
        myuc = object.__getattribute__(self, '_uc')

        s = "Unicorn Registers:\n----------------\n"
        for reg in myuc.arch.register_list:
            if not reg.artificial:
                n = reg.name
                if "d" not in n:
                    try:
                        val = getattr(self, reg.name)
                        s += "%s: 0x%08x\n" % (n, val)
                    except AttributeError:
                        pass
        return s


class SparklyMem():
    _uc = None

    def __init__(self, uc):
        self._uc = uc

    def __getitem__(self, key):
        myuc = object.__getattribute__(self, '_uc')
        if isinstance(key, slice):
            return myuc.mem_read(key.start, (key.stop-key.start))
        return myuc.mem_read(key, 4)

    def __setitem__(self, key, value):
        myuc = object.__getattribute__(self, '_uc')

        if isinstance(value, bytes):
            myuc.mem_write(key, value)
        else:
            raise ValueError("Must be a bytes object")

    def u32(self, addr, num=1):
        res = struct.unpack("<"+num*"I", self._uc.mem_read(addr, num * 4))
        if num == 1:
            return res[0]
        return res

    def u16(self, addr, num=1):
        res = struct.unpack("<"+num*"H", self._uc.mem_read(addr, num * 2))
        if num == 1:
            return res[0]
        return res

    def u8(self, addr, num=1):
        res = struct.unpack("<"+num*"B", self._uc.mem_read(addr, num))
        if num == 1:
            return res[0]
        return res

class SparklyStack():

    _uc = None

    def __init__(self, uc):
        self._uc = uc

    def __getitem__(self, key):
        myuc = object.__getattribute__(self, '_uc')
        sp = myuc.reg_read(unicorn.arm_const.UC_ARM_REG_SP)
        if isinstance(key, slice):
            return myuc.mem_read(sp + key.start, (key.stop-key.start))
        return myuc.mem_read(sp + key, 4)

    def __setitem__(self, key, value):
        myuc = object.__getattribute__(self, '_uc')
        if isinstance(value, bytes):
            myuc.mem_write(sp + key, value)
        else:
            raise ValueError("Must be a bytes object")

    def _pp(self, start=-0x10, end=0x10, downward=True):
        if start % 4 != 0 or end % 4 != 0:
            logger.warning("The stack on ARM is word-aligned!")
            start -= start % 4
            end -= end % 4
        myuc = object.__getattribute__(self, '_uc')
        data = self[start:end]
        sp = myuc.regs.sp
        start_addr = sp+start
        regs = myuc.regs.get_all()

        points_to = defaultdict(list)
        for reg, val in regs.items():
            points_to[val - (val % 4)].append(reg)
        out = []
        for word in range(0, len(data), 4):
            bs = struct.unpack("<I", data[word:word+4])[0]
            line = "%#08x(SP%+#02x): %#010x" % (start_addr+word, (start_addr+word)-sp, bs)
            if points_to[start_addr+word]:
                line += "<-" + ",".join(points_to[start_addr+word])
            out.append(line)
        if downward is True:
            out = list(reversed(out))
        return "\n".join(out)

    def pp(self, start=-0x10, end=0x20, downward=False):
        print(self._pp(start, end, downward))

def break_it(uc):
    if uc.gdb is not None:
        uc.gdb.running.clear()
        uc.gdb.running.wait()
    elif uc.shell is True:
    # global u32,r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,r10,r11,r12,pc,lr,sp
        print(repr(uc.stack.pp()))
        print(repr(uc.regs))

        # Add some convenience wrappers
        u32 = uc.mem.u32
        def die():
            import os;
            os.kill(os.getpid(), 9)
        import monkeyhex
        import ipdb;

        ipdb.set_trace()


def add_breakpoint(self, addr):
    global breakpoints
    breakpoints.append(addr)
    return breakpoints.index(addr)


def del_breakpoint(self, handle):
    global breakpoints
    if handle in breakpoints:
        breakpoints[breakpoints.index(handle)] = -1
    else:
        breakpoints[handle] = -1


breakpoints = []
def breakpoint_handler(uc, address, size=0, user_data=None):
    global breakpoints
    if address in breakpoints:
        print("[*] Breakpoint hit at %#08x" % address)
        break_it(uc)
    if uc.gdb is not None and not uc.gdb.running.is_set():
        print("[*] Execution interrupted at %#08x" % address)
        break_it(uc)

def add_sparkles(uc, args):
    global breakpoints
    uc.regs = SparklyRegs(uc)
    uc.mem = SparklyMem(uc)
    uc.stack = SparklyStack(uc)
    uc.shell = args.shell
    uc.add_breakpoint = types.MethodType(add_breakpoint,uc)
    uc.b = types.MethodType(add_breakpoint,uc)
    uc.del_breakpoint = types.MethodType(del_breakpoint, uc)
    if args.breakpoints:
        for bp in args.breakpoints:
            try:
                bp_addr = int(bp, 0)
            except ValueError:
                bp_addr = util.parse_address_value(uc.symbols, bp)
            breakpoints.append(bp_addr & ~1)
        uc.hook_add(unicorn.UC_HOOK_BLOCK_UNCONDITIONAL, breakpoint_handler)
    uc.arch = archinfo.ArchARMCortexM()
    # uc.arch = None
    return uc

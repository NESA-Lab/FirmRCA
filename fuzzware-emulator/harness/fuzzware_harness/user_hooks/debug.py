import logging
from unicorn.arm_const import (UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1,
                               UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4,
                               UC_ARM_REG_R5, UC_ARM_REG_R7, UC_ARM_REG_SP)

def stop(uc):
    print_context(uc)
    input("...")

def print_context(uc):
    print("==== State ====")
    r0 = uc.reg_read(UC_ARM_REG_R0)
    r1 = uc.reg_read(UC_ARM_REG_R1)
    r2 = uc.reg_read(UC_ARM_REG_R2)
    r3 = uc.reg_read(UC_ARM_REG_R3)
    r4 = uc.reg_read(UC_ARM_REG_R4)
    r5 = uc.reg_read(UC_ARM_REG_R5)
    r7 = uc.reg_read(UC_ARM_REG_R7)
    sp = uc.reg_read(UC_ARM_REG_SP)
    pc = uc.reg_read(UC_ARM_REG_PC)
    print("r0: 0x{:x}\nr1: 0x{:x}\nr2: 0x{:x}\nr3: 0x{:x}\nr4: 0x{:x}\nr5: 0x{:x}\nr7: 0x{:x}\npc: 0x{:x}\nsp: 0x{:x}".format(r0, r1, r2, r3, r4, r5, r7, pc, sp), flush=True)

def print_fn_args(uc, regvals):
    pc = uc.reg_read(UC_ARM_REG_PC)
    fn_name = uc.syms_by_addr.get(pc, None)
    if fn_name is None:
        fn_name = uc.syms_by_addr.get(pc | 1, None)
        if fn_name is None:
            fn_name = f"UNKNOWN_FUNC_{pc:08x}"
    args_text = ','.join([f"{addr:#010x}" for addr in regvals])
    print(f"{fn_name}({args_text})", flush=True)

def print_args_0(uc):
    print_fn_args(uc, ())

def print_args_1(uc):
    regvals = (uc.regs.r0, )
    print_fn_args(uc, regvals)

def print_args_2(uc):
    regvals = (uc.regs.r0, uc.regs.r1)
    print_fn_args(uc, regvals)

def print_args_3(uc):
    regvals = (uc.regs.r0, uc.regs.r1, uc.regs.r2)
    print_fn_args(uc, regvals)

def print_args_4(uc):
    regvals = (uc.regs.r0, uc.regs.r1, uc.regs.r2, uc.regs.r3)
    print_fn_args(uc, regvals)

def breakpoint(uc):
    import ipdb
    ipdb.set_trace()

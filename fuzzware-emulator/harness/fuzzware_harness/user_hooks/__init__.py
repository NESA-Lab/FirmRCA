import binascii
import importlib
import re
import struct
import sys
import logging

from unicorn import UC_HOOK_BLOCK_UNCONDITIONAL

from .. import globs
from ..exit import do_exit


logger = logging.getLogger("emulator")

func_hooks = {}

def remove_func_hook(address, func):
    assert (address in func_hooks) and func in func_hooks[address]
    func_hooks[address].remove(func)
    # is the address fully gone?
    if not func_hooks[address]:
        del func_hooks[address]
        from .. import native
        native.remove_function_handler_hook_address(globs.uc, address)

""" ASM
ldr r0, =0x90909090
bx lr
NOP
"""
LDR_R0_LITERAL_POOL_RET = b"\x00\x48\x70\x47"
THUMB_NOP = b"\xC0\x46"

# bx lr
THUMB_RET = b'\x70\x47'

native_ret_regex        = r"retu?r?n?_0?x?([0-9a-fA-F]+)"
native_inline_asm_regex = r"inline_asm_([0-9a-fA-f]+)"
def patch_native_handler(uc, addr, magic_funcname):
    logger.info(f"Native patch handler looking at {magic_funcname}")

    # native.return_0xdeadbeef
    if re.match(native_ret_regex, magic_funcname):
        val = int(re.match(native_ret_regex, magic_funcname).group(1), 16)
        if val > 1<<32:
            logger.error(f"[Native handler] too large value {val:x}")
            sys.exit(1)
        patch = LDR_R0_LITERAL_POOL_RET + struct.pack("<I", val)
        # For unaligned addresses, align the instruction first for a correct pc-relative load
        if addr & 2 == 2:
            patch = THUMB_NOP + patch
    elif re.match(native_inline_asm_regex, magic_funcname):
        inline_patch_hex = re.match(native_inline_asm_regex, magic_funcname).group(1)
        try:
            patch = binascii.unhexlify(inline_patch_hex)
        except binascii.Error:
            logger.error(f"[Native handler] invalid hex: {inline_patch_hex}")
            sys.exit(1)
    else:
        logger.error(f"[Native handler] Unknown native function: {magic_funcname}")
        sys.exit(1)

    uc.mem_write(addr, patch)

def add_func_hook(uc, addr, func, do_return=True):
    """
    Add a function hook.

    If func is None (and do_return is True) this is effectively a nop-out without using a real hook!
    Makes it faster to not have to call into python for hooks we don't need.
    """

    real_addr = addr & 0xFFFFFFFE  # Drop the thumb bit
    if func:
        if isinstance(func, str):
            try:
                # Resolve the function name
                mod_name, func_name = func.rsplit('.', 1)
                if mod_name == "native":
                    patch_native_handler(uc, addr, func_name)
                    return

                mod = importlib.import_module(mod_name)
                func_obj = getattr(mod, func_name)
            except (ModuleNotFoundError, AttributeError):
                import traceback
                logger.error("Unable to hook function %s at address %#08x" % (repr(func), addr))
                traceback.print_exc()
                do_exit(uc, 1)
        else:
            func_obj = func

        if real_addr not in func_hooks:
            func_hooks[real_addr] = []
        func_hooks[real_addr].append(func_obj)

    if do_return:
        uc.mem_write(real_addr, THUMB_RET)


def func_hook_handler(uc, addr, size, user_data):
    if addr in func_hooks:
        for hook in func_hooks[addr]:
            logger.debug(f"Calling hook {hook.__name__} at {addr:#08x}")
            try:
                hook(uc)
            except:
                import traceback
                traceback.print_exc()
                do_exit(uc, 1)

block_hooks = []

def add_block_hook(hook):
    block_hooks.append(hook)

def maybe_register_global_block_hook(uc):
    if block_hooks:
        logger.debug("Registering block hook wrapper for {} hooks: {}".format(len(block_hooks), list(map(lambda fn: fn.__name__, block_hooks))))
        uc.hook_add(UC_HOOK_BLOCK_UNCONDITIONAL, block_hook_handler)
    else:
        logger.debug("No non-native unconditional basic block hooks registered, not adding global hook")

def block_hook_handler(uc, address, size=0, user_data=None):
    for hook in block_hooks:
        hook(uc, address, size, user_data)

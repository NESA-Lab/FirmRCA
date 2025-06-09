import logging

from .. import native
from ..globs import MMIO_HOOK_PC_ALL_ACCESS_SITES
from ..util import ensure_rw_mapped, int2bytes, parse_address_value

logger = logging.getLogger("emulator")

constants = {}
def mmio_access_handler_constant_values(uc, access, address, size, value, user_data):
    val = constants[address]

    logger.info("Constant value mmio callback called! Writing 0x{:08x} to 0x{:08x}".format(val, address))
    uc.mem_write(address, int2bytes(val))

    return True

def register_constant_mmio_models(uc, starts, ends, pcs, vals):
    for start, end in zip(starts, ends):
        ensure_rw_mapped(uc, start, end)

    native.register_constant_mmio_models(uc, starts, ends, pcs, vals)

def parse_constant_handlers(symbols, declarations):
    starts, ends, vals, pcs = [], [], [], []
    for entry in declarations.values():
        assert (
            'addr' in entry and
            'val' in entry
        )
        address = parse_address_value(symbols, entry['addr'])
        value = parse_address_value(symbols, entry['val'])
        pc = parse_address_value(symbols, entry['pc']) if 'pc' in entry else MMIO_HOOK_PC_ALL_ACCESS_SITES

        starts.append(address)
        ends.append(address)
        vals.append(value)
        pcs.append(pc)

    return starts, ends, pcs, vals

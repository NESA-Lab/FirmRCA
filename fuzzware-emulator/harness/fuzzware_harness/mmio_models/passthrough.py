from ..util import int2bytes, ensure_rw_mapped, parse_address_value
from ..native import set_ignored_mmio_addresses
from ..globs import MMIO_HOOK_PC_ALL_ACCESS_SITES

def register_passthrough_handlers(uc, addrs, pcs, vals):
    for address, value in zip(addrs, vals):
        if value != 0:
            pl = int2bytes(value)
            uc.mem_write(address, pl)

        ensure_rw_mapped(uc, address, address)

    set_ignored_mmio_addresses(addrs, pcs)

def parse_passthrough_handlers(symbols, declarations):
    addrs = []
    pcs = []
    vals = []
    for entry in declarations.values():
        assert (
            'addr' in entry
        )
        address = parse_address_value(symbols, entry['addr'])
        pc = parse_address_value(symbols, entry['pc']) if 'pc' in entry else MMIO_HOOK_PC_ALL_ACCESS_SITES
        value = parse_address_value(symbols, entry['init_val']) if 'init_val' in entry else 0

        addrs.append(address)
        pcs.append(pc)
        vals.append(value)

    return addrs, pcs, vals

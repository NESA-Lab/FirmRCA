from ..util import ensure_rw_mapped, parse_address_value
from .. import native

def register_value_set_mmio_models(uc, starts, ends, pcs, val_lists):
    for start, end in zip(starts, ends):
        ensure_rw_mapped(uc, start, end)

    native.register_value_set_mmio_models(uc, starts, ends, pcs, val_lists)

def parse_value_set_handlers(symbols, declarations):
    starts, ends, val_lists, pcs = [], [], [], []
    for entry in declarations.values():
        assert (
            'addr' in entry and
            'vals' in entry and
            'pc' in entry
        )
        address = parse_address_value(symbols, entry['addr'])
        pc = parse_address_value(symbols, entry['pc'])
        vals = list(map(lambda v: parse_address_value(symbols, v), entry['vals']))

        starts.append(address)
        ends.append(address)
        val_lists.append(vals)
        pcs.append(pc)

    return starts, ends, pcs, val_lists

from . import native
from .globs import FUZZ_MODES, TRIGGER_MODES
from .util import parse_address_value

def init_triggers(uc, entries):
    for entry in entries.values():
        # 1. When to trigger
        addr = parse_address_value(uc.symbols, entry['address']) if 'address' in entry else(parse_address_value(uc.symbols, entry['addr']) if 'addr' in entry else None)
        if addr is not None:
            # We have a fixed address to trigger at
            trigger_mode = 'addr'
        else:
            # We trigger time-based
            every_nth_tick = entry.get('every_nth_tick', None)
            if every_nth_tick in ('fuzzed', 'fuzz'):
                trigger_mode = 'fuzzed'
            else:
                trigger_mode = 'every_nth_tick'

        # 2. What to trigger
        irq = entry['irq'] if 'irq' in entry else 0
        if irq != 0:
            # We have a fixed irq, use fixed mode
            fuzz_mode = 'fixed'
        else:
            # We are dynamically choosing which irq to pend
            fuzz_mode = entry['fuzz_mode'] if 'fuzz_mode' in entry else 'round_robin'

        # 3. Generic Configs
        num_pends = entry['num_pends'] if 'num_pends' in entry else 1
        num_skips = entry['num_skips'] if 'num_skips' in entry else (1 if trigger_mode == 'addr' else 0)

        # Sanity check the When-config
        assert (
            (trigger_mode == 'every_nth_tick' and (every_nth_tick is not None)) or
            (trigger_mode == 'addr' and (addr is not None)) or
            (trigger_mode == 'fuzzed')
        )
        # Add non-used default values for When-config
        if trigger_mode != 'addr':
            addr = 0
        if trigger_mode != 'every_nth_tick':
            every_nth_tick = 0

        # Backwards compatibility with previous syntax
        if 'fuzzed' in entry:
            if entry['fuzzed'] is True:
                fuzz_mode = 'fuzzed'
            elif entry['fuzzed'] is False:
                fuzz_mode = 'fixed'

        # Naming synonyms
        if fuzz_mode == 'fuzz':
            fuzz_mode = 'fuzzed'
        elif 'round' in fuzz_mode.lower() or 'robin' in fuzz_mode.lower():
            fuzz_mode = 'round_robin'

        # Sanity check the What-config
        assert 'irq' in entry or fuzz_mode != 'fixed'
        assert fuzz_mode in FUZZ_MODES

        native.add_interrupt_trigger(uc, addr, irq, num_skips, num_pends, FUZZ_MODES.index(fuzz_mode), TRIGGER_MODES.index(trigger_mode), every_nth_tick)

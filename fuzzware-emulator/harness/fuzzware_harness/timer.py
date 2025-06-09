import importlib
import sys
import logging

from unicorn.arm_const import UC_ARM_REG_PC

from . import globs, native
from .exit import do_exit
from .user_hooks import add_func_hook, remove_func_hook

logger = logging.getLogger("emulator")

DEFAULT_TIMER_RELOAD_VAL = 0x1000

callbacks = {}
internal_indices = {}
# map {start_at_1: [timer_id_1, timer_id_2], start_at_2: [timer_id_x]}
delayed_timers = {}

def timer_start_block_hook(uc):
    address = uc.reg_read(UC_ARM_REG_PC)
    if address in delayed_timers:
        # Remove the timer along the way
        for timer_id in delayed_timers.pop(address):
            logger.info("Starting delayed timer '{}' at {:08x}".format(timer_id, address))
            resume_timer(timer_id)

        # We only ever want to start the timer once
        remove_func_hook(address, timer_start_block_hook)

def central_timer_hook(uc, internal_timer_id, userdata):
    trigger_timer(uc, internal_timer_id)

def ticks():
    return native.get_global_ticker()

def start_timer(timer_id, timer_rate, timer_func_irq):
    """
    Start a timer.

    :param timer_id: The 'id' of the timer.  This is either its name, or a base address.
    Generally anything we need to identify that timer again later.
    :param timer_rate:  The timer's 'rate', in ticks. After this many ticks, the event will occur.
    :param timer_func_irq: What to do when the timer elapses.  If this is an int, inject that interrupt.  If it
    is a function object, just call that instead.
    :return:
    """
    assert timer_id not in internal_indices
    if isinstance(timer_func_irq, int):
        internal_ind = native.add_timer(timer_rate, isr_num=timer_func_irq)
    else:
        internal_ind = native.add_timer(timer_rate, callback=timer_func_irq)
        callbacks[internal_ind] = timer_func_irq

    native.start_timer(globs.uc, internal_ind)
    internal_indices[timer_id] = internal_ind

    logger.info("Starting timer %s with rate %s (internal id: %d)" % (repr(timer_id), timer_rate, internal_ind))
    return internal_ind

def configure_timers(uc, config):
    if 'use_timers' in config and config['use_timers'] is True:
        # Parse config for timer function handlers
        if 'timers' in config:
            for timer_id, timer_config in config['timers'].items():
                if 'reload_val' in timer_config:
                    reload_val = timer_config['reload_val']
                else:
                    reload_val = DEFAULT_TIMER_RELOAD_VAL
                    logger.warning("did not find 'reload_val' for timer '{}', assigning default of {}".format(timer_id, reload_val))

                if 'handler' in timer_config:
                    # Register handler function
                    func = timer_config['handler']

                    try:
                        # Resolve the function name
                        mod_name, func_name = func.rsplit('.', 1)
                        mod = importlib.import_module(mod_name)
                        func_obj = getattr(mod, func_name)
                    except:
                        import traceback
                        logger.info("Unable to hook function %s for timer %r" % (repr(func), timer_id))
                        traceback.print_exc()
                        do_exit(uc, 1)
                    timer_func_irq = func_obj
                elif 'irq' in timer_config:
                    # Register with an irq number
                    timer_func_irq = timer_config['irq']
                else:
                    logger.info("[Timer Config ERROR] For a timer configuration, either 'irq' or 'handler' is required")
                    sys.exit(-1)

                start_timer(timer_id, reload_val, timer_func_irq)

                # See if there is a particular address in the firmware execution to start the timer at
                if 'start_at' in timer_config:
                    stop_timer(timer_id)
                    addr = timer_config['start_at']
                    if not delayed_timers:
                        add_func_hook(uc, addr, timer_start_block_hook, do_return=False)
                    if addr not in delayed_timers:
                        delayed_timers[addr] = []
                    delayed_timers[addr].append(timer_id)

def timer_exists(timer_id):
    return timer_id in internal_indices

def stop_timer(timer_id):
    logger.info("Stopping timer %s" % repr(timer_id))
    if timer_id not in internal_indices:
        logger.warning("UH OH: We never started timer %s" % repr(timer_id))
        return
    native.stop_timer(globs.uc, internal_indices[timer_id])

def is_running(timer_id):
    if timer_id not in internal_indices:
        logger.warning("UH OH: We never created timer %s" % repr(timer_id))
        return False
    return native.is_running(internal_indices[timer_id])

def resume_timer(timer_id):
    logger.info("Resuming timer %s" % repr(timer_id))
    if timer_id not in internal_indices:
        logger.warning("UH OH: We never started timer %s" % repr(timer_id))
        return
    native.start_timer(globs.uc, internal_indices[timer_id])

def reset_timer(timer_id):
    if timer_id not in internal_indices:
        logger.warning("UH OH: We never started timer %s" % repr(timer_id))
        return
    native.reload_timer(internal_indices[timer_id])

def trigger_timer(uc, internal_timer_id):
    callbacks[internal_timer_id](uc)

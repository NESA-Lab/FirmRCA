import os
import signal
import string
import struct
import sys
from glob import glob as directory_glob

import yaml

from . import globs

import logging
logger = logging.getLogger("emulator")

def parse_address_value(symbols, value, enforce=True):
    if isinstance(value, int):
        return value
    if "+" in value:
        name, offset = value.split("+")
        name = name.rstrip(" ")
        offset = int(offset, 0)
    else:
        name = value
        offset = 0
    if name in symbols:
        return symbols[name] + offset
    try:
        return int(value, 16)
    except ValueError:
        if enforce:
            logger.error(f"Could not resolve symbol '{value}' and cannot proceed. Exiting...")
            if not symbols:
                logger.info("Hint: No symbols found - did you forget to (generate and) include a symbols file?")
            if sum([value.count(d) for d in string.digits]) > 2:
                logger.info("Hint: Found multiple digits in the value - did you mis-type a number?")
            sys.exit(1)
        return None

def parse_symbols(config):
    name_to_addr = {}
    addr_to_name = {}
    # Create the symbol table
    if 'symbols' in config:
        try:
            addr_to_name = {k&0xFFFFFFFE: v for k, v in config['symbols'].items()}
            name_to_addr = {v: k&0xFFFFFFFE for k, v in config['symbols'].items()}
        except TypeError as e:
            logger.error("Type error while parsing symbols. The symbols configuration was likely mis-formatted. The format is 0xdeadbeef: my_symbol_name. Raising original error.")
            raise e
    return name_to_addr, addr_to_name

def closest_symbol(addr_to_name, addr, max_offset=0x1000):
    """
    Find the symbol which is closest to addr, alongside with its offset.

    Returns:
        - (symbol_name, offset_to_symbol) if a symbol exists with an offset of a maximum of max_offset
        - Otherwise, (None, None) is returned in case no symbol with appropriate offset exists
    """
    if not addr_to_name:
        return (None, None)

    sorted_addrs = sorted(addr_to_name)
    for i, sym_addr in enumerate(sorted_addrs):
        # last entry?
        if i == len(sorted_addrs) - 1 or sorted_addrs[i+1] > addr:
            off = addr - sym_addr
            if 0 <= off <= max_offset:
                return addr_to_name[sym_addr], off
            return (None, None)
    return (None, None)

def bytes2int(bs):
    if len(bs) == 4:
        return struct.unpack("<I", bs)[0]
    if len(bs) == 2:
        return struct.unpack("<H", bs)[0]
    if len(bs) == 1:
        return struct.unpack("<B", bs)[0]
    if len(bs) == 8:
        return struct.unpack("<Q", bs)[0]
    from binascii import hexlify
    logger.info("Can not unpack {} bytes: {}".format(len(bs), hexlify(bs)))
    assert False


def int2bytes(i):
    return struct.pack("<I", i)


def crash(sig=signal.SIGSEGV):
    logger.error("-------------------------------- CRASH DETECTED-------------------------")
    os.kill(os.getpid(), sig)


def ensure_rw_mapped(uc, start, end):
    start = start & (~0xfff)
    end = (end + 0xfff) & (~0xfff)
    if start == end:
        end += 0x1000

    if all([start < rstart or end > rstart + size for rstart, size, _ in globs.regions.values()]):
        logger.info("Adding mapping {:08x}-{:08x} because of a configured mmio model".format(start, end))
        globs.regions['mmio_model_region_{:x}_{:x}'.format(start, end)] = (start, end-start, 3)
        uc.mem_map(start, end-start, 3)

###########
# Stuff about configuration files

def _merge_dict(dct, merge_dct):
    for k, _ in merge_dct.items():
        if (k in dct and isinstance(dct[k], dict)
                and isinstance(merge_dct[k], dict)):
            _merge_dict(dct[k], merge_dct[k])
        else:
            dct[k] = merge_dct[k]

def adjust_config_relative_paths(config, base_path):
    # "./"-prefixed paths to properly resolve relative to config snippet
    if 'memory_map' not in config:
        return

    for _, region in config['memory_map'].items():
        if 'file' in region and region['file'].startswith("./"):
            region['file'] = os.path.join(os.path.dirname(base_path), region['file'])
            logger.debug("Fixed up file path to '{}'".format(region['file']))

def resolve_config_includes(config, base_path):
    """
    Recursively resolves a config file, adjusting paths along
    the way
    """
    if 'include' in config:
        # Merge config files listed in 'include' in listed order
        # Root file gets priority
        newconfig = {}
        for f in config['include']:
            if not f.startswith("/"):
                # Make configs relative to the including config file
                cur_dir = os.path.dirname(base_path)
                f = os.path.abspath(os.path.join(cur_dir, f))

            logger.info(f"\tIncluding configuration from {f}")
            with open(f, 'rb') as infile:
                other_config_snippet = yaml.load(infile, Loader=yaml.FullLoader)
            adjust_config_relative_paths(other_config_snippet, f)
            other_config_snippet = resolve_config_includes(other_config_snippet, f)
            _merge_dict(newconfig, other_config_snippet)
        _merge_dict(newconfig, config)
        config = newconfig
    return config

def resolve_config_file_pattern(config_dir_path, f):
    """
    Resolve the path pattern in a config to the actual file path
    """
    if not f.startswith("/"):
        f = os.path.join(config_dir_path, f)

    if '*' in f:
        candidates = directory_glob(f)
        if len(candidates) != 1:
            raise ValueError("Could not unambiguously find pattern '{}' matching paths: {}".format(f, candidates))

        f = candidates[0]

    return os.path.abspath(f)

def resolve_region_file_paths(config_file_path, config):
    """
    Updates the config map's 'memory_map' entry, resolving patterns
    and relative paths.
    """

    for _, region in config['memory_map'].items():
        path = region.get('file')
        if path:
            region['file'] = resolve_config_file_pattern(os.path.dirname(config_file_path), path)
            logger.info("Found path '{}' for pattern '{}'".format(region['file'], path))

def load_config_deep(path):
    if not os.path.isfile(path):
        return {}
    with open(path, 'rb') as infile:
        config = yaml.load(infile, Loader=yaml.FullLoader)
    if config is None:
        return {}
    return resolve_config_includes(config, path)

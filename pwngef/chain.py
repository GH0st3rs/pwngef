#!/usr/bin/python
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import string
from pwngef.color import Color
import pwngef.memory

LIMIT = pwngef.config.set('self.dereference_limit', 5, 'max number of pointers to dereference in a chain')
string_limit = pwngef.config.set('self.dereference_string_limit', 30, 'max number of chars to dereference string')


def format(value, limit=LIMIT, code=True):
    """
    Recursively dereferences an address into string representation, or convert the list representation
    of address dereferences into string representation.

    Arguments:
        value(int|list): Either the starting address to be sent to get, or the result of get (a list)
        limit(int): Number of valid pointers
        code(bool): Hint that indicates the value may be an instruction
        offset(int): Offset into the address to get the next pointer
        hard_stop(int): Value to stop on
        hard_end: Value to append when hard_stop is reached: null, value of hard stop, a string.

    Returns:
        A string representing pointers of each address and reference
        Strings format: 0x0804a10 —▸ 0x08061000 ◂— 0x41414141
    """
    limit = int(limit)
    # Get config params
    base_address_color = pwngef.config.get("theme.dereference_base_address")
    string_color = pwngef.config.get("theme.dereference_string")
    config_arrow_right = pwngef.config.get("theme.chain_arrow_right")
    # Allow results from get function to be passed to format
    if isinstance(value, list):
        chain = value
    else:
        chain = examine_mem_value(value, limit)
    # Set arrow separate
    arrow_right = ' %s ' % config_arrow_right
    # Colorize the chain
    rest = []
    for link in chain:
        if isinstance(link, int):
            rest.append(Color.colorify('%#x' % link, base_address_color))
        if isinstance(link, str):
            rest.append(Color.colorify('"{:s}"'.format(link), string_color))
        # symbol = pwngef.symbol.get(link) or None
        # if symbol:
        #     symbol = '%#x (%s)' % (link, symbol)
        # rest.append(M.get(link, symbol))
    return arrow_right.join(rest)


def examine_mem_value(address, limit=LIMIT):
    """
    Recursively dereferences an address. For bare metal, it will stop when the address is not in any of vmmap pages to avoid redundant dereference.

    Arguments:
        address(int): the first address to begin dereferencing
        limit(int): number of valid pointers

    Returns:
        A list representing pointers of each ```address``` and reference
    """
    result = [address]

    def dereference(value):
        bits = pwngef.arch.ptrsize * 8
        try_string = pwngef.memory.string(value)
        if not try_string or not all(chr(s) in string.printable for s in try_string):
            if pwngef.memory.peek(value):
                return pwngef.memory.u32(value) if bits == 32 else pwngef.memory.u64(value)
            return None
        # return string
        if len(try_string) > string_limit:
            return try_string.decode()[:string_limit] + '...'
        return try_string.decode()

    for i in range(limit):
        # Don't follow cycles, except to stop at the second occurrence.
        if result.count(address) >= 2:
            break
        deref = dereference(address)
        if deref is None:
            break
        if isinstance(deref, str):
            result.append(deref)
            break
        address = deref & pwngef.arch.ptrmask
        result.append(address)

    return result

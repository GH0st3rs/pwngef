#!/usr/bin/python
"""
Common types, and routines for manually loading types from file
via GCC.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import sys
import gdb

import pwngef.events

module = sys.modules[__name__]


def is_pointer(value):
    type = value

    if isinstance(value, gdb.Value):
        type = value.type

    type = type.strip_typedefs()
    return type.code == gdb.TYPE_CODE_PTR


def lookup_types(*types):
    for type_str in types:
        try:
            return gdb.lookup_type(type_str)
        except Exception as e:
            exc = e
    raise exc


@pwngef.events.stop
def update(event):
    module.char = gdb.lookup_type('char')
    module.ulong = lookup_types('unsigned long', 'uint', 'u32')
    module.long = lookup_types('long', 'int', 'i32')
    module.uchar = lookup_types('unsigned char', 'ubyte', 'u8')
    module.ushort = lookup_types('unsigned short', 'ushort', 'u16')
    module.uint = lookup_types('unsigned int', 'uint', 'u32')
    module.void = lookup_types('void', '()')
    module.uint8 = module.uchar
    module.uint16 = module.ushort
    module.uint32 = module.uint
    module.uint64 = lookup_types('unsigned long long', 'ulong', 'u64')

    module.int8 = lookup_types('char', 'i8')
    module.int16 = lookup_types('short', 'i16')
    module.int32 = lookup_types('int', 'i32')
    module.int64 = lookup_types('long long', 'long', 'i64')

    module.ssize_t = module.long
    module.size_t = module.ulong

    module.pvoid = module.void.pointer()
    module.ppvoid = module.pvoid.pointer()
    module.pchar = module.char.pointer()

    module.ptrsize = module.pvoid.sizeof

    if module.pvoid.sizeof == 4:
        module.ptrdiff = module.uint32
    if module.pvoid.sizeof == 8:
        module.ptrdiff = module.uint64

    module.null = gdb.Value(0).cast(module.void)


# Call it once so we load all of the types
update(None)

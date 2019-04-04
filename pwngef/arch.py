#!/usr/bin/python
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import struct
import sys

import gdb

import pwngef.events
import pwngef.typeinfo
import pwngef.regs

current = 'i386'
qemu = current
ptrmask = 0xfffffffff
endian = 'little'
ptrsize = pwngef.typeinfo.ptrsize
fmt = '=I'
native_endian = str(sys.byteorder)
CURRENT_ARCH = None


def fix_arch(arch):
    arches = ['x86-64', 'i386', 'mips', 'powerpc', 'sparc', 'arm', 'aarch64', arch]
    return next(a for a in arches if a in arch)


@pwngef.events.new_objfile
def update(event=None):
    m = sys.modules[__name__]
    # GDB 7.7 (Ubuntu Trusty) does not like selected_frame() when EBP/RBP
    # is not mapped / pounts to an invalid address.
    #
    # As a work-around for Trusty users, handle the exception and bail.
    # This may lead to inaccurate results, but there's not much to be done.
    try:
        m.current = fix_arch(gdb.newest_frame().architecture().name())
    except Exception:
        return

    m.ptrsize = pwngef.typeinfo.ptrsize
    m.ptrmask = (1 << 8 * pwngef.typeinfo.ptrsize) - 1

    if 'little' in gdb.execute('show endian', to_string=True).lower():
        m.endian = 'little'
    else:
        m.endian = 'big'

    m.fmt = {
        (4, 'little'): '<I',
        (4, 'big'): '>I',
        (8, 'little'): '<Q',
        (8, 'big'): '>Q',
    }.get((m.ptrsize, m.endian))

    # Work around Python 2.7.6 struct.pack / unicode incompatibility
    # See https://github.com/pwngef/pwngef/pull/336 for more information.
    m.fmt = str(m.fmt)

    # Attempt to detect the qemu-user binary name
    if m.current == 'arm' and m.endian == 'big':
        m.qemu = 'armeb'
    elif m.current == 'mips' and m.endian == 'little':
        m.qemu = 'mipsel'
    else:
        m.qemu = m.current
    set_arch(m.current)


def pack(integer):
    return struct.pack(fmt, integer & ptrmask)


def unpack(data):
    return struct.unpack(fmt, data)[0]


def signed(integer):
    return unpack(pack(integer), signed=True)


def unsigned(integer):
    return unpack(pack(integer))


def set_arch(arch=None, default=None):
    """Sets the current architecture.
    If an arch is explicitly specified, use that one, otherwise try to parse it
    out of the ELF header. If that fails, and default is specified, select and
    set that arch.
    Return the selected arch, or raise an OSError.
    """
    module = sys.modules[__name__]
    if arch:
        try:
            module.CURRENT_ARCH = pwngef.regs.arch_to_regs[arch]()
            return module.CURRENT_ARCH
        except KeyError:
            raise OSError("Specified arch {:s} is not supported".format(arch))

    # module.current_elf = module.current_elf or get_elf_headers()
    try:
        module.CURRENT_ARCH = pwngef.regs.arch_to_regs[module.current]()
    except KeyError:
        if default:
            try:
                module.CURRENT_ARCH = pwngef.regs.arch_to_regs[default.upper()]()
            except KeyError:
                raise OSError("CPU not supported, neither is default {:s}".format(default))
        else:
            raise OSError("CPU type is currently not supported: {:s}".format(module.current))
    return module.CURRENT_ARCH

#!/usr/bin/python
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import gdb

import pwngef.config
import pwngef.commands
from pwngef.commands import GenericCommand
import pwngef.arch
import pwngef.proc
from pwngef.color import message
from pwngef.color import Color


@pwngef.commands.register_command
class DetailRegistersCommand(GenericCommand):
    """Display full details on one, many or all registers value from current architecture."""

    _cmdline_ = "registers"
    _syntax_ = "{:s} [[Register1][Register2] ... [RegisterN]]".format(_cmdline_)
    _example_ = "\n{0:s}\n{0:s} $eax $eip $esp".format(_cmdline_)
    _aliases_ = ["regs", ]

    @pwngef.proc.OnlyWhenRunning
    def do_invoke(self, argv):
        if argv:
            regs = [reg for reg in pwngef.arch.CURRENT_ARCH.all_registers if reg in argv]
            if not regs:
                message.warn("No matching registers found")
        else:
            regs = pwngef.arch.CURRENT_ARCH.all_registers

        print_registers(registers=regs)
        return None


def print_registers(registers, ignored_registers=[], old_registers={}, flags=False):
    '''Print dereferenced registers

    Arguments:
        registers(list): List of printed registers
        ignored_registers(list): List of registers witch didn't printed
        old_registers(list): Old registers, needed for check if registers was changed
        flags(bool): Print flags

    Returns:
        A string representing pointers of each address and reference
        REG_NAME: 0x0804a10 —▸ 0x08061000 —▸ AAAA
    '''
    widest = max(map(len, registers))
    changed_color = pwngef.config.get("theme.registers_value_changed")
    regname_color = pwngef.config.get("theme.registers_register_name")
    line = ''
    # Print registers value
    for reg in registers:
        if reg in ignored_registers:
            continue

        try:
            r = pwngef.regs.get_register(reg)
            if r.type.code == gdb.TYPE_CODE_VOID:
                continue
            new_value_type_flag = (r.type.code == gdb.TYPE_CODE_FLAGS)
            new_value = int(r)
        except (gdb.MemoryError, gdb.error):
            # If this exception is triggered, it means that the current register
            # is corrupted. Just use the register "raw" value (not eval-ed)
            new_value = pwngef.regs.get_register(reg)
            new_value_type_flag = False
        except Exception:
            new_value = 0

        old_value = old_registers.get(reg, 0)
        padreg = reg.ljust(widest, " ")
        value = new_value
        if value == old_value:
            line += "{}: ".format(Color.colorify(padreg, regname_color))
        else:
            line += "{}: ".format(Color.colorify(padreg, changed_color))
        if new_value_type_flag:
            line += "{:s} ".format(str(value))
        else:
            line += pwngef.chain.format(value)
        print(line)
        line = ""
    # Print Flags
    if flags and pwngef.arch.CURRENT_ARCH.flags_table:
        print("Flags: {:s}".format(pwngef.arch.CURRENT_ARCH.flag_register_to_human()))

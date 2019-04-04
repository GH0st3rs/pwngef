#!/usr/bin/python
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import gdb

import pwngef.commands
from pwngef.commands import GenericCommand
from pwngef.color import message
import pwngef.proc
import pwngef.hexdump
import pwngef.memory


@pwngef.commands.register_command
class HexDumpCommand(GenericCommand):
    '''Hexdumps data at the specified address (or at $sp)'''
    _cmdline_ = "hexdump"
    _syntax_ = "{:s} [address|reg] [count]".format(_cmdline_)
    _example_ = "\n{0:s}\n{0:s} 0x10000 100\n{0:s} $sp 0x100\n{0:s} $sp+10 0x100".format(_cmdline_)

    def __init__(self):
        super(HexDumpCommand, self).__init__()
        self.add_setting("hexdump_width", 16, "line width of hexdump command")
        self.add_setting('hexdump_bytes', 64, 'number of bytes printed by hexdump command')
        self.add_setting('hexdump_colorize_ascii', True, 'whether to colorize the hexdump command ascii section')
        self.add_setting('hexdump_ascii_block_separator', '│', 'block separator char of the hexdump command')
        self.offset = 0
        self.last_address = 0

    @pwngef.proc.OnlyWhenRunning
    def do_invoke(self, argv):
        width = self.get_setting('hexdump_width')
        count = self.get_setting('hexdump_bytes')
        if not argv:
            message.warn("No arguments found! Default dump %d byte by $sp" % count)
            address = int(pwngef.arch.CURRENT_ARCH.sp)
        else:
            count = int(gdb.parse_and_eval(argv[0])) if len(argv) > 1 else count
            address = int(gdb.parse_and_eval(argv[0]))

        data = pwngef.memory.read(address, count, partial=True)
        for _, line in enumerate(pwngef.hexdump.hexdump(data, address=address, width=width)):
            print(line)
        return None

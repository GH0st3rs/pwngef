#!/usr/bin/python
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import signal

import gdb

import pwngef.arch
import pwngef.color
import pwngef.commands
import pwngef.commands.context
import pwngef.commands.heap
import pwngef.commands.hexdump
import pwngef.commands.ida
import pwngef.commands.next
import pwngef.commands.pcustom
import pwngef.commands.registers
import pwngef.commands.theme
import pwngef.commands.self
import pwngef.disassemble
import pwngef.exception
import pwngef.functions
import pwngef.handlers
import pwngef.memory
import pwngef.proc
import pwngef.prompt
import pwngef.regs
import pwngef.typeinfo
import pwngef.ui


__version__ = '0.1.0'
version = __version__


__all__ = [
    'arch',
    'chain',
    'color',
    'events',
    'heap',
    'hexdump',
    'ida',
    'memoize',
    'memory',
    'proc',
    'regs',
    'typeinfo',
    'ui',
]

gdb.prompt_hook = pwngef.prompt.set_prompt


pre_commands = [
    'set confirm off',
    'set verbose off',
    'set pagination off',
    'set height 0',
    'set history expansion on',
    'set history save on',
    'set follow-fork-mode child',
    'set backtrace past-main on',
    'set step-mode on',
    'set print pretty on',
    'set width %i' % pwngef.ui.get_window_size()[1],
    'handle SIGALRM nostop print nopass',
    'handle SIGBUS  stop   print nopass',
    'handle SIGPIPE nostop print nopass',
    'handle SIGSEGV stop   print nopass',
]

for line in pre_commands:
    gdb.execute(line.strip())

try:
    # this will raise a gdb.error unless we're on x86
    gdb.execute("set disassembly-flavor intel")
except gdb.error:
    # we can safely ignore this
    pass

# handle resize event to align width and completion
signal.signal(signal.SIGWINCH, lambda signum, frame: gdb.execute("set width %i" % pwngef.ui.get_window_size()[1]))

# More info: https://sourceware.org/bugzilla/show_bug.cgi?id=21946
# As stated on GDB's bugzilla that makes remote target search slower.
# After GDB gets the fix, we should disable this only for bugged GDB versions.
if 1:
    gdb.execute('set remote search-memory-packet off')


pwngef.events.cont(pwngef.handlers.continue_handler)
pwngef.events.stop(pwngef.handlers.hook_stop_handler)
pwngef.events.new_objfile(pwngef.handlers.new_objfile_handler)
pwngef.events.exit(pwngef.handlers.exit_handler)

if gdb.progspaces()[0].filename is not None:
    pwngef.arch.update()

pwngef.commands.self.SelfAliases()
pwngef.commands.self.SelfTmuxSetup()

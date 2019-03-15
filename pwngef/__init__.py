#!/usr/bin/python
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import signal

import gdb

# import pwngef.android
import pwngef.arch
# import pwngef.arguments
# import pwngef.argv
import pwngef.color
import pwngef.commands
# import pwngef.commands.argv
# import pwngef.commands.aslr
# import pwngef.commands.auxv
# import pwngef.commands.canary
# import pwngef.commands.checksec
# import pwngef.commands.config
import pwngef.commands.context
# import pwngef.commands.cpsr
# import pwngef.commands.dt
# import pwngef.commands.dumpargs
# import pwngef.commands.elf
# import pwngef.commands.gdbinit
# import pwngef.commands.got
import pwngef.commands.heap
import pwngef.commands.hexdump
import pwngef.commands.ida
# import pwngef.commands.misc
import pwngef.commands.next
import pwngef.commands.pcustom
# import pwngef.commands.peda
# import pwngef.commands.pie
# import pwngef.commands.probeleak
# import pwngef.commands.procinfo
# import pwngef.commands.radare2
# import pwngef.commands.reload
# import pwngef.commands.rop
# import pwngef.commands.ropper
import pwngef.commands.registers
# import pwngef.commands.search
# import pwngef.commands.segments
# import pwngef.commands.shell
# import pwngef.commands.stack
# import pwngef.commands.start
# import pwngef.commands.telescope
import pwngef.commands.theme
# import pwngef.commands.version
# import pwngef.commands.vmmap
# import pwngef.commands.windbg
# import pwngef.commands.xinfo
# import pwngef.commands.xor
import pwngef.commands.gef
# import pwngef.constants
import pwngef.disassemble
# import pwngef.disasm.arm
# import pwngef.disasm.jump
# import pwngef.disasm.mips
# import pwngef.disasm.ppc
# import pwngef.disasm.sparc
# import pwngef.disasm.x86
# import pwngef.dt
# import pwngef.elf
import pwngef.exception
import pwngef.functions
# import pwngef.gdbutils.functions
# import pwngef.heap
import pwngef.handlers
# import pwngef.inthook
import pwngef.memory
# import pwngef.net
import pwngef.proc
import pwngef.prompt
import pwngef.regs
# import pwngef.stack
import pwngef.typeinfo
import pwngef.ui
# import pwngef.version
# import pwngef.vmmap
# import pwngef.wrappers
# import pwngef.wrappers.checksec
# import pwngef.wrappers.readelf

__version__ = '0.1.0'
version = __version__


__all__ = [
    'arch',
    'auxv',
    'chain',
    'color',
    'disasm',
    'dt',
    'elf',
    'enhance',
    'events',
    'file',
    'function',
    'heap',
    'hexdump',
    'ida',
    'info',
    'linkmap',
    'malloc',
    'memoize',
    'memory',
    'proc',
    'regs',
    'remote',
    'search',
    'stack',
    'strings',
    'symbol',
    'typeinfo',
    'ui',
    'vmmap'
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

# Workaround for gdb bug described in #321 ( https://github.com/pwngef/pwngef/issues/321 )
# More info: https://sourceware.org/bugzilla/show_bug.cgi?id=21946
# As stated on GDB's bugzilla that makes remote target search slower.
# After GDB gets the fix, we should disable this only for bugged GDB versions.
if 1:
    gdb.execute('set remote search-memory-packet off')


pwngef.events.cont(pwngef.handlers.continue_handler)
pwngef.events.stop(pwngef.handlers.hook_stop_handler)
pwngef.events.new_objfile(pwngef.handlers.new_objfile_handler)
pwngef.events.exit(pwngef.handlers.exit_handler)

if gdb.current_progspace().filename is not None:
    pwngef.arch.update()

pwngef.commands.gef.GefAliases()
pwngef.commands.gef.GefTmuxSetup()

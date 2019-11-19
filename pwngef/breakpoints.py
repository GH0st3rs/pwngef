#!/usr/bin/python
import gdb
import pwngef.arch


class IdaTraceFunctionBreakpoint(gdb.Breakpoint):
    """Track ida basic blocks done."""

    def stop(self):
        pc = int(pwngef.arch.CURRENT_ARCH.pc)
        gdb.execute('ida SetBbColor %#x' % pc, from_tty=False)
        return False

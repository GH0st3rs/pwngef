#!/usr/bin/python
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import gdb
import pwngef.arch


class IdaTraceFunctionBreakpoint(gdb.Breakpoint):
    """Track ida basic blocks done."""

    def stop(self):
        pc = int(pwngef.arch.CURRENT_ARCH.pc)
        gdb.execute('ida SetBbColor %#x' % pc, from_tty=False)
        return False

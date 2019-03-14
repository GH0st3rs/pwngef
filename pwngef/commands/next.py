#!/usr/bin/python
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import gdb


class StepOver(gdb.Command):
    """Greet the whole world."""

    def __init__(self):
        super(StepOver, self).__init__("next", gdb.COMMAND_RUNNING)

    def invoke(self, arg, from_tty):
        pc = int(gdb.parse_and_eval('$pc'))
        gdb.Breakpoint('*%#x' % (pc + 8), internal=True, temporary=True)
        gdb.execute('continue', from_tty=False, to_string=False)


StepOver()

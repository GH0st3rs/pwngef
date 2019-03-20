#!/usr/bin/python
"""
Information about whether the debuggee is local (under GDB) or remote
(under GDBSERVER or QEMU stub).
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import gdb

__pwngef_remote__ = None
__pwngef_qemu_mode__ = False


def is_remote():
    # N.B.: We cannot use "info program" because of:
    # https://sourceware.org/bugzilla/show_bug.cgi?id=18335
    #
    # return 'serial line' in gdb.execute('info program',to_string=True,)
    info_file = gdb.execute('info file', to_string=True, from_tty=False)

    # target remote
    if 'Remote serial target' in info_file:
        return True

    # target extended-remote
    if 'Extended remote serial target' in info_file:
        return True

    if 'Debugging a target over a serial line.' in info_file:
        return True

    return False

#!/usr/bin/python
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import shutil
import gdb

import pwngef.events
import pwngef.config
import pwngef.arch


def continue_handler(event):
    """GDB event handler for new object continue cases."""
    return


def hook_stop_handler(event):
    """GDB event handler for stop cases."""
    pwngef.events.reset_all_caches()
    gdb.execute("context")
    return


def new_objfile_handler(event):
    """GDB event handler for new object file cases."""
    print('new_objfile_handler')
    pwngef.events.reset_all_caches()
    pwngef.arch.set_arch()
    return


def exit_handler(event):
    """GDB event handler for exit cases."""
    pwngef.events.reset_all_caches()
    pwngef.remote.__pwngef_qemu_mode__ = False
    if pwngef.remote.__pwngef_remote__ and pwngef.config.get("pwngef-remote.clean_on_exit") is True:
        shutil.rmtree("/tmp/pwngef/{:d}".format(pwngef.remote.__pwngef_remote__))
        pwngef.remote.__pwngef_remote__ = None
    return

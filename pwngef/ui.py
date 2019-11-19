#!/usr/bin/python
"""
A few helpers for making things print pretty-like.
"""
import fcntl
import os
import struct
import sys
import termios
import gdb


def get_window_size():
    fallback = (int(os.environ.get('LINES', 20)), int(os.environ.get('COLUMNS', 80)))
    if not sys.stdin.isatty:
        return fallback
    try:
        # get terminal size and force ret buffer len of 4 bytes for safe unpacking by passing equally long arg
        rows, cols = struct.unpack('hh', fcntl.ioctl(sys.stdin.fileno(), termios.TIOCGWINSZ, '1234'))
    except:
        rows, cols = fallback
    return rows, cols


def enable_redirect_output(to_file="/dev/null"):
    """Redirect all GDB output to `to_file` parameter. By default, `to_file` redirects to `/dev/null`."""
    gdb.execute("set logging overwrite")
    gdb.execute("set logging file {:s}".format(to_file))
    gdb.execute("set logging redirect on")
    gdb.execute("set logging on")
    return


def disable_redirect_output():
    """Disable the output redirection, if any."""
    gdb.execute("set logging off")
    gdb.execute("set logging redirect off")
    return

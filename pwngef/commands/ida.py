#!/usr/bin/python
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import socket
import gdb

import xmlrpc.client as xmlrpclib

import pwngef.commands
from pwngef.commands import GenericCommand
from pwngef.color import message
from pwngef.color import Color
import pwngef.config
import pwngef.events
from pwngef.breakpoints import IdaTraceFunctionBreakpoint


def connect(host=None, port=None):
    """Connect to the XML-RPC service."""
    def is_target_alive():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((host, port))
            s.close()
        except socket.error:
            return False
        return True
    # get config params
    host = host or pwngef.config.get("ida.host")
    port = port or pwngef.config.get("ida.port")
    try:
        sock = xmlrpclib.ServerProxy("http://{:s}:{:d}".format(host, port))
    finally:
        if not is_target_alive():
            message.error("Failed to connect to '{:s}:{:d}'".format(host, port))
            sock = None
    return sock


@pwngef.commands.register_command
class IdaCommand(GenericCommand):
    """IDA: set of commands to interact with IDA via a XML RPC service
    deployed via the IDA script `ida_script.py`."""

    _cmdline_ = "ida"
    _syntax_ = "{:s} (versions|bp)".format(_cmdline_)

    def __init__(self):
        super(IdaCommand, self).__init__(prefix=True)
        host, port = "127.0.0.1", 1337
        self.add_setting("host", host, "IDA xmlrpc server address")
        self.add_setting("port", port, "IDA xmlrpc server port")

        self._ida = None
        self._breakpoints = set()
        return None

    def disconnect(self):
        self._ida = None
        return None

    def do_invoke(self, argv):
        # check connect
        if self._ida is None:
            # trying to reconnect
            self._ida = connect()
            if self._ida is None:
                self.disconnect()
                return None
        # check help
        if len(argv) == 0 or argv[0] in ("-h", "--help"):
            method_name = argv[1] if len(argv) > 1 else None
            self.usage(method_name)
            return None
        # send methods
        method_name = argv[0]
        if method_name == "versions":
            self.versions = self._ida.versions()
            message.hint('Python: %(python)s\nHexRays: %(hexrays)s\nIDA: %(ida)s' % self.versions)
            return None
        elif method_name == 'bp':
            self.update_breakpoints()
        else:
            method = getattr(self._ida, method_name)
            if len(argv) > 1:
                args = pwngef.commands.parse_arguments(argv[1:])
                res = method(*args)
            else:
                res = method()
            print(res)
        return

    def get_breakpoints(self):
        for i in range(self._ida.GetBptQty()):
            yield self._ida.GetBptEA(i)

    def update_breakpoints(self):
        gdb.execute('delete breakpoints', from_tty=False)
        for bp in self.get_breakpoints():
            message.success('Set new breakpoint at %#x' % bp)
            gdb.Breakpoint('*%#x' % bp)


@pwngef.commands.register_command
class IdaTraceFunctionCommand(GenericCommand):
    """Connect to IDA for trace by function base blocks"""

    _cmdline_ = "ida trace"
    _syntax_ = "{:s} [0xADDRESS|clear]".format(_cmdline_)

    def __init__(self):
        super(IdaTraceFunctionCommand, self).__init__(complete=gdb.COMPLETE_LOCATION, command=gdb.COMMAND_TRACEPOINTS)
        self._ida = None
        self.tracepoints = []
        return None

    def do_invoke(self, argv):
        for _ in range(1):
            self._ida = self._ida or connect()
        if self._ida is None:
            return None
        # Check argv
        if not argv:
            pc = int(pwngef.arch.CURRENT_ARCH.pc)
        elif argv[0] == 'clear':
            for bb_addr in self.tracepoints:
                self._ida.SetBbColor(bb_addr, 0xFFFFFF)
            return None
        else:
            pc = int(argv[0], 16) if argv[0].lower().startswith('0x') else int(argv[0])
        # iterate for base blocks
        for bb_addr in self._ida._get_base_blocks(pc):
            self.tracepoints.append(bb_addr)
            self._ida.SetBbColor(bb_addr, 0xFFFFFF)
            print(Color.cyanify('Set tracepoint at: %#x' % bb_addr))
            IdaTraceFunctionBreakpoint('*%#x' % bb_addr, internal=True, temporary=True)
        return None

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
    # def disassemble(self, addr, nb_insn, nb_prev=0):
    #     line = ''
    #     if prev_count:
    #         start_addr = gdb_get_nth_previous_instruction_address(addr, nb_prev)
    #         line +=
    #     address = gdb.parse_and_eval(addr)
    #     nmemo = ida._ida.GetMnem(address)
    #     operands =
    #     self._ida.GetDisasm(addr).split(' # ')
    #     yield Instruction(address, '', mnemo, operands, comment)


#         method_name = argv[0]
#         if method_name == "version":
#             self.version = self._ida.version()
#             utils.info("Enhancing {:s} with {:s} (v.{:s})".format(
#                 Color.greenify("gef"),
#                 Color.redify(self.version[0]),
#                 Color.yellowify(self.version[1])
#             ))
#             return None

#         if not is_alive():
#             main_base_address = main_end_address = 0
#         else:
#             vmmap = get_process_maps()
#             main_base_address = min([x.page_start for x in vmmap if x.realpath == get_filepath()])
#             main_end_address = max([x.page_end for x in vmmap if x.realpath == get_filepath()])

#         try:
#             if method_name == "Sync":
#                 self.synchronize()
#             else:
#                 method = getattr(self._ida, method_name)
#                 if len(argv) > 1:
#                     args = parsed_arglist(argv[1:])
#                     res = method(*args)
#                 else:
#                     res = method()

#                 if method_name in ("ImportStruct", "ImportStructs"):
#                     self.import_structures(res)
#                 else:
#                     gef_print(str(res))

#             if self.get_setting("sync_cursor") is True:
#                 jump = getattr(self._ida, "Jump")
#                 jump(hex(CURRENT_ARCH.pc - main_base_address),)

#         except socket.error:
#             self.disconnect()
#         return None

#     def synchronize(self):
#         """Submit all active breakpoint addresses to IDA/BN."""
#         pc = CURRENT_ARCH.pc
#         vmmap = get_process_maps()
#         base_address = min([x.page_start for x in vmmap if x.path == get_filepath()])
#         end_address = max([x.page_end for x in vmmap if x.path == get_filepath()])
#         if not (base_address <= pc < end_address):
#             # do not sync in library
#             return None

#         breakpoints = gdb.breakpoints() or []
#         gdb_bps = set()
#         for bp in breakpoints:
#             if bp.enabled and not bp.temporary:
#                 if bp.location[0] == "*":  # if it's an address i.e. location starts with "*"
#                     addr = int(gdb.parse_and_eval(bp.location[1:]))
#                 else:  # it is a symbol
#                     addr = int(gdb.parse_and_eval(bp.location).address)
#                 if not (base_address <= addr < end_address):
#                     continue
#                 gdb_bps.add(addr - base_address)

#         added = gdb_bps - self.old_bps
#         removed = self.old_bps - gdb_bps
#         self.old_bps = gdb_bps

#         try:
#             # it is possible that the server was stopped between now and the last sync
#             rc = self._ida.Sync("{:#x}".format(pc - base_address), list(added), list(removed))
#         except ConnectionRefusedError:
#             self.disconnect()
#             return None

#         ida_added, ida_removed = rc

#         # add new bp from IDA
#         for new_bp in ida_added:
#             location = base_address + new_bp
#             gdb.Breakpoint("*{:#x}".format(location), type=gdb.BP_BREAKPOINT)
#             self.old_bps.add(location)

#         # and remove the old ones
#         breakpoints = gdb.breakpoints() or []
#         for bp in breakpoints:
#             if bp.enabled and not bp.temporary:
#                 if bp.location[0] == "*":  # if it's an address i.e. location starts with "*"
#                     addr = int(gdb.parse_and_eval(bp.location[1:]))
#                 else:  # it is a symbol
#                     addr = int(gdb.parse_and_eval(bp.location).address)

#                 if not (base_address <= addr < end_address):
#                     continue

#                 if (addr - base_address) in ida_removed:
#                     if (addr - base_address) in self.old_bps:
#                         self.old_bps.remove((addr - base_address))
#                     bp.delete()
#         return None


#         if meth is not None:
#             gef_print(utils.titlify(meth))
#             gef_print(self._ida.system.methodHelp(meth))
#             return None

#         for m in self._ida.system.listMethods():
#             if m.startswith("system."):
#                 continue
#             gef_print(utils.titlify(m))
#             gef_print(self._ida.system.methodHelp(m))
#         return None

#     def import_structures(self, structs):
#         if self.version[0] != "IDA Pro":
#             return None

#         path = get_gef_setting("pcustom.struct_path")
#         if path is None:
#             return None

#         if not os.path.isdir(path):
#             gef_makedirs(path)

#         for struct_name in structs:
#             fullpath = os.path.join(path, "{}.py".format(struct_name))
#             with open(fullpath, "w") as f:
#                 f.write("from ctypes import *\n\n\n")
#                 f.write("class ")
#                 f.write(struct_name)
#                 f.write("(BigEndianStructure):\n")
#                 f.write("    _fields_ = [\n")
#                 for _, name, size in structs[struct_name]:
#                     if size == 1:
#                         csize = "c_uint8"
#                     elif size == 2:
#                         csize = "c_uint16"
#                     elif size == 4:
#                         csize = "c_uint32"
#                     elif size == 8:
#                         csize = "c_uint64"
#                     else:
#                         csize = "c_byte * {}".format(size)
#                     m = '        (\"{}\", {}),\n'.format(name, csize)
#                     f.write(m)
#                 f.write("]\n")
#         utils.ok("Success, {:d} structure{:s} imported".format(
#             len(structs),
#             "s" if len(structs) > 1 else ""
#         ))
#         return None

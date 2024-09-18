#!/usr/bin/python
try:
    from xmlrpc.server import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler
except ImportError:
    from SimpleXMLRPCServer import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler
import threading

import idautils
import idc
import idaapi


# Save the database so nothing gets lost.
if idaapi.IDA_SDK_VERSION >= 700:
    idaapi.save_database(idc.GetIdbPath())
else:
    idc.SaveBase(idc.GetIdbPath())


HOST, PORT = "0.0.0.0", 1337
DEBUG = True


# class Gef:
#     """
#     Top level class where exposed methods are declared.
#     """

#     def __init__(self, server, *args, **kwargs):
#         self.server = server
#         self._version = ("IDA Pro", str(idaapi.IDA_SDK_VERSION))
#         return

#     def _dispatch(self, method, params):
#         """
#         Plugin dispatcher
#         """
#         if DEBUG:
#             print("Received '%s'" % method)

#         func = getattr(self, method)
#         if not is_exposed(func):
#             raise NotImplementedError('Method "%s" is not exposed' % method)

#         if DEBUG:
#             print("Executing %s(%s)" % (method, params))
#         return func(*params)

#     def _listMethods(self):
#         """
#         Class method listing (required for introspection API).
#         """
#         m = []
#         for x in list_public_methods(self):
#             if x.startswith("_"):
#                 continue
#             if not is_exposed(getattr(self, x)):
#                 continue
#             m.append(x)
#         return m

#     def _methodHelp(self, method):
#         """
#         Method help (required for introspection API).
#         """
#         f = getattr(self, method)
#         return inspect.getdoc(f)

#     @expose
#     def version(self):
#         """ version() => None
#         Return a tuple containing the tool used and its version
#         Example: ida version
#         """
#         return self._version

#     @expose
#     def shutdown(self):
#         """ shutdown() => None
#         Cleanly shutdown the XML-RPC service.
#         Example: ida shutdown
#         """
#         self.server.server_close()
#         print("[+] XMLRPC server stopped")
#         setattr(self.server, "shutdown", True)
#         return 0

#     @expose
#     def MakeComm(self, address, comment):
#         """ MakeComm(int addr, string comment) => None
#         Add a comment to the current IDB at the location `address`.
#         Example: ida MakeComm 0x40000 "Important call here!"
#         """
#         addr = int(address, 16) if ishex(address) else int(address)
#         return idc.MakeComm(addr, comment)

#     @expose
#     def SetColor(self, address, color="0x005500"):
#         """ SetColor(int addr [, int color]) => None
#         Set the location pointed by `address` in the IDB colored with `color`.
#         Example: ida SetColor 0x40000
#         """
#         addr = int(address, 16) if ishex(address) else int(address)
#         color = int(color, 16) if ishex(color) else int(color)
#         return idc.SetColor(addr, idc.CIC_ITEM, color)

#     @expose
#     def MakeName(self, address, name):
#         """ MakeName(int addr, string name]) => None
#         Set the location pointed by `address` with the name specified as argument.
#         Example: ida MakeName 0x4049de __entry_point
#         """
#         addr = int(address, 16) if ishex(address) else int(address)
#         return idc.MakeName(addr, name)

#     @expose
#     def Jump(self, address):
#         """ Jump(int addr) => None
#         Move the IDA EA pointer to the address pointed by `addr`.
#         Example: ida Jump 0x4049de
#         """
#         addr = int(address, 16) if ishex(address) else int(address)
#         return idc.Jump(addr)

#     def GetStructByName(self, name):
#         for (_, struct_sid, struct_name) in idautils.Structs():
#             if struct_name == name:
#                 return struct_sid
#         return None

#     @expose
#     def ImportStruct(self, struct_name):
#         """ ImportStruct(string name) => dict
#         Import an IDA structure in GDB which can be used with the `pcustom`
#         command.
#         Example: ida ImportStruct struct_1
#         return: {struct_name: [(type, param, size), ...]}
#         """
#         struct_sid = self.GetStructByName(struct_name)
#         if struct_sid is None:
#             return {}

#         def gmi(y): return idc.GetType(idc.GetMemberId(struct_sid, y))
#         res = {struct_name: [(gmi(x[0]), x[1], x[2]) for x in idautils.StructMembers(struct_sid)]}
#         return res

#     @expose
#     def ImportStructs(self):
#         """ ImportStructs() => dict
#         Import all structures from the current IDB into GDB, to be used with the `pcustom`
#         command.
#         Example: ida ImportStructs
#         """
#         res = {}
#         for s in idautils.Structs():
#             res.update(self.ImportStruct(s[2]))
#         return res

#     @expose
#     def Sync(self, offset, added, removed):
#         """ Sync(offset, added, removed) => None
#         Synchronize debug info with gef. This is an internal function. It is
#         not recommended using it from the command line.
#         """
#         global _breakpoints, _current_instruction, _current_instruction_color

#         if _current_instruction > 0:
#             idc.SetColor(_current_instruction, idc.CIC_ITEM, _current_instruction_color)

#         base_addr = idaapi.get_imagebase()
#         pc = base_addr + int(offset, 16)
#         _current_instruction = int(pc)
#         _current_instruction_color = idc.GetColor(_current_instruction, idc.CIC_ITEM)
#         idc.SetColor(_current_instruction, idc.CIC_ITEM, 0x00ff00)
#         print("PC @ %#x" % _current_instruction)
#         # post it to the ida main thread to prevent race conditions
#         idaapi.execute_sync(lambda: idc.Jump(_current_instruction), idaapi.MFF_WRITE)

#         cur_bps = set([idc.GetBptEA(n) - base_addr for n in range(idc.GetBptQty())])
#         ida_added = cur_bps - _breakpoints
#         ida_removed = _breakpoints - cur_bps
#         _breakpoints = cur_bps

#         # update bp from gdb
#         for bp in added:
#             idc.AddBpt(base_addr + bp)
#             _breakpoints.add(bp)
#         for bp in removed:
#             if bp in _breakpoints:
#                 _breakpoints.remove(bp)
#             idc.DelBpt(base_addr + bp)

#         return [list(ida_added), list(ida_removed)]


class PwnGef:
    def __init__(self, server, *args, **kwargs):
        self.server = server

    def _dispatch(self, method, params):
        """
        Plugin dispatcher
        """
        if DEBUG:
            print("Received '%s'" % method)
        if not hasattr(self, method):
            raise NotImplementedError('Method "%s" is not exposed' % method)
        func = getattr(self, method)
        if DEBUG:
            print("Executing %s(%s)" % (method, params))
        return func(*params)

    def shutdown(self):
        """ shutdown() => None
        Cleanly shutdown the XML-RPC service.
        Example: ida shutdown
        """
        self.server.server_close()
        # self.server.shutdown()
        print("[+] XMLRPC server stopped")
        setattr(self.server, "shutdown", True)
        return None

    def SetBbColor(self, ea=None, color=0x55ff7f):
        ''' SetBbColor(ea, color) => None
        Set Color for selected base block (default color = green)
        Example: ida SetBbColor 0x456789 [0xFFFFFF]
        '''
        def get_bb(graph, ea):
            for block in graph:
                if block.startEA <= ea and block.endEA > ea:
                    return block

        f = idaapi.get_func(ea)
        g = idaapi.FlowChart(f, flags=idaapi.FC_PREDS)
        bb = get_bb(g, ea)
        # create color node
        p = idaapi.node_info_t()
        p.bg_color = color
        # Set Color
        idaapi.set_node_info2(f.start_ea, bb.id, p, idaapi.NIF_BG_COLOR | idaapi.NIF_FRAME_COLOR)
        idaapi.refresh_idaview_anyway()
        return None

    def _get_base_blocks(self, ea):
        '''Received list of base blocks for current function'''
        function = idaapi.get_func(ea)
        flowchart = idaapi.FlowChart(function)
        bb_list = []
        for bb in flowchart:
            bb_list.append(bb.start_ea)
        return bb_list

    def GetFuncItems(self, ea=None):
        result = []
        for i in map(int, idautils.FuncItems(ea)):
            result.append(i)
        if result:
            pre = list(map(int, idautils.FuncItems(result[0] - 1)))
            post = list(map(int, idautils.FuncItems(result[-1] + 1)))
            result = pre + result + post
        return result


class ReqHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ("/RPC2",)


def versions():
    """Returns IDA & Python versions"""
    import sys
    return {
        'python': sys.version,
        'ida': idaapi.get_kernel_version(),
        'hexrays': idaapi.get_hexrays_version() if idaapi.init_hexrays_plugin() else None
    }


def start_xmlrpc_server():
    """
    Initialize the XMLRPC thread
    """
    def register_module(module):
        for name, function in module.__dict__.items():
            if hasattr(function, '__call__'):
                server.register_function(function, name)

    print("[+] Starting XMLRPC server: {}:{}".format(HOST, PORT))
    server = SimpleXMLRPCServer((HOST, PORT), requestHandler=ReqHandler, logRequests=False, allow_none=True)
    # register ida python modules
    register_module(idc)
    register_module(idautils)
    register_module(idaapi)
    server.register_function(versions)
    server.register_introspection_functions()
    server.register_instance(PwnGef(server))
    print("[+] Registered {} functions.".format(len(server.system_listMethods())))
    while True:
        if hasattr(server, "shutdown") and server.shutdown is True:
            break
        server.handle_request()
    return


if __name__ == "__main__":
    t = threading.Thread(target=start_xmlrpc_server, args=())
    t.daemon = True
    print("[+] Creating new thread for XMLRPC server: {}".format(t.name))
    t.start()

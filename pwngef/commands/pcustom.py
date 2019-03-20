#!/usr/bin/python
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import os
import gdb

import pwngef.config
import pwngef.proc
import pwngef.commands
from pwngef.commands import GenericCommand
from pwngef.color import message


@pwngef.commands.register_command
class PCustomCommand(GenericCommand):
    """Dump user defined structure.
    This command attempts to reproduce WinDBG awesome `dt` command for GDB and allows
    to apply structures (from symbols or custom) directly to an address.
    Custom structures can be defined in pure Python using ctypes, and should be stored
    in a specific directory, whose path must be stored in the `pcustom.struct_path`
    configuration setting."""

    _cmdline_ = "pcustom"
    _syntax_ = "{:s} [-l] [StructA [0xADDRESS] [-e]]".format(_cmdline_)
    _aliases_ = ['dt', ]

    def __init__(self):
        super(PCustomCommand, self).__init__(complete=gdb.COMPLETE_SYMBOL)
        self.add_setting(
            "struct_path",
            os.path.join(pwngef.config.PWNGEF_TEMP_DIR, "structs"),
            "Path to store/load the structure ctypes files"
        )
        return None

    def do_invoke(self, argv):
        argc = len(argv)
        if argc == 0:
            self.usage()
            return None

        if argv[0] == "-l":
            self.list_custom_structures()
            return None

        modname, structname = argv[0].split(":", 1) if ":" in argv[0] else (argv[0], argv[0])
        structname = structname.split(".", 1)[0] if "." in structname else structname

        if argc == 1:
            self.dump_structure(modname, structname)
            return None

        if argv[1] == "-e":
            self.create_or_edit_structure(modname, structname)
            return None

        if not pwngef.proc.alive:
            return None

        try:
            address = int(gdb.parse_and_eval(argv[1]))
        except gdb.error:
            message.error("Failed to parse '{:s}'".format(argv[1]))
            return None

        self.apply_structure_to_address(modname, structname, address)
        return None

    def get_struct_path(self):
        path = os.path.expanduser(self.get_setting("struct_path"))
        path = os.path.realpath(path)
        return path if os.path.isdir(path) else None

    def pcustom_filepath(self, x):
        p = self.get_struct_path()
        if not p:
            return None
        return os.path.join(p, "{}.py".format(x))

    def is_valid_struct(self, x):
        p = self.pcustom_filepath(x)
        return os.access(p, os.R_OK) if p else None

    def dump_structure(self, mod_name, struct_name):
        # If it's a builtin or defined in the ELF use gdb's `ptype`
        try:
            gdb.execute("ptype struct {:s}".format(struct_name))
            return None
        except gdb.error:
            pass

        self.dump_custom_structure(mod_name, struct_name)
        return None

    def dump_custom_structure(self, mod_name, struct_name):
        if not self.is_valid_struct(mod_name):
            message.error("Invalid structure name '{:s}'".format(struct_name))
            return None

        _class = self.get_class(mod_name, struct_name)
        _offset = 0

        for _name, _type in _class._fields_:
            _size = ctypes.sizeof(_type)
            print("+{:04x} {:s} {:s} ({:#x})".format(_offset, _name, _type.__name__, _size))
            _offset += _size
        return None

    def deserialize(self, struct, data):
        length = min(len(data), ctypes.sizeof(struct))
        ctypes.memmove(ctypes.addressof(struct), data, length)
        return None

    def get_module(self, modname):
        _fullname = self.pcustom_filepath(modname)
        return imp.load_source(modname, _fullname)

    def get_class(self, modname, classname):
        _mod = self.get_module(modname)
        return getattr(_mod, classname)()

    def list_all_structs(self, modname):
        _mod = self.get_module(modname)
        _invalid = set(["BigEndianStructure", "LittleEndianStructure", "Structure"])
        _structs = set([x for x in dir(_mod) if inspect.isclass(getattr(_mod, x)) and issubclass(getattr(_mod, x), ctypes.Structure)])
        return _structs - _invalid

    def apply_structure_to_address(self, mod_name, struct_name, addr, depth=0):
        if not self.is_valid_struct(mod_name):
            message.error("Invalid structure name '{:s}'".format(struct_name))
            return None

        try:
            _class = self.get_class(mod_name, struct_name)
            data = read_memory(addr, ctypes.sizeof(_class))
        except gdb.MemoryError:
            message.error("{}Cannot reach memory {:#x}".format(" " * depth, addr))
            return None

        self.deserialize(_class, data)

        _regsize = get_memory_alignment()
        _offset = 0

        for field in _class._fields_:
            _name, _type = field
            _size = ctypes.sizeof(_type)
            _value = getattr(_class, _name)

            if (_regsize == 4 and _type is ctypes.c_uint32) \
               or (_regsize == 8 and _type is ctypes.c_uint64) \
               or (_regsize == ctypes.sizeof(ctypes.c_void_p) and _type is ctypes.c_void_p):
                # try to dereference pointers
                _value = RIGHT_ARROW.join(DereferenceCommand.dereference_from(_value))

            line = []
            line += "  " * depth
            line += ("{:#x}+0x{:04x} {} : ".format(addr, _offset, _name)).ljust(40)
            line += "{} ({})".format(_value, _type.__name__)
            parsed_value = self.get_ctypes_value(_class, _name, _value)
            if parsed_value:
                line += " {} {}".format(RIGHT_ARROW, parsed_value)
            print("".join(line))

            if issubclass(_type, ctypes.Structure):
                self.apply_structure_to_address(mod_name, _type.__name__, addr + _offset, depth + 1)
                _offset += ctypes.sizeof(_type)
            else:
                _offset += _size
        return None

    def get_ctypes_value(self, struct, item, value):
        if not hasattr(struct, "_values_"):
            return ""
        values_list = getattr(struct, "_values_")
        default = ""
        for name, values in values_list:
            if name != item:
                continue
            if callable(values):
                return values(value)
            try:
                for val, desc in values:
                    if value == val:
                        return desc
                    if val is None:
                        default = desc
            except:
                message.error("Error while trying to obtain values from _values_[\"{}\"]".format(name))

        return default

    def create_or_edit_structure(self, mod_name, struct_name):
        path = self.get_struct_path()
        if path is None:
            message.error("Invalid struct path")
            return None

        fullname = self.pcustom_filepath(mod_name)
        if not self.is_valid_struct(mod_name):
            message.hint("Creating '{:s}' from template".format(fullname))
            with open(fullname, "w") as f:
                f.write(self.get_template(struct_name))
                f.flush()
        else:
            message.hint("Editing '{:s}'".format(fullname))

        cmd = os.getenv("EDITOR").split() if os.getenv("EDITOR") else ["nano", ]
        cmd.append(fullname)
        retcode = subprocess.call(cmd)
        return retcode

    def get_template(self, structname):
        d = [
            "from ctypes import *\n\n\n",
            "class ", structname, "(BigEndianStructure):\n",
            "    _fields_ = []\n"
        ]
        return "".join(d)

    def list_custom_structures(self):
        path = self.get_struct_path()
        if path is None:
            message.error("Cannot open '{0}': check directory and/or `gef config {0}` "
                          "setting, currently: '{1}'".format("pcustom.struct_path", self.get_setting("struct_path")))
            return None

        message.hint("Listing custom structures from '{:s}'".format(path))
        for filen in os.listdir(path):
            name, ext = os.path.splitext(filen)
            if ext != ".py":
                continue
            _modz = self.list_all_structs(name)
            message.success("{:s} {:s} ({:s})".format(RIGHT_ARROW, name, ", ".join(_modz)))
        return None

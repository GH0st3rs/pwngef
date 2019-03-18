#!/usr/bin/python
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import abc
import sys

import gdb
from pwngef.color import Color
from pwngef.color import message
import pwngef.config

__commands__ = []


def register_command(cls):
    """Decorator for registering new PWNGEF (sub-)command to GDB."""
    sys.modules[__name__].__commands__.append(cls)
    return cls


def register_priority_command(cls):
    """Decorator for registering new command with priority, meaning that it must
    loaded before the other generic commands."""
    sys.modules[__name__].__commands__.insert(0, cls)
    return cls


class GenericCommand(gdb.Command):
    """This is an abstract class for invoking commands, should not be instantiated."""
    __metaclass__ = abc.ABCMeta

    def __init__(self, *args, **kwargs):
        self.pre_load()
        syntax = Color.yellowify("\nSyntax: ") + self._syntax_
        example = Color.yellowify("\nExample: ") + self._example_ if self._example_ else ""
        self.__doc__ = self.__doc__.replace(" " * 4, "") + syntax + example
        self.repeat = False
        self.repeat_count = 0
        self.__last_command = None
        command_type = kwargs.setdefault("command", gdb.COMMAND_OBSCURE)
        complete_type = kwargs.setdefault("complete", gdb.COMPLETE_NONE)
        prefix = kwargs.setdefault("prefix", False)
        super(GenericCommand, self).__init__(self._cmdline_, command_type, complete_type, prefix)
        self.post_load()
        return None

    def invoke(self, args, from_tty):
        try:
            argv = gdb.string_to_argv(args)
            self.__set_repeat_count(argv, from_tty)
            self.do_invoke(argv)
        except Exception as e:
            message.error("Command '{:s}' failed to execute properly, reason: {:s}".format(self._cmdline_, str(e)))
        return None

    def usage(self):
        message.error("Syntax\n{}".format(self._syntax_))
        return None

    @abc.abstractproperty
    def _cmdline_(self):
        pass

    @abc.abstractproperty
    def _syntax_(self):
        pass

    @abc.abstractproperty
    def _example_(self):
        return ""

    @abc.abstractmethod
    def do_invoke(self, argv):
        pass

    def pre_load(self):
        pass

    def post_load(self):
        pass

    def __get_setting_name(self, name):
        def __sanitize_class_name(clsname):
            if " " not in clsname:
                return clsname
            return "-".join(clsname.split())

        class_name = __sanitize_class_name(self.__class__._cmdline_)
        return "{:s}.{:s}".format(class_name, name)

    @property
    def settings(self):
        """Return the list of settings for this command."""
        return pwngef.config.get_command(self._cmdline_)

    def get_setting(self, name):
        key = self.__get_setting_name(name)
        setting = pwngef.config.get(key)
        return setting

    def has_setting(self, name):
        key = self.__get_setting_name(name)
        return pwngef.config.has(key)

    def add_setting(self, name, value, description=""):
        name = '%s.%s' % (self._cmdline_, name)
        return pwngef.config.set(name, value, description)

    def del_setting(self, name):
        key = self.__get_setting_name(name)
        return pwngef.config.delete(key)

    def __set_repeat_count(self, argv, from_tty):
        if not from_tty:
            self.repeat = False
            self.repeat_count = 0
            return None

        command = gdb.execute("show commands", to_string=True).strip().split("\n")[-1]
        self.repeat = self.__last_command == command
        self.repeat_count = self.repeat_count + 1 if self.repeat else 0
        self.__last_command = command
        return None


def parse_arguments(args):
    result = []
    for item in args:
        if item.isdigit():
            result.append(int(item))
        if item.lower().startswith('0x'):
            result.append(int(item, 16))
        else:
            result.append(item)
    return result

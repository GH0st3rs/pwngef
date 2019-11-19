#!/usr/bin/python
import pwngef.commands
from pwngef.commands import GenericCommand
from pwngef.color import Color
from pwngef.color import message


@pwngef.commands.register_priority_command
class GefThemeCommand(GenericCommand):
    """Customize PWNGEF appearance."""
    _cmdline_ = "theme"
    _syntax_ = "{:s} [KEY [VALUE]]".format(_cmdline_)

    def __init__(self, *args, **kwargs):
        super(GefThemeCommand, self).__init__()
        self.add_setting("context_title_line", "gray", "Color of the borders in context window")
        self.add_setting("context_title_message", "cyan", "Color of the title in context window")
        self.add_setting("default_title_line", "gray", "Default color of borders")
        self.add_setting("default_title_message", "cyan", "Default color of title")
        self.add_setting("table_heading", "blue", "Color of the column headings to tables (e.g. vmmap)")
        self.add_setting("disassemble_current_instruction", "green", "Color to use to highlight the current $pc when disassembling")
        self.add_setting("dereference_string", "yellow", "Color of dereferenced string")
        self.add_setting("dereference_code", "gray", "Color of dereferenced code")
        self.add_setting("dereference_base_address", "cyan", "Color of dereferenced address")
        self.add_setting("dereference_register_value", "bold blue", "Color of dereferenced register")
        self.add_setting("registers_register_name", "blue", "Color of the register name in the register window")
        self.add_setting("registers_value_changed", "bold red", "Color of the changed register in the register window")
        self.add_setting("address_stack", "pink", "Color to use when a stack address is found")
        self.add_setting("address_heap", "green", "Color to use when a heap address is found")
        self.add_setting("address_code", "red", "Color to use when a code address is found")
        self.add_setting("source_current_line", "green", "Color to use for the current code line in the source window")
        self.add_setting('chain_arrow_left', '◂—', 'left arrow of chain formatting')
        self.add_setting('chain_arrow_right', '—▸', 'right arrow of chain formatting')
        return None

    def do_invoke(self, args):
        self.dont_repeat()
        argc = len(args)

        if argc == 0:
            for setting in sorted(self.settings):
                value = self.get_setting(setting)
                value = Color.colorify(value, value)
                print("{:40s}: {:s}".format(setting, value))
            return None

        setting = args[0]
        if not self.has_setting(setting):
            message.error("Invalid key")
            return None

        if argc == 1:
            value = self.get_setting(setting)
            value = Color.colorify(value, value)
            print("{:40s}: {:s}".format(setting, value))
            return None

        val = [x for x in args[1:] if x in Color.colors]
        self.add_setting(setting, " ".join(val))
        return None

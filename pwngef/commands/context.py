#!/usr/bin/python
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import sys
import os
import re
import collections
import gdb

import pwngef.config
import pwngef.commands
from pwngef.commands import GenericCommand
import pwngef.commands.registers
from pwngef.color import Color
from pwngef.color import message
import pwngef.proc
import pwngef.ui
import pwngef.regs
import pwngef.hexdump
import pwngef.chain
import pwngef.disassemble as disass


context_hidden = pwngef.config.set('context.context_hidden', False, 'Hide context messages')
config_arrow_right = pwngef.config.set('theme.chain_arrow_right', '—▸', 'right arrow of chain formatting')


def clear_screen():
    """
    Clear the screen by moving the cursor to top-left corner and
    clear the content
    """
    sys.stdout.write('\x1b[H\x1b[J')


@pwngef.commands.register_command
class ContextCommand(GenericCommand):
    """Displays a comprehensive and modular summary of runtime context. Unless setting `enable` is
    set to False, this command will be spawned automatically every time GDB hits a breakpoint, a
    watchpoint, or any kind of interrupt. By default, it will show panes that contain the register
    states, the stack, and the disassembly code around $pc."""

    _cmdline_ = "context"
    _syntax_ = "{:s} [legend|regs|stack|code|args|memory|source|trace|threads|extra]".format(_cmdline_)
    _aliases_ = ["ctx", ]

    old_registers = {}

    def __init__(self):
        super(ContextCommand, self).__init__()
        self.add_setting("enable", True, "Enable/disable printing the context when breaking")
        self.add_setting("show_stack_raw", False, "Show the stack pane as raw hexdump (no dereference)")
        self.add_setting("show_registers_raw", False, "Show the registers pane with raw values (no dereference)")
        self.add_setting("peek_calls", True, "Peek into calls")
        self.add_setting("peek_ret", True, "Peek at return address")
        self.add_setting("nb_lines_stack", 8, "Number of line in the stack pane")
        self.add_setting("grow_stack_down", False, "Order of stack downward starts at largest down to stack pointer")
        self.add_setting("nb_lines_backtrace", 10, "Number of line in the backtrace pane")
        self.add_setting("nb_lines_threads", -1, "Number of line in the threads pane")
        self.add_setting("nb_lines_code", 6, "Number of instruction after $pc")
        self.add_setting("nb_lines_code_prev", 3, "Number of instruction before $pc")
        self.add_setting("ignore_registers", "", "Space-separated list of registers not to display (e.g. '$cs $ds $gs')")
        self.add_setting("clear_screen", False, "Clear the screen before printing the context")
        self.add_setting("layout", "legend regs code stack args source memory threads trace extra", "Change the order/presence of the context sections")
        self.add_setting("redirect", "", "Redirect the context information to another TTY")

        if "capstone" in list(sys.modules.keys()):
            self.add_setting("use_capstone", False, "Use capstone as disassembler in the code pane (instead of GDB)")
        self.add_setting("use_ida", False, "Use IDA as disassembler in the code pane (instead of GDB)")

        self.layout_mapping = {
            "legend": self.show_legend,
            "regs": self.context_regs,
            "stack": self.context_stack,
            "code": self.context_code,
            "args": self.context_args,
            "memory": self.context_memory,
            "source": self.context_source,
            "trace": self.context_trace,
            "threads": self.context_threads,
            "extra": self.context_additional_information,
        }
        return None

    def post_load(self):
        pwngef.events.cont(self.update_registers)
        pwngef.events.cont(self.empty_extra_messages)
        return None

    def show_legend(self):
        if pwngef.config.get("gef.disable_colors") is not True:
            str_color = pwngef.config.get("theme.dereference_string")
            code_addr_color = pwngef.config.get("theme.address_code")
            stack_addr_color = pwngef.config.get("theme.address_stack")
            heap_addr_color = pwngef.config.get("theme.address_heap")
            changed_register_color = pwngef.config.get("theme.registers_value_changed")

            print("[ Legend: {} | {} | {} | {} | {} ]".format(
                Color.colorify("Modified register", changed_register_color),
                Color.colorify("Code", code_addr_color),
                Color.colorify("Heap", heap_addr_color),
                Color.colorify("Stack", stack_addr_color),
                Color.colorify("String", str_color)
            ))
        return None

    @pwngef.proc.OnlyWhenRunning
    def do_invoke(self, argv):
        if not self.get_setting("enable") or context_hidden:
            return None

        if not all(_ in self.layout_mapping for _ in argv):
            self.usage()
            return None

        if len(argv) > 0:
            current_layout = argv
        else:
            current_layout = self.get_setting("layout").strip().split()

        if not current_layout:
            return None

        self.tty_rows, self.tty_columns = pwngef.ui.get_window_size()

        redirect = self.get_setting("redirect")
        if redirect and os.access(redirect, os.W_OK):
            pwngef.ui.enable_redirect_output(to_file=redirect)

        if self.get_setting("clear_screen") and len(argv) == 0:
            clear_screen(redirect)

        for section in current_layout:
            if section[0] == "-":
                continue

            try:
                self.layout_mapping[section]()
            except gdb.MemoryError as e:
                # a MemoryError will happen when $pc is corrupted (invalid address)
                message.error(str(e))

        self.context_title("")

        if redirect and os.access(redirect, os.W_OK):
            pwngef.ui.disable_redirect_output()
        return None

    def context_title(self, m):
        line_color = pwngef.config.get("theme.context_title_line")
        msg_color = pwngef.config.get("theme.context_title_message")

        if not m:
            print(Color.colorify(pwngef.config.HORIZONTAL_LINE * self.tty_columns, line_color))
            return None

        trail_len = len(m) + 6
        title = ""
        title += Color.colorify(
            "{:{padd}<{width}} ".format(
                "",
                width=max(self.tty_columns - trail_len, 0),
                padd=pwngef.config.HORIZONTAL_LINE
            ),
            line_color
        )
        title += Color.colorify(m, msg_color)
        title += Color.colorify(" {:{padd}<4}".format("", padd=pwngef.config.HORIZONTAL_LINE),
                                line_color)
        print(title)
        return None

    def context_regs(self):
        self.context_title("registers")
        ignored_registers = set(self.get_setting("ignore_registers").split())

        if self.get_setting("show_registers_raw") is True:
            regs = set(pwngef.arch.CURRENT_ARCH.all_registers)
            printable_registers = " ".join(list(regs - ignored_registers))
            gdb.execute("registers {}".format(printable_registers))
            return None

        pwngef.commands.registers.print_registers(
            registers=pwngef.arch.CURRENT_ARCH.all_registers,
            old_registers=self.old_registers,
            ignored_registers=ignored_registers,
            flags=pwngef.arch.CURRENT_ARCH.flags_table
        )
        return None

    def context_stack(self):
        self.context_title("stack")

        show_raw = self.get_setting("show_stack_raw")
        nb_lines = self.get_setting("nb_lines_stack")

        try:
            sp = int(pwngef.arch.CURRENT_ARCH.sp)
            if show_raw is True:
                mem = pwngef.memory.read(sp, 0x10 * nb_lines)
                for _, line in enumerate(pwngef.hexdump.hexdump(mem, address=sp)):
                    print(line)
            else:
                for offset in range(nb_lines):
                    print(pwngef.chain.format(sp + (offset * pwngef.arch.ptrsize)))
                # gdb.execute("dereference {:#x} l{:d}".format(sp, nb_lines))
        except gdb.MemoryError:
            message.error("Cannot read memory from $SP (corrupted stack pointer?)")

        return None

    def context_code(self):
        nb_insn = self.get_setting("nb_lines_code")
        nb_insn_prev = self.get_setting("nb_lines_code_prev")
        use_capstone = self.has_setting("use_capstone") and self.get_setting("use_capstone")
        use_ida = self.get_setting("use_ida")
        cur_insn_color = pwngef.config.get("theme.disassemble_current_instruction")
        pc = int(pwngef.arch.CURRENT_ARCH.pc)

        frame = gdb.selected_frame()
        arch_name = "{}:{}".format(pwngef.arch.CURRENT_ARCH.arch.lower(), pwngef.arch.CURRENT_ARCH.mode)

        self.context_title("code:{}".format(arch_name))

        try:
            instruction_iterator = disass.capstone_disassemble if use_capstone else disass.gef_disassemble
            instruction_iterator = disass.ida_disassemble if use_ida else instruction_iterator
            for insn in instruction_iterator(pc, nb_insn, nb_prev=nb_insn_prev):
                line = []
                is_taken = False
                target = None
                text = str(insn)

                if insn.address < pc:
                    line += Color.grayify("   {}".format(text))
                elif insn.address == pc:
                    line += Color.colorify("{:s}{:s}".format(config_arrow_right.rjust(3), text), cur_insn_color)

                    if pwngef.arch.CURRENT_ARCH.is_conditional_branch(insn):
                        is_taken, reason = pwngef.arch.CURRENT_ARCH.is_branch_taken(insn)
                        if is_taken:
                            target = insn.operands[-1].split()[0]
                            reason = "[Reason: {:s}]".format(reason) if reason else ""
                            line += Color.colorify("\tTAKEN {:s}".format(reason), "bold green")
                        else:
                            reason = "[Reason: !({:s})]".format(reason) if reason else ""
                            line += Color.colorify("\tNOT taken {:s}".format(reason), "bold red")
                    elif pwngef.arch.CURRENT_ARCH.is_call(insn) and self.get_setting("peek_calls") is True:
                        target = insn.operands[-1].split()[0]
                    elif pwngef.arch.CURRENT_ARCH.is_ret(insn) and self.get_setting("peek_ret") is True:
                        target = int(pwngef.arch.CURRENT_ARCH.get_ra(insn, frame))
                else:
                    line += "   {}".format(text)

                print("".join(line))
                if target:
                    try:
                        target = int(target, 0)
                    except TypeError:  # Already an int
                        pass
                    except ValueError:
                        # If the operand isn't an address right now we can't parse it
                        continue
                    for i, tinsn in enumerate(instruction_iterator(target, nb_insn)):
                        text = "   {}  {}".format(pwngef.config.DOWN_ARROW if i == 0 else " ", str(tinsn))
                        print(text)
                    break
        except gdb.MemoryError:
            message.error("Cannot disassemble from $PC")
        except Exception:
            import traceback
            print(traceback.format_exc())
        return None

    def context_args(self):
        insn = disass.gef_current_instruction(int(pwngef.arch.CURRENT_ARCH.pc))
        if not pwngef.arch.CURRENT_ARCH.is_call(insn):
            return None

        self.size2type = {
            1: "BYTE",
            2: "WORD",
            4: "DWORD",
            8: "QWORD",
        }

        if insn.operands[-1].startswith(self.size2type[pwngef.arch.CURRENT_ARCH.ptrsize] + " PTR"):
            target = "*" + insn.operands[-1].split()[-1]
        elif "$" + insn.operands[0] in pwngef.arch.CURRENT_ARCH.all_registers:
            target = "*{:#x}".format(int(pwngef.regs.get_register("$" + insn.operands[0])))
        else:
            # is there a symbol?
            ops = " ".join(insn.operands)
            if "<" in ops and ">" in ops:
                # extract it
                target = re.sub(r".*<([^\(> ]*).*", r"\1", ops)
            else:
                # it's an address, just use as is
                target = re.sub(r".*(0x[a-fA-F0-9]*).*", r"\1", ops)

        sym = gdb.lookup_global_symbol(target)
        if sym is None:
            self.print_guessed_arguments(target)
            return None

        if sym.type.code != gdb.TYPE_CODE_FUNC:
            message.error("Symbol '{}' is not a function: type={}".format(target, sym.type.code))
            return None

        self.print_arguments_from_symbol(target, sym)
        return None

    def print_arguments_from_symbol(self, function_name, symbol):
        """If symbols were found, parse them and print the argument adequately."""
        args = []

        for i, f in enumerate(symbol.type.fields()):
            _value = pwngef.arch.CURRENT_ARCH.get_ith_parameter(i)[1]
            _value = pwngef.chain.format(_value)
            _name = f.name or "var_{}".format(i)
            _type = f.type.name or self.size2type[f.type.sizeof]
            args.append("{} {} = {}".format(_type, _name, _value))

        self.context_title("arguments")

        if not args:
            print("{} (<void>)".format(function_name))
            return None

        print("{} (".format(function_name))
        print("   " + ",\n   ".join(args))
        print(")")
        return None

    def print_guessed_arguments(self, function_name):
        """When no symbol, read the current basic block and look for "interesting" instructions."""

        def __get_current_block_start_address():
            pc = int(pwngef.arch.CURRENT_ARCH.pc)
            try:
                block_start = gdb.block_for_pc(pc).start
            except RuntimeError:
                # if stripped, let's roll back 5 instructions
                block_start = disass.gdb_get_nth_previous_instruction_address(pc, 5)
            return block_start

        parameter_set = set()
        pc = int(pwngef.arch.CURRENT_ARCH.pc)
        block_start = __get_current_block_start_address()
        use_capstone = self.has_setting("use_capstone") and self.get_setting("use_capstone")
        use_ida = self.get_setting("use_ida")
        instruction_iterator = disass.capstone_disassemble if use_capstone else disass.gef_disassemble
        instruction_iterator = disass.ida_disassemble if use_ida else instruction_iterator
        function_parameters = pwngef.arch.CURRENT_ARCH.function_parameters
        arg_key_color = pwngef.config.get("theme.registers_register_name")

        insn_count = (pc - block_start) // pwngef.arch.CURRENT_ARCH.instruction_length
        if pwngef.arch.current == 'mips':
            insn_count += 1  # for branch delay slot
        for insn in instruction_iterator(block_start, insn_count):
            if not insn.operands:
                continue
            if pwngef.arch.current == 'i386':
                if insn.mnemonic == "push":
                    parameter_set.add(insn.operands[0])
            else:
                op = "$" + insn.operands[0]
                if op in function_parameters:
                    parameter_set.add(op)
                if pwngef.arch.current == 'x86-64':
                    # also consider extended registers
                    extended_registers = {"$rdi": ["$edi", "$di"],
                                          "$rsi": ["$esi", "$si"],
                                          "$rdx": ["$edx", "$dx"],
                                          "$rcx": ["$ecx", "$cx"],
                                          }
                    for exreg in extended_registers:
                        if op in extended_registers[exreg]:
                            parameter_set.add(exreg)
        # cicle end
        if pwngef.arch.current == 'i386':
            nb_argument = len(parameter_set)
        else:
            nb_argument = 0
            for p in parameter_set:
                nb_argument = max(nb_argument, function_parameters.index(p) + 1)

        args = []
        for i in range(nb_argument):
            _key, _value = pwngef.arch.CURRENT_ARCH.get_ith_parameter(i)
            _value = pwngef.chain.format(int(_value))
            args.append("{} = {}".format(Color.colorify(_key, arg_key_color), _value))

        self.context_title("arguments (guessed)")
        print("{} (".format(function_name))
        if args:
            print("   " + ",\n   ".join(args))
        print(")")
        return None

    def context_source(self):
        try:
            pc = pwngef.arch.CURRENT_ARCH.pc
            symtabline = gdb.find_pc_line(pc)
            symtab = symtabline.symtab
            line_num = symtabline.line - 1     # we substract one because line number returned by gdb start at 1
            if not symtab.is_valid():
                return None

            fpath = symtab.fullname()
            with open(fpath, "r") as f:
                lines = [l.rstrip() for l in f.readlines()]

        except Exception:
            return None

        nb_line = self.get_setting("nb_lines_code")
        fn = symtab.filename
        if len(fn) > 20:
            fn = "{}[...]{}".format(fn[:15], os.path.splitext(fn)[1])
        title = "source:{}+{}".format(fn, line_num + 1)
        cur_line_color = pwngef.config.get("theme.source_current_line")
        self.context_title(title)

        for i in range(line_num - nb_line + 1, line_num + nb_line):
            if i < 0:
                continue

            if i < line_num:
                print(Color.grayify("   {:4d}\t {:s}".format(i + 1, lines[i],)))

            if i == line_num:
                extra_info = self.get_pc_context_info(pc, lines[i])
                prefix = "{}{:4d}\t ".format(config_arrow_right, i + 1)
                leading = len(lines[i]) - len(lines[i].lstrip())
                if extra_info:
                    print("{}{}".format(" " * (len(prefix) + leading), extra_info))
                print(Color.colorify("{}{:s}".format(prefix, lines[i]), cur_line_color))

            if i > line_num:
                try:
                    print("   {:4d}\t {:s}".format(i + 1, lines[i],))
                except IndexError:
                    break
        return None

    def get_pc_context_info(self, pc, line):
        try:
            current_block = gdb.block_for_pc(pc)
            if not current_block.is_valid():
                return ""
            m = collections.OrderedDict()
            while current_block and not current_block.is_static:
                for sym in current_block:
                    symbol = sym.name
                    if not sym.is_function and re.search(r"\W{}\W".format(symbol), line):
                        val = gdb.parse_and_eval(symbol)
                        if val.type.code in (gdb.TYPE_CODE_PTR, gdb.TYPE_CODE_ARRAY):
                            addr = int(val.address)
                            addrs = pwngef.chain.examine_mem_value(addr)
                            if len(addrs) > 2:
                                addrs = [addrs[0], "[...]", addrs[-1]]

                            f = " {:s} ".format(config_arrow_right)
                            val = f.join(addrs)
                        elif val.type.code == gdb.TYPE_CODE_INT:
                            val = hex(int(val))
                        else:
                            continue

                        if symbol not in m:
                            m[symbol] = val
                current_block = current_block.superblock

            if m:
                return "// " + ", ".join(["{}={}".format(Color.yellowify(a), b) for a, b in m.items()])
        except Exception:
            pass
        return ""

    def context_trace(self):
        self.context_title("trace")

        nb_backtrace = self.get_setting("nb_lines_backtrace")
        if nb_backtrace <= 0:
            return None
        orig_frame = current_frame = gdb.selected_frame()
        i = 0

        # backward compat for gdb (gdb < 7.10)
        if not hasattr(gdb, "FrameDecorator"):
            gdb.execute("backtrace {:d}".format(nb_backtrace))
            return None

        while current_frame:
            current_frame.select()
            if not current_frame.is_valid():
                continue

            pc = current_frame.pc()
            name = current_frame.name()
            items = []
            items.append("{:#x}".format(pc))
            if name:
                frame_args = gdb.FrameDecorator.FrameDecorator(current_frame).frame_args() or []
                m = "{}({})".format(Color.greenify(name),
                                    ", ".join(["{}={!s}".format(Color.yellowify(x.sym),
                                                                x.sym.value(current_frame)) for x in frame_args]))
                items.append(m)
            else:
                try:
                    insn = next(disass.gef_disassemble(pc, 1))
                except gdb.MemoryError:
                    break
                items.append(Color.redify("{} {}".format(insn.mnemonic, ", ".join(insn.operands))))

            print("[{}] {}".format(
                Color.colorify("#{}".format(i), "bold pink"),
                config_arrow_right.join(items)
            ))
            current_frame = current_frame.older()
            i += 1
            nb_backtrace -= 1
            if nb_backtrace == 0:
                break

        orig_frame.select()
        return None

    def context_threads(self):
        def reason():
            res = gdb.execute("info program", to_string=True).splitlines()
            if not res:
                return "NOT RUNNING"

            for line in res:
                line = line.strip()
                if line.startswith("It stopped with signal "):
                    return line.replace("It stopped with signal ", "").split(",", 1)[0]
                if line == "The program being debugged is not being run.":
                    return "NOT RUNNING"
                if line == "It stopped at a breakpoint that has since been deleted.":
                    return "TEMPORARY BREAKPOINT"
                if line.startswith("It stopped at breakpoint "):
                    return "BREAKPOINT"
                if line == "It stopped after being stepped.":
                    return "SINGLE STEP"

            return "STOPPED"

        self.context_title("threads")

        threads = gdb.selected_inferior().threads()[::-1]
        idx = self.get_setting("nb_lines_threads")
        if idx > 0:
            threads = threads[0:idx]

        if idx == 0:
            return None

        if not threads:
            message.error("No thread selected")
            return None

        for i, thread in enumerate(threads):
            line = """[{:s}] Id {:d}, Name: "{:s}", """.format(Color.colorify("#{:d}".format(i), "bold pink"),
                                                               thread.num, thread.name or "")
            if thread.is_running():
                line += Color.colorify("running", "bold green")
            elif thread.is_stopped():
                line += Color.colorify("stopped", "bold red")
                line += ", reason: {}".format(Color.colorify(reason(), "bold pink"))
            elif thread.is_exited():
                line += Color.colorify("exited", "bold yellow")
            print(line)
            i += 1
        return None

    def context_additional_information(self):
        if not __context_messages__:
            return None
        self.context_title("extra")
        for level, text in __context_messages__:
            if level == "error":
                message.error(text)
            elif level == "warn":
                message.warn(text)
            elif level == "success":
                message.success(text)
            else:
                message.notice(text)
        return None

    def context_memory(self):
        global __watches__
        for address, opt in sorted(__watches__.items()):
            self.context_title("memory:{:#x}".format(address))
            gdb.execute("hexdump {fmt:s} {address:d} {size:d}".format(
                address=address,
                size=opt[0],
                fmt=opt[1]
            ))

    @classmethod
    def update_registers(cls, event):
        for reg in pwngef.arch.CURRENT_ARCH.all_registers:
            try:
                cls.old_registers[reg] = pwngef.regs.get_register(reg)
            except Exception:
                cls.old_registers[reg] = 0
        return None

    def empty_extra_messages(self, event):
        global __context_messages__
        __context_messages__ = []
        return None

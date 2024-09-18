#!/usr/bin/python
import abc
import gdb

from pwngef.color import Color
import pwngef.proc
import pwngef.arch
from pwngef.chain import lazy_dereference


@pwngef.proc.OnlyWhenRunning
def gdb77_get_register(name):
    if name.startswith('$'):
        name = name[1:]
    return gdb.parse_and_eval('$' + name)


@pwngef.proc.OnlyWhenRunning
def gdb79_get_register(name):
    if name.startswith('$'):
        name = name[1:]
    return gdb.newest_frame().read_register(name)


try:
    gdb.Frame.read_register
    get_register = gdb79_get_register
except AttributeError:
    get_register = gdb77_get_register


def flags_to_human(reg_value, value_table):
    """Return a human readable string showing the flag states."""
    flags = []
    for i in value_table:
        flag_str = Color.boldify(value_table[i].upper()) if reg_value & (1 << i) else value_table[i].lower()
        flags.append(flag_str)
    return "[{}]".format(" ".join(flags))


class Architecture(object):
    """Generic metaclass for the architecture supported by PWNGEF."""
    __metaclass__ = abc.ABCMeta

    @abc.abstractproperty
    def all_registers(self):
        pass

    @abc.abstractproperty
    def instruction_length(self):
        pass

    @abc.abstractproperty
    def nop_insn(self):
        pass

    @abc.abstractproperty
    def return_register(self):
        pass

    @abc.abstractproperty
    def flag_register(self):
        pass

    @abc.abstractproperty
    def flags_table(self):
        pass

    @abc.abstractproperty
    def function_parameters(self):
        pass

    @abc.abstractmethod
    def flag_register_to_human(self, val=None):
        pass

    @abc.abstractmethod
    def is_call(self, insn):
        pass

    @abc.abstractmethod
    def is_ret(self, insn):
        pass

    @abc.abstractmethod
    def is_conditional_branch(self, insn):
        pass

    @abc.abstractmethod
    def is_branch_taken(self, insn):
        pass

    @abc.abstractmethod
    def get_ra(self, insn, frame):
        pass

    special_registers = []

    @property
    def pc(self):
        return get_register("$pc")

    @property
    def sp(self):
        return get_register("$sp")

    @property
    def fp(self):
        return get_register("$fp")

    @property
    def ptrsize(self):
        return pwngef.arch.ptrsize

    def get_ith_parameter(self, i):
        """Retrieves the correct parameter used for the current function call."""
        reg = self.function_parameters[i]
        val = get_register(reg)
        key = reg
        return key, val


class RISCV(Architecture):
    arch = "RISCV"
    mode = "RISCV"

    all_registers = ["$zero", "$ra", "$sp", "$gp", "$x4", "$t0", "$t1",
                     "$t2", "$fp", "$s1", "$a1", "$a2", "$a3", "$a4",
                     "$a5", "$a6", "$a7", "$s2", "$s3", "$s4", "$s5",
                     "$s6", "$s7", "$s8", "$s9", "$s10", "$s11", "$t3",
                     "$t4", "$t5", "$t6"]
    return_register = "$a0"
    function_parameters = ["$a0", "$a1", "$a2", "$a3", "$a4", "$a5", "$a6", "$a7"]
    syscall_register = "$a7"
    syscall_register = "ecall"
    nop_insn = b"\x00\x00\x00\x13"
    # RISC-V has no flags registers
    flag_register = None
    flag_register_to_human = None
    flags_table = None

    @property
    def instruction_length(self):
        return 4

    def is_call(self, insn):
        return insn.mnemonic == "call"

    def is_ret(self, insn):
        mnemo = insn.mnemonic
        if mnemo == "ret":
            return True
        elif (mnemo == "jalr" and insn.operands[0] == "zero" and
              insn.operands[1] == "ra" and insn.operands[2] == 0):
            return True
        elif (mnemo == "c.jalr" and insn.operands[0] == "ra"):
            return True
        return False

    @classmethod
    def mprotect_asm(cls, addr, size, perm):
        raise OSError("Architecture {:s} not supported yet".format(cls.arch))

    def is_conditional_branch(self, insn):
        return insn.mnemonic.startswith("b")

    def is_branch_taken(self, insn):
        def long_to_twos_complement(v):
            """Convert a python long value to its two's complement."""
            if is_elf32():
                if v & 0x80000000:
                    return v - 0x100000000
            elif is_elf64():
                if v & 0x8000000000000000:
                    return v - 0x10000000000000000
            else:
                raise OSError("RISC-V: ELF file is not ELF32 or ELF64. This is not currently supported")
            return v

        mnemo = insn.mnemonic
        condition = mnemo[1:]

        if condition.endswith("z"):
            # r2 is the zero register if we are comparing to 0
            rs1 = get_register(insn.operands[0])
            rs2 = get_register("$zero")
            condition = condition[:-1]
        elif len(insn.operands) > 2:
            # r2 is populated with the second operand
            rs1 = get_register(insn.operands[0])
            rs2 = get_register(insn.operands[1])
        else:
            raise OSError("RISC-V: Failed to get rs1 and rs2 for instruction: `{}`".format(insn))

        # If the conditional operation is not unsigned, convert the python long into
        # its two's complement
        if not condition.endswith("u"):
            rs2 = long_to_twos_complement(rs2)
            rs1 = long_to_twos_complement(rs1)
        else:
            condition = condition[:-1]

        if condition == "eq":
            if rs1 == rs2:
                taken, reason = True, "{}={}".format(rs1, rs2)
            else:
                taken, reason = False, "{}!={}".format(rs1, rs2)
        elif condition == "ne":
            if rs1 != rs2:
                taken, reason = True, "{}!={}".format(rs1, rs2)
            else:
                taken, reason = False, "{}={}".format(rs1, rs2)
        elif condition == "lt":
            if rs1 < rs2:
                taken, reason = True, "{}<{}".format(rs1, rs2)
            else:
                taken, reason = False, "{}>={}".format(rs1, rs2)
        elif condition == "ge":
            if rs1 < rs2:
                taken, reason = True, "{}>={}".format(rs1, rs2)
            else:
                taken, reason = False, "{}<{}".format(rs1, rs2)
        else:
            raise OSError("RISC-V: Conditional instruction `{:s}` not supported yet".format(insn))

        return taken, reason

    def get_ra(self, insn, frame):
        ra = None
        if self.is_ret(insn):
            ra = get_register("$ra")
        elif frame.older():
            ra = frame.older().pc()
        return ra


class ARM(Architecture):
    arch = "ARM"

    all_registers = ["$r0", "$r1", "$r2", "$r3", "$r4", "$r5", "$r6",
                     "$r7", "$r8", "$r9", "$r10", "$r11", "$r12", "$sp",
                     "$lr", "$pc", "$cpsr", ]

    # http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0041c/Caccegih.html
    # return b"\x00\x00\xa0\xe1" # mov r0,r0
    nop_insn = b"\x01\x10\xa0\xe1"  # mov r1,r1
    return_register = "$r0"
    flag_register = "$cpsr"
    flags_table = {
        31: "negative",
        30: "zero",
        29: "carry",
        28: "overflow",
        7: "interrupt",
        6: "fast",
        5: "thumb"
    }
    function_parameters = ["$r0", "$r1", "$r2", "$r3"]
    syscall_register = "$r7"
    syscall_instructions = ["swi 0x0", "swi NR"]

    def is_thumb(self):
        """Determine if the machine is currently in THUMB mode."""
        return pwngef.proc.alive and get_register("$cpsr") & (1 << 5)

    @property
    def pc(self):
        pc = get_register("$pc")
        if self.is_thumb():
            pc += 1
        return pc

    @property
    def mode(self):
        return "THUMB" if self.is_thumb() else "ARM"

    @property
    def instruction_length(self):
        # Thumb instructions have variable-length (2 or 4-byte)
        return None if self.is_thumb() else 4

    def is_call(self, insn):
        mnemo = insn.mnemonic
        call_mnemos = {"bl", "blx"}
        return mnemo in call_mnemos

    def is_ret(self, insn):
        pop_mnemos = {"pop"}
        branch_mnemos = {"bl", "bx"}
        write_mnemos = {"ldr", "add"}
        if insn.mnemonic in pop_mnemos:
            return insn.operands[-1] == " pc}"
        if insn.mnemonic in branch_mnemos:
            return insn.operands[-1] == "lr"
        if insn.mnemonic in write_mnemos:
            return insn.operands[0] == "pc"
        return None

    def flag_register_to_human(self, val=None):
        # http://www.botskool.com/user-pages/tutorials/electronics/arm-7-tutorial-part-1
        if val is None:
            reg = self.flag_register
            val = get_register(reg)
        return flags_to_human(val, self.flags_table)

    def is_conditional_branch(self, insn):
        conditions = {"eq", "ne", "lt", "le", "gt", "ge", "vs", "vc", "mi", "pl", "hi", "ls"}
        return insn.mnemonic[-2:] in conditions

    def is_branch_taken(self, insn):
        mnemo = insn.mnemonic
        # ref: http://www.davespace.co.uk/arm/introduction-to-arm/conditional.html
        flags = dict((self.flags_table[k], k) for k in self.flags_table)
        val = get_register(self.flag_register)
        taken, reason = False, ""

        if mnemo.endswith("eq"):
            taken, reason = bool(val & (1 << flags["zero"])), "Z"
        elif mnemo.endswith("ne"):
            taken, reason = not val & (1 << flags["zero"]), "!Z"
        elif mnemo.endswith("lt"):
            taken, reason = bool(val & (1 << flags["negative"])) != bool(val & (1 << flags["overflow"])), "N!=V"
        elif mnemo.endswith("le"):
            taken, reason = val & (1 << flags["zero"]) or \
                bool(val & (1 << flags["negative"])) != bool(val & (1 << flags["overflow"])), "Z || N!=V"
        elif mnemo.endswith("gt"):
            taken, reason = val & (1 << flags["zero"]) == 0 and \
                bool(val & (1 << flags["negative"])) == bool(val & (1 << flags["overflow"])), "!Z && N==V"
        elif mnemo.endswith("ge"):
            taken, reason = bool(val & (1 << flags["negative"])) == bool(val & (1 << flags["overflow"])), "N==V"
        elif mnemo.endswith("vs"):
            taken, reason = bool(val & (1 << flags["overflow"])), "V"
        elif mnemo.endswith("vc"):
            taken, reason = not val & (1 << flags["overflow"]), "!V"
        elif mnemo.endswith("mi"):
            taken, reason = bool(val & (1 << flags["negative"])), "N"
        elif mnemo.endswith("pl"):
            taken, reason = not val & (1 << flags["negative"]), "N==0"
        elif mnemo.endswith("hi"):
            taken, reason = val & (1 << flags["carry"]) and not val & (1 << flags["zero"]), "C && !Z"
        elif mnemo.endswith("ls"):
            taken, reason = not val & (1 << flags["carry"]) or val & (1 << flags["zero"]), "!C || Z"
        return taken, reason

    def get_ra(self, insn, frame):
        ra = None
        if self.is_ret(insn):
            # If it's a pop, we have to peek into the stack, otherwise use lr
            if insn.mnemonic == "pop":
                ra_addr = pwngef.arch.CURRENT_ARCH.sp + (len(insn.operands) - 1) * pwngef.arch.ptrsize
                ra = lazy_dereference(ra_addr)
            elif insn.mnemonic == "ldr":
                return lazy_dereference(pwngef.arch.CURRENT_ARCH.sp)
            else:  # 'bx lr' or 'add pc, lr, #0'
                return get_register("$lr")
        elif frame.older():
            ra = frame.older().pc()
        return ra

    @classmethod
    def mprotect_asm(cls, addr, size, perm):
        _NR_mprotect = 125
        insns = [
            "push {r0-r2, r7}",
            "mov r0, {:d}".format(addr),
            "mov r1, {:d}".format(size),
            "mov r2, {:d}".format(perm),
            "mov r7, {:d}".format(_NR_mprotect),
            "svc 0",
            "pop {r0-r2, r7}", ]
        return "; ".join(insns)


class AARCH64(ARM):
    arch = "ARM64"
    mode = "ARM"

    all_registers = [
        "$x0", "$x1", "$x2", "$x3", "$x4", "$x5", "$x6", "$x7",
        "$x8", "$x9", "$x10", "$x11", "$x12", "$x13", "$x14", "$x15",
        "$x16", "$x17", "$x18", "$x19", "$x20", "$x21", "$x22", "$x23",
        "$x24", "$x25", "$x26", "$x27", "$x28", "$x29", "$x30", "$sp",
        "$pc", "$cpsr", "$fpsr", "$fpcr",
    ]
    return_register = "$x0"
    flag_register = "$cpsr"
    flags_table = {
        31: "negative",
        30: "zero",
        29: "carry",
        28: "overflow",
        7: "interrupt",
        6: "fast"
    }
    function_parameters = ["$x0", "$x1", "$x2", "$x3", "$x4", "$x5", "$x6", "$x7"]
    syscall_register = "$x8"
    syscall_instructions = ["svc $x0"]

    def is_call(self, insn):
        mnemo = insn.mnemonic
        call_mnemos = {"bl", "blr"}
        return mnemo in call_mnemos

    def flag_register_to_human(self, val=None):
        # http://events.linuxfoundation.org/sites/events/files/slides/KoreaLinuxForum-2014.pdf
        reg = self.flag_register
        if not val:
            val = get_register(reg)
        return flags_to_human(val, self.flags_table)

    @classmethod
    def mprotect_asm(cls, addr, size, perm):
        raise OSError("Architecture {:s} not supported yet".format(cls.arch))

    def is_conditional_branch(self, insn):
        # https://www.element14.com/community/servlet/JiveServlet/previewBody/41836-102-1-229511/ARM.Reference_Manual.pdf
        # sect. 5.1.1
        mnemo = insn.mnemonic
        branch_mnemos = {"cbnz", "cbz", "tbnz", "tbz"}
        return mnemo.startswith("b.") or mnemo in branch_mnemos

    def is_branch_taken(self, insn):
        mnemo, operands = insn.mnemonic, insn.operands
        # flags = dict((self.flags_table[k], k) for k in self.flags_table)
        # val = get_register(self.flag_register)
        taken, reason = False, ""

        if mnemo in {"cbnz", "cbz", "tbnz", "tbz"}:
            reg = operands[0]
            op = get_register(reg)
            if mnemo == "cbnz":
                if op != 0:
                    taken, reason = True, "{}!=0".format(reg)
                else:
                    taken, reason = False, "{}==0".format(reg)
            elif mnemo == "cbz":
                if op == 0:
                    taken, reason = True, "{}==0".format(reg)
                else:
                    taken, reason = False, "{}!=0".format(reg)
            elif mnemo == "tbnz":
                # operands[1] has one or more white spaces in front, then a #, then the number
                # so we need to eliminate them
                i = int(operands[1].strip().lstrip("#"))
                if (op & 1 << i) != 0:
                    taken, reason = True, "{}&1<<{}!=0".format(reg, i)
                else:
                    taken, reason = False, "{}&1<<{}==0".format(reg, i)
            elif mnemo == "tbz":
                # operands[1] has one or more white spaces in front, then a #, then the number
                # so we need to eliminate them
                i = int(operands[1].strip().lstrip("#"))
                if (op & 1 << i) == 0:
                    taken, reason = True, "{}&1<<{}==0".format(reg, i)
                else:
                    taken, reason = False, "{}&1<<{}!=0".format(reg, i)

        if not reason:
            taken, reason = super(AARCH64, self).is_branch_taken(insn)
        return taken, reason


class X86(Architecture):
    arch = "X86"
    mode = "32"

    nop_insn = b"\x90"
    flag_register = "$eflags"
    special_registers = ["$cs", "$ss", "$ds", "$es", "$fs", "$gs", ]
    gpr_registers = ["$eax", "$ebx", "$ecx", "$edx", "$esp", "$ebp", "$esi", "$edi", "$eip", ]
    all_registers = gpr_registers + [flag_register, ] + special_registers
    instruction_length = None
    return_register = "$eax"
    function_parameters = ["$esp", ]
    flags_table = {
        6: "zero",
        0: "carry",
        2: "parity",
        4: "adjust",
        7: "sign",
        8: "trap",
        9: "interrupt",
        10: "direction",
        11: "overflow",
        16: "resume",
        17: "virtualx86",
        21: "identification",
    }
    syscall_register = "$eax"
    syscall_instructions = ["sysenter", "int 0x80"]

    def flag_register_to_human(self, val=None):
        reg = self.flag_register
        if not val:
            val = get_register(reg)
        return flags_to_human(val, self.flags_table)

    def is_call(self, insn):
        mnemo = insn.mnemonic
        call_mnemos = {"call", "callq"}
        return mnemo in call_mnemos

    def is_ret(self, insn):
        return insn.mnemonic == "ret"

    def is_conditional_branch(self, insn):
        mnemo = insn.mnemonic
        branch_mnemos = {
            "ja", "jnbe", "jae", "jnb", "jnc", "jb", "jc", "jnae", "jbe", "jna",
            "jcxz", "jecxz", "jrcxz", "je", "jz", "jg", "jnle", "jge", "jnl",
            "jl", "jnge", "jle", "jng", "jne", "jnz", "jno", "jnp", "jpo", "jns",
            "jo", "jp", "jpe", "js"
        }
        return mnemo in branch_mnemos

    def is_branch_taken(self, insn):
        mnemo = insn.mnemonic
        # all kudos to fG! (https://github.com/gdbinit/Gdbinit/blob/master/gdbinit#L1654)
        flags = dict((self.flags_table[k], k) for k in self.flags_table)
        val = get_register(self.flag_register)

        taken, reason = False, ""

        if mnemo in ("ja", "jnbe"):
            taken, reason = not val & (1 << flags["carry"]) and not val & (1 << flags["zero"]), "!C && !Z"
        elif mnemo in ("jae", "jnb", "jnc"):
            taken, reason = not val & (1 << flags["carry"]), "!C"
        elif mnemo in ("jb", "jc", "jnae"):
            taken, reason = val & (1 << flags["carry"]), "C"
        elif mnemo in ("jbe", "jna"):
            taken, reason = val & (1 << flags["carry"]) or val & (1 << flags["zero"]), "C || Z"
        elif mnemo in ("jcxz", "jecxz", "jrcxz"):
            cx = get_register("$rcx") if self.mode == 64 else get_register("$ecx")
            taken, reason = cx == 0, "!$CX"
        elif mnemo in ("je", "jz"):
            taken, reason = val & (1 << flags["zero"]), "Z"
        elif mnemo in ("jne", "jnz"):
            taken, reason = not val & (1 << flags["zero"]), "!Z"
        elif mnemo in ("jg", "jnle"):
            taken, reason = not val & (1 << flags["zero"]) and bool(val & (1 << flags["overflow"])) == bool(val & (1 << flags["sign"])), "!Z && S==O"
        elif mnemo in ("jge", "jnl"):
            taken, reason = bool(val & (1 << flags["sign"])) == bool(val & (1 << flags["overflow"])), "S==O"
        elif mnemo in ("jl", "jnge"):
            taken, reason = val & (1 << flags["overflow"]) != val & (1 << flags["sign"]), "S!=O"
        elif mnemo in ("jle", "jng"):
            taken, reason = val & (1 << flags["zero"]) or bool(val & (1 << flags["overflow"])) != bool(val & (1 << flags["sign"])), "Z || S!=O"
        elif mnemo in ("jo",):
            taken, reason = val & (1 << flags["overflow"]), "O"
        elif mnemo in ("jno",):
            taken, reason = not val & (1 << flags["overflow"]), "!O"
        elif mnemo in ("jpe", "jp"):
            taken, reason = val & (1 << flags["parity"]), "P"
        elif mnemo in ("jnp", "jpo"):
            taken, reason = not val & (1 << flags["parity"]), "!P"
        elif mnemo in ("js",):
            taken, reason = val & (1 << flags["sign"]), "S"
        elif mnemo in ("jns",):
            taken, reason = not val & (1 << flags["sign"]), "!S"
        return taken, reason

    def get_ra(self, insn, frame):
        ra = None
        if self.is_ret(insn):
            ra = lazy_dereference(pwngef.arch.CURRENT_ARCH.sp)
        if frame.older():
            ra = frame.older().pc()
        return ra

    @classmethod
    def mprotect_asm(cls, addr, size, perm):
        _NR_mprotect = 125
        insns = [
            "pushad",
            "mov eax, {:d}".format(_NR_mprotect),
            "mov ebx, {:d}".format(addr),
            "mov ecx, {:d}".format(size),
            "mov edx, {:d}".format(perm),
            "int 0x80",
            "popad", ]
        return "; ".join(insns)

    def get_ith_parameter(self, i):
        sp = pwngef.arch.CURRENT_ARCH.sp
        sz = pwngef.arch.CURRENT_ARCH.ptrsize
        loc = sp + (i * sz)
        val = pwngef.memory.u32(loc)
        key = "[sp + {:#x}]".format(i * sz)
        return key, val


class X86_64(X86):
    arch = "X86"
    mode = "64"

    gpr_registers = [
        "$rax", "$rbx", "$rcx", "$rdx", "$rsp", "$rbp", "$rsi", "$rdi", "$rip",
        "$r8", "$r9", "$r10", "$r11", "$r12", "$r13", "$r14", "$r15", ]
    all_registers = gpr_registers + [X86.flag_register, ] + X86.special_registers
    return_register = "$rax"
    function_parameters = ["$rdi", "$rsi", "$rdx", "$rcx", "$r8", "$r9"]
    syscall_register = "$rax"
    syscall_instructions = ["syscall"]
    # We don't want to inherit x86's stack based param getter
    get_ith_parameter = Architecture.get_ith_parameter

    @classmethod
    def mprotect_asm(cls, addr, size, perm):
        _NR_mprotect = 10
        insns = ["push rax", "push rdi", "push rsi", "push rdx",
                 "mov rax, {:d}".format(_NR_mprotect),
                 "mov rdi, {:d}".format(addr),
                 "mov rsi, {:d}".format(size),
                 "mov rdx, {:d}".format(perm),
                 "syscall",
                 "pop rdx", "pop rsi", "pop rdi", "pop rax"]
        return "; ".join(insns)


class PowerPC(Architecture):
    arch = "PPC"
    mode = "PPC32"

    all_registers = [
        "$r0", "$r1", "$r2", "$r3", "$r4", "$r5", "$r6", "$r7",
        "$r8", "$r9", "$r10", "$r11", "$r12", "$r13", "$r14", "$r15",
        "$r16", "$r17", "$r18", "$r19", "$r20", "$r21", "$r22", "$r23",
        "$r24", "$r25", "$r26", "$r27", "$r28", "$r29", "$r30", "$r31",
        "$pc", "$msr", "$cr", "$lr", "$ctr", "$xer", "$trap",
    ]
    instruction_length = 4
    nop_insn = b"\x60\x00\x00\x00"  # http://www.ibm.com/developerworks/library/l-ppc/index.html
    return_register = "$r0"
    flag_register = "$cr"
    flags_table = {
        3: "negative[0]",
        2: "positive[0]",
        1: "equal[0]",
        0: "overflow[0]",
        # cr7
        31: "less[7]",
        30: "greater[7]",
        29: "equal[7]",
        28: "overflow[7]",
    }
    function_parameters = ["$i0", "$i1", "$i2", "$i3", "$i4", "$i5"]
    syscall_register = "$r0"
    syscall_instructions = ["sc"]

    def flag_register_to_human(self, val=None):
        # http://www.cebix.net/downloads/bebox/pem32b.pdf (% 2.1.3)
        if not val:
            reg = self.flag_register
            val = get_register(reg)
        return flags_to_human(val, self.flags_table)

    def is_call(self, insn):
        return False

    def is_ret(self, insn):
        return insn.mnemonic == "blr"

    def is_conditional_branch(self, insn):
        mnemo = insn.mnemonic
        branch_mnemos = {"beq", "bne", "ble", "blt", "bgt", "bge"}
        return mnemo in branch_mnemos

    def is_branch_taken(self, insn):
        mnemo = insn.mnemonic
        flags = dict((self.flags_table[k], k) for k in self.flags_table)
        val = get_register(self.flag_register)
        taken, reason = False, ""
        if mnemo == "beq":
            taken, reason = val & (1 << flags["equal[7]"]), "E"
        elif mnemo == "bne":
            taken, reason = val & (1 << flags["equal[7]"]) == 0, "!E"
        elif mnemo == "ble":
            taken, reason = val & (1 << flags["equal[7]"]) or val & (1 << flags["less[7]"]), "E || L"
        elif mnemo == "blt":
            taken, reason = val & (1 << flags["less[7]"]), "L"
        elif mnemo == "bge":
            taken, reason = val & (1 << flags["equal[7]"]) or val & (1 << flags["greater[7]"]), "E || G"
        elif mnemo == "bgt":
            taken, reason = val & (1 << flags["greater[7]"]), "G"
        return taken, reason

    def get_ra(self, insn, frame):
        ra = None
        if self.is_ret(insn):
            ra = get_register("$lr")
        elif frame.older():
            ra = frame.older().pc()
        return ra

    @classmethod
    def mprotect_asm(cls, addr, size, perm):
        # Ref: http://www.ibm.com/developerworks/library/l-ppc/index.html
        _NR_mprotect = 125
        insns = ["addi 1, 1, -16",                 # 1 = r1 = sp
                 "stw 0, 0(1)", "stw 3, 4(1)",     # r0 = syscall_code | r3, r4, r5 = args
                 "stw 4, 8(1)", "stw 5, 12(1)",
                 "li 0, {:d}".format(_NR_mprotect),
                 "lis 3, {:#x}@h".format(addr),
                 "ori 3, 3, {:#x}@l".format(addr),
                 "lis 4, {:#x}@h".format(size),
                 "ori 4, 4, {:#x}@l".format(size),
                 "li 5, {:d}".format(perm),
                 "sc",
                 "lwz 0, 0(1)", "lwz 3, 4(1)",
                 "lwz 4, 8(1)", "lwz 5, 12(1)",
                 "addi 1, 1, 16", ]
        return ";".join(insns)


class PowerPC64(PowerPC):
    arch = "PPC"
    mode = "PPC64"


class SPARC(Architecture):
    """ Refs:
    - http://www.cse.scu.edu/~atkinson/teaching/sp05/259/sparc.pdf
    """
    arch = "SPARC"
    mode = ""

    all_registers = [
        "$g0", "$g1", "$g2", "$g3", "$g4", "$g5", "$g6", "$g7",
        "$o0", "$o1", "$o2", "$o3", "$o4", "$o5", "$o7",
        "$l0", "$l1", "$l2", "$l3", "$l4", "$l5", "$l6", "$l7",
        "$i0", "$i1", "$i2", "$i3", "$i4", "$i5", "$i7",
        "$pc", "$npc", "$sp ", "$fp ", "$psr", ]
    instruction_length = 4
    nop_insn = b"\x00\x00\x00\x00"  # sethi 0, %g0
    return_register = "$i0"
    flag_register = "$psr"
    flags_table = {
        23: "negative",
        22: "zero",
        21: "overflow",
        20: "carry",
        7: "supervisor",
        5: "trap",
    }
    function_parameters = ["$o0 ", "$o1 ", "$o2 ", "$o3 ", "$o4 ", "$o5 ", "$o7 ", ]
    syscall_register = "%g1"
    syscall_instructions = ["t 0x10"]

    def flag_register_to_human(self, val=None):
        # http://www.gaisler.com/doc/sparcv8.pdf
        reg = self.flag_register
        if not val:
            val = get_register(reg)
        return flags_to_human(val, self.flags_table)

    def is_call(self, insn):
        return False

    def is_ret(self, insn):
        # TODO: rett?
        return insn.mnemonic == "ret"

    def is_conditional_branch(self, insn):
        mnemo = insn.mnemonic
        # http://moss.csc.ncsu.edu/~mueller/codeopt/codeopt00/notes/condbranch.html
        branch_mnemos = {
            "be", "bne", "bg", "bge", "bgeu", "bgu", "bl", "ble", "blu", "bleu",
            "bneg", "bpos", "bvs", "bvc", "bcs", "bcc"
        }
        return mnemo in branch_mnemos

    def is_branch_taken(self, insn):
        mnemo = insn.mnemonic
        flags = dict((self.flags_table[k], k) for k in self.flags_table)
        val = get_register(self.flag_register)
        taken, reason = False, ""

        if mnemo == "be":
            taken, reason = val & (1 << flags["zero"]), "Z"
        elif mnemo == "bne":
            taken, reason = val & (1 << flags["zero"]) == 0, "!Z"
        elif mnemo == "bg":
            taken, reason = val & (1 << flags["zero"]) == 0 and (val & (1 << flags["negative"]) == 0 or val & (1 << flags["overflow"]) == 0), "!Z && (!N || !O)"
        elif mnemo == "bge":
            taken, reason = val & (1 << flags["negative"]) == 0 or val & (1 << flags["overflow"]) == 0, "!N || !O"
        elif mnemo == "bgu":
            taken, reason = val & (1 << flags["carry"]) == 0 and val & (1 << flags["zero"]) == 0, "!C && !Z"
        elif mnemo == "bgeu":
            taken, reason = val & (1 << flags["carry"]) == 0, "!C"
        elif mnemo == "bl":
            taken, reason = val & (1 << flags["negative"]) and val & (1 << flags["overflow"]), "N && O"
        elif mnemo == "blu":
            taken, reason = val & (1 << flags["carry"]), "C"
        elif mnemo == "ble":
            taken, reason = val & (1 << flags["zero"]) or (val & (1 << flags["negative"]) or val & (1 << flags["overflow"])), "Z || (N || O)"
        elif mnemo == "bleu":
            taken, reason = val & (1 << flags["carry"]) or val & (1 << flags["zero"]), "C || Z"
        elif mnemo == "bneg":
            taken, reason = val & (1 << flags["negative"]), "N"
        elif mnemo == "bpos":
            taken, reason = val & (1 << flags["negative"]) == 0, "!N"
        elif mnemo == "bvs":
            taken, reason = val & (1 << flags["overflow"]), "O"
        elif mnemo == "bvc":
            taken, reason = val & (1 << flags["overflow"]) == 0, "!O"
        elif mnemo == "bcs":
            taken, reason = val & (1 << flags["carry"]), "C"
        elif mnemo == "bcc":
            taken, reason = val & (1 << flags["carry"]) == 0, "!C"
        return taken, reason

    def get_ra(self, insn, frame):
        ra = None
        if self.is_ret(insn):
            ra = get_register("$o7")
        elif frame.older():
            ra = frame.older().pc()
        return ra

    @classmethod
    def mprotect_asm(cls, addr, size, perm):
        hi = (addr & 0xffff0000) >> 16
        lo = (addr & 0x0000ffff)
        _NR_mprotect = 125
        insns = ["add %sp, -16, %sp",
                 "st %g1, [ %sp ]", "st %o0, [ %sp + 4 ]",
                 "st %o1, [ %sp + 8 ]", "st %o2, [ %sp + 12 ]",
                 "sethi  %hi({}), %o0".format(hi),
                 "or  %o0, {}, %o0".format(lo),
                 "clr  %o1",
                 "clr  %o2",
                 "mov  {}, %g1".format(_NR_mprotect),
                 "t 0x10",
                 "ld [ %sp ], %g1", "ld [ %sp + 4 ], %o0",
                 "ld [ %sp + 8 ], %o1", "ld [ %sp + 12 ], %o2",
                 "add %sp, 16, %sp", ]
        return "; ".join(insns)


class SPARC64(SPARC):
    """ Refs:
    - http://math-atlas.sourceforge.net/devel/assembly/abi_sysV_sparc.pdf
    - https://cr.yp.to/2005-590/sparcv9.pdf
    """
    arch = "SPARC"
    mode = "V9"

    all_registers = [
        "$g0", "$g1", "$g2", "$g3", "$g4", "$g5", "$g6", "$g7",
        "$o0", "$o1", "$o2", "$o3", "$o4", "$o5", "$o7",
        "$l0", "$l1", "$l2", "$l3", "$l4", "$l5", "$l6", "$l7",
        "$i0", "$i1", "$i2", "$i3", "$i4", "$i5", "$i7",
        "$pc", "$npc", "$sp", "$fp", "$state", ]

    flag_register = "$state"  # sparcv9.pdf, 5.1.5.1 (ccr)
    flags_table = {
        35: "negative",
        34: "zero",
        33: "overflow",
        32: "carry",
    }

    syscall_instructions = ["t 0x6d"]

    @classmethod
    def mprotect_asm(cls, addr, size, perm):
        hi = (addr & 0xffff0000) >> 16
        lo = (addr & 0x0000ffff)
        _NR_mprotect = 125
        insns = ["add %sp, -16, %sp",
                 "st %g1, [ %sp ]", "st %o0, [ %sp + 4 ]",
                 "st %o1, [ %sp + 8 ]", "st %o2, [ %sp + 12 ]",
                 "sethi  %hi({}), %o0".format(hi),
                 "or  %o0, {}, %o0".format(lo),
                 "clr  %o1",
                 "clr  %o2",
                 "mov  {}, %g1".format(_NR_mprotect),
                 "t 0x6d",
                 "ld [ %sp ], %g1", "ld [ %sp + 4 ], %o0",
                 "ld [ %sp + 8 ], %o1", "ld [ %sp + 12 ], %o2",
                 "add %sp, 16, %sp", ]
        return "; ".join(insns)


class MIPS(Architecture):
    arch = "MIPS"
    mode = "MIPS32"

    # http://vhouten.home.xs4all.nl/mipsel/r3000-isa.html
    all_registers = [
        "$zero", "$at", "$v0", "$v1", "$a0", "$a1", "$a2", "$a3",
        "$t0", "$t1", "$t2", "$t3", "$t4", "$t5", "$t6", "$t7",
        "$s0", "$s1", "$s2", "$s3", "$s4", "$s5", "$s6", "$s7",
        "$t8", "$t9", "$k0", "$k1", "$s8", "$pc", "$sp", "$hi",
        "$lo", "$fir", "$ra", "$gp", ]
    instruction_length = 4
    nop_insn = b"\x00\x00\x00\x00"  # sll $0,$0,0
    return_register = "$v0"
    flag_register = "$fcsr"
    flags_table = {}
    function_parameters = ["$a0", "$a1", "$a2", "$a3"]
    syscall_register = "$v0"
    syscall_instructions = ["syscall"]

    def flag_register_to_human(self, val=None):
        return Color.colorify("No flag register", "yellow underline")

    def is_call(self, insn):
        return (insn.mnemonic == "jalr" and insn.operands[0] == "t9") or (insn.mnemonic == "jal")

    def is_ret(self, insn):
        return insn.mnemonic == "jr" and insn.operands[0] == "ra"

    def is_conditional_branch(self, insn):
        mnemo = insn.mnemonic
        branch_mnemos = {"beq", "bne", "beqz", "bnez", "bgtz", "bgez", "bltz", "blez"}
        return mnemo in branch_mnemos

    def is_branch_taken(self, insn):
        mnemo, ops = insn.mnemonic, insn.operands
        taken, reason = False, ""

        if mnemo == "beq":
            taken, reason = get_register(ops[0]) == get_register(ops[1]), "{0[0]} == {0[1]}".format(ops)
        elif mnemo == "bne":
            taken, reason = get_register(ops[0]) != get_register(ops[1]), "{0[0]} != {0[1]}".format(ops)
        elif mnemo == "beqz":
            taken, reason = get_register(ops[0]) == 0, "{0[0]} == 0".format(ops)
        elif mnemo == "bnez":
            taken, reason = get_register(ops[0]) != 0, "{0[0]} != 0".format(ops)
        elif mnemo == "bgtz":
            taken, reason = get_register(ops[0]) > 0, "{0[0]} > 0".format(ops)
        elif mnemo == "bgez":
            taken, reason = get_register(ops[0]) >= 0, "{0[0]} >= 0".format(ops)
        elif mnemo == "bltz":
            taken, reason = get_register(ops[0]) < 0, "{0[0]} < 0".format(ops)
        elif mnemo == "blez":
            taken, reason = get_register(ops[0]) <= 0, "{0[0]} <= 0".format(ops)
        return taken, reason

    def get_ra(self, insn, frame):
        ra = None
        if self.is_ret(insn):
            ra = get_register("$ra")
        elif frame.older():
            ra = frame.older().pc()
        return ra

    @classmethod
    def mprotect_asm(cls, addr, size, perm):
        _NR_mprotect = 4125
        insns = ["addi $sp, $sp, -16",
                 "sw $v0, 0($sp)", "sw $a0, 4($sp)",
                 "sw $a3, 8($sp)", "sw $a3, 12($sp)",
                 "li $v0, {:d}".format(_NR_mprotect),
                 "li $a0, {:d}".format(addr),
                 "li $a1, {:d}".format(size),
                 "li $a2, {:d}".format(perm),
                 "syscall",
                 "lw $v0, 0($sp)", "lw $a1, 4($sp)",
                 "lw $a3, 8($sp)", "lw $a3, 12($sp)",
                 "addi $sp, $sp, 16", ]
        return "; ".join(insns)


arch_to_regs = {
    'i386': X86,
    'x86-64': X86_64,
    'mips': MIPS,
    'sparc': SPARC,
    'sparc64': SPARC64,
    'arm': ARM,
    'aarch64': AARCH64,
    'powerpc': PowerPC,
    'riscv': RISCV,
}

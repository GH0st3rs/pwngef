#!/usr/bin/python
import sys
import json
import gdb
import pwngef.arch
import pwngef.memory


class Instruction:
    """PWNGEF representation of a CPU instruction."""

    def __init__(self, address, location, mnemo, operands, comment=''):
        self.address = address
        self.location = location
        self.mnemonic = mnemo
        self.operands = operands
        self.comment = ' # %s' % comment if comment else ''

    def __str__(self):
        return "{:#10x} {:16} {:6} {:s}{:s}".format(
            self.address,
            self.location,
            self.mnemonic,
            ", ".join(self.operands),
            self.comment
        )

    def is_valid(self):
        return "(bad)" not in self.mnemonic


def gdb_get_location_from_symbol(address):
    """Retrieve the location of the `address` argument from the symbol table.
    Return a tuple with the name and offset if found, None otherwise."""
    # this is horrible, ugly hack and shitty perf...
    # find a *clean* way to get gdb.Location from an address
    name = None
    sym = gdb.execute("info symbol {:#x}".format(address), to_string=True)
    if sym.startswith("No symbol matches"):
        return None
    # Check sections
    i = sym.find(" in section ")
    sym = sym[:i].split()
    name, offset = sym[0], 0
    if len(sym) == 3 and sym[2].isdigit():
        offset = int(sym[2])
    return name, offset


def gdb_disassemble(start_pc, **kwargs):
    """Disassemble instructions from `start_pc` (Integer). Accepts the following named parameters:
    - `end_pc` (Integer) only instructions whose start address fall in the interval from start_pc to end_pc are returned.
    - `count` (Integer) list at most this many disassembled instructions
    If `end_pc` and `count` are not provided, the function will behave as if `count=1`.
    Return an iterator of Instruction objects
    """
    frame = gdb.selected_frame()
    arch = frame.architecture()

    for insn in arch.disassemble(start_pc, **kwargs):
        address = insn["addr"]
        asm = insn["asm"].rstrip().split(None, 1)
        if len(asm) > 1:
            mnemo, operands = asm
            operands = operands.split(",")
        else:
            mnemo, operands = asm[0], []

        loc = gdb_get_location_from_symbol(address)
        location = "<{}+{}>".format(*loc) if loc else ""

        yield Instruction(address, location, mnemo, operands)


def gdb_get_nth_next_instruction_address(addr, n):
    """Return the address (Integer) of the `n`-th instruction after `addr`."""
    # fixed-length ABI
    if pwngef.arch.CURRENT_ARCH.instruction_length:
        return addr + n * pwngef.arch.CURRENT_ARCH.instruction_length
    # variable-length ABI
    insn = list(gdb_disassemble(addr, count=n))[-1]
    return insn.address


def gdb_get_nth_previous_instruction_address(addr, n):
    """Return the address (Integer) of the `n`-th instruction before `addr`."""
    # fixed-length ABI
    if pwngef.arch.CURRENT_ARCH.instruction_length:
        return addr - n * pwngef.arch.CURRENT_ARCH.instruction_length
    # variable-length ABI
    cur_insn_addr = gef_current_instruction(addr).address

    # we try to find a good set of previous instructions by "guessing" disassembling backwards
    # the 15 comes from the longest instruction valid size
    for i in range(15 * n, 0, -1):
        try:
            insns = list(gdb_disassemble(addr - i, end_pc=cur_insn_addr, count=n + 1))
        except gdb.MemoryError:
            # this is because we can hit an unmapped page trying to read backward
            break
        # 1. check that the disassembled instructions list size is correct
        if len(insns) != n + 1:  # we expect the current instruction plus the n before it
            continue
        # 2. check all instructions are valid
        for insn in insns:
            if not insn.is_valid():
                continue
        # 3. if cur_insn is at the end of the set
        if insns[-1].address == cur_insn_addr:
            return insns[0].address

    return None


def gef_instruction_n(addr, n):
    """Return the `n`-th instruction after `addr` as an Instruction object."""
    return list(gdb_disassemble(addr, count=n + 1))[n]


def gef_get_instruction_at(addr):
    """Return the full Instruction found at the specified address."""
    insn = next(gef_disassemble(addr, 1))
    return insn


def gef_current_instruction(addr):
    """Return the current instruction as an Instruction object."""
    return gef_instruction_n(addr, 0)


def gef_next_instruction(addr):
    """Return the next instruction as an Instruction object."""
    return gef_instruction_n(addr, 1)


def gef_disassemble(addr, nb_insn, nb_prev=0):
    """Disassemble `nb_insn` instructions after `addr` and `nb_prev` before `addr`.
    Return an iterator of Instruction objects."""
    count = nb_insn + 1 if nb_insn & 1 else nb_insn

    if nb_prev:
        start_addr = gdb_get_nth_previous_instruction_address(addr, nb_prev)
        if start_addr:
            for insn in gdb_disassemble(start_addr, count=nb_prev):
                if insn.address == addr:
                    break
                yield insn

    for insn in gdb_disassemble(addr, count=count):
        yield insn


def capstone_disassemble(location, nb_insn, **kwargs):
    """Disassemble `nb_insn` instructions after `addr` and `nb_prev` before
    `addr` using the Capstone-Engine disassembler, if available.
    Return an iterator of Instruction objects."""

    def cs_insn_to_gef_insn(cs_insn):
        sym_info = gdb_get_location_from_symbol(cs_insn.address)
        loc = "<{}+{}>".format(*sym_info) if sym_info else ""
        ops = [] + cs_insn.op_str.split(", ")
        return Instruction(cs_insn.address, loc, cs_insn.mnemonic, ops)

    capstone = sys.modules["capstone"]
    arch = getattr(capstone, 'CS_ARCH_%s' % pwngef.arch.current.upper())
    mode = getattr(capstone, 'CS_MODE_%s' % pwngef.arch.current.upper())
    mode |= getattr(capstone, 'CS_MODE_%s_ENDIAN' % pwngef.arch.endian.upper())
    cs = capstone.Cs(arch, mode)
    cs.detail = True

    page_start = pwngef.memory.page_size_align(location)
    offset = location - page_start
    pc = pwngef.arch.CURRENT_ARCH.pc

    skip = int(kwargs.get("skip", 0))
    nb_prev = int(kwargs.get("nb_prev", 0))
    if nb_prev > 0:
        location = gdb_get_nth_previous_instruction_address(pc, nb_prev)
        nb_insn += nb_prev

    code = kwargs.get("code", pwngef.memory.read(location, pwngef.memory.PAGE_SIZE - offset - 1))
    code = bytes(code)

    for insn in cs.disasm(code, location):
        if skip:
            skip -= 1
            continue
        nb_insn -= 1
        yield cs_insn_to_gef_insn(insn)
        if nb_insn == 0:
            break
    return


def ida_disassemble(addr, nb_insn, nb_prev=0):
    """Disassemble `nb_insn` instructions after `addr` and `nb_prev` before
    `addr` using the IDA PRO disassembler, if available.
    Return an iterator of Instruction objects."""
    def ida_insn_to_pwngef_insn(address, ida_insn):
        sym_info = gdb_get_location_from_symbol(address)
        loc = "<{}+{}>".format(*sym_info) if sym_info else ""
        asm = ida_insn.split(None, 1)
        if len(asm) > 1:
            mnemonic, ops = asm
        else:
            mnemonic, ops = asm[0], ''
        comment = ''
        if ' # ' in ops:
            ops, comment = ops.split(' # ', 1)
        ops = [] + ops.split(", ")
        return Instruction(address, loc, mnemonic, ops, comment)

    def get_disasm(start_addr, inst_length):
        items = gdb.execute('ida GetFuncItems %#x' % start_addr, to_string=True)
        items = json.loads(items)
        for address in range(start_addr, start_addr + inst_length * nb_insn, inst_length):
            if items and address in items:
                ida_insn = gdb.execute('ida GetDisasm %#x' % address, to_string=True).strip()
                yield ida_insn_to_pwngef_insn(address, ida_insn)
            else:
                yield gef_get_instruction_at(address)

    length = pwngef.arch.CURRENT_ARCH.instruction_length
    if nb_prev:
        start_addr = gdb_get_nth_previous_instruction_address(addr, nb_prev)
        if start_addr:
            for insn in get_disasm(start_addr, length):
                if insn.address == addr:
                    break
                yield insn
    for insn in get_disasm(addr, length):
        yield insn

#!/usr/bin/python
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import gdb

import pwngef.commands
from pwngef.commands import GenericCommand
import pwngef.proc
from pwngef.color import message
from pwngef.color import Color


@pwngef.commands.register_command
class GlibcHeapCommand(GenericCommand):
    """Base command to get information about the Glibc heap structure."""

    _cmdline_ = "heap"
    _syntax_ = "{:s} (chunk|chunks|bins|arenas|set-arena)".format(_cmdline_)

    def __init__(self):
        super(GlibcHeapCommand, self).__init__(prefix=True)
        return None

    @pwngef.proc.OnlyWhenRunning
    def do_invoke(self, argv):
        self.usage()
        return None


@pwngef.commands.register_command
class GlibcHeapChunkCommand(GenericCommand):
    """Display information on a heap chunk.
    See https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1123."""

    _cmdline_ = "heap chunk"
    _syntax_ = "{:s} LOCATION".format(_cmdline_)

    def __init__(self):
        super(GlibcHeapChunkCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        return None

    @pwngef.proc.OnlyWhenRunning
    def do_invoke(self, argv):
        if not argv:
            message.error("Missing chunk address")
            self.usage()
            return None
        addr = int(gdb.parse_and_eval(argv[0]))
        chunk = GlibcChunk(addr)
        print(chunk.psprint())
        return None


@pwngef.commands.register_command
class GlibcHeapChunksCommand(GenericCommand):
    """Display information all chunks from main_arena heap. If a location is passed,
    it must correspond to the base address of the first chunk."""

    _cmdline_ = "heap chunks"
    _syntax_ = "{0} [LOCATION]".format(_cmdline_)
    _example_ = "\n{0}\n{0} 0x555555775000".format(_cmdline_)

    def __init__(self):
        super(GlibcHeapChunksCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        self.add_setting("peek_nb_byte", 16, "Hexdump N first byte(s) inside the chunk data (0 to disable)")
        return None

    @pwngef.proc.OnlyWhenRunning
    def do_invoke(self, argv):
        if not argv:
            # heap_section = [x for x in get_process_maps() if x.path == "[heap]"]
            heap_section = None
            if not heap_section:
                message.error("No heap section")
                return None
            heap_section = heap_section[0].page_start
        else:
            heap_section = int(argv[0], 0)

        class arena:
            pass
        # arena = get_main_arena()
        # if arena is None:
            # message.error("No valid arena")
            # return None
        arena.top = 0xFFFFFFFF

        nb = self.get_setting("peek_nb_byte")
        current_chunk = GlibcChunk(heap_section, from_base=True)
        chain_arrow_left = pwngef.config.get('chain_arrow_left')
        while True:
            if current_chunk.chunk_base_address == arena.top:
                print("{} {} {}".format(str(current_chunk), chain_arrow_left, Color.greenify("top chunk")))
                break
            if current_chunk.chunk_base_address > arena.top:
                break
            if current_chunk.size == 0:
                # EOF
                break
            line = str(current_chunk)
            if nb:
                hex_data = pwngef.memory.read(current_chunk.address, nb, partial=True)
                for ln in pwngef.hexdump.hexdump(hex_data, address=current_chunk.address):
                    line += '\n [%s]' % ln
            print(line)
            next_chunk = current_chunk.get_next_chunk()
            if next_chunk is None:
                break
            next_chunk_addr = pwngef.memory.peek(next_chunk.address)
            if next_chunk_addr is None:
                # corrupted
                break
            current_chunk = next_chunk
        return None


class GlibcChunk:
    """Glibc chunk class.
    Ref:  https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/."""

    def __init__(self, addr, from_base=False):
        self.ptrsize = pwngef.arch.CURRENT_ARCH.ptrsize
        if from_base:
            self.chunk_base_address = addr
            self.address = addr + 2 * self.ptrsize
        else:
            self.chunk_base_address = int(addr - 2 * self.ptrsize)
            self.address = addr
        self.size_addr = int(self.address - self.ptrsize)
        self.prev_size_addr = self.chunk_base_address
        return None

    def get_chunk_size(self):
        return pwngef.memory.u32(self.size_addr) & (~0x07)

    @property
    def size(self):
        return self.get_chunk_size()

    def get_usable_size(self):
        # https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L4537
        cursz = self.get_chunk_size()
        if cursz == 0:
            return cursz
        if self.has_m_bit():
            return cursz - 2 * self.ptrsize
        return cursz - self.ptrsize

    @property
    def usable_size(self):
        return self.get_usable_size()

    def get_prev_chunk_size(self):
        return pwngef.memory.u32(self.prev_size_addr)

    def get_next_chunk(self):
        if pwngef.memory.peek(self.chunk_base_address) is None:
            return None
        addr = self.address + self.get_chunk_size()
        return GlibcChunk(addr)

    # if free-ed functions
    def get_fwd_ptr(self):
        return pwngef.memory.u32(self.address)

    @property
    def fwd(self):
        return self.get_fwd_ptr()

    fd = fwd  # for compat

    def get_bkw_ptr(self):
        return pwngef.memory.u32(self.address + self.ptrsize)

    @property
    def bck(self):
        return self.get_bkw_ptr()

    bk = bck  # for compat
    # endif free-ed functions

    def has_p_bit(self):
        return pwngef.memory.u32(self.size_addr) & 0x01

    def has_m_bit(self):
        return pwngef.memory.u32(self.size_addr) & 0x02

    def has_n_bit(self):
        return pwngef.memory.u32(self.size_addr) & 0x04

    def is_used(self):
        """Check if the current block is used by:
        - checking the M bit is true
        - or checking that next chunk PREV_INUSE flag is true """
        if self.has_m_bit():
            return True
        next_chunk = self.get_next_chunk()
        return True if next_chunk.has_p_bit() else False

    def str_chunk_size_flag(self):
        msg = []
        msg.append("PREV_INUSE flag: {}".format(Color.greenify("On") if self.has_p_bit() else Color.redify("Off")))
        msg.append("IS_MMAPPED flag: {}".format(Color.greenify("On") if self.has_m_bit() else Color.redify("Off")))
        msg.append("NON_MAIN_ARENA flag: {}".format(Color.greenify("On") if self.has_n_bit() else Color.redify("Off")))
        return "\n".join(msg)

    def _str_sizes(self):
        msg = []
        failed = False
        try:
            msg.append("Chunk size: {0:d} ({0:#x})".format(self.get_chunk_size()))
            msg.append("Usable size: {0:d} ({0:#x})".format(self.get_usable_size()))
            failed = True
        except gdb.MemoryError:
            msg.append("Chunk size: Cannot read at {:#x} (corrupted?)".format(self.size_addr))
        try:
            msg.append("Previous chunk size: {0:d} ({0:#x})".format(self.get_prev_chunk_size()))
            failed = True
        except gdb.MemoryError:
            msg.append("Previous chunk size: Cannot read at {:#x} (corrupted?)".format(self.chunk_base_address))
        if failed:
            msg.append(self.str_chunk_size_flag())
        return "\n".join(msg)

    def _str_pointers(self):
        fwd = self.address
        bkw = self.address + self.ptrsize
        msg = []
        try:
            msg.append("Forward pointer: {0:#x}".format(self.get_fwd_ptr()))
        except gdb.MemoryError:
            msg.append("Forward pointer: {0:#x} (corrupted?)".format(fwd))
        try:
            msg.append("Backward pointer: {0:#x}".format(self.get_bkw_ptr()))
        except gdb.MemoryError:
            msg.append("Backward pointer: {0:#x} (corrupted?)".format(bkw))
        return "\n".join(msg)

    def str_as_alloced(self):
        return self._str_sizes()

    def str_as_freed(self):
        return "{}\n\n{}".format(self._str_sizes(), self._str_pointers())

    def flags_as_string(self):
        flags = []
        if self.has_p_bit():
            flags.append(Color.colorify("PREV_INUSE", "red bold"))
        if self.has_m_bit():
            flags.append(Color.colorify("IS_MMAPPED", "red bold"))
        if self.has_n_bit():
            flags.append(Color.colorify("NON_MAIN_ARENA", "red bold"))
        return "|".join(flags)

    def __str__(self):
        msg = "{:s}(addr={:#x}, size={:#x}, flags={:s})".format(
            Color.colorify("Chunk", "yellow bold underline"),
            int(self.address),
            self.get_chunk_size(),
            self.flags_as_string()
        )
        return msg

    def psprint(self):
        msg = []
        msg.append(str(self))
        if self.is_used():
            msg.append(self.str_as_alloced())
        else:
            msg.append(self.str_as_freed())
        return "\n".join(msg) + "\n"

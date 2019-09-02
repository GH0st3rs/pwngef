import string
import re
import struct

import gdb

import pwngef.arch
from pwngef.color import Color
import pwngef.commands
from pwngef.commands import GenericCommand
import pwngef.proc
import pwngef.regs


def cyclic_pattern_charset():
    """
    Generate charset for cyclic pattern
    """
    charset = []
    charset += [string.ascii_uppercase]
    charset += [string.ascii_lowercase]
    charset += [string.digits]
    charset_type = pwngef.config.get("pattern.type")

    if charset_type == 1:  # extended type
        charset[1] = "%$-;" + re.sub("[sn]", "", charset[1])
        charset[2] = "sn()" + charset[2]
    elif charset_type == 2:  # maximum type
        charset += [string.punctuation]
    mixed_charset = mixed = ''
    k = 0
    while True:
        for i in range(0, len(charset)):
            mixed += charset[i][k:k + 1]
        if not mixed:
            break
        mixed_charset += mixed
        mixed = ''
        k += 1
    return mixed_charset


def de_bruijn(charset, n, maxlen):
    """
    Generate the De Bruijn Sequence up to `maxlen` characters for the charset `charset`
    and subsequences of length `n`.
    Algorithm modified from wikipedia http://en.wikipedia.org/wiki/De_Bruijn_sequence
    """
    k = len(charset)
    a = [0] * k * n
    sequence = []

    def db(t, p):
        if len(sequence) == maxlen:
            return
        if t > n:
            if n % p == 0:
                for j in range(1, p + 1):
                    sequence.append(charset[a[j]])
                    if len(sequence) == maxlen:
                        return
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)
    db(1, 1)
    return ''.join(sequence)


def cyclic_pattern(size=0x10000):
    charset = cyclic_pattern_charset()
    pattern = de_bruijn(charset, 3, size)
    return pattern


def cyclic_pattern_offset(value, pattern=None):
    """
    Search a value if it is a part of cyclic pattern
    Args:
        - value: value to search for (String/Int)
    Returns:
        - offset in pattern if found
    """
    pattern = pattern or cyclic_pattern().encode()
    if isinstance(value, int):
        search = struct.pack(pwngef.arch.fmt, value)
    elif isinstance(value, (bytearray, bytes)):
        search = value
    elif isinstance(value, str):
        search = value.encode()
    pos = pattern.find(search)
    return pos if pos != -1 else None


@pwngef.commands.register_command
class PatternCommand(GenericCommand):
    """Generate, search, or write a cyclic pattern to memory"""

    _cmdline_ = "pattern"
    _syntax_ = "{:s} (create|search)".format(_cmdline_)

    def __init__(self):
        super(PatternCommand, self).__init__(prefix=True)
        self.add_setting("type", 1, "Charset type: 0 - basic; 1 - default; 2 - maximum")
        return None

    def do_invoke(self, argv):
        self.usage()
        return None


@pwngef.commands.register_command
class PatternCreateCommand(GenericCommand):
    """Generate a cyclic pattern"""

    _cmdline_ = "pattern create"
    _syntax_ = "{:s} [size]".format(_cmdline_)

    def __init__(self):
        super(PatternCreateCommand, self).__init__()
        return None

    def do_invoke(self, argv):
        if not argv:
            size = 0x100
        else:
            size = int(gdb.parse_and_eval(argv[0]))
        pattern = cyclic_pattern(size)
        print(pattern)


@pwngef.commands.register_command
class PatternSearchCommand(GenericCommand):
    """Search a cyclic pattern into the memory"""

    _cmdline_ = "pattern search"
    _syntax_ = "{:s}".format(_cmdline_)

    def __init__(self):
        super(PatternSearchCommand, self).__init__()
        return None

    @pwngef.proc.OnlyWhenRunning
    def do_invoke(self, argv):
        pattern = cyclic_pattern().encode()
        registers = pwngef.arch.CURRENT_ARCH.all_registers
        reg_result = {}
        for reg in registers:
            r = int(pwngef.regs.get_register(reg))
            result = self.check_offsets(r, pattern)
            if result:
                reg_result[reg] = result
        if reg_result:
            print(Color.redify('Registers contain pattern buffer:'))
            for (reg, (pos, offset)) in reg_result.items():
                print("{}+{} found at offset: {}".format(reg.upper(), offset, pos))

    def check_offsets(self, v, pattern=None):
        if v - 128 <= 0:
            return None
        for offset in range(-128, 128, 4):
            pos = cyclic_pattern_offset(v + offset, pattern)
            if pos is not None:
                return (pos, offset)
        return None

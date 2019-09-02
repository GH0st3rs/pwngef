import string
import re

import gdb

import pwngef.commands
from pwngef.commands import GenericCommand
import pwngef.proc


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
        charset = cyclic_pattern_charset()
        pattern = de_bruijn(charset, 3, size)
        print(pattern)


@pwngef.commands.register_command
class PatternSearchCommand(GenericCommand):
    """Generate a cyclic pattern"""

    _cmdline_ = "pattern search"
    _syntax_ = "{:s} [pattern]".format(_cmdline_)

    def __init__(self):
        super(PatternSearchCommand, self).__init__()
        return None

    @pwngef.proc.OnlyWhenRunning
    def do_invoke(self, argv):
        print('Not yet!')

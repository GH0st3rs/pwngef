import gdb
import pwngef.arch
import pwngef.disassemble as disass


class StepOver(gdb.Command):
    """Greet the whole world."""

    def __init__(self):
        super(StepOver, self).__init__("next", gdb.COMMAND_RUNNING)

    def invoke(self, arg, from_tty):
        pc = int(pwngef.arch.CURRENT_ARCH.pc)
        insn = disass.gef_current_instruction(pc)
        if pwngef.arch.CURRENT_ARCH.is_call(insn):
            gdb.Breakpoint('*%#x' % (pc + 8), internal=True, temporary=True)
            gdb.execute('continue', from_tty=False, to_string=False)


StepOver()

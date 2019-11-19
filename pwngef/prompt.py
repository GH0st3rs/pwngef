#!/usr/bin/python
import pwngef.config
import pwngef.proc

PWNGEF_PROMPT = "pwngef\u27a4  "
PWNGEF_PROMPT_ON = "\001\033[1;32m\002{0:s}\001\033[0m\002".format(PWNGEF_PROMPT)
PWNGEF_PROMPT_OFF = "\001\033[1;31m\002{0:s}\001\033[0m\002".format(PWNGEF_PROMPT)


def set_prompt(current_prompt):
    """PWNPWNGEF custom prompt function."""
    if pwngef.config.get("self.readline_compat") is True:
        return PWNGEF_PROMPT
    if pwngef.config.get("self.disable_color") is True:
        return PWNGEF_PROMPT
    if pwngef.proc.alive:
        return PWNGEF_PROMPT_ON
    return PWNGEF_PROMPT_OFF

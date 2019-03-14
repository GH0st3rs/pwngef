#!/usr/bin/python
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from pwngef import config
from pwngef.color import generateColorFunction
import pwngef.ui

config.set('color.message_status_on_color', 'green', 'color of on status messages')
config.set('color.message_status_off_color', 'red', 'color of off status messages')

config.set('color.message_notice_color', 'purple', 'color of notice messages')
config.set('color.message_hint_color', 'yellow', 'color of hint and marker messages')
config.set('color.message_success_color', 'green', 'color of success messages')
config.set('color.message_warning_color', 'yellow', 'color of warning messages')
config.set('color.message_error_color', 'red', 'color of error messages')
config.set('color.message_system_color', 'light-red', 'color of system messages')

config.set('color.message_exit_color', 'red', 'color of exit messages')
config.set('color.message_breakpoint_color', 'yellow', 'color of breakpoint messages')
config.set('color.message_signal_color', 'bold,red', 'color of signal messages')

config.set('color.message_prompt_color', 'bold,red', 'prompt color')


def on(msg):
    return print(generateColorFunction(config.get('color.message_status_on_color'))(msg))


def off(msg):
    return print(generateColorFunction(config.get('color.message_status_off_color'))(msg))


def notice(msg):
    return print(generateColorFunction(config.get('color.message_notice_color'))(msg))


def hint(msg):
    return print(generateColorFunction(config.get('color.message_hint_color'))(msg))


def success(msg):
    return print(generateColorFunction(config.get('color.message_success_color'))(msg))


def warn(msg):
    return print(generateColorFunction(config.get('color.message_warning_color'))(msg))


def error(msg):
    return print(generateColorFunction(config.get('color.message_error_color'))(msg))


def system(msg):
    return print(generateColorFunction(config.get('color.message_system_color'))(msg))


def exit(msg):
    return print(generateColorFunction(config.get('color.message_exit_color'))(msg))


def breakpoint(msg):
    return print(generateColorFunction(config.get('color.message_breakpoint_color'))(msg))


def signal(msg):
    return print(generateColorFunction(config.get('color.message_signal_color'))(msg))


def prompt(msg):
    return print(generateColorFunction(config.get('color.message_prompt_color'))(msg))


def titlify(text, color=None, msg_color=None):
    """Print a centered title."""
    cols = pwngef.ui.get_window_size()[1]
    nb = (cols - len(text) - 2) // 2
    if color is None:
        color = config.get("theme.default_title_line") or 'normal'
    if msg_color is None:
        msg_color = config.get("theme.default_title_message") or 'normal'

    msg = []

    msg.append(generateColorFunction(color)("{} ".format(config.HORIZONTAL_LINE * nb)))
    msg.append(generateColorFunction(msg_color)(text))
    msg.append(generateColorFunction(color)(" {}".format(config.HORIZONTAL_LINE * nb)))
    return "".join(msg)

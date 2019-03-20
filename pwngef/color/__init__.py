#!/usr/bin/python
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import os

import pwngef.config
import pwngef.memoize

disable_colors = pwngef.config.set('self.disable_colors', bool(os.environ.get('PWNDBG_DISABLE_COLORS')), 'whether to color the output or not')


class Color:
    """Used to colorify terminal output."""
    colors = {
        "normal": "\033[0m",
        "gray": "\033[1;38;5;240m",
        "red": "\033[31m",
        "green": "\033[32m",
        "yellow": "\033[33m",
        "blue": "\033[34m",
        "pink": "\033[35m",
        "cyan": "\033[36m",
        "bold": "\033[1m",
        "underline": "\033[4m",
        "underline_off": "\033[24m",
        "highlight": "\033[3m",
        "highlight_off": "\033[23m",
        "blink": "\033[5m",
        "blink_off": "\033[25m",
    }

    @staticmethod
    def redify(msg):
        return Color.colorify(msg, "red")

    @staticmethod
    def greenify(msg):
        return Color.colorify(msg, "green")

    @staticmethod
    def blueify(msg):
        return Color.colorify(msg, "blue")

    @staticmethod
    def yellowify(msg):
        return Color.colorify(msg, "yellow")

    @staticmethod
    def grayify(msg):
        return Color.colorify(msg, "gray")

    @staticmethod
    def pinkify(msg):
        return Color.colorify(msg, "pink")

    @staticmethod
    def cyanify(msg):
        return Color.colorify(msg, "cyan")

    @staticmethod
    def boldify(msg):
        return Color.colorify(msg, "bold")

    @staticmethod
    def underlinify(msg):
        return Color.colorify(msg, "underline")

    @staticmethod
    def highlightify(msg):
        return Color.colorify(msg, "highlight")

    @staticmethod
    def blinkify(msg):
        return Color.colorify(msg, "blink")

    @staticmethod
    def colorify(text, attrs):
        """Color text according to the given attributes."""
        if pwngef.config.get("self.disable_color") is True:
            return text

        colors = Color.colors
        msg = [colors[attr] for attr in attrs.split() if attr in colors]
        msg.append(str(text))
        if colors["highlight"] in msg:
            msg.append(colors["highlight_off"])
        if colors["underline"] in msg:
            msg.append(colors["underline_off"])
        if colors["blink"] in msg:
            msg.append(colors["blink_off"])
        msg.append(colors["normal"])
        return "".join(msg)


@pwngef.memoize.reset_on_stop
def generateColorFunctionInner(old, new):
    def wrapper(text):
        return new(old(text))
    return wrapper


def generateColorFunction(config):
    def function(x):
        return x
    # check disabled_color
    if disable_colors:
        return function
    # select color wrapper
    for color in config.split(','):
        color = color.lower().replace('-', '_')
        if hasattr(Color, '%sify' % color):
            function = generateColorFunctionInner(function, getattr(Color, '%sify' % color))
    return function

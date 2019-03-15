#!/usr/bin/python
"""
Dynamic configuration system for pwngef, using GDB's built-in Parameter
mechanism.

All pwngef Parameter types are accessible via property access on this
module, for example:

    >>> pwngef.config.set('example_value', 7, 'an example')
    >>> pwngef.config.get('example_value')
    7
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import os
import sys
import tempfile

__config__ = {}

PWNGEF_RC = os.path.join(os.getenv("HOME"), ".gef.rc")
PWNGEF_TEMP_DIR = os.path.join(tempfile.gettempdir(), "gef")
HORIZONTAL_LINE = "-"
VERTICAL_LINE = "|"

DOWN_ARROW = "\u21b3"


def get(name, get_all=False):
    module = sys.modules[__name__]
    name = name.replace('-', '_')
    setting = module.__config__.get(name, None)
    if not setting or get_all:
        return setting
    return setting[0]


def set(name, default, docstring):
    module = sys.modules[__name__]
    name = name.replace('-', '_')
    docstring = docstring.strip()
    module.__config__[name] = [default, docstring]
    return module.__config__[name][0]


def delete(name):
    module = sys.modules[__name__]
    del module.__config__[name]
    return None


def has(name):
    module = sys.modules[__name__]
    return name in module.__config__


def get_command(name):
    module = sys.modules[__name__]
    return [x.split(".", 1)[1] for x in module.__config__ if x.startswith("{:s}.".format(name))]

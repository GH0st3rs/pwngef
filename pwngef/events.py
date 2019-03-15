#!/usr/bin/python
"""
Enables callbacks into functions to be automatically invoked
when various events occur to the debuggee (e.g. STOP on SIGINT)
by using a decorator.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import sys
from functools import wraps
import gdb

import pwngef.config

debug = pwngef.config.set('gef.debug_events', False, 'display internal event debugging info')


# In order to support reloading, we must be able to re-fire
# all 'objfile' and 'stop' events.
registered = {
    gdb.events.exited: [],
    gdb.events.cont: [],
    gdb.events.new_objfile: [],
    gdb.events.stop: [],
}

# GDB 7.9 and above only
try:
    registered[gdb.events.memory_changed] = []
    registered[gdb.events.register_changed] = []
except (NameError, AttributeError):
    pass


# When performing remote debugging, gdbserver is very noisy about which
# objects are loaded.  This greatly slows down the debugging session.
# In order to combat this, we keep track of which objfiles have been loaded
# this session, and only emit objfile events for each *new* file.
objfile_cache = dict()


def connect(func, event_handler, name=''):
    if debug:
        print("Connecting", func.__name__, event_handler)

    @wraps(func)
    def caller(*args, **kwargs):
        if debug:
            sys.stdout.write('%r %s.%s %r\n' % (name, func.__module__, func.__name__, args))
        return func(*args, **kwargs)

    registered[event_handler].append(caller)
    event_handler.connect(caller)
    return caller


def exit(func):
    return connect(func, gdb.events.exited, 'exit')


def cont(func):
    return connect(func, gdb.events.cont, 'cont')


def new_objfile(func):
    return connect(func, gdb.events.new_objfile, 'obj')


def stop(func):
    return connect(func, gdb.events.stop, 'stop')


# before_prompt = partial(connect, event_handler=gdb.events.before_prompt, name='before_prompt')


def reg_changed(func):
    try:
        return connect(func, gdb.events.register_changed, 'reg_changed')
    except AttributeError:
        return func


def mem_changed(func):
    try:
        return connect(func, gdb.events.memory_changed, 'mem_changed')
    except AttributeError:
        return func


# def log_objfiles(ofile=None):
#     if not (debug and ofile):
#         return

#     name = ofile.new_objfile.filename

#     print("objfile: %r" % name)
#     gdb.execute('info sharedlibrary')


# gdb.events.new_objfile.connect(log_objfiles)


# def after_reload(start=True):
#     if gdb.selected_inferior().pid:
#         for f in registered[gdb.events.stop]:
#             f()
#         for f in registered[gdb.events.start]:
#             if start:
#                 f()
#         for f in registered[gdb.events.new_objfile]:
#             f()
#         for f in registered[gdb.events.before_prompt]:
#             f()


# def on_reload():
#     for event, functions in registered.items():
#         for function in functions:
#             event.disconnect(function)
#         registered[event] = []


@exit
def _reset_objfiles(event):
    global objfile_cache
    objfile_cache = dict()


def reset_all_caches():
    """Free all caches. If an object is cached, it will have a callable attribute `cache_clear`
    which will be invoked to purge the function cache."""
    for mod in dir(sys.modules["__main__"]):
        obj = getattr(sys.modules["__main__"], mod)
        if hasattr(obj, "cache_clear"):
            obj.cache_clear()
    return

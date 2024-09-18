#!/usr/bin/python
"""
Caches return values until some event in the inferior happens,
e.g. execution stops because of a SIGINT or breakpoint, or a
new library/objfile are loaded, etc.
"""
try:
    # Python >= 3.10
    from collections.abc import Hashable
except ImportError:
    # Python < 3.10
    from collections import Hashable
import functools
import sys

import pwngef.events

debug = False


class memoize(object):
    """
    Base memoization class. Do not use directly. Instead use one of classes defined below.
    """
    caching = True

    def __init__(self, func):
        self.func = func
        self.cache = {}
        self.caches.append(self)  # must be provided by base class
        functools.update_wrapper(self, func)

    def __call__(self, *args, **kwargs):
        how = None

        if not isinstance(args, Hashable):
            print("Cannot memoize %r!", file=sys.stderr)
            how = "Not memoizeable!"
            value = self.func(*args)

        if self.caching and args in self.cache:
            how = "Cached"
            value = self.cache[args]

        else:
            how = "Executed"
            value = self.func(*args, **kwargs)
            self.cache[args] = value

            if isinstance(value, list):
                print("Shouldnt cache mutable types! %r" % self.func.__name__)

        if debug:
            print("%s: %s(%r)" % (how, self, args))
            print(".... %r" % (value,))
        return value

    def __repr__(self):
        funcname = self.func.__module__ + '.' + self.func.__name__
        return "<%s-memoized function %s>" % (self.kind, funcname)

    def __get__(self, obj, objtype):
        return functools.partial(self.__call__, obj)

    def clear(self):
        if debug:
            print("Clearing %s %r" % (self, self.cache))
        self.cache.clear()


class forever(memoize):
    """
    Memoizes forever - for a pwngef session or until `_reset` is called explicitly.
    """
    caches = []

    @staticmethod
    def _reset():
        for obj in forever.caches:
            obj.cache.clear()


class reset_on_stop(memoize):
    caches = []
    kind = 'stop'

    @staticmethod
    @pwngef.events.stop
    @pwngef.events.mem_changed
    @pwngef.events.reg_changed
    def __reset_on_stop(event):
        for obj in reset_on_stop.caches:
            obj.cache.clear()

    _reset = __reset_on_stop


class reset_on_exit(memoize):
    caches = []
    kind = 'exit'

    @staticmethod
    @pwngef.events.exit
    def __reset_on_exit(event):
        for obj in reset_on_exit.caches:
            obj.clear()

    _reset = __reset_on_exit


class reset_on_objfile(memoize):
    caches = []
    kind = 'objfile'

    @staticmethod
    @pwngef.events.new_objfile
    def __reset_on_objfile(event):
        for obj in reset_on_objfile.caches:
            obj.clear()

    _reset = __reset_on_objfile


class reset_on_start(memoize):
    caches = []
    kind = 'start'

    @staticmethod
    @pwngef.events.stop
    def __reset_on_start(event):
        for obj in reset_on_start.caches:
            obj.clear()

    _reset = __reset_on_start


class reset_on_cont(memoize):
    caches = []
    kind = 'cont'

    @staticmethod
    @pwngef.events.cont
    def __reset_on_cont(event):
        for obj in reset_on_cont.caches:
            obj.clear()

    _reset = __reset_on_cont


class while_running(memoize):
    caches = []
    kind = 'running'
    caching = False

    @staticmethod
    def __start_caching(event):
        while_running.caching = True

    @staticmethod
    @pwngef.events.exit
    def __reset_while_running(event):
        for obj in while_running.caches:
            obj.clear()
        while_running.caching = False

    _reset = __reset_while_running


def reset():
    forever._reset()
    reset_on_stop._reset()
    reset_on_exit._reset()
    reset_on_objfile._reset()
    reset_on_start._reset()
    reset_on_cont._reset()
    while_running._reset()

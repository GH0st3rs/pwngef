#!/usr/bin/python
import os
import sys
import time
import functools
import tempfile
import platform
import configparser
import gdb

import pwngef.config
from pwngef.color import Color
from pwngef.color import message
import pwngef.commands
import pwngef.functions
from pwngef.which import which

__aliases__ = []


@functools.lru_cache()
def get_os():
    """Return the current OS."""
    return platform.system().lower()


def execute_gdb_script(commands):
    """Execute the parameter `source` as GDB command. This is done by writing `commands` to
    a temporary file, which is then executed via GDB `source` command. The tempfile is then deleted."""
    fd, fname = tempfile.mkstemp(suffix=".gdb", prefix="pwngef_")
    with os.fdopen(fd, "w") as f:
        f.write(commands)
        f.flush()
    if os.access(fname, os.R_OK):
        gdb.execute("source {:s}".format(fname))
        os.unlink(fname)
    return


class SelfCommand(gdb.Command):
    """PWNGEF main command: view all new commands by typing `self`."""

    _cmdline_ = "self"
    _syntax_ = "{:s} (missing|config|save|restore|set|run)".format(_cmdline_)
    _aliases_ = ['pwngef', ]

    def __init__(self):
        super(SelfCommand, self).__init__(SelfCommand._cmdline_,
                                          gdb.COMMAND_SUPPORT,
                                          gdb.COMPLETE_NONE,
                                          True)
        pwngef.config.set("self.follow_child", True, "Automatically set GDB to follow child when forking")
        pwngef.config.set("self.readline_compat", False, "Workaround for readline SOH/ETX issue (SEGV)")
        pwngef.config.set("self.debug", False, "Enable debug mode for PWNGEF")
        pwngef.config.set("self.autosave_breakpoints_file", "", "Automatically save and restore breakpoints")
        pwngef.config.set("self.extra_plugins_dir", "", "Autoload additional PWNGEF commands from external directory")
        pwngef.config.set("self.disable_color", False, "Disable all colors in PWNGEF")
        self.loaded_commands = []
        self.loaded_functions = []
        self.missing_commands = {}
        return None

    def setup(self):
        self.load(initial=True)
        # loading PWNGEF sub-commands
        self.doc = SelfHelpCommand(self.loaded_commands)
        self.cfg = SelfConfigCommand(self.loaded_command_names)
        SelfSaveCommand()
        SelfRestoreCommand()
        SelfMissingCommand()
        SelfSetCommand()
        SelfRunCommand()

        # load the saved settings
        gdb.execute("self restore")

        # restore the autosave/autoreload breakpoints policy (if any)
        self.__reload_auto_breakpoints()

        # load plugins from `extra_plugins_dir`
        if self.__load_extra_plugins() > 0:
            # if here, at least one extra plugin was loaded, so we need to restore
            # the settings once more
            gdb.execute("self restore quiet")
        return None

    def __reload_auto_breakpoints(self):
        bkp_fname = pwngef.config.get("self.autosave_breakpoints_file")
        if bkp_fname:
            # restore if existing
            print(pwngef.config.__config__)
            if os.access(bkp_fname, os.R_OK):
                gdb.execute("source {:s}".format(bkp_fname))

            # add hook for autosave breakpoints on quit command
            source = [
                "define hook-quit",
                " save breakpoints {:s}".format(bkp_fname),
                "end"
            ]
            execute_gdb_script("\n".join(source) + "\n")
        return None

    def __load_extra_plugins(self):
        nb_added = -1
        try:
            nb_inital = len(self.loaded_commands)
            directories = pwngef.config.get("self.extra_plugins_dir")
            if directories:
                for directory in directories.split(";"):
                    directory = os.path.realpath(os.path.expanduser(directory))
                    if os.path.isdir(directory):
                        sys.path.append(directory)
                        for fname in os.listdir(directory):
                            if not fname.endswith(".py"):
                                continue
                            fpath = "{:s}/{:s}".format(directory, fname)
                            if os.path.isfile(fpath):
                                gdb.execute("source {:s}".format(fpath))
            nb_added = len(self.loaded_commands) - nb_inital
            if nb_added > 0:
                message.success("{:s} extra commands added from '{:s}'".format(Color.colorify(nb_added, "bold green"),
                                                                               Color.colorify(directory, "bold blue")))
        except gdb.error as e:
            message.error("failed: {}".format(str(e)))
        return nb_added

    @property
    def loaded_command_names(self):
        return [x[0] for x in self.loaded_commands]

    def invoke(self, args, from_tty):
        self.dont_repeat()
        gdb.execute("self help")
        return None

    def load(self, initial=False):
        """Load all the commands and functions defined by PWNGEF into GDB."""
        nb_missing = 0
        self.commands = [(x._cmdline_, x) for x in pwngef.commands.__commands__]

        # load all of the functions
        for function_class_name in pwngef.functions.__functions__:
            self.loaded_functions.append(function_class_name())

        def is_loaded(x):
            return any(filter(lambda u: x == u[0], self.loaded_commands))

        for cmd, class_name in self.commands:
            if is_loaded(cmd):
                continue

            try:
                self.loaded_commands.append((cmd, class_name, class_name()))

                if hasattr(class_name, "_aliases_"):
                    aliases = getattr(class_name, "_aliases_")
                    for alias in aliases:
                        SelfAlias(alias, cmd)

            except Exception as reason:
                self.missing_commands[cmd] = reason
                nb_missing += 1

        # sort by command name
        self.loaded_commands = sorted(self.loaded_commands, key=lambda x: x[1]._cmdline_)

        if initial:
            print("{:s} for {:s} ready, type `{:s}' to start, `{:s}' to configure".format(
                Color.greenify("PWNGEF"), get_os(),
                Color.colorify("self", "underline yellow"),
                Color.colorify("self config", "underline pink")
            ))

            ver = "{:d}.{:d}".format(sys.version_info.major, sys.version_info.minor)
            nb_cmds = len(self.loaded_commands)
            print("{:s} commands loaded for GDB {:s} using Python engine {:s}".format(
                Color.colorify(nb_cmds, "bold green"),
                Color.colorify(gdb.VERSION, "bold yellow"),
                Color.colorify(ver, "bold red")))

            if nb_missing:
                message.warn("{:s} command{} could not be loaded, run `{:s}` to know why.".format(
                    Color.colorify(nb_missing, "bold red"),
                    "s" if nb_missing > 1 else "",
                    Color.colorify("self missing", "underline pink")
                ))
        return None


class SelfHelpCommand(gdb.Command):
    """PWNGEF help sub-command."""
    _cmdline_ = "self help"
    _syntax_ = _cmdline_

    def __init__(self, commands, *args, **kwargs):
        super(SelfHelpCommand, self).__init__(SelfHelpCommand._cmdline_,
                                              gdb.COMMAND_SUPPORT,
                                              gdb.COMPLETE_NONE,
                                              False)
        self.docs = []
        self.generate_help(commands)
        self.refresh()
        return None

    def invoke(self, args, from_tty):
        self.dont_repeat()
        print(message.titlify("PWNGEF - GDB Extra Features"))
        print(self.__doc__)
        return None

    def generate_help(self, commands):
        """Generate builtin commands documentation."""
        for command in commands:
            self.add_command_to_doc(command)
        return None

    def add_command_to_doc(self, command):
        """Add command to PWNGEF documentation."""
        cmd, class_name, _ = command
        if " " in cmd:
            # do not print subcommands in gef help
            return None
        doc = getattr(class_name, "__doc__", "").lstrip()
        doc = "\n                         ".join(doc.split("\n"))
        aliases = " (alias: {:s})".format(", ".join(class_name._aliases_)) if hasattr(class_name, "_aliases_") else ""
        msg = "{cmd:<25s} -- {help:s}{aliases:s}".format(cmd=cmd, help=Color.greenify(doc), aliases=aliases)
        self.docs.append(msg)
        return None

    def refresh(self):
        """Refresh the documentation."""
        self.__doc__ = "\n".join(sorted(self.docs))
        return None


class SelfConfigCommand(gdb.Command):
    """PWNGEF configuration sub-command
    This command will help set/view PWNGEF settingsfor the current debugging session.
    It is possible to make those changes permanent by running `gef save` (refer
    to this command help), and/or restore previously saved settings by running
    `gef restore` (refer help).
    """
    _cmdline_ = "self config"
    _syntax_ = "{:s} [setting_name] [setting_value]".format(_cmdline_)

    def __init__(self, loaded_commands, *args, **kwargs):
        super(SelfConfigCommand, self).__init__(SelfConfigCommand._cmdline_, gdb.COMMAND_NONE, prefix=False)
        self.loaded_commands = loaded_commands
        return None

    def invoke(self, args, from_tty):
        self.dont_repeat()
        argv = gdb.string_to_argv(args)
        argc = len(argv)

        if not (0 <= argc <= 2):
            message.error("Invalid number of arguments")
            return None

        if argc == 0:
            print(message.titlify("PWNGEF configuration settings"))
            self.print_settings()
            return None

        if argc == 1:
            prefix = argv[0]
            names = list(filter(lambda x: x.startswith(prefix), pwngef.config.__config__.keys()))
            if names:
                if len(names) == 1:
                    print(message.titlify("PWNGEF configuration setting: {:s}".format(names[0])))
                    self.print_setting(names[0], verbose=True)
                else:
                    print(message.titlify("PWNGEF configuration settings matching '{:s}'".format(argv[0])))
                    for name in names:
                        self.print_setting(name)
            return None
        self.set_setting(argc, argv)
        return None

    def print_setting(self, plugin_name, verbose=False):
        res = pwngef.config.get(plugin_name, get_all=True)
        string_color = pwngef.config.get("theme.dereference_string")
        misc_color = pwngef.config.get("theme.dereference_base_address")

        if not res:
            return None

        _value, _desc = res
        _setting = Color.colorify(plugin_name, "green")
        _type = type(_value).__name__
        if isinstance(_value, str):
            _value = '"{:s}"'.format(Color.colorify(_value, string_color))
        else:
            _value = Color.colorify(_value, misc_color)

        print("{:s} ({:s}) = {:s}".format(_setting, _type, _value))

        if verbose:
            print(Color.colorify("\nDescription:", "bold underline"))
            print("\t{:s}".format(_desc))
        return None

    def print_settings(self):
        for x in sorted(pwngef.config.__config__):
            self.print_setting(x)
        return None

    def set_setting(self, argc, argv):
        if "." not in argv[0]:
            message.error("Invalid command format")
            return None

        loaded_commands = [x[0] for x in pwngef.config.__pwngef__.loaded_commands] + ["self"]
        plugin_name = argv[0].split(".", 1)[0]
        if plugin_name not in loaded_commands:
            message.error("Unknown plugin '{:s}'".format(plugin_name))
            return None

        _value, _doc = pwngef.config.get(argv[0], get_all=True)
        if _value is None:
            message.error("Failed to get '{:s}' config setting".format(argv[0],))
            return None

        _type = type(_value)
        if isinstance(_value, bool):
            _newval = True if argv[1] == 'True' else False
        else:
            _newval = _type(argv[1])

        pwngef.config.set(argv[0], _newval, _doc)
        pwngef.events.reset_all_caches()
        return None

    def complete(self, text, word):
        settings = sorted(pwngef.config.__config__)

        if text == "":
            # no prefix: example: `self config TAB`
            return [s for s in settings if word in s]

        if "." not in text:
            # if looking for possible prefix
            return [s for s in settings if s.startswith(text.strip())]

        # finally, look for possible values for given prefix
        return [s.split(".", 1)[1] for s in settings if s.startswith(text.strip())]


class SelfSaveCommand(gdb.Command):
    """PWNGEF save sub-command.
    Saves the current configuration of PWNGEF to disk (by default in file '~/.pwngef.rc')."""
    _cmdline_ = "self save"
    _syntax_ = _cmdline_

    def __init__(self, *args, **kwargs):
        super(SelfSaveCommand, self).__init__(SelfSaveCommand._cmdline_, gdb.COMMAND_SUPPORT,
                                              gdb.COMPLETE_NONE, False)
        return None

    def invoke(self, args, from_tty):
        self.dont_repeat()
        cfg = configparser.RawConfigParser()
        old_sect = None

        # save the configuration
        for key in sorted(pwngef.config.__config__):
            sect, optname = key.split(".", 1)
            value = pwngef.config.get(key)

            if old_sect != sect:
                cfg.add_section(sect)
                old_sect = sect

            cfg.set(sect, optname, value)

        # save the aliases
        cfg.add_section("aliases")
        for alias in __aliases__:
            cfg.set("aliases", alias._alias, alias._command)

        with open(pwngef.config.PWNGEF_RC, "w") as fd:
            cfg.write(fd)

        message.success("Configuration saved to '{:s}'".format(pwngef.config.PWNGEF_RC))
        return None


class SelfRestoreCommand(gdb.Command):
    """PWNGEF restore sub-command.
    Loads settings from file '~/.pwngef.rc' and apply them to the configuration of PWNGEF."""
    _cmdline_ = "self restore"
    _syntax_ = _cmdline_

    def __init__(self, *args, **kwargs):
        super(SelfRestoreCommand, self).__init__(SelfRestoreCommand._cmdline_,
                                                 gdb.COMMAND_SUPPORT,
                                                 gdb.COMPLETE_NONE,
                                                 False)
        return None

    def invoke(self, args, from_tty):
        self.dont_repeat()
        if not os.access(pwngef.config.PWNGEF_RC, os.R_OK):
            return None

        quiet = args.lower() == "quiet"
        cfg = configparser.ConfigParser()
        cfg.read(pwngef.config.PWNGEF_RC)

        for section in cfg.sections():
            if section == "aliases":
                # load the aliases
                for key in cfg.options(section):
                    SelfAlias(key, cfg.get(section, key))
                continue

            # load the other options
            for optname in cfg.options(section):
                try:
                    key = "{:s}.{:s}".format(section, optname)
                    _value, _doc = pwngef.config.get(key, get_all=True)
                    new_value = cfg.get(section, optname)
                    if isinstance(_value, bool):
                        new_value = True if new_value == "True" else False
                    new_value = int(new_value) if new_value.isdigit() or isinstance(_value, int) else new_value
                    pwngef.config.set(key, new_value, _doc)
                except Exception:
                    pass

        if not quiet:
            message.success("Configuration from '{:s}' restored".format(
                Color.colorify(pwngef.config.PWNGEF_RC, "bold blue")
            ))
        return None


class SelfMissingCommand(gdb.Command):
    """PWNGEF missing sub-command
    Display the PWNGEF commands that could not be loaded, along with the reason of why
    they could not be loaded.
    """
    _cmdline_ = "self missing"
    _syntax_ = _cmdline_

    def __init__(self, *args, **kwargs):
        super(SelfMissingCommand, self).__init__(SelfMissingCommand._cmdline_,
                                                 gdb.COMMAND_SUPPORT,
                                                 gdb.COMPLETE_NONE,
                                                 False)
        return None

    def invoke(self, args, from_tty):
        self.dont_repeat()
        config_arrow_right = pwngef.config.get('theme.chain_arrow_right')
        missing_commands = pwngef.config.__pwngef__.missing_commands.keys()
        if not missing_commands:
            message.success("No missing command")
            return None

        for missing_command in missing_commands:
            reason = pwngef.config.__pwngef__.missing_commands[missing_command]
            message.warn("Command `{}` is missing, reason {} {}".format(
                missing_command,
                config_arrow_right,
                reason
            ))
        return None


class SelfSetCommand(gdb.Command):
    """Override GDB set commands with the context from PWNGEF.
    """
    _cmdline_ = "self set"
    _syntax_ = "{:s} [GDB_SET_ARGUMENTS]".format(_cmdline_)

    def __init__(self, *args, **kwargs):
        super(SelfSetCommand, self).__init__(SelfSetCommand._cmdline_,
                                             gdb.COMMAND_SUPPORT,
                                             gdb.COMPLETE_SYMBOL,
                                             False)
        return None

    def invoke(self, args, from_tty):
        self.dont_repeat()
        args = args.split()
        cmd = ["set", args[0], ]
        for p in args[1:]:
            if p.startswith("$_pwngef"):
                c = gdb.parse_and_eval(p)
                cmd.append(c.string())
            else:
                cmd.append(p)

        gdb.execute(" ".join(cmd))
        return None


class SelfRunCommand(gdb.Command):
    """Override GDB run commands with the context from PWNGEF.
    Simple wrapper for GDB run command to use arguments set from `self set args`. """
    _cmdline_ = "self run"
    _syntax_ = "{:s} [GDB_RUN_ARGUMENTS]".format(_cmdline_)

    def __init__(self, *args, **kwargs):
        super(SelfRunCommand, self).__init__(SelfRunCommand._cmdline_,
                                             gdb.COMMAND_SUPPORT,
                                             gdb.COMPLETE_FILENAME,
                                             False)
        return None

    def invoke(self, args, from_tty):
        self.dont_repeat()
        if pwngef.proc.alive:
            gdb.execute("continue")
            return None

        argv = args.split()
        gdb.execute("self set args {:s}".format(" ".join(argv)))
        gdb.execute("run")
        return None


class SelfAlias(gdb.Command):
    """Simple aliasing wrapper because GDB doesn't do what it should."""

    def __init__(self, alias, command, completer_class=gdb.COMPLETE_NONE, command_class=gdb.COMMAND_NONE):
        p = command.split()
        if not p:
            return None

        if list(filter(lambda x: x._alias == alias, __aliases__)):
            return None

        self._command = command
        self._alias = alias
        c = command.split()[0]
        r = self.lookup_command(c)
        self.__doc__ = "Alias for '{}'".format(Color.greenify(command))
        if r is not None:
            _instance = r[2]
            self.__doc__ += ": {}".format(_instance.__doc__)

            if hasattr(_instance, "complete"):
                self.complete = _instance.complete

        super(SelfAlias, self).__init__(alias, command_class, completer_class=completer_class)
        sys.modules[__name__].__aliases__.append(self)
        return None

    def invoke(self, args, from_tty):
        gdb.execute("{} {}".format(self._command, args), from_tty=from_tty)
        return None

    def lookup_command(self, cmd):
        for _name, _class, _instance in pwngef.config.__pwngef__.loaded_commands:
            if cmd == _name:
                return _name, _class, _instance

        return None


class SelfAliases(gdb.Command):
    """List all custom aliases."""

    def __init__(self):
        super(SelfAliases, self).__init__("aliases", gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE)
        return None

    def invoke(self, args, from_tty):
        self.dont_repeat()
        message.success("Aliases defined:")
        for _alias in __aliases__:
            print("{:30s} {} {}".format(_alias._alias, pwngef.config.RIGHT_ARROW, _alias._command))
        return None


class SelfTmuxSetup(gdb.Command):
    """Setup a confortable tmux debugging environment."""

    def __init__(self):
        super(SelfTmuxSetup, self).__init__("tmux-setup", gdb.COMMAND_NONE, gdb.COMPLETE_NONE)
        SelfAlias("screen-setup", "tmux-setup")
        return None

    def invoke(self, args, from_tty):
        self.dont_repeat()

        tmux = os.getenv("TMUX")
        if tmux:
            self.tmux_setup()
            return None

        screen = os.getenv("TERM")
        if screen is not None and screen == "screen":
            self.screen_setup()
            return None

        message.warn("Not in a tmux/screen session")
        return None

    def tmux_setup(self):
        """Prepare the tmux environment by vertically splitting the current pane, and
        forcing the context to be redirected there."""
        tmux = which("tmux")
        message.success("tmux session found, splitting window...")
        old_ptses = set(os.listdir("/dev/pts"))
        gdb.execute("! {} split-window -h 'clear ; cat'".format(tmux))
        gdb.execute("! {} select-pane -L".format(tmux))
        new_ptses = set(os.listdir("/dev/pts"))
        pty = list(new_ptses - old_ptses)[0]
        pty = "/dev/pts/{}".format(pty)
        message.success("Setting `context.redirect` to '{}'...".format(pty))
        gdb.execute("pwngef config context.redirect {}".format(pty))
        message.success("Done!")
        return None

    def screen_setup(self):
        """Hackish equivalent of the tmux_setup() function for screen."""
        screen = which("screen")
        sty = os.getenv("STY")
        message.success("screen session found, splitting window...")
        fd_script, script_path = tempfile.mkstemp()
        fd_tty, tty_path = tempfile.mkstemp()
        os.close(fd_tty)

        with os.fdopen(fd_script, "w") as f:
            f.write("startup_message off\n")
            f.write("split -v\n")
            f.write("focus right\n")
            f.write("screen /bin/bash -c 'tty > {}; clear; cat'\n".format(tty_path))
            f.write("focus left\n")

        gdb.execute("""! {} -r {} -m -d -X source {}""".format(screen, sty, script_path))
        # artificial delay to make sure `tty_path` is populated
        time.sleep(0.25)
        with open(tty_path, "r") as f:
            pty = f.read().strip()
        message.success("Setting `context.redirect` to '{}'...".format(pty))
        gdb.execute("pwngef config context.redirect {}".format(pty))
        message.success("Done!")
        os.unlink(script_path)
        os.unlink(tty_path)
        return None


# Initialize commands
pwngef.config.__pwngef__ = SelfCommand()
pwngef.config.__pwngef__.setup()

import pwngef.config as config
from pwngef.color import generateColorFunction

config_normal = config.set('color.hexdump_normal_color', 'normal', 'color for hexdump command (normal bytes)')
config_printable = config.set('color.hexdump_printable_color', 'bold', 'color for hexdump command (printable characters)')
config_zero = config.set('color.hexdump_zero_color', 'red', 'color for hexdump command (zero bytes)')
config_special = config.set('color.hexdump_special_color', 'yellow', 'color for hexdump command (special bytes)')
config_offset = config.set('color.hexdump_offset_color', 'normal', 'color for hexdump command (offset label)')
config_address = config.set('color.hexdump_address_color', 'normal', 'color for hexdump command (address label)')
config_separator = config.set('color.hexdump_separator_color', 'normal', 'color for hexdump command (group separator)')


def normal(x):
    return generateColorFunction(config_normal)(x)


def printable(x):
    return generateColorFunction(config_printable)(x)


def zero(x):
    return generateColorFunction(config_zero)(x)


def special(x):
    return generateColorFunction(config_special)(x)


def offset(x):
    return generateColorFunction(config_offset)(x)


def address(x):
    return generateColorFunction(config_address)(x)


def separator(x):
    return generateColorFunction(config_separator)(x)

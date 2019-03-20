# pwngef [![license](https://img.shields.io/github/license/mashape/apistatus.svg?maxAge=2592000)](https://github.com/GH0st3rs/pwngef/blob/master/LICENSE.md)

`pwngef` is a GDB plug-in based on [pwngdb][pwndbg], [GEF][GEF] and [PEDA][PEDA] that makes debugging MIPS with GDB suck less.


[PEDA]: https://github.com/longld/peda
[GEF]: https://github.com/hugsy/gef
[pwndbg]: https://github.com/pwndbg/pwndbg
[peda-mips]: https://github.com/mutepigz/peda-mips

## Why?

Because anybody didn't like MIPS architecture:
* [pwngdb][pwndbg] - Does not support MIPS
* [GEF][GEF] - There is support for MIPS, but the reference string does not work, and very many errors in the code
* [peda-mips][peda-mips] - There is support for MIPS, but it is very difficult to expand the functionality

## How?

 It is based on the [pwngdb][pwndbg] structure, the beauty of the [GEF][GEF] modules, and the simplicity of the implementation of [PEDA][PEDA].
 
## Installation

```
git clone https://github.com/GH0st3rs/pwngef.git ~/pwngef
echo "source ~/pwngef/gdbinit.py" >> ~/.gdbinit
```
# tcpslice installation notes

If you have not built libpcap, do so first.  See [this file](README.md)
for the source code location.

You will need a C99 compiler to build tcpslice.  The `configure`
script will abort if your compiler is not C99 compliant.  If this
happens, use the generally available GNU C compiler (GCC) or Clang.

After libpcap has been built (either install it with `make install`
or make sure both the libpcap and tcpslice source trees are in the same
directory), run `./autogen.sh` (a shell script).  `autogen.sh` will
build the `configure` and `config.h.in` files.  Then run `./configure`
(a shell script).  `configure` will determine your system attributes
and generate an appropriate `Makefile` from `Makefile.in`.
Now build tcpslice by running `make`.

On some system, you may need to set the `AUTORECONF` variable, like:
`AUTORECONF=autoreconf-2.69 ./autogen.sh`
to select the `autoreconf` version you want to use.

On OpenBSD, you may need to set, before the `make`, the `AUTOCONF_VERSION`
variable like:
`AUTOCONF_VERSION=2.69 make`

If everything builds OK, `su` and run `make install`.  This will install
tcpslice and the manual entry.

If your system is not one which we have tested tcpslice on, you may
have to modify the `configure.ac` and `Makefile.in` files.  Please send us
patches for any modifications you need to make.

## Description of files
```
CHANGES         - description of differences between releases
INSTALL.md      - this file
Makefile.in	- compilation rules (input to the configure script)
Makefile-devel-adds - additional rules if .devel file exists
README.md	- description of distribution
VERSION		- version of this release
aclocal.m4	- autoconf macros
autogen.sh	- build configure and config.h.in (run this first)
compiler-tests.h - compiler version definitions
config.guess	- autoconf support
config.sub	- autoconf support
configure.ac	- configure script source
diag-control.h	- diagnostic control #defines
gmt2local.c	- time conversion routines
gmt2local.h	- time conversion prototypes
gwtm2secs.c	- GMT to Unix timestamp conversion
install-sh	- BSD style install script
instrument-functions.c - instrumentation of functions
lbl/os-*.h	- os dependent defines and prototypes
machdep.c	- machine dependent routines
machdep.h	- machine dependent definitions
missing/*	- replacements for missing library functions
mkdep		- construct Makefile dependency list
search.c	- fast savefile search routines
seek-tell.c	- fseek64() and ftell64() routines
sessions.c	- session tracking routines
sessions.h	- session tracking prototypes
tcpslice.1	- manual entry
tcpslice.c	- main program
tcpslice.h	- global prototypes
util.c		- utility routines
varattrs.h	- compiler attribute definitions
```

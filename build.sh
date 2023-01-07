#!/bin/sh -e

# This script runs one build with the setup environment variable CC (usually
# "gcc" or "clang").
: "${CC:=gcc}"
: "${TCPSLICE_TAINTED:=no}"
: "${MAKE_BIN:=make}"

. ./build_common.sh
# Install directory prefix
if [ -z "$PREFIX" ]; then
    PREFIX=`mktempdir tcpslice_build`
    echo "PREFIX set to '$PREFIX'"
    DELETE_PREFIX=yes
fi

print_cc_version
run_after_echo ./autogen.sh
run_after_echo ./configure --prefix="$PREFIX"
run_after_echo "$MAKE_BIN" -s clean

# If necessary, set TCPSLICE_TAINTED here to exempt particular builds from
# warnings. Use as specific terms as possible (e.g. some specific compiler and
# some specific OS).

[ "$TCPSLICE_TAINTED" != yes ] && CFLAGS=`cc_werr_cflags`
run_after_echo "$MAKE_BIN" -s ${CFLAGS:+CFLAGS="$CFLAGS"}
run_after_echo ./tcpslice -h
print_so_deps tcpslice
run_after_echo "$MAKE_BIN" install
run_after_echo "$MAKE_BIN" releasetar
handle_matrix_debug
if [ "$DELETE_PREFIX" = yes ]; then
    run_after_echo rm -rf "$PREFIX"
fi
# vi: set tabstop=4 softtabstop=0 expandtab shiftwidth=4 smarttab autoindent :

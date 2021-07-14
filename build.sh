#!/bin/sh -e

# This script runs one build with the setup environment variable CC (usually
# "gcc" or "clang").
: "${CC:=gcc}"

# GCC and Clang recognize --version and print to stdout. Sun compilers
# recognize -V and print to stderr.
"$CC" --version 2>/dev/null || "$CC" -V || :
# Install directory prefix
if [ -z "$PREFIX" ]; then
    PREFIX=$(mktemp -d -t tcpslice_build_XXXXXXXX)
    echo "PREFIX set to '$PREFIX'"
    DELETE_PREFIX=yes
fi

# Run a command after displaying it
run_after_echo() {
    printf '$ '
    echo "$@"
    # shellcheck disable=SC2068
    $@
}

echo '$ ./configure [...]'
./configure --prefix="$PREFIX"
run_after_echo "make -s clean"
run_after_echo "make"
run_after_echo "./tcpslice -h"
echo '$ make install'
make install
run_after_echo "make releasetar"
if [ "$MATRIX_DEBUG" = true ]; then
    echo '$ cat Makefile [...]'
    sed '/^# DO NOT DELETE THIS LINE -- mkdep uses it.$/q' < Makefile
    echo '$ cat config.h'
    cat config.h
    echo '$ cat config.log'
    cat config.log
fi
if [ "$DELETE_PREFIX" = yes ]; then
    rm -rf "$PREFIX"
fi
# vi: set tabstop=4 softtabstop=0 expandtab shiftwidth=4 smarttab autoindent :

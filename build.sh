#!/bin/sh -e

# This script runs one build with the setup environment variable: CC
# (default: CC=gcc).

# CC: gcc or clang
CC=${CC:-gcc}
# GCC and Clang recognize --version and print to stdout. Sun compilers
# recognize -V and print to stderr.
"$CC" --version 2>/dev/null || "$CC" -V || :
# Install directory prefix
if [ -z "$PREFIX" ]; then
    PREFIX=$(mktemp -d -t tcpslice_build_XXXXXXXX)
    echo "PREFIX set to '$PREFIX'"
    DELETE_PREFIX=yes
fi

travis_fold() {
    tf_action=${1:?}
    tf_name=${2:?}
    if [ "$TRAVIS" != true ]; then return; fi
    printf 'travis_fold:%s:%s.script.%s\r' "$tf_action" "$LABEL" "$tf_name"
    sleep 1
}

# Run a command after displaying it
run_after_echo() {
    printf '$ '
    echo "$@"
    # shellcheck disable=SC2068
    $@
}

# LABEL is needed to build the travis fold labels
LABEL="$CC"
echo '$ ./configure [...]'
travis_fold start configure
./configure --prefix="$PREFIX"
travis_fold end configure
run_after_echo "make -s clean"
run_after_echo "make"
run_after_echo "./tcpslice -h"
echo '$ make install'
travis_fold start make_install
make install
travis_fold end make_install
system=$(uname -s)
if [ "$system" = Darwin ] || [ "$system" = Linux ]; then
    run_after_echo "make releasetar"
fi
if [ "$TRAVIS" = true ]; then
    echo '$ cat Makefile [...]'
    travis_fold start cat_makefile
    sed '/^# DO NOT DELETE THIS LINE -- mkdep uses it.$/q' < Makefile
    travis_fold end cat_makefile
    echo '$ cat config.h'
    travis_fold start cat_config_h
    cat config.h
    travis_fold end cat_config_h
    echo '$ cat config.log'
    travis_fold start cat_config_log
    cat config.log
    travis_fold end cat_config_log
fi
if [ "$DELETE_PREFIX" = yes ]; then
    rm -rf "$PREFIX"
fi
# vi: set tabstop=4 softtabstop=0 expandtab shiftwidth=4 smarttab autoindent :

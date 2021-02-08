#!/usr/bin/env bash

# This script runs one build with the setup environment variable: CC
# (default: CC=gcc).

set -e

# CC: gcc or clang
CC=${CC:-gcc}
# Install directory prefix
PREFIX=/tmp/local

travis_fold() {
    local action="$1"
    local name="$2"
    if [ "$TRAVIS" != true ]; then return; fi
    echo -ne "travis_fold:$action:$LABEL.script.$name\\r"
    sleep 1
}

# Run a command after displaying it
run_after_echo() {
    echo -n '$ '
    echo "$@"
    $@
}

# LABEL is needed to build the travis fold labels
LABEL="$CC"
echo '$ ./configure [...]'
travis_fold start configure
./configure --prefix=$PREFIX
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
    sed -n '1,/DO NOT DELETE THIS LINE -- mkdep uses it/p' < Makefile
    cat Makefile
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
# vi: set tabstop=4 softtabstop=0 expandtab shiftwidth=4 smarttab autoindent :

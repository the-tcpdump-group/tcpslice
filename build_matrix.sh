#!/usr/bin/env bash

# This script executes the matrix loop, exclude tests and cleaning.
# The matrix can be configured with the environment variable MATRIX_CC
# (default: MATRIX_CC='gcc clang')
# It calls the build.sh script which runs one build with the setup environment
# variable : CC (default: CC=gcc).

set -e

# ANSI color escape sequences
ANSI_MAGENTA="\\033[35;1m"
ANSI_RESET="\\033[0m"
uname -a
date
# Install directory prefix
if [ -z "$PREFIX" ]; then
    PREFIX=$(mktemp -d -t tcpslice_build_matrix_XXXXXXXX)
    echo "PREFIX set to '$PREFIX'"
    export PREFIX
fi
COUNT=0

travis_fold() {
    local action="$1"
    local name="$2"
    if [ "$TRAVIS" != true ]; then return; fi
    echo -ne "travis_fold:$action:$LABEL.script.$name\\r"
    sleep 1
}

# Display text in magenta
echo_magenta() {
    echo -ne "$ANSI_MAGENTA"
    echo "$@"
    echo -ne "$ANSI_RESET"
}

touch .devel configure
for CC in ${MATRIX_CC:-gcc clang}; do
    export CC
    # Exclude gcc on OSX (it is just an alias for clang)
    if [ "$CC" = gcc ] && [ "$TRAVIS_OS_NAME" = osx ]; then continue; fi
    COUNT=$((COUNT+1))
    echo_magenta "===== SETUP $COUNT: CC=$CC ====="
    # LABEL is needed to build the travis fold labels
    LABEL="$CC"
    # Run one build with the setup environment variable: CC
    ./build.sh
    echo 'Cleaning...'
    travis_fold start cleaning
    make distclean
    rm -rf "$PREFIX"/*
    git status -suall
    # Cancel changes in configure
    git checkout configure
    travis_fold end cleaning
done
rm -rf "$PREFIX"
echo_magenta "Tested setup count: $COUNT"
# vi: set tabstop=4 softtabstop=0 expandtab shiftwidth=4 smarttab autoindent :

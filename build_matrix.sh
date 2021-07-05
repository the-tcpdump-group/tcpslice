#!/bin/sh -e

# This script executes the matrix loop, exclude tests and cleaning.
# The matrix can be configured with the environment variable MATRIX_CC
# (default: MATRIX_CC='gcc clang')
# It calls the build.sh script which runs one build with the setup environment
# variable : CC (default: CC=gcc).

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
    tf_action=${1:?}
    tf_name=${2:?}
    if [ "$TRAVIS" != true ]; then return; fi
    printf 'travis_fold:%s:%s.script.%s\r' "$tf_action" "$LABEL" "$tf_name"
    sleep 1
}

# Display text in magenta
echo_magenta() {
    printf '\033[35;1m' # ANSI magenta
    echo "$@"
    printf '\033[0m' # ANSI reset
}

touch .devel configure
for CC in ${MATRIX_CC:-gcc clang}; do
    export CC
    # Exclude gcc on macOS (it is just an alias for clang).
    if [ "$CC" = gcc ] && [ "$(uname -s)" = Darwin ]; then
        echo '(skipped)'
        continue
    fi
    for BUILD_LIBPCAP in ${MATRIX_BUILD_LIBPCAP:-yes no}; do
        COUNT=$((COUNT+1))
        echo_magenta "===== SETUP $COUNT: CC=$CC BUILD_LIBPCAP=$BUILD_LIBPCAP ====="
        if [ "$BUILD_LIBPCAP" = yes ]; then
            echo_magenta "Build libpcap (CMAKE=no)"
            (cd ../libpcap && CMAKE=no ./build.sh)
        else
            echo_magenta 'Use system libpcap'
            rm -rf "${PREFIX:?}"/*
            if [ -d ../libpcap ]; then
                make -C ../libpcap distclean || :
            fi
        fi
        # LABEL is needed to build the travis fold labels
        LABEL="$CC.$BUILD_LIBPCAP"
        # Run one build with the setup environment variable: CC
        ./build.sh
        echo 'Cleaning...'
        travis_fold start cleaning
        make distclean
        rm -rf "${PREFIX:?}"/*
        git status -suall
        # Cancel changes in configure
        git checkout configure
        travis_fold end cleaning
    done
done
rm -rf "$PREFIX"
echo_magenta "Tested setup count: $COUNT"
# vi: set tabstop=4 softtabstop=0 expandtab shiftwidth=4 smarttab autoindent :

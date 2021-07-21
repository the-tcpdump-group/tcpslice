#!/bin/sh -e

# This script executes the matrix loop, exclude tests and cleaning.
# The matrix can be configured with the following environment variables:
: "${MATRIX_CC:=gcc clang}"
: "${MATRIX_BUILD_LIBPCAP:=yes no}"
# It calls the build.sh script which runs one build with the setup environment
# variable CC.

. ./build_common.sh
print_sysinfo
# Install directory prefix
if [ -z "$PREFIX" ]; then
    # shellcheck disable=SC2006
    PREFIX=`mktempdir tcpslice_build_matrix`
    echo "PREFIX set to '$PREFIX'"
    export PREFIX
fi
COUNT=0

touch .devel configure
for CC in $MATRIX_CC; do
    export CC
    # Exclude gcc on macOS (it is just an alias for clang).
    # shellcheck disable=SC2006
    if [ "$CC" = gcc ] && [ "`uname -s`" = Darwin ]; then
        echo '(skipped)'
        continue
    fi
    for BUILD_LIBPCAP in $MATRIX_BUILD_LIBPCAP; do
        # shellcheck disable=SC2006
        COUNT=`increment $COUNT`
        echo_magenta "===== SETUP $COUNT: CC=$CC BUILD_LIBPCAP=$BUILD_LIBPCAP ====="
        if [ "$BUILD_LIBPCAP" = yes ]; then
            echo_magenta "Build libpcap (CMAKE=no)"
            (cd ../libpcap && CMAKE=no ./build.sh)
        else
            echo_magenta 'Use system libpcap'
            purge_directory "$PREFIX"
            if [ -d ../libpcap ]; then
                (cd ../libpcap; make distclean || echo '(Ignoring the make error.)')
            fi
        fi
        # Run one build with the setup environment variable: CC
        run_after_echo ./build.sh
        echo 'Cleaning...'
        make distclean
        purge_directory "$PREFIX"
        run_after_echo git status -suall
        # Cancel changes in configure
        run_after_echo git checkout configure
    done
done
run_after_echo rm -rf "$PREFIX"
echo_magenta "Tested setup count: $COUNT"
# vi: set tabstop=4 softtabstop=0 expandtab shiftwidth=4 smarttab autoindent :

#!/bin/sh -e

# This script executes the matrix loop, exclude tests and cleaning.
# The matrix can be configured with the following environment variables:
: "${MATRIX_CC:=gcc clang}"
: "${MATRIX_BUILD_LIBPCAP:=yes no}"
# Set this variable to "yes" before calling this script to disregard all
# warnings in a particular environment (CI or a local working copy). Set it to
# "yes" in this script or in build.sh when a matrix subset is known to be not
# warning-free because of the OS, the compiler or whatever other factor that
# the scripts can detect both in and out of CI.
: "${TCPSLICE_TAINTED:=no}"
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
export TCPSLICE_TAINTED

touch .devel configure
for CC in $MATRIX_CC; do
    export CC
    discard_cc_cache
    if gcc_is_clang_in_disguise; then
        echo '(skipped)'
        continue
    fi
    for BUILD_LIBPCAP in $MATRIX_BUILD_LIBPCAP; do
        # shellcheck disable=SC2006
        COUNT=`increment $COUNT`
        echo_magenta "===== SETUP $COUNT: CC=$CC BUILD_LIBPCAP=$BUILD_LIBPCAP ====="  >&2
        if [ "$BUILD_LIBPCAP" = yes ]; then
            echo_magenta "Build libpcap (CMAKE=no)" >&2
            (cd ../libpcap && CMAKE=no ./build.sh)
        else
            echo_magenta 'Use system libpcap' >&2
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
echo_magenta "Tested setup count: $COUNT" >&2
# vi: set tabstop=4 softtabstop=0 expandtab shiftwidth=4 smarttab autoindent :

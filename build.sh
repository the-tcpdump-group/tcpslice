#!/bin/sh -e

# This script runs one build with the setup environment variable CC (usually
# "gcc" or "clang").
: "${CC:=gcc}"
: "${TCPSLICE_TAINTED:=no}"

. ./build_common.sh
# Install directory prefix
if [ -z "$PREFIX" ]; then
    # shellcheck disable=SC2006
    PREFIX=`mktempdir tcpslice_build`
    echo "PREFIX set to '$PREFIX'"
    DELETE_PREFIX=yes
fi

print_cc_version
run_after_echo ./configure --prefix="$PREFIX"
run_after_echo make -s clean

# shellcheck disable=SC2006
case `cc_id`/`os_id` in
*/SunOS-5.9)
    # config.h triggers a warning with Sun C and GCC.
    TCPSLICE_TAINTED=yes
    ;;
*/SunOS-5.10)
    # config.h triggers a warning with Sun C and GCC.
    TCPSLICE_TAINTED=yes
    ;;
suncc-*/SunOS-5.11)
    # config.h triggers a warning with Sun C.
    TCPSLICE_TAINTED=yes
    ;;
esac

# shellcheck disable=SC2006
[ "$TCPSLICE_TAINTED" != yes ] && CFLAGS=`cc_werr_cflags`
run_after_echo make -s ${CFLAGS:+CFLAGS="$CFLAGS"}
run_after_echo ./tcpslice -h
print_so_deps tcpslice
run_after_echo make install
run_after_echo make releasetar
handle_matrix_debug
if [ "$DELETE_PREFIX" = yes ]; then
    run_after_echo rm -rf "$PREFIX"
fi
# vi: set tabstop=4 softtabstop=0 expandtab shiftwidth=4 smarttab autoindent :

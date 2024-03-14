#!/bin/sh -e

# This script runs one build with the setup environment variable CC (usually
# "gcc" or "clang").
: "${CC:=gcc}"
: "${TCPSLICE_TAINTED:=no}"
: "${MAKE_BIN:=make}"
# At least one OS (AIX 7) where this software can build does not have at least
# one command (mktemp) required for a successful run of "make releasetar".
: "${TEST_RELEASETAR:=yes}"

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

case `cc_id`/`os_id` in
clang-*/SunOS-5.11)
    # Work around https://www.illumos.org/issues/16369
    [ "`uname -o`" = illumos ] && grep -Fq OpenIndiana /etc/release && CFLAGS="-Wno-fuse-ld-path${CFLAGS:+ $CFLAGS}"
    ;;
esac

run_after_echo "$MAKE_BIN" -s ${CFLAGS:+CFLAGS="$CFLAGS"}
print_so_deps tcpslice
run_after_echo ./tcpslice -h
run_after_echo "$MAKE_BIN" install
[ "$TEST_RELEASETAR" = yes ] && run_after_echo "$MAKE_BIN" releasetar
handle_matrix_debug
if [ "$DELETE_PREFIX" = yes ]; then
    run_after_echo rm -rf "$PREFIX"
fi
# vi: set tabstop=4 softtabstop=0 expandtab shiftwidth=4 smarttab autoindent :

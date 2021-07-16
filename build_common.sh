#!/bin/sh

# To make CI scripts maintenance simpler, copies of this file in the
# libpcap, tcpdump and tcpslice git repositories should be identical.

mktempdir() {
    mktempdir_prefix=${1:?}
    case $(uname -s) in
    Darwin|FreeBSD|NetBSD)
        # In these operating systems mktemp(1) always appends an implicit
        # ".XXXXXXXX" suffix to the requested template when creating a
        # temporary directory.
        ;;
    *)
        # At least Linux and OpenBSD implementations require explicit trailing
        # X'es in the template, so make it the same suffix as above.
        mktempdir_prefix="${mktempdir_prefix}.XXXXXXXX"
        ;;
    esac
    mktemp -d -t "$mktempdir_prefix"
}

print_sysinfo() {
    uname -a
    date
}

print_cc_version() {
    # GCC and Clang recognize --version and print to stdout. Sun compilers
    # recognize -V and print to stderr.
    "$CC" --version 2>/dev/null || "$CC" -V || :
}

# Display text in magenta.
echo_magenta() {
    # ANSI magenta, the imploded text, ANSI reset, newline.
    printf '\033[35;1m%s\033[0m\n' "$*"
}

# Run a command after displaying it.
run_after_echo() {
    : "${1:?}" # Require at least one argument.
    printf '$ %s\n' "$*"
    "$@"
}

handle_matrix_debug() {
    [ "$MATRIX_DEBUG" != yes ] && return
    echo '$ cat Makefile [...]'
    sed '/^# DO NOT DELETE THIS LINE -- mkdep uses it.$/q' <Makefile
    run_after_echo cat config.h
    [ "$CMAKE" = yes ] || run_after_echo cat config.log
}

# vi: set tabstop=4 softtabstop=0 expandtab shiftwidth=4 smarttab autoindent :

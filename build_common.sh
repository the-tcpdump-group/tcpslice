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
        mktemp -d -t "$mktempdir_prefix"
        ;;
    AIX)
        # A poor man's mktemp(1) because AIX does not have one.
        mktempdir_prefix=${TMPDIR:-/tmp}/${mktempdir_prefix}
        while true; do
            mktempdir_suffix='.'
            for xx in XX XX XX XX; do
                # /bin/sh implements RANDOM in AIX.
                # shellcheck disable=SC2039
                xx=$(printf '%02x' $((RANDOM % 256)))
                mktempdir_suffix="${mktempdir_suffix}${xx}"
            done
            if ! [ -e "${mktempdir_prefix}${mktempdir_suffix}" ]; then
                mkdir -p "${mktempdir_prefix}${mktempdir_suffix}"
                chmod go= "${mktempdir_prefix}${mktempdir_suffix}"
                echo "${mktempdir_prefix}${mktempdir_suffix}"
                break
            fi
        done
        ;;
    *)
        # At least Linux and OpenBSD implementations require explicit trailing
        # X'es in the template, so make it the same suffix as above.
        mktemp -d -t "${mktempdir_prefix}.XXXXXXXX"
        ;;
    esac
}

print_sysinfo() {
    uname -a
    date
}

print_cc_version() {
    # GCC and Clang recognize --version and print to stdout. Sun compilers
    # recognize -V and print to stderr. XL C for AIX recognizes -qversion
    # and prints to stdout, but on an unknown command-line flag displays its
    # man page and waits.
    case $(basename "$CC") in
    gcc*|clang*)
        "$CC" --version
        ;;
    xl*)
        "$CC" -qversion
        ;;
    *)
        "$CC" --version || "$CC" -V || :
        ;;
    esac
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

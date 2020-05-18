dnl Copyright (c) 1995, 1996, 1997, 1999
dnl	The Regents of the University of California.  All rights reserved.
dnl
dnl Process this file with autoconf to produce a configure script.
dnl

#
# See
#
#	https://ftp.gnu.org/gnu/config/README
#
# for the URLs to use to fetch new versions of config.guess and
# config.sub.
#

AC_PREREQ(2.64)
AC_INIT(tcpslice, m4_esyscmd_s([cat VERSION]))
AC_CONFIG_SRCDIR(tcpslice.c)

AC_CANONICAL_HOST

AC_LBL_C_INIT_BEFORE_CC(V_INCLS)
#
# Try to enable as many C99 features as we can.
# At minimum, we want C++/C99-style // comments.
#
AC_PROG_CC_C99
if test "$ac_cv_prog_cc_c99" = "no"; then
	AC_MSG_WARN([The C compiler does not support C99; there may be compiler errors])
fi
AC_LBL_C_INIT(V_CCOPT, V_INCLS)
AC_LBL_C_INLINE

AC_CHECK_HEADERS(fcntl.h)

AC_HEADER_TIME

tcpslice_telloseeko=yes

#
# Try to arrange for large file support.
#
AC_SYS_LARGEFILE
AC_FUNC_FSEEKO

AC_REPLACE_FUNCS(vfprintf strlcpy)

AC_LBL_LIBPCAP(V_PCAPDEP, V_INCLS)
saveCPPFLAGS=$CPPFLAGS

AC_CHECK_LIB(nids, nids_pcap_handler,,
	AC_MSG_WARN(Libnids not present or too old; tcpslice won't be able to track sessions!)
	AC_MSG_WARN(Get the latest version of Libnids at http://libnids.sourceforge.net/)
)

AC_CHECK_LIB(osipparser2, osip_message_parse,,
	AC_MSG_WARN(Libosip2 not present or too old; tcpslice won't be able to track SIP calls!)
	AC_MSG_WARN(Get the latest version of Libosip at http://www.osip.org/)
)

AC_CHECK_LIB(ooh323c, asn1PD_H225RasMessage,,
	AC_MSG_WARN(Libooh323c not present or too old; tcpslice won't be able to track H.323 calls!)
	AC_MSG_WARN(Get the latest version of Libooh323c at http://ooh323c.sourceforge.net/)
)

#
# Check whether we have pcap/pcap-inttypes.h.
# If we do, we use that to get the C99 types defined.
#
savedcppflags="$CPPFLAGS"
CPPFLAGS="$CPPFLAGS $V_INCLS"
AC_CHECK_HEADERS(pcap/pcap-inttypes.h)
CPPFLAGS="$savedcppflags"

#
# Define the old BSD specified-width types in terms of the C99 types;
# we may need them with libpcap include files.
#
AC_CHECK_TYPE([u_int8_t], ,
	[AC_DEFINE([u_int8_t], [uint8_t],
	[Define to `uint8_t' if u_int8_t not defined.])],
	[AC_INCLUDES_DEFAULT
#include <sys/types.h>
])
AC_CHECK_TYPE([u_int16_t], ,
	[AC_DEFINE([u_int16_t], [uint16_t],
	[Define to `uint16_t' if u_int16_t not defined.])],
	[AC_INCLUDES_DEFAULT
#include <sys/types.h>
])
AC_CHECK_TYPE([u_int32_t], ,
	[AC_DEFINE([u_int32_t], [uint32_t],
	[Define to `uint32_t' if u_int32_t not defined.])],
	[AC_INCLUDES_DEFAULT
#include <sys/types.h>
])
AC_CHECK_TYPE([u_int64_t], ,
	[AC_DEFINE([u_int64_t], [uint64_t],
	[Define to `uint64_t' if u_int64_t not defined.])],
	[AC_INCLUDES_DEFAULT
#include <sys/types.h>
])

AC_LBL_DEVEL(V_CCOPT)

if test "${srcdir}" = "." ; then
	srcdirprefix=""
else
	srcdirprefix="./"
fi

if test -r ${srcdirprefix}lbl/gnuc.h ; then
	rm -f gnuc.h
	ln -s ${srcdirprefix}lbl/gnuc.h gnuc.h
fi

AC_SUBST(V_CCOPT)
AC_SUBST(V_DEFS)
AC_SUBST(V_INCLS)
AC_SUBST(V_PCAPDEP)

AC_PROG_INSTALL

AC_CONFIG_HEADER(config.h)

AC_OUTPUT_COMMANDS([if test -f .devel; then
	echo timestamp > stamp-h
	cat $srcdir/Makefile-devel-adds >> Makefile
	make depend
fi])
AC_OUTPUT(Makefile)
exit 0

dnl Copyright (c) 1995, 1996, 1997, 1999
dnl	The Regents of the University of California.  All rights reserved.
dnl
dnl Process this file with autoconf to produce a configure script.
dnl

AC_REVISION($Revision$)
AC_PREREQ(2.50)
AC_INIT(tcpslice.c)

AC_CANONICAL_HOST

AC_LBL_C_INIT(V_CCOPT, V_INCLS)
AC_LBL_C_INLINE
AC_C___ATTRIBUTE__
AC_CHECK_HEADERS(fcntl.h net/bpf.h)

AC_HEADER_TIME

tcpslice_telloseeko=yes
AC_CHECK_FUNCS(ftello fseeko, ,AC_MSG_WARN(tcpslice may have trouble with dump files larger than 2 gigabytes); tcpslice_telloseeko=no; break)
if test "${tcpslice_telloseeko}" = "yes" ; then
	AC_DEFINE(FTELL, ftello)
	AC_DEFINE(FSEEK, fseeko)
else
	AC_DEFINE(FTELL, ftell)
	AC_DEFINE(FSEEK, fseek)
fi

AC_REPLACE_FUNCS(vfprintf strlcpy)

AC_LBL_LIBPCAP(V_PCAPDEP, V_INCLS)
saveCPPFLAGS=$CPPFLAGS
CPPFLAGS="$CPPFLAGS $V_INCLS"
AC_CHECK_HEADER(pcap-int.h)
CPPFLAGS=$saveCPPFLAGS
if test "$ac_cv_header_pcap_int_h" = "yes"
then
	AC_DEFINE(HAVE_PCAP_INT_H)
else
	AC_MSG_WARN(No pcap-int.h; tcpslice may not be able to read dump files.)
	AC_MSG_WARN(Try building with a local copy of the libpcap source.)
fi

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

dnl
dnl check sizeof basic types.
dnl They're very likely to be wrong for cross-compiling.
AC_CHECK_SIZEOF(char, 1)
AC_CHECK_SIZEOF(short, 2)
AC_CHECK_SIZEOF(int, 4)
AC_CHECK_SIZEOF(long, 4)
AC_CHECK_SIZEOF(long long, 8)

dnl
dnl Checks for u_intXX_t
dnl AC_CHECK_BITTYPES(ac_cv_bittypes)
dnl if test "$ac_cv_bittypes" = no; then
dnl 	missing_includes=yes
dnl fi

AC_CHECK_HEADERS(sys/bitypes.h)

AC_CHECK_TYPE([int8_t], ,
	[AC_DEFINE([int8_t], [signed char],
	[Define to `signed char' if int8_t not defined.])])
AC_CHECK_TYPE([u_int8_t], ,
	[AC_DEFINE([u_int8_t], [unsigned char],
	[Define to `unsigned char' if u_int8_t not defined.])],
	[AC_INCLUDES_DEFAULT
#ifdef HAVE_SYS_BITYPES_H
#include <sys/bitypes.h>
#endif])
AC_CHECK_TYPE([int16_t], ,
	[AC_DEFINE([int16_t], [short],
	[Define to `short' if int16_t not defined.])])
AC_CHECK_TYPE([u_int16_t], ,
	[AC_DEFINE([u_int16_t], [unsigned short],
	[Define to `unsigned short' if u_int16_t not defined.])],
	[AC_INCLUDES_DEFAULT
#ifdef HAVE_SYS_BITYPES_H
#include <sys/bitypes.h>
#endif])
AC_CHECK_TYPE([int32_t], ,
	[AC_DEFINE([int32_t], [int],
	[Define to `int' if int32_t not defined.])])
AC_CHECK_TYPE([u_int32_t], ,
	[AC_DEFINE([u_int32_t], [unsigned int],
	[Define to `unsigned int' if u_int32_t not defined.])],
	[AC_INCLUDES_DEFAULT
#ifdef HAVE_SYS_BITYPES_H
#include <sys/bitypes.h>
#endif])
AC_CHECK_TYPE([int64_t], ,
	[AC_DEFINE([int64_t], [long long],
	[Define to `long long' if int64_t not defined.])])
AC_CHECK_TYPE([u_int64_t], ,
	[AC_DEFINE([u_int64_t], [unsigned long long],
	[Define to `unsigned long long' if u_int64_t not defined.])],
	[AC_INCLUDES_DEFAULT
#ifdef HAVE_SYS_BITYPES_H
#include <sys/bitypes.h>
#endif])

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
	cat Makefile-devel-adds >> Makefile
	make depend
fi])
AC_OUTPUT(Makefile)
exit 0

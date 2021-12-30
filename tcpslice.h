/*
 * Copyright (c) 1993, 1995
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifndef TCPSLICE_H
#define TCPSLICE_H

#include "compiler-tests.h"

#include "varattrs.h"

/*
 * If we're compiling with Visual Studio, make sure we have at least
 * VS 2015 or later, so we have sufficient C99 support.
 *
 * XXX - verify that we have at least C99 support on UN*Xes?
 *
 * What about MinGW or various DOS toolchains?  We're currently assuming
 * sufficient C99 support there.
 */
#if defined(_MSC_VER)
  /*
   * Make sure we have VS 2015 or later.
   */
  #if _MSC_VER < 1900
    #error "Building tcpslice requires VS 2015 or later"
  #endif
#endif

/*
 * Get the C99 types, and the PRI[doux]64 format strings, defined.
 */
#ifdef HAVE_PCAP_PCAP_INTTYPES_H
  /*
   * We have pcap/pcap-inttypes.h; use that, as it'll do all the
   * work, and won't cause problems if a file includes this file
   * and later includes a pcap header file that also includes
   * pcap/pcap-inttypes.h.
   */
  #include <pcap/pcap-inttypes.h>
#else
  /*
   * OK, we don't have pcap/pcap-inttypes.h, so we'll have to
   * do the work ourselves, but at least we don't have to
   * worry about other headers including it and causing
   * clashes.
   */

  /*
   * Include <inttypes.h> to get the integer types and PRi[doux]64 values
   * defined.
   *
   * If the compiler is MSVC, we require VS 2015 or newer, so we
   * have <inttypes.h> - and support for %zu in the formatted
   * printing functions.
   *
   * If the compiler is MinGW, we assume we have <inttypes.h> - and
   * support for %zu in the formatted printing functions.
   *
   * If the target is UN*X, we assume we have a C99-or-later development
   * environment, and thus have <inttypes.h> - and support for %zu in
   * the formatted printing functions.
   *
   * If the target is MS-DOS, we assume we have <inttypes.h> - and support
   * for %zu in the formatted printing functions.
   */
  #include <inttypes.h>

  #if defined(_MSC_VER)
    /*
     * Suppress definition of intN_t in bittypes.h, which might be included
     * by <pcap/pcap.h> in older versions of WinPcap.
     * (Yes, HAVE_U_INTn_T, as the definition guards are UN*X-oriented.)
     */
    #define HAVE_U_INT8_T
    #define HAVE_U_INT16_T
    #define HAVE_U_INT32_T
    #define HAVE_U_INT64_T
  #endif
#endif /* HAVE_PCAP_PCAP_INTTYPES_H */

#include <time.h>
#include <sys/types.h>
#include <sys/time.h>
#include <pcap.h>

#define IS_LEAP_YEAR(year)	\
	(year % 4 == 0 && (year % 100 != 0 || year % 400 == 0))

/*
 * OpenBSD libpcap compensation: in struct pcap_pkthdr "ts" instead of struct
 * timeval uses struct bpf_timeval, which declares members with the same names
 * and a different type, which is a 32-bit unsigned, whilst on 64-bit systems
 * struct timeval uses a 64-bit integer type.
 */
#define TIMEVAL_FROM_PKTHDR_TS(dst, src) { \
	(dst).tv_sec = (src).tv_sec; \
	(dst).tv_usec = (src).tv_usec; \
}

extern const int days_in_month[];
time_t			gwtm2secs( const struct tm *tm );

int			sf_find_end( struct pcap *p, const struct timeval *first_timestamp,
					struct timeval *last_timestamp );
int			sf_timestamp_less_than( const struct timeval *t1, const struct timeval *t2 );
int			sf_find_packet( struct pcap *p,
				struct timeval *min_time, int64_t min_pos,
				struct timeval *max_time, int64_t max_pos,
				const struct timeval *desired_time );

int			fseek64(FILE *p, const int64_t offset, const int whence);
int64_t			ftell64(FILE *p);
extern char *timestamp_to_string(const struct timeval *timestamp);

#ifndef HAVE_STRLCPY
extern size_t strlcpy(char *, const char *, size_t);
#endif

void			error(const char *fmt, ...);
void			warning(const char *fmt, ...);

extern pcap_dumper_t	*global_dumper;
#endif /* TCPSLICE_H */

/*
 * Copyright (c) 1993, 1995, 1996
 *	The Regents of the University of California.  All rights reserved.
 *
 * SPDX-License-Identifier: BSD-4-Clause-Shortened
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that:
 *
 * 1. source code distributions retain the above copyright notice and this
 *    paragraph in its entirety,
 *
 * 2. distributions including binary code include the above copyright notice
 *    and this paragraph in its entirety in the documentation or other
 *    materials provided with the distribution, and
 *
 * 3. all advertising materials mentioning features or use of this software
 *    display the following acknowledgement:
 *
 * "This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors."
 *
 * Neither the name of the University nor the names of its contributors may be
 * used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif

#include "tcpslice.h"

static void
complain(const char *fmt, va_list ap)
{
	(void)fprintf(stderr, "tcpslice: ");
	(void)vfprintf(stderr, fmt, ap);
	if (*fmt) {
		fmt += strlen(fmt);
		if (fmt[-1] != '\n')
			(void)fputc('\n', stderr);
	}
}

/* VARARGS */
void
warning(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	complain(fmt, ap);
	va_end(ap);
}

/* VARARGS */
void
error(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	complain(fmt, ap);
	va_end(ap);
	exit(1);
	/* NOTREACHED */
}

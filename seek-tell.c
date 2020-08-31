/*
 * Copyright (c) 1993, 1994, 1995, 1996, 1997
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
 *
 * 64-bit-offset fseek and ftell.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>

#include "tcpslice.h"

#if defined(HAVE_FSEEKO)
/*
 * We have fseeko(), so we have ftello().
 * If we have large file support (files larger than 2^31-1 bytes),
 * fseeko() will let us seek to a current file position with more
 * than 32 bits and ftello() will give us a current file position
 * with more than 32 bits.
 */
int
fseek64(FILE *p, const int64_t offset, const int whence)
{
	off_t off_t_offset;

	/*
	 * Make sure the offset fits.
	 */
	off_t_offset = (off_t)offset;
	if (offset != off_t_offset) {
		/*
		 * It doesn't.  Fail with EINVAL.
		 */
		errno = EINVAL;
		return (-1);
	}
	return (fseeko(p, off_t_offset, whence));
}

int64_t
ftell64(FILE *p)
{
	return (ftello(p));
}
#elif defined(_MSC_VER)
/*
 * We have Visual Studio; we support only 2005 and later, so we have
 * _fseeki64() and _ftelli64().
 */
int
fseek64(FILE *p, const int64_t offset, const int whence)
{
	return (_fseeki64(p, offset, whence));
}

int64_t
ftell64(FILE *p)
{
	return (_ftelli64(p));
}
#else
/*
 * We don't have ftello() or _ftelli64(), so fall back on ftell().
 * Either long is 64 bits, in which case ftell() should suffice,
 * or this is probably an older 32-bit UN*X without large file
 * support, which means you'll probably get errors trying to
 * write files > 2^31-1, so it won't matter anyway.
 *
 * XXX - what about MinGW?
 */
int
fseek64(FILE *p, const int64_t offset, const int whence)
{
	long long_offset;

	/*
	 * Make sure the offset fits.
	 */
	long_offset = (long)offset;
	if (offset != long_offset) {
		/*
		 * It doesn't.  Fail with EINVAL.
		 */
		errno = EINVAL;
		return (-1);
	}
	return (fseek(p, long_offset, whence));
}

int64_t
ftell64(FILE *p)
{
	return (ftell(p));
}
#endif

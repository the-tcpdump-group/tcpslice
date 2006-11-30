/* ip.h
 *
 * Copyright (C) 2005 by Sebastien Raveau
 * sebastien.raveau@epita.fr
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the
 * Free Software Foundation, Inc.,
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef _HAWKEYE_IP_H
# define _HAWKEYE_IP_H

# include <netinet/in.h>

/**
 * The IP structure, according to RFC 791
 * http://www.ietf.org/rfc/rfc0791.txt
 */
struct rfc_ip
{
# if BYTE_ORDER == LITTLE_ENDIAN
  unsigned char		ihl:4;
  unsigned char		version:4;
# elif BYTE_ORDER == BIG_ENDIAN
  unsigned char		version:4;
  unsigned char		ihl:4;
# else
#  error "Please define the BYTE_ORDER macro!"
# endif
  unsigned char		tos;
  unsigned short	tot_len;
  unsigned short	id;
# if BYTE_ORDER == LITTLE_ENDIAN
  unsigned short	frag_off:13;
  unsigned short	flags:3;
# elif BYTE_ORDER == BIG_ENDIAN
  unsigned short	flags:3;
  unsigned short	frag_off:13;
# else
#  error "Please define the BYTE_ORDER macro!"
# endif
  unsigned char		ttl;
  unsigned char		protocol;
  unsigned short	checksum;
  struct in_addr	saddr;
  struct in_addr	daddr;
} __attribute__ ((packed));

# define IPHDRLEN	sizeof (struct rfc_ip)

#endif

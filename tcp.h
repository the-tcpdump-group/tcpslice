/* tcp.h
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

#ifndef _HAWKEYE_TCP_H
# define _HAWKEYE_TCP_H

/**
 * The TCP structure, according to RFC 793
 * http://www.ietf.org/rfc/rfc0793.txt
 */
struct rfc_tcp
{
  unsigned short	sport;
  unsigned short	dport;
  unsigned int		seq;
  unsigned int		ack_seq;
# if BYTE_ORDER == LITTLE_ENDIAN
  unsigned short	reserved:4;
  unsigned short	data_off:4;
  unsigned short	fin:1;
  unsigned short	syn:1;
  unsigned short	rst:1;
  unsigned short	psh:1;
  unsigned short	ack:1;
  unsigned short	urg:1;
  unsigned short	ece:1;
  unsigned short	cwr:1;
# elif BYTE_ORDER == BIG_ENDIAN
  unsigned short	data_off:4;
  unsigned short	reserved:4;
  unsigned short	cwr:1;
  unsigned short	ece:1;
  unsigned short	urg:1;
  unsigned short	ack:1;
  unsigned short	psh:1;
  unsigned short	rst:1;
  unsigned short	syn:1;
  unsigned short	fin:1;
# else
#  error "Please define the BYTE_ORDER macro!"
# endif
  unsigned short	window;
  unsigned short	checksum;
  unsigned short	urgent_ptr;
} __attribute__ ((packed));

# define TCPHDRLEN	sizeof (struct rfc_tcp)

#endif

/* udp.h
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

#ifndef _HAWKEYE_UDP_H
# define _HAWKEYE_UDP_H

/**
 * The UDP structure, according to RFC 768
 * http://www.ietf.org/rfc/rfc0768.txt
 */
struct rfc_udp
{
  unsigned short	sport;
  unsigned short	dport;
  unsigned short	length;
  unsigned short	checksum;
} __attribute__ ((packed));

# define UDPHDRLEN	sizeof (struct rfc_udp)

#endif

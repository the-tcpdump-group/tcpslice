/*
 * Copyright (c) 2006 Sebastien Raveau <sebastien.raveau@epita.fr>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This file contains code for tracking TCP and VoIP (SIP & H.323) sessions.
 *
 * IMPORTANT: None of these features are available if libnids >= 1.21 wasn't
 * found by ./configure; SIP session tracking is available only if Libosip was
 * found by ./configure and H.323 session tracking is available only if
 * Libooh323c was found by ./configure. These libraries can be downloaded from:
 *  - http://libnids.sourceforge.net/
 *  - https://www.gnu.org/software/osip/
 *  - https://sourceforge.net/projects/ooh323c/
 *
 * There are several entry points (from tcpslice.c) to this file:
 *  - sessions_init() has to be called once before any tracking can be done
 *  - sessions_nids_init() has to be called each time we change PCAP file
 *  - sessions_exit() is used to clean up and report after we're done
 *  - ip_callback() is called for defragmented IPv4 packets, including UDP & TCP
 *  - udp_callback() is called upon reception of correct UDP data
 *  - tcp_callback() is called upon reception of correct TCP data
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "varattrs.h"
#include "sessions.h"

/*
 * The global variables below have the following purposes:
 *
 * `verbose' counts how many times -v was specified on the
 * command line. It is currently used by sessions_add() and
 * sessions_del() to show when sessions are opened and closed.
 * Specify -v once and it will show opening and closing of
 * primary sessions, but specify it at least twice to see
 * the opening and closing of subsessions, i.e. sessions that
 * are created because of some primary sessions (for example
 * a SIP session will open a RTP session for the call data).
 *
 * `bonus_time' equals 0 when we are between the start-time and
 * end-time specified by the user on the command line, and 1 when
 * we are past the end-time, in which case we continue to track
 * the existing sessions but ignore new sessions.
 *
 * `track_sessions' is a flag set by sessions_init() and
 * sessions_exit() but it is mostly used in tcpslice.c to know
 * wether or not to pass each PCAP frame to libnids in order to
 * track sessions (it saves further processing if the user did
 * not want to track sessions, which should be the case most of
 * the time).
 *
 * `sessions_count` is the number of active sessions at a time;
 * it is especially used by sessions_exit() to print a report about
 * unclosed sessions in case there are any left when we are done.
 *
 * `sessions_file_format' is either NULL if the user does not want
 * each primary session and all of its subsessions to be extracted
 * and saved to separate PCAP files, or a string of the form
 * "/path/filename-%s-%d.pcap", where %s will be replaced by the
 * primary session type string in lowercase ("tcp", "sip" or "h323")
 * and %d by the primary session ID. Note that you can specify %.6d
 * instead of %d so that files can correctly be sorted by session ID
 * (which will be zero-padded on the left up to six digits); this
 * prevents having x-sip-10.pcap before x-sip-2.pcap for example.
 *
 * `sessions_expiration_delay' can be set by the user to a number
 * of seconds after which an idle tracked session will be considered
 * to be closed. This is useful to deal with faulty implementations
 * of some protocols or packet loss, which otherwise would keep
 * resources allocated until the call to sessions_exit().
 */
int				verbose = 0;
int				bonus_time = 0;
int				track_sessions = 0;
uint32_t			sessions_count = 0;
char				*sessions_file_format = NULL;
time_t				sessions_expiration_delay = 0;

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#ifndef HAVE_LIBNIDS

void				sessions_init(char *types _U_)
{
  fprintf(stderr, "Libnids required for session tracking support, sorry.\n");
  exit(-1);
}

void				sessions_exit(void)
{
}

void				sessions_nids_init(pcap_t *p _U_)
{
}

#else

# include <string.h>
# include <nids.h>
# ifdef HAVE_LIBOSIPPARSER2
#  include <osip2/osip.h>
#  include <osipparser2/sdp_message.h>
# endif
# ifdef HAVE_LIBOOH323C
#  include <ooh323.h>
#  include <ooCalls.h>
#  include <printHandler.h>
# endif
# include "tcpslice.h"
# include <netinet/ip.h>
# define IPHDRLEN sizeof(struct ip)
# include <netinet/udp.h>
# define UDPHDRLEN sizeof(struct udphdr)
# include <netinet/tcp.h>
# define TCPHDRLEN sizeof(struct tcphdr)
#include <netinet/in.h>
#include <arpa/inet.h>

/*
 * Session type identifiers, used as bitmasks for
 * convenience in searchs among tracked sessions.
 */
enum type
{
  TYPE_NONE			= 0x00,
  TYPE_UDP			= 0x01,
  TYPE_TCP			= 0x02,
  TYPE_SIP			= 0x04,
  TYPE_RTP			= 0x08,
  TYPE_RTCP			= 0x10,
  TYPE_H225_RAS			= 0x20,
  TYPE_H225_CS			= 0x40,
  CLASS_SIP			= TYPE_SIP | TYPE_RTP,
  CLASS_H323			= TYPE_H225_RAS | TYPE_H225_CS | TYPE_RTP | TYPE_RTCP
};

/*
 * Structure used by sessions and subsessions to safely share
 * the same file descriptor, when they have to be saved in the
 * same PCAP file and can be closed in a different order than
 * they were opened.
 */
struct shared_dumper
{
  char				*filename;
  pcap_dumper_t			*filedesc;
  uint32_t			references;
};

/*
 * (Almost) generic session description object containing
 * the following properties:
 *  - addr: IPv4 address & port for source and destination
 *  - type: protocol bitmask (e.g. TYPE_UDP | TYPE_SIP)
 *  - id: unique number assigned to each session
 *  - parent_id: instead of a pointer (which is dangerous because parents
 *               are sometimes destroyed before their children) an ID
 *               that can be used to search for children of a specific session
 *  - parent_id: 0 for primary sessions, parent's ID for subsessions
 *  - timeout: when the session has to be forcefully closed
 *  - callback: method to call in order to process session data
 *  - dumper: file to which this session's packets will be extracted
 *  - lastseen: timestamp of the last packet in this session
 *  - bytes: total amount of data captured for this session
 *  - next: pointer to the next session in the list of all sessions
 *  - prev: pointer to the previous session in the list of all sessions
 *  - u: union containing extra properties that are needed for some session types
 */
struct session
{
  struct tuple4			addr;
  enum type			type;
  uint32_t			id;
  uint32_t			parent_id;
  time_t			timeout;
  struct session		*(*callback)(struct session *elt, u_char *data, uint32_t len);
  struct shared_dumper		*dumper;
  struct timeval		lastseen;
  uint64_t			bytes;
  struct session		*next;
  struct session		*prev;
# if defined(HAVE_LIBOSIPPARSER2) || defined(HAVE_LIBOOH323C)
  union
  {
# endif
# ifdef HAVE_LIBOSIPPARSER2
    struct
    {
      struct tuple4		rtp_addr;
      osip_call_id_t		*call_id;
      int			picked_up;
    } sip_params;
# endif
# ifdef HAVE_LIBOOH323C
    struct
    {
      struct tuple4		cs_addr;
      H225RequestSeqNum		seqnum;
      char			call_id[16];
    } ras_params;
# endif
# if defined(HAVE_LIBOSIPPARSER2) || defined(HAVE_LIBOOH323C)
  } u;
# endif
};

/*
 * Pointer to the head of the list containing all tracked sessions
 */
static struct session		*first_session = NULL;

/*
 * Bitmask of the session types the user asked to track
 */
static enum type		sessions_track_types = TYPE_NONE;

/*
 * Count how many PCAP savefiles were opened, to cope with the
 * "Too many open files" errors and work around them by closing
 * the oldest 10% of the file descriptors.
 */
static unsigned int		dumper_fd_count = 0;

/*
 * The static functions declared below have the following purposes:
 *
 * `sessions_add' checks if a session must be tracked or not depending on
 * what the user wants (i.e. if `t' matches `sessions_track_types'); if so
 * it creates a new session object, fills in the properties (based on `addr'
 * and `parent' if there is one) and inserts in the list of tracked sessions.
 *
 * `sessions_del' properly removes a session object from the list.
 *
 * `sessions_find' is a small search engine acting on several criteria; it
 * can search starting from the beginning of the list or from the element
 * pointed by the `start' parameter, it can search for sessions with specific
 * types described by the `t' parameter, or by parent ID, or most of the time
 * by source and destination IP address & port.
 *
 * `dumper_open' and `dumper_close' manage multiple references to the same
 * PCAP file used for saving packets when the user asked for extraction of
 * sessions into separate files. `dumper_too_many_open_files' tries to cope
 * with the "Too many open files" error that can happen when dealing with
 * large PCAP files containing many simultaneous sessions.
 *
 * `dump_frame' actually saves the current packet to a PCAP file.
 *
 * `parse_type' simply converts a type from string to numerical form.
 *
 * `type2string' simply converts a type from numerical form to string.
 *
 * `ip_callback', `tcp_callback' and `udp_callback' are called from inside
 * libnids upon reception of respectively IPv4, TCP and UDP packets.
 *
 * `sip_callback', `h225_ras_callback' and `h225_cs_callback' are called
 * from `tcp_callback' and `udp_callback' via the session::callback field,
 * in order to process respectively IETF's Session Initialization Protocol,
 * ITU's H.225 Registration Admission Status and H.225 Call Signaling (both
 * part of H.323) data.
 */
static struct session		*sessions_add(uint8_t t, struct tuple4 *addr, struct session *parent);
static void			sessions_del(struct session *elt);
static struct session		*sessions_find(struct session *start, uint8_t t, uint32_t parent_id, struct tuple4 *addr);
static struct shared_dumper	*dumper_open(enum type t, uint32_t id);
static void			dumper_too_many_open_files(struct shared_dumper **d);
static void			dumper_close(struct shared_dumper *d);
static void			dump_frame(u_char *data, int len, struct shared_dumper *output);
static enum type		parse_type(const char *str);
static const char		*type2string(enum type t, int upper);
static void			ip_callback(struct ip *ip, int len);
static void			tcp_callback(struct tcp_stream *tcp, void **user);
static void			udp_callback(struct tuple4 *addr, u_char *data, int len, struct ip *ip);
static struct session		*sip_callback(struct session *elt, u_char *data, uint32_t len);
static struct session		*h225_ras_callback(struct session *elt, u_char *data, uint32_t len);
static struct session		*h225_cs_callback(struct session *elt, u_char *data, uint32_t len);

static enum type		parse_type(const char *str)
{
  if (!strcmp("tcp", str))
    return TYPE_TCP;
# ifdef HAVE_LIBOSIPPARSER2
  if (!strcmp("sip", str))
    return CLASS_SIP;
# endif
# ifdef HAVE_LIBOOH323C
  if (!strcmp("h323", str))
    return CLASS_H323;
# endif
  fprintf(stderr, "Error: unsupported session type `%s'\n", str);
  exit(-1);
}

void				sessions_init(char *types)
{
  char				*comma;

  bonus_time = 0;
  sessions_track_types = TYPE_NONE;
  while (NULL != (comma = strchr(types, ','))) {
    *comma = '\0';
    sessions_track_types |= parse_type(types);
    types = comma + 1;
  }
  sessions_track_types |= parse_type(types);
  while (sessions_count) {
    struct session *elt = first_session;
    first_session = first_session->next;
    --sessions_count;
    dumper_close(elt->dumper);
    free(elt);
  }
# ifdef HAVE_LIBOOH323C
  ooH323EpInitialize(OO_CALLMODE_AUDIOCALL, "/dev/null");
  ooH323EpDisableAutoAnswer();
# endif
  track_sessions = 1;
}

void				sessions_exit(void)
{
  struct session		*elt;
  struct session		*elt_next;
  time_t			one_minute_later = 0;

  /*
   * Last pass to close timeout'd session... It is needed
   * because the last packet of a session marked for
   * deletion can be followed only by non-IP packets, so
   * it won't be deleted by ip_callback and would otherwise
   * appear as unclosed in the report generated below.
   * We jump forward one minute in order to timeout TCP
   * sessions that were opened during the last minute
   * of capture, which were given 60 seconds to complete
   * handshake but failed to do so.
   *
   * Also close SIP sessions that did not result in a call:
   * it happens often and the resulting spam in the report
   * generated below can be really annoying.
   */
  if (NULL != nids_last_pcap_header)
    one_minute_later = nids_last_pcap_header->ts.tv_sec + 60;
  for (elt = first_session; NULL != elt; elt = elt_next) {
    elt_next = elt->next;
    if (elt->timeout && (one_minute_later >= elt->timeout)) {
      sessions_del(elt);
      continue;
    }
# ifdef HAVE_LIBOSIPPARSER2
    if ((elt->type & TYPE_SIP) && !elt->u.sip_params.picked_up)
      sessions_del(elt);
# endif
  }

  /*
   * Print a report about unclosed sessions.
   */
  if (sessions_count) {
    fprintf(stderr,
	    "%u unclosed %s (id, type, last, source, destination, bytes):\n",
	    sessions_count, sessions_count > 1 ? "sessions" : "session");
    while (NULL != first_session) {
      fprintf(stderr, "#%u\t", first_session->id);
      fprintf(stderr, "%s\t", type2string(first_session->type, 1));
      fprintf(stderr, "%s\t", timestamp_to_string(&first_session->lastseen));
      fprintf(stderr, "%15s:%-5d\t",
	  inet_ntoa(*((struct in_addr *)&first_session->addr.saddr)),
	  first_session->addr.source);
      fprintf(stderr, "%15s:%-5d\t",
	  inet_ntoa(*((struct in_addr *)&first_session->addr.daddr)),
	  first_session->addr.dest);
      fprintf(stderr, "%12" PRIu64 "\n", first_session->bytes);
      dumper_close(first_session->dumper);
      if (NULL != first_session->next) {
	first_session = first_session->next;
	free(first_session->prev);
	first_session->prev = NULL;
      } else {
	free(first_session);
	first_session = NULL;
      }
      --sessions_count;
    }
  }
  track_sessions = 0;
  nids_exit();
}

void				sessions_nids_init(pcap_t *p)
{
  nids_params.pcap_desc = p;
  nids_params.tcp_workarounds = 1;
  if (!nids_init()) {
    fprintf(stderr, "nids_init: %s\n", nids_errbuf);
    exit(-1);
  }
  nids_register_ip(ip_callback);
  nids_register_udp(udp_callback);
  nids_register_tcp(tcp_callback);
}

static struct session		*sessions_add(uint8_t t, struct tuple4 *addr, struct session *parent)
{
  struct session		*elt;
  static uint32_t		counter = 0;

  if (!(t & sessions_track_types))
    return NULL;
  elt = calloc(1, sizeof (struct session));
  elt->addr = *addr;
  elt->type = t;
  elt->id = ++counter;
  if (sessions_expiration_delay)
    elt->timeout = nids_last_pcap_header->ts.tv_sec + sessions_expiration_delay;
  if (t & TYPE_SIP)
    elt->callback = sip_callback;
  else
    if (t & TYPE_H225_RAS)
      elt->callback = h225_ras_callback;
    else
      if (t & TYPE_H225_CS)
	elt->callback = h225_cs_callback;
      else
	elt->callback = NULL;
  if (NULL != parent) {
    elt->parent_id = parent->id;
    elt->dumper = parent->dumper;
    elt->dumper->references++;
  } else
    elt->dumper = sessions_file_format ? dumper_open(t, elt->id) : NULL;
  elt->next = first_session;
  if (NULL != elt->next)
    elt->next->prev = elt;
  elt->prev = NULL;
  first_session = elt;
  ++sessions_count;
  if (verbose && (!elt->parent_id || verbose > 1))
    printf("Session #%u (%s) opened at %s (active sessions total: %u)\n",
	elt->parent_id ? elt->parent_id : elt->id,
	type2string(t, 1),
	timestamp_to_string(&nids_last_pcap_header->ts),
	sessions_count);
  return elt;
}

static void			sessions_del(struct session *elt)
{
  struct tcp_stream		*tcp;

  if (NULL == elt)
    return;
  --sessions_count;
  if ((bonus_time || verbose) && (!elt->parent_id || verbose > 1))
    printf("Session #%u (%s) closed at %s (active sessions total: %u)\n",
	elt->parent_id ? elt->parent_id : elt->id,
	type2string(elt->type, 1),
	timestamp_to_string(&nids_last_pcap_header->ts),
	sessions_count);
  if (NULL != elt->next)
    elt->next->prev = elt->prev;
  if (NULL != elt->prev)
    elt->prev->next = elt->next;
  else
    first_session = elt->next;

  /*
   * If this is a TCP connection, tell libnids we do not
   * want to be notified of new data in this connection.
   *
   * We must not do it when the stream is already in a
   * closing state (NIDS_CLOSE, NIDS_TIMED_OUT, NIDS_RESET
   * or NIDS_EXITING) because nids_free_tcp_stream() would
   * then be called twice, resulting in a crash.
   */
  if ((elt->type & TYPE_TCP) &&
      (NULL != (tcp = nids_find_tcp_stream(&elt->addr))) &&
      (NIDS_DATA == tcp->nids_state))
    nids_free_tcp_stream(tcp);

# ifdef HAVE_LIBOSIPPARSER2
  /*
   * If this is a SIP session, finally free the memory
   * allocated for the call ID (couldn't be done before)
   */
  if (elt->type & TYPE_SIP)
    if (NULL != elt->u.sip_params.call_id)
      osip_call_id_free(elt->u.sip_params.call_id);
# endif

  dumper_close(elt->dumper);
  free(elt);
}

static struct session		*sessions_find(struct session *start, uint8_t t, uint32_t parent_id, struct tuple4 *addr)
{
  struct session		*elt;

  for (elt = start; NULL != elt; elt = elt->next) {
    if (!(elt->type & t))
      continue;
    if (parent_id && (elt->parent_id != parent_id))
      continue;
    if (NULL != addr) {
      if ((!elt->addr.source || elt->addr.source == addr->source) &&
	  (!elt->addr.dest || elt->addr.dest == addr->dest) &&
	  (!elt->addr.saddr || elt->addr.saddr == addr->saddr) &&
	  (!elt->addr.daddr || elt->addr.daddr == addr->daddr))
	return elt;
      if ((!elt->addr.source || elt->addr.source == addr->dest) &&
	  (!elt->addr.dest || elt->addr.dest == addr->source) &&
	  (!elt->addr.saddr || elt->addr.saddr == addr->daddr) &&
	  (!elt->addr.daddr || elt->addr.daddr == addr->saddr))
	return elt;
    }
    if (parent_id)
      return elt;
  }
  return NULL;
}

static struct shared_dumper	*dumper_open(enum type t, uint32_t id)
{
  struct shared_dumper		*d;

  d = malloc(sizeof (struct shared_dumper));
  d->filename = malloc(strlen(sessions_file_format) + strlen(type2string(t, 0)) + 16);
  sprintf(d->filename, sessions_file_format, type2string(t, 0), id);
  d->filedesc = pcap_dump_open(nids_params.pcap_desc, d->filename);
  if (NULL == d->filedesc)
    dumper_too_many_open_files(&d);
  ++dumper_fd_count;
  d->references = 1;
  return d;
}

static void			dumper_too_many_open_files(struct shared_dumper **d)
{
  struct session		*elt;
  unsigned int			oldest_ten_percent;

  oldest_ten_percent = sessions_count / 10;
  if (EMFILE == errno && oldest_ten_percent) {
    for (elt = first_session; NULL != elt; elt = elt->next) {
      if (NULL != elt->dumper->filedesc) {
	pcap_dump_close(elt->dumper->filedesc);
	elt->dumper->filedesc = NULL;
	--dumper_fd_count;
	if (!--oldest_ten_percent)
	  break;
      }
    }
    (*d)->filedesc = pcap_dump_open(nids_params.pcap_desc, (*d)->filename);
  }
  if (NULL == (*d)->filedesc) {
    fprintf(stderr,
	"pcap_dump_open: %s: %s\n",
	(*d)->filename,
	pcap_geterr(nids_params.pcap_desc));
    exit(-1);
  }
}

static void			dumper_close(struct shared_dumper *d)
{
  if (NULL == d)
    return;
  --d->references;
  if (!d->references) {
    free(d->filename);
    if (NULL != d->filedesc) {
      pcap_dump_close(d->filedesc);
      --dumper_fd_count;
    }
  }
}

static const char		*type2string(enum type t, int upper)
{
  if (t & TYPE_SIP)
    return upper ? "SIP" : "sip";
  if ((t & TYPE_H225_RAS) || (t & TYPE_H225_CS))
    return upper ? "H323" : "h323";
  if (t & TYPE_RTP)
    return upper ? "RTP" : "rtp";
  if (t & TYPE_TCP)
    return upper ? "TCP" : "tcp";
  return "???";
}

static void			dump_frame(u_char *data, int len, struct shared_dumper *output)
{
  u_char			*frame;
  struct pcap_pkthdr		ph;

  if (!bonus_time && NULL == output)
    return;
  frame = malloc(len + nids_linkoffset);
  memcpy(frame, nids_last_pcap_data, nids_linkoffset);
  memcpy(frame + nids_linkoffset, data, len);
  ph.ts = nids_last_pcap_header->ts;
  ph.caplen = ph.len = len + nids_linkoffset;
  if (NULL != output) {
    if (NULL == output->filedesc) {
      output->filedesc = pcap_dump_open(nids_params.pcap_desc, output->filename);
      if (NULL == output->filedesc)
	dumper_too_many_open_files(&output);
      ++dumper_fd_count;
    }
    pcap_dump((u_char *)output->filedesc, &ph, frame);
  }
  if (bonus_time)
    pcap_dump((u_char *)global_dumper, &ph, frame);
  free(frame);
}

/*
 * This function is called upon reception of all IPv4 packets, which
 * means some packets will be processed by both ip_callback and
 * {udp,tcp}_callback. It is necessary for TCP packets though because
 * tcp_callback is only called once a connection is established (i.e.
 * after the first SYN, SYN+ACK and ACK packets have passed) and only
 * when data is available (PSH packets).
 * Since we don't want failed TCP connections (portscans etc) to
 * mobilize resources, we give TCP sessions 60 seconds to complete
 * the TCP handshake or else they are considered to be closed.
 */
static void			ip_callback(struct ip *ip, int len)
{
  struct tuple4			addr;
  struct tcphdr			*tcp;
  struct session		*elt;
  struct session		*elt_next;
  unsigned int			ip_data_offset = IPHDRLEN;

  for (elt = first_session; NULL != elt; elt = elt_next) {
    elt_next = elt->next;
    if (elt->timeout && (nids_last_pcap_header->ts.tv_sec >= elt->timeout))
      sessions_del(elt);
  }
  if ((ip->ip_hl > 5) && ((ip->ip_hl * 4) <= len))
    ip_data_offset = ip->ip_hl * 4;
  if ((ip->ip_p != 6) || (len < (ip_data_offset + TCPHDRLEN)))
    return; /* not TCP or too short */
  tcp = (struct tcphdr *)((char *)ip + ip_data_offset);
  addr.saddr = *((u_int *)&ip->ip_src);
  addr.daddr = *((u_int *)&ip->ip_dst);
  addr.source = ntohs(tcp->th_sport);
  addr.dest = ntohs(tcp->th_dport);
  if (NULL != (elt = sessions_find(first_session, TYPE_TCP, 0, &addr))) {
    dump_frame((u_char *)ip, len, elt->dumper);
    if (sessions_expiration_delay)
      elt->timeout = nids_last_pcap_header->ts.tv_sec + sessions_expiration_delay;
    elt->lastseen = nids_last_pcap_header->ts;
    return;
  }
  if (!(tcp->th_flags & TH_SYN) || bonus_time)
    return;
  if (addr.source == 5060 || addr.dest == 5060)
    elt = sessions_add(TYPE_TCP | TYPE_SIP, &addr, NULL);
  else
    elt = sessions_add(TYPE_TCP, &addr, NULL);
  if (NULL == elt)
    return;
  dump_frame((u_char *)ip, len, elt->dumper);
  elt->timeout = nids_last_pcap_header->ts.tv_sec + 60;
  /* 60 seconds to complete TCP handshake */
}

static void			udp_callback(struct tuple4 *addr, u_char *udp_data, int udp_data_len, struct ip *ip)
{
  struct session		*elt;
  unsigned int			udp_data_offset = IPHDRLEN + UDPHDRLEN;

  if (NULL == (elt = sessions_find(first_session, TYPE_UDP, 0, addr))) {
    if (bonus_time)
      return;
    if (addr->source == 1719 || addr->dest == 1719)
      elt = sessions_add(TYPE_UDP | TYPE_H225_RAS, addr, NULL);
    else
      if (addr->source == 5060 || addr->dest == 5060)
	elt = sessions_add(TYPE_UDP | TYPE_SIP, addr, NULL);
  }
  if (NULL == elt)
    return;
  elt->bytes += udp_data_len;
  elt->lastseen = nids_last_pcap_header->ts;
  if (NULL != elt->callback)
    elt = elt->callback(elt, udp_data, udp_data_len);

  /*
   * We can dump the frame only after the data is processed because
   * a new session object (`elt') might be created by the callback,
   * with a pointer to a different PCAP file.
   */
  if ((ip->ip_hl > 5) && ((ip->ip_hl * 4) < (udp_data_offset + udp_data_len)))
    udp_data_offset = ip->ip_hl * 4 + UDPHDRLEN;
  dump_frame((u_char *)ip, udp_data_offset + udp_data_len, elt->dumper);
}

static void			tcp_callback(struct tcp_stream *tcp, void **user)
{
  struct session		*elt;
  struct session		*rtp;
  struct session		*start;

  switch (tcp->nids_state) {
    case NIDS_JUST_EST:
      if (bonus_time)
	return;
      elt = sessions_find(first_session, TYPE_TCP, 0, &tcp->addr);
      if (NULL == elt)
	return;
      if (elt->type & TYPE_H225_CS) {
	elt->addr.saddr = tcp->addr.saddr;
	elt->addr.source = tcp->addr.source;
      }
      *user = elt;
      if (!sessions_expiration_delay)
	elt->timeout = 0;
      tcp->client.collect++;
      tcp->server.collect++;
      return;
    case NIDS_DATA:
      elt = (struct session *)*user;
      elt->bytes += tcp->client.count_new + tcp->server.count_new;
      if (NULL != elt->callback) {
	if (tcp->client.count_new)
	  elt->callback(elt, (u_char *)tcp->client.data, tcp->client.count_new);
	if (tcp->server.count_new)
	  elt->callback(elt, (u_char *)tcp->server.data, tcp->server.count_new);
      }
      return;
    case NIDS_CLOSE:
    case NIDS_RESET:
    case NIDS_TIMED_OUT:
      elt = (struct session *)*user;
      if (elt->type & TYPE_H225_CS)
	for (start = first_session; NULL != (rtp = sessions_find(start, TYPE_RTP | TYPE_RTCP, elt->id, NULL)); start = rtp->next)
	  sessions_del(rtp);
      sessions_del((struct session *)*user);
  }
}

# ifdef HAVE_LIBOSIPPARSER2
static int		sip_get_address(osip_message_t *msg, u_int *host, u_short *port)
{
  osip_content_type_t	*ctt;
  sdp_message_t		*sdp;
  int			i;
  int			j;

  if (NULL == (ctt = osip_message_get_content_type(msg)))
    return 0;
  if ((NULL == ctt->type) || (NULL == ctt->subtype))
    return 0;
  if (osip_strcasecmp(ctt->type, "application"))
    return 0;
  if (osip_strcasecmp(ctt->subtype, "sdp"))
    return 0;
  for (i = 0; !osip_list_eol(&msg->bodies, i); ++i) {
    sdp = NULL;
    sdp_message_init(&sdp);
    char *tmp = ((osip_body_t *)osip_list_get(&msg->bodies, i))->body;
    if (sdp_message_parse(sdp, tmp)) {
      sdp_message_free(sdp);
      continue;
    }
    for (j = 0; NULL != sdp_message_m_media_get(sdp, j); ++j) {
      if (NULL == (tmp = sdp_message_m_port_get(sdp, j)))
	continue;
      *port = atoi(tmp);
      if (NULL == (tmp = sdp_message_c_addr_get(sdp, -1, 0)))
	if (NULL == (tmp = sdp_message_c_addr_get(sdp, j, 0)))
	  continue;
      *host = (u_int)inet_addr(tmp);
      sdp_message_free(sdp);
      return 1;
    }
    sdp_message_free(sdp);
  }
  return 0;
}

static struct session			*sip_callback(struct session *sip, u_char *data, uint32_t len)
{
  osip_message_t			*msg;
  struct session			*start;
  struct session			*rtp;
  osip_call_id_t			*call_id;

  osip_message_init(&msg);
  if (!osip_message_parse(msg, (char *)data, len)) {
    if (NULL == sip->u.sip_params.call_id) {
      /*
       * If the session object was created by udp_callback
       * we need to fill in the call_id field here because
       * udp_callback doesn't know anything about SIP
       */
      if (NULL != (call_id = osip_message_get_call_id(msg)))
	osip_call_id_clone(call_id, &sip->u.sip_params.call_id);
    } else {
      /*
       * Otherwise check if the session object passed to this
       * function call was really the one corresponding to the
       * call ID in the SIP packet, in case several SIP calls
       * are passed upon the same transport layer protocol,
       * source and destination IPv4 address & port combination.
       * udp_callback has no way of knowing how to distinguish
       * SIP session objects based on call ID, so we have to do
       * it here. We just continue searching in the list of all
       * tracked sessions for similar SIP objects until we find
       * one that has the same call ID, or else we create a new
       * SIP session object that corresponds to the new call.
       */
      start = sip;
      do {
	if (NULL == (call_id = osip_message_get_call_id(msg)))
	  continue;
	if (!osip_call_id_match(sip->u.sip_params.call_id, call_id))
	  break;
      } while ((sip = sessions_find(sip->next, TYPE_SIP, 0, &sip->addr)));
      if (NULL == sip) {
	if (bonus_time) {
	  osip_message_free(msg);
	  return start;
	}
	sip = sessions_add(start->type, &start->addr, NULL);
	if (NULL != (call_id = osip_message_get_call_id(msg)))
	  osip_call_id_clone(call_id, &sip->u.sip_params.call_id);
      }
    }
    /*
     * If the current SIP packet is an INVITE message, store the
     * advertised source port and IPv4 address. It is not very
     * important, since we can do only with the destination part
     * (useful in case the capture missed the INVITE packet), but
     * it helps discriminating from unrelated packets.
     *
     * Unfortunately, some SIP implementations such as the one in
     * Audiocodes Mediant 1000 SIP gateways actually use a source
     * port different from the one they advertised in the INVITE
     * message parameters - how outrageous! - so we have to make
     * our sessions search engine ignore the source port part by
     * zeroing it :-/
     */
    if (MSG_IS_INVITE(msg)) {
      if (!bonus_time) {
	sip_get_address(msg, &sip->u.sip_params.rtp_addr.saddr, &sip->u.sip_params.rtp_addr.source);
#ifndef USING_NON_STUPID_SIP_IMPLEMENTATIONS
	sip->u.sip_params.rtp_addr.source = 0;
#endif
      }
    } else
      if (MSG_TEST_CODE(msg, 200)) {
	if (MSG_IS_RESPONSE_FOR(msg, "INVITE")) {
	  if (!bonus_time && sip_get_address(msg, &sip->u.sip_params.rtp_addr.daddr, &sip->u.sip_params.rtp_addr.dest)) {
	    sessions_add(TYPE_UDP | TYPE_RTP, &sip->u.sip_params.rtp_addr, sip);
	    sip->u.sip_params.picked_up = 1;
	  }
	} else
	  if (MSG_IS_RESPONSE_FOR(msg, "BYE") ||
	      MSG_IS_RESPONSE_FOR(msg, "CANCEL")) {
	    start = first_session;
	    while (NULL != (rtp = sessions_find(start, TYPE_RTP, sip->id, NULL))) {
	      sessions_del(rtp);
	      start = rtp->next;
	    }
	    /*
	     * Mark for deletion in 2 seconds, in order to give some
	     * time to the extra ACK packets that might be exchanged
	     */
	    if (sip->type & TYPE_UDP)
	      sip->timeout = nids_last_pcap_header->ts.tv_sec + 2;
	  }
      }
  }
  osip_message_free(msg);
  return sip;
}
# else
static struct session			*sip_callback(struct session *sip, u_char *data _U_, uint32_t len _U_)
{
  return sip;
}
# endif

# ifdef HAVE_LIBOOH323C
static struct session			*h225_ras_callback(struct session *ras, u_char *data, uint32_t len)
{
  OOCTXT				ctxt;
  H225RasMessage			*pRasMsg;
  struct session			*cs;
  struct session			*rasbkp;

  initContext(&ctxt);
  if (ASN_OK != setPERBuffer(&ctxt, data, len, TRUE))
    return ras;
  rasbkp = ras;
  pRasMsg = (H225RasMessage *)memAlloc(&ctxt, sizeof (H225RasMessage));
  if (ASN_OK == asn1PD_H225RasMessage(&ctxt, pRasMsg))
    switch (pRasMsg->t) {
      case T_H225RasMessage_admissionRequest:
	if (bonus_time)
	  break;
	if ('\0' != ras->u.ras_params.call_id[0])
	  ras = sessions_add(TYPE_UDP | TYPE_H225_RAS, &ras->addr, NULL);
	memcpy(ras->u.ras_params.call_id, pRasMsg->u.admissionRequest->conferenceID.data, 16);
	ras->u.ras_params.seqnum = pRasMsg->u.admissionRequest->requestSeqNum;
	ras->timeout = nids_last_pcap_header->ts.tv_sec + 60;
	/* 60 seconds for the gatekeeper to confirm admission */
	break;
      case T_H225RasMessage_admissionConfirm:
	if (bonus_time)
	  break;
	while ((NULL != ras) && (ras->u.ras_params.seqnum != pRasMsg->u.admissionConfirm->requestSeqNum))
	  ras = sessions_find(ras->next, TYPE_UDP | TYPE_H225_RAS, 0, &ras->addr);
	if (NULL == ras) {
	  ras = rasbkp;
	  break;
	}
	if (pRasMsg->u.admissionConfirm->destCallSignalAddress.t != T_H225TransportAddress_ipAddress) {
	  ras->timeout = nids_last_pcap_header->ts.tv_sec; /* delete after dumping frame */
	  break;
	}
	ras->u.ras_params.cs_addr.dest = pRasMsg->u.admissionConfirm->destCallSignalAddress.u.ipAddress->port;
	ras->u.ras_params.cs_addr.daddr = *((u_int *)pRasMsg->u.admissionConfirm->destCallSignalAddress.u.ipAddress->ip.data);
	if (NULL != (cs = sessions_add(TYPE_TCP | TYPE_H225_CS, &ras->u.ras_params.cs_addr, ras)))
	  cs->timeout = nids_last_pcap_header->ts.tv_sec + 60;
	/* 60 seconds to establish the Call Signaling stream */
	break;
      case T_H225RasMessage_admissionReject:
	while ((NULL != ras) && (ras->u.ras_params.seqnum != pRasMsg->u.admissionReject->requestSeqNum))
	  ras = sessions_find(ras->next, TYPE_UDP | TYPE_H225_RAS, 0, &ras->addr);
	if (NULL == ras) {
	  ras = rasbkp;
	  break;
	}
	ras->timeout = nids_last_pcap_header->ts.tv_sec; /* delete after dumping frame */
	break;
      case T_H225RasMessage_disengageRequest:
	while ((NULL != ras) && memcmp(ras->u.ras_params.call_id, pRasMsg->u.disengageRequest->conferenceID.data, 16))
	  ras = sessions_find(ras->next, TYPE_UDP | TYPE_H225_RAS, 0, &ras->addr);
	if (NULL == ras) {
	  ras = rasbkp;
	  break;
	}
	ras->u.ras_params.seqnum = pRasMsg->u.disengageRequest->requestSeqNum;
	break;
      case T_H225RasMessage_disengageConfirm:
	while ((NULL != ras) && (ras->u.ras_params.seqnum != pRasMsg->u.disengageConfirm->requestSeqNum))
	  ras = sessions_find(ras->next, TYPE_UDP | TYPE_H225_RAS, 0, &ras->addr);
	if (NULL == ras) {
	  ras = rasbkp;
	  break;
	}
	ras->timeout = nids_last_pcap_header->ts.tv_sec; /* delete after dumping frame */
    }
  memFreePtr(&ctxt, pRasMsg);
  freeContext(&ctxt);
  return ras;
}

static struct session			*h225_cs_callback(struct session *cs, u_char *data, uint32_t len)
{
  char					callToken[20];
  OOH323CallData			*call;
  Q931Message				q931;
  DListNode				*node;
  H245OpenLogicalChannel		*olc;
  H245H2250LogicalChannelParameters	*lcp;
  struct tuple4				addr;

  ooGenerateCallToken(callToken, 20);
  call = ooCreateCall("incoming", callToken);
  call->pH225Channel = (OOH323Channel*) memAllocZ (call->pctxt, sizeof (OOH323Channel));
  if (OO_OK == ooQ931Decode(call, &q931, ntohs(*((u_short *)(data + 2))) - 4, data + 4)) {
    if (OO_OK == ooHandleH2250Message(call, &q931)) {
      if (!bonus_time && (q931.messageType == Q931CallProceedingMsg)) {
	for (node = call->remoteFastStartOLCs.head; NULL != node; node = node->next) {
	  olc = node->data;
	  if (4 == olc->forwardLogicalChannelParameters.multiplexParameters.t) {
	    lcp = olc->forwardLogicalChannelParameters.multiplexParameters.u.h2250LogicalChannelParameters;
	    if (lcp->m.mediaChannelPresent &&
		(1 == lcp->mediaChannel.t) &&
		(1 == lcp->mediaChannel.u.unicastAddress->t)) {
	      addr.source = 0;
	      addr.saddr = 0;
	      addr.dest = lcp->mediaChannel.u.unicastAddress->u.iPAddress->tsapIdentifier;
	      addr.daddr = *((u_int *)lcp->mediaChannel.u.unicastAddress->u.iPAddress->network.data);
	      sessions_add(TYPE_UDP | TYPE_RTP, &addr, cs);
	      if (lcp->m.mediaControlChannelPresent &&
		  (2 == lcp->mediaControlChannel.t) &&
		  (1 == lcp->mediaControlChannel.u.multicastAddress->t)) {
		addr.source = 0;
		addr.saddr = 0;
		addr.dest = lcp->mediaControlChannel.u.unicastAddress->u.iPAddress->tsapIdentifier;
		addr.daddr = *((u_int *)lcp->mediaControlChannel.u.unicastAddress->u.iPAddress->network.data);
		sessions_add(TYPE_UDP | TYPE_RTCP, &addr, cs);
	      }
	      /* break; */
	    }
	  }
	}
      }
    }
  }
  ooCleanCall(call);
  return cs;
}

# else
static struct session			*h225_ras_callback(struct session *ras, u_char *data _U_, uint32_t len _U_)
{
  return ras;
}

static struct session			*h225_cs_callback(struct session *cs, u_char *data _U_, uint32_t len _U_)
{
  return cs;
}
# endif

#endif

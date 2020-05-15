/*
 * Copyright (c) 1991, 1992, 1993, 1995, 1996, 1997, 1999, 2000
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
#ifndef lint
static const char copyright[] =
    "@(#) Copyright (c) 1991, 1992, 1993, 1995, 1996, 1997, 1999, 2000\n\
The Regents of the University of California.  All rights reserved.\n";
#endif

/*
 * tcpslice - extract pieces of and/or glue together tcpdump files
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <sys/file.h>
#include <sys/stat.h>

#ifdef HAVE_NET_BPF_H
# include <net/bpf.h>
#else
# include <pcap-bpf.h>
#endif

#include <ctype.h>
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include <memory.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef TIME_WITH_SYS_TIME
#include <time.h>
#endif
#include <unistd.h>

#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif

#include "tcpslice.h"
#include "gmt2local.h"
#include "machdep.h"
#include "sessions.h"

#ifndef HAVE_STRLCPY
extern size_t strlcpy(char *, const char *, size_t);
#endif

#ifndef __dead
# define __dead
#endif

/* compute a + b, store in c */
#define	TV_ADD(a,b,c)	{ \
	(c)->tv_sec = (a)->tv_sec + (b)->tv_sec; \
	(c)->tv_usec = (a)->tv_usec + (b)->tv_usec; \
	if ((c)->tv_usec > 1000000) { \
		(c)->tv_usec -= 1000000; \
		(c)->tv_sec += 1; \
	} \
}

/* compute a - b, store in c */
#define	TV_SUB(a,b,c)	{ \
	(c)->tv_sec = (a)->tv_sec - (b)->tv_sec; \
	if ((a)->tv_usec < (b)->tv_usec) { \
		(c)->tv_sec -= 1;		/* need to borrow */ \
		(c)->tv_usec = ((a)->tv_usec + 1000000) - (b)->tv_usec; \
	} else { \
		(c)->tv_usec = (a)->tv_usec - (b)->tv_usec; \
	} \
}

/* The structure used to keep track of files being merged. */
struct state {
	int64_t	start_pos,	/* seek position corresponding to start time */
		stop_pos;	/* seek position corresponding to stop time */
	struct timeval
		file_start_time,	/* time of first pkt in file */
		file_stop_time,		/* time of last pkt in file */
		last_pkt_time;		/* time of most recently read pkt */
	pcap_t	*p;
	struct pcap_pkthdr hdr;
	const u_char *pkt;
	char	*filename;
	int	done;
};

int tflag = 0;	/* global that util routines are sensitive to */

char *program_name;

/* Style in which to print timestamps; RAW is "secs.usecs"; READABLE is
 * ala the Unix "date" tool; and PARSEABLE is tcpslice's custom format,
 * designed to be easy to parse.  The default is RAW.
 */
enum stamp_styles { TIMESTAMP_RAW, TIMESTAMP_READABLE, TIMESTAMP_PARSEABLE };
enum stamp_styles timestamp_style = TIMESTAMP_RAW;


int is_timestamp( char *str );
struct timeval parse_time(char *time_string, struct timeval base_time);
void fill_tm(char *time_string, int is_delta, struct tm *t, time_t *usecs_addr);
struct timeval lowest_start_time(struct state *states, int numfiles);
struct timeval latest_end_time(struct state *states, int numfiles);
void get_next_packet(struct state *s);
struct state *open_files(char *filenames[], int numfiles);
static void extract_slice(struct state *states, int numfiles,
			const char *write_file_name,
			struct timeval *start_time, struct timeval *stop_time,
			int keep_dups, int relative_time_merge,
			struct timeval *base_time);
char *timestamp_to_string(struct timeval *timestamp);
void dump_times(struct state *states, int numfiles);
__dead void usage(void)__attribute__((volatile));


pcap_dumper_t *global_dumper = 0;

extern  char *optarg;
extern  int optind, opterr;

int snaplen;	/* needed by search.c, extract_slice() */

int
main(int argc, char **argv)
{
	int op;
	int dump_flag = 0;
	int keep_dups = 0;
	int report_times = 0;
	int relative_time_merge = 0;
	int numfiles;
	register char *cp;
	char *start_time_string = 0;
	char *stop_time_string = 0;
	const char *write_file_name = "-";	/* default is stdout */
	struct timeval first_time, start_time, stop_time;
	char ebuf[PCAP_ERRBUF_SIZE];
	struct state *states;

	if ((cp = strrchr(argv[0], '/')) != NULL)
		program_name = cp + 1;
	else
		program_name = argv[0];

	/*
	 * On platforms where the CPU doesn't support unaligned loads,
	 * force unaligned accesses to abort with SIGBUS, rather than
	 * being fixed up (slowly) by the OS kernel; on those platforms,
	 * misaligned accesses are bugs, and we want tcpdump to crash so
	 * that the bugs are reported.
	 */
	if (abort_on_misalignment(ebuf, sizeof(ebuf)) < 0)
		error("%s", ebuf);

	opterr = 0;
	while ((op = getopt(argc, argv, "dDe:f:lRrs:tvw:")) != EOF)
		switch (op) {

		case 'd':
			dump_flag = 1;
			break;

		case 'D':
			keep_dups = 1;
			break;

		case 'e':
			sessions_expiration_delay = atoi(optarg);
			break;

		case 'f':
			sessions_file_format = optarg;
			break;

		case 'l':
			relative_time_merge = 1;
			break;

		case 'R':
			++report_times;
			timestamp_style = TIMESTAMP_RAW;
			break;

		case 'r':
			++report_times;
			timestamp_style = TIMESTAMP_READABLE;
			break;

		case 's':
			timestamp_style = TIMESTAMP_PARSEABLE;
			sessions_init(optarg);
			break;

		case 't':
			++report_times;
			timestamp_style = TIMESTAMP_PARSEABLE;
			break;

		case 'v':
			++verbose;
			break;

		case 'w':
			write_file_name = optarg;
			break;

		default:
			usage();
			/* NOTREACHED */
		}

	if ( report_times > 1 )
		error( "only one of -R, -r, or -t can be specified" );

	if (optind < argc)
		/* See if the next argument looks like a possible
		 * start time, and if so assume it is one.
		 */
		if (isdigit(argv[optind][0]) || argv[optind][0] == '+')
			start_time_string = argv[optind++];

	if (optind < argc)
		if (isdigit(argv[optind][0]) || argv[optind][0] == '+')
			stop_time_string = argv[optind++];

	if (optind >= argc)
		error("at least one input file must be given");

	numfiles = argc - optind;

	if ( numfiles == 1 )
		keep_dups = 1;	/* no dups can occur, so don't do the work */

	states = open_files(&argv[optind], numfiles);
	first_time = lowest_start_time(states, numfiles);

	if (start_time_string)
		start_time = parse_time(start_time_string, first_time);
	else
		start_time = first_time;

	if (stop_time_string)
		stop_time = parse_time(stop_time_string, start_time);
	else
		stop_time = latest_end_time(states, numfiles);

	if (report_times) {
		dump_times(states, numfiles);
	}

	if (dump_flag) {
		printf( "start\t%s\nstop\t%s\n",
			timestamp_to_string( &start_time ),
			timestamp_to_string( &stop_time ) );
	}

	if (! report_times && ! dump_flag) {
		if ( ! strcmp( write_file_name, "-" ) &&
		     isatty( fileno(stdout) ) )
			error("stdout is a terminal; redirect or use -w");

		extract_slice(states, numfiles, write_file_name,
		    &start_time, &stop_time, keep_dups, relative_time_merge,
		    &first_time);
	}

	return 0;
}


/* Returns non-zero if a string matches the format for a timestamp,
 * 0 otherwise.
 */
int is_timestamp( char *str )
	{
	while ( isdigit(*str) || *str == '.' )
		++str;

	return *str == '\0';
	}


/* Given a string specifying a time (or a time offset) and a "base time"
 * from which to compute offsets and fill in defaults, returns a timeval
 * containing the specified time.
 */

struct timeval
parse_time(char *time_string, struct timeval base_time)
{
	struct tm *bt = localtime((time_t *) &base_time.tv_sec);
	struct tm t;
	struct timeval result;
	time_t usecs = 0;
	int is_delta = (time_string[0] == '+');

	if ( is_delta )
		++time_string;	/* skip over '+' sign */

	if ( is_timestamp( time_string ) )
		{ /* interpret as a raw timestamp or timestamp offset */
		char *time_ptr;

		result.tv_sec = atoi( time_string );
		time_ptr = strchr( time_string, '.' );

		if ( time_ptr )
			{ /* microseconds are specified, too */
			int num_digits = strlen( time_ptr + 1 );
			result.tv_usec = atoi( time_ptr + 1 );

			/* turn 123.456 into 123 seconds plus 456000 usec */
			while ( num_digits++ < 6 )
				result.tv_usec *= 10;
			}

		else
			result.tv_usec = 0;

		if ( is_delta )
			TV_ADD(&result, &base_time, &result);

		return result;
		}

	if (is_delta) {
		t = *bt;
		usecs = base_time.tv_usec;
	} else {
		/* Zero struct (easy way around lack of tm_gmtoff/tm_zone
		 * under older systems) */
		memset((char *)&t, 0, sizeof(t));

		/* Set values to "not set" flag so we can later identify
		 * and default them.
		 */
		t.tm_sec = t.tm_min = t.tm_hour = t.tm_mday = t.tm_mon =
			t.tm_year = -1;
	}

	fill_tm(time_string, is_delta, &t, &usecs);

	/* Now until we reach a field that was specified, fill in the
	 * missing fields from the base time.
	 */
#define CHECK_FIELD(field_name)			\
	if (t.field_name < 0)			\
		t.field_name = bt->field_name;	\
	else					\
		break

	do {	/* bogus do-while loop so "break" in CHECK_FIELD will work */
		CHECK_FIELD(tm_year);
		CHECK_FIELD(tm_mon);
		CHECK_FIELD(tm_mday);
		CHECK_FIELD(tm_hour);
		CHECK_FIELD(tm_min);
		CHECK_FIELD(tm_sec);
	} while ( 0 );

	/* Set remaining unspecified fields to 0. */
#define ZERO_FIELD_IF_NOT_SET(field_name,zero_val)	\
	if (t.field_name < 0)				\
		t.field_name = zero_val

	if (! is_delta) {
		ZERO_FIELD_IF_NOT_SET(tm_year,90);  /* should never happen */
		ZERO_FIELD_IF_NOT_SET(tm_mon,0);
		ZERO_FIELD_IF_NOT_SET(tm_mday,1);
		ZERO_FIELD_IF_NOT_SET(tm_hour,0);
		ZERO_FIELD_IF_NOT_SET(tm_min,0);
		ZERO_FIELD_IF_NOT_SET(tm_sec,0);
	}

	result.tv_sec = gwtm2secs(&t);
	result.tv_sec -= gmt2local(result.tv_sec);
	result.tv_usec = usecs;

	return result;
}


/* Fill in (or add to, if is_delta is true) the time values in the
 * tm struct "t" as specified by the time specified in the string
 * "time_string".  "usecs_addr" is updated with the specified number
 * of microseconds, if any.
 */
void
fill_tm(char *time_string, int is_delta, struct tm *t, time_t *usecs_addr)
{
	char *t_start, *t_stop, format_ch;
	int val;

#define SET_VAL(lhs,rhs)	\
	if (is_delta)		\
		lhs += rhs;	\
	else			\
		lhs = rhs

	/* Loop through the time string parsing one specification at
	 * a time.  Each specification has the form <number><letter>
	 * where <number> indicates the amount of time and <letter>
	 * the units.
	 */
	for (t_stop = t_start = time_string; *t_start; t_start = ++t_stop) {
		if (! isdigit(*t_start))
			error("bad date format %s, problem starting at %s",
			      time_string, t_start);

		while (isdigit(*t_stop))
			++t_stop;
		if (! t_stop)
			error("bad date format %s, problem starting at %s",
			      time_string, t_start);

		val = atoi(t_start);

		format_ch = *t_stop;
		if ( isupper( format_ch ) )
			format_ch = tolower( format_ch );

		switch (format_ch) {
			case 'y':
				if ( val >= 100 && val < 1970)
					error("Can't handle year %d\n", val);
				if ( val > 1900 )
					val -= 1900;
				SET_VAL(t->tm_year, val);
				break;

			case 'm':
				if (strchr(t_stop+1, 'D') ||
				    strchr(t_stop+1, 'd'))
					/* it's months */
					SET_VAL(t->tm_mon, val - 1);
				else	/* it's minutes */
					SET_VAL(t->tm_min, val);
				break;

			case 'd':
				SET_VAL(t->tm_mday, val);
				break;

			case 'h':
				SET_VAL(t->tm_hour, val);
				break;

			case 's':
				SET_VAL(t->tm_sec, val);
				break;

			case 'u':
				SET_VAL(*usecs_addr, val);
				break;

			default:
				error(
				"bad date format %s, problem starting at %s",
				      time_string, t_start);
		}
	}
}



/* Of all the files, what is the lowest start time. */
struct timeval
lowest_start_time(struct state *states, int numfiles)
{
	struct timeval min_time = states->file_start_time;

	while (numfiles--) {
		if (sf_timestamp_less_than(&states->file_start_time, &min_time)) {
			min_time = states->file_start_time;
		}
		++states;
	}
	return min_time;
}

/* Of all the files, what is the latest end time. */
struct timeval
latest_end_time(struct state *states, int numfiles)
{
	struct timeval max_time = states->file_start_time;

	while (numfiles--) {
		if (sf_timestamp_less_than(&max_time, &states->file_stop_time)) {
			max_time = states->file_stop_time;
		}
		++states;
	}
	return max_time;
}

/* Get the next record in a file.  Deal with end of file.
 *
 * This routine also prevents time from going "backwards"
 * within a single file.
 */

void
get_next_packet(struct state *s)
{
	do {
		s->pkt = pcap_next(s->p, &s->hdr);
		if (! s->pkt) {
			s->done = 1;
			if (track_sessions)
				sessions_exit();
			pcap_close(s->p);
		}
	} while ((! s->done) &&
		 sf_timestamp_less_than(&s->hdr.ts, &s->last_pkt_time));

	s->last_pkt_time = s->hdr.ts;
}

struct state *
open_files(char *filenames[], int numfiles)
{
	struct state *states;
	struct state *s;
	char errbuf[PCAP_ERRBUF_SIZE];
	int i, this_snap;

	if (numfiles == 0)
		error("no input files specified");

	/* allocate memory for all the files */
	states = (struct state *) malloc(sizeof(struct state) * numfiles);
	if (! states)
		error("unable to allocate memory for %d input files", numfiles);
	memset(states, 0, sizeof(struct state) * numfiles);

	for (i = 0; i < numfiles; ++i) {
		s = &states[i];
		s->filename = filenames[i];
		s->p = pcap_open_offline(s->filename, errbuf);
		if (! s->p)
			error( "bad tcpdump file %s: %s", s->filename, errbuf );
		if (track_sessions)
			sessions_nids_init(s->p);

		this_snap = pcap_snapshot( s->p );
		if (this_snap > snaplen) {
			snaplen = this_snap;
		}

		s->start_pos = ftell64( pcap_file( s->p ) );

		if (pcap_next(s->p, &s->hdr) == 0)
			error( "error reading packet in %s: ",
				s->filename, pcap_geterr( s->p ) );

		s->file_start_time = s->hdr.ts;

		if ( ! sf_find_end( s->p, &s->file_start_time,
					  &s->file_stop_time ) )
			error( "problems finding end packet of file %s",
				s->filename );

		s->stop_pos = ftell64( pcap_file( s->p ) );
	}

	return states;
}


/*
 * Extract from a given set of files all packets with timestamps between
 * the two time values given (inclusive).  These packets are written
 * to the save file given by write_file_name.
 *
 * Upon return, start_time is adjusted to reflect a time just after
 * that of the last packet written to the output.
 */

void
extract_slice(struct state *states, int numfiles, const char *write_file_name,
		struct timeval *start_time, struct timeval *stop_time,
		int keep_dups, int relative_time_merge,
		struct timeval *base_time)
{
	struct state *s, *min_state;
	struct timeval temp1, temp2, relative_start, relative_stop;
	int i;

	struct state *last_state;	/* remember the last packet */
	struct pcap_pkthdr last_hdr;	/* in order to remove duplicates */
	u_char* last_pkt;

	if (numfiles == 0)
		error("no input files specified");

	last_state = 0;
	last_hdr.ts.tv_sec = last_hdr.ts.tv_usec = 0;
	last_hdr.caplen = last_hdr.len = 0;
	last_pkt = (u_char*) malloc(snaplen);

	if (! last_pkt)
		error("out of memory");

	memset(last_pkt, 0, snaplen);

	TV_SUB(start_time, base_time, &relative_start);
	TV_SUB(stop_time, base_time, &relative_stop);

	for (i = 0; i < numfiles; ++i) {
		s = &states[i];

		/* compute the first packet time within *this* file */
		if (relative_time_merge) {
			/* relative time within this file */
			TV_ADD(&s->file_start_time, &relative_start, &temp1);
		} else {
			/* absolute time */
			temp1 = *start_time;
		}

		/* check if this file has *anything* for us ... */
		if (sf_timestamp_less_than(&s->file_stop_time, &temp1)) {
			/* there aren't any packets of interest in this file */
			s->done = 1;
			pcap_close(s->p);
			continue;
		}

		/*
		 * sf_find_packet() requires that the time it's passed as
		 * its last argument be in the range [min_time, max_time],
		 * so we enforce that constraint here.
		 */

		if (sf_timestamp_less_than(&temp1, &s->file_start_time)){
			temp1 = s->file_start_time;
		}

		sf_find_packet(s->p, &s->file_start_time, s->start_pos,
				&s->file_stop_time, s->stop_pos,
				&temp1);

		/* get first packet for this file */
		get_next_packet(s);
	}

	global_dumper = pcap_dump_open(states->p, write_file_name);
	if (!global_dumper) {
		error( "error creating output file %s: ",
			write_file_name, pcap_geterr( states->p ) );
	}


	/*
	 * Now, loop thru all the packets in all the files,
	 * putting packets out in timestamp order.
	 *
	 * Quite often, the files will not have overlapping
	 * timestamps, so it would be nice to try to deal
	 * efficiently with that situation. (XXX)
	 */

	while (1) {
		min_state = 0;
		for (i = 0; i < numfiles; ++i) {
			s = &states[i];
			if (! s->done) {
				if (! min_state)
					min_state = s;

				if (relative_time_merge) {
					/* compare *relative* times */
					TV_SUB(&s->hdr.ts,
						&s->file_start_time, &temp1);
					TV_SUB(&min_state->hdr.ts,
						&min_state->file_start_time, &temp2);
				} else {
					/* compare *absolute* times */
					temp1 = s->hdr.ts;
					temp2 = min_state->hdr.ts;
				}
				if (sf_timestamp_less_than( &temp1, &temp2))
					min_state = s;
			}
		}

		if (! min_state)
			break;	/* didn't find any !done files */

		if (relative_time_merge) {
			/* relative time w/in this file */
			TV_ADD(&min_state->file_start_time, &relative_stop, &temp1);
		} else
			/* take absolute times */
			temp1 = *stop_time;

		if (sf_timestamp_less_than(&temp1, &min_state->hdr.ts)) {
			if (!sessions_count) {
				/* We've gone beyond the end of the region
				 * of interest ... We're done with this file.
				 */
				if (track_sessions)
					sessions_exit();
				min_state->done = 1;
				pcap_close(min_state->p);
				break;
			} else {
				/* We need to wait for the sessions to close */
				bonus_time = 1;
				*stop_time = min_state->file_stop_time;
			}
		}

		if (relative_time_merge) {
			TV_SUB(&min_state->hdr.ts, &min_state->file_start_time, &temp1);
			TV_ADD(&temp1, base_time, &min_state->hdr.ts);
		}

#ifdef HAVE_LIBNIDS
		/* Keep track of sessions, if specified by the user */
		if (track_sessions)
			nids_pcap_handler((u_char *)min_state->p, &min_state->hdr, (u_char *)min_state->pkt);
#endif

		/* Dump it, unless it's a duplicate. */
		if (!bonus_time)
			if ( keep_dups ||
			     min_state == last_state ||
			     memcmp(&last_hdr, &min_state->hdr, sizeof(last_hdr)) ||
			     memcmp(last_pkt, min_state->pkt, last_hdr.caplen) ) {
				pcap_dump((u_char *) global_dumper, &min_state->hdr, min_state->pkt);

				if ( ! keep_dups ) {
					last_state = min_state;
					last_hdr = min_state->hdr;
					memcpy(last_pkt, min_state->pkt, min_state->hdr.caplen);
				}
			}

		get_next_packet(min_state);
	}

	free(last_pkt);
}


/* Translates a timestamp to the time format specified by the user.
 * Returns a pointer to the translation residing in a static buffer.
 * There are two such buffers, which are alternated on subseqeuent
 * calls, so two calls may be made to this routine without worrying
 * about the results of the first call being overwritten by the
 * results of the second.
 */

char *
timestamp_to_string(struct timeval *timestamp)
{
	struct tm *t;
#define NUM_BUFFERS 2
	static char buffers[NUM_BUFFERS][128];
	static int buffer_to_use = 0;
	char *buf;

	buf = buffers[buffer_to_use];
	buffer_to_use = (buffer_to_use + 1) % NUM_BUFFERS;

	switch ( timestamp_style ) {

	    case TIMESTAMP_RAW:
		sprintf( buf, "%u.%06u",
		    (u_int32_t)timestamp->tv_sec,
		    (u_int32_t)timestamp->tv_usec );
		break;

	    case TIMESTAMP_READABLE:
		t = localtime((time_t *) &timestamp->tv_sec);
		strlcpy(buf, asctime(t), 128);
		buf[24] = '\0';	/* nuke final newline */
		break;

	    case TIMESTAMP_PARSEABLE:
		t = localtime((time_t *) &timestamp->tv_sec);
		sprintf( buf, "%04dy%02dm%02dd%02dh%02dm%02ds%06uu",
			t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
			t->tm_hour, t->tm_min, t->tm_sec,
			(u_int32_t)timestamp->tv_usec );
		break;

	}

	return buf;
}


/* Given a tcpdump save filename, reports on the times of the first
 * and last packets in the file.
 */

void
dump_times(struct state *states, int numfiles)
{
	for (; numfiles--; states++) {
		printf( "%s\t%s\t%s\n",
			states->filename,
			timestamp_to_string( &states->file_start_time ),
			timestamp_to_string( &states->file_stop_time ) );
	}
}

__dead void
usage(void)
{
	extern char version[];

	(void)fprintf(stderr, "Version %s\n", version);
        (void)fprintf(stderr,
		      "Usage: tcpslice [-DdlRrtv] [-w file]\n"
		      "                [ -s types [ -e seconds ] [ -f format ] ]\n"
		      "                [start-time [end-time]] file ... \n");

	exit(-1);
}


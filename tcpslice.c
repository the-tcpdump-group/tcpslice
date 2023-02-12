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

/*
 * tcpslice - extract pieces of and/or glue together pcap files
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <ctype.h>
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include <memory.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#if HAVE_STDINT_H
#include <stdint.h>
#endif
#ifndef INT32_MAX
#define INT32_MAX (2147483647)
#endif

#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif

#ifdef HAVE_LIBNIDS
#include <nids.h>
# ifdef HAVE_LIBOOH323C
# include <ootypes.h>
# endif /* HAVE_LIBOOH323C */
#endif /* HAVE_LIBNIDS */

#include "tcpslice.h"
#include "gmt2local.h"
#include "machdep.h"
#include "sessions.h"

/* For Solaris before 11. */
/* compute a + b, store in c */
#ifndef timeradd
#define timeradd(a, b, c) { \
	(c)->tv_sec = (a)->tv_sec + (b)->tv_sec; \
	(c)->tv_usec = (a)->tv_usec + (b)->tv_usec; \
	if ((c)->tv_usec > 1000000) { \
		(c)->tv_usec -= 1000000; \
		(c)->tv_sec += 1; \
	} \
}
#endif /* timeradd */
/* compute a - b, store in c */
#ifndef timersub
#define timersub(a, b, c) { \
	(c)->tv_sec = (a)->tv_sec - (b)->tv_sec; \
	if ((a)->tv_usec < (b)->tv_usec) { \
		(c)->tv_sec -= 1;		/* need to borrow */ \
		(c)->tv_usec = ((a)->tv_usec + 1000000) - (b)->tv_usec; \
	} else { \
		(c)->tv_usec = (a)->tv_usec - (b)->tv_usec; \
	} \
}
#endif /* timersub */

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

/* Style in which to print timestamps; RAW is "secs.usecs"; READABLE is
 * ala the Unix "date" tool; and PARSEABLE is tcpslice's custom format,
 * designed to be easy to parse.  The default is RAW.
 */
enum stamp_styles { TIMESTAMP_RAW, TIMESTAMP_READABLE, TIMESTAMP_PARSEABLE };
enum stamp_styles timestamp_style = TIMESTAMP_RAW;

/* Let's for now define that as far as tcpslice command-line argument parsing
 * of raw timestamps goes, valid Unix time is the non-negative range of a
 * 32-bit signed integer.  This way it is possible to validate input without
 * knowing the size and signedness of the local time_t type.  Someone please
 * invent a better solution before year 2038.
 */
#define TS_RAW_S_MAX_VALUE      INT32_MAX
#define TS_RAW_US_MAX_DIGITS    6 /* 000000~999999 */
#define TS_PARSEABLE_MAX_TOKENS 7 /* ymdhmsu */

struct parseable_token_t {
	unsigned amount;
	/* Bigger units must have bigger integer values for validation. */
	enum {
		MICROSECOND,
		SECOND,
		MINUTE, /* the default for "m" */
		HOUR,
		DAY,
		MONTH, /* potentially after disambiguation */
		YEAR,
	} unit;
};


static unsigned char timestamp_input_format_correct(const char *str);
static struct timeval parse_time(const char *time_string, struct timeval base_time);
static void fill_tm(const char *time_string, const int is_delta, struct tm *t, time_t *usecs_addr);
static struct timeval lowest_start_time(const struct state *states, int numfiles);
static struct timeval latest_end_time(const struct state *states, int numfiles);
static struct state *open_files(char *filenames[], const int numfiles);
static u_char validate_files(struct state[], const int);
static void close_files(struct state[], const int);
static void extract_slice(struct state *states, const int numfiles,
			const char *write_file_name,
			const struct timeval *start_time, struct timeval *stop_time,
			const int keep_dups, const int relative_time_merge,
			const struct timeval *base_time);
static void dump_times(const struct state *states, int numfiles);
static void print_usage(FILE *);


pcap_dumper_t *global_dumper = 0;

extern  char *optarg;
extern  int optind, opterr;

int snaplen = 0;	/* needed by search.c, extract_slice() */

int
main(int argc, char **argv)
{
	int op;
	int dump_flag = 0;
	int keep_dups = 0;
	int report_times = 0;
	int relative_time_merge = 0;
	int numfiles;
	char *start_time_string = NULL;
	char *stop_time_string = NULL;
	const char *write_file_name = "-";	/* default is stdout */
	struct timeval first_time, start_time, stop_time;
	char ebuf[PCAP_ERRBUF_SIZE];
	struct state *states;

	/*
	 * On platforms where the CPU doesn't support unaligned loads,
	 * force unaligned accesses to abort with SIGBUS, rather than
	 * being fixed up (slowly) by the OS kernel; on those platforms,
	 * misaligned accesses are bugs, and we want tcpslice to crash so
	 * that the bugs are reported.
	 */
	if (abort_on_misalignment(ebuf, sizeof(ebuf)) < 0)
		error("%s", ebuf);

	opterr = 0;
	while ((op = getopt(argc, argv, "dDe:f:hlRrs:tvw:")) != EOF)
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

		case 'h':
			print_usage(stdout);
			exit(0);
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
			(void)fprintf(stderr, "Error: invalid command-line option and/or argument!\n");
			print_usage(stderr);
			exit(-1);
			/* NOTREACHED */
		}

	if ( report_times > 1 )
		error( "only one of -R, -r, or -t can be specified" );

	/* As far as command-line argument parsing is concerned, iff a string
	 * conforms to a timestamp format, it is a time argument no matter
	 * which format and what value.  Whether a parseable time argument
	 * produces a valid date and a valid time is a different test a bit
	 * later with an additional input (base time) and a different error
	 * reporting.  This way, the argument "25h70m80s" should always make
	 * tcpslice exit with an invalid time argument error instead of trying
	 * to open a file with that name.
	 */
	if (optind < argc)
		if (timestamp_input_format_correct(argv[optind]))
			start_time_string = argv[optind++];

	if (optind < argc)
		if (timestamp_input_format_correct(argv[optind]))
			stop_time_string = argv[optind++];

	if (optind >= argc)
		error("at least one input file must be given");

	numfiles = argc - optind;

	if ( numfiles == 1 )
		keep_dups = 1;	/* no dups can occur, so don't do the work */

	states = open_files(&argv[optind], numfiles);
	/* validate_files() might identify multiple issues before returning. */
	if (validate_files(states, numfiles))
		exit(1);
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

	close_files (states, numfiles);
	return 0;
}

/* Test if the string has a form of "sssssssss" or "sssssssss.uuuuuu" (as
 * discussed in the man page) and the integer part does not exceed the upper
 * limit and the fractional part (if any) does not try to specify more
 * precision than the format allows.  Return 1 on good and 0 on bad.
 */
static unsigned char
timestamp_raw_format_correct(const char *str)
{
	enum { START, SECONDS, POINT, MICROSECONDS } fsm_state = START;
	uint64_t s_value = 0; /* Initialize to squelch a warning. */
	unsigned us_digits = 0; /* Initialize to squelch a warning. */

	while (1) {
		switch (fsm_state) {
		case START: /* Have not seen anything yet. */
			if (! isdigit((u_char)*str))
				return 0;
			s_value = *str - '0';
			fsm_state = SECONDS;
			break;
		case SECONDS: /* Have seen one or more digits for the seconds. */
			if (*str == '\0')
				return 1; /* "uuuuuuuuu" */
			if (*str == '.') {
				fsm_state = POINT;
				break;
			}
			if (! isdigit((u_char)*str) ||
			    (s_value = s_value * 10 + *str - '0') > TS_RAW_S_MAX_VALUE)
				return 0;
			break;
		case POINT: /* Have seen the decimal point. */
			if (! isdigit((u_char)*str))
				return 0;
			us_digits = 1;
			fsm_state = MICROSECONDS;
			break;
		case MICROSECONDS: /* Have seen one or more digits for the microseconds. */
			if (*str == '\0')
				return 1; /* "uuuuuuuuu.ssssss" */
			if (! isdigit((u_char)*str) || ++us_digits > TS_RAW_US_MAX_DIGITS)
				return 0;
			break;
		default:
			error("invalid FSM state in %s()", __func__);
		} /* switch (fsm_state) */
		str++;
	} /* while (1) */
}

/* Try to read one complete token (amount, unit) from the given string into
 * the provided structure by advancing the pointer and consuming characters.
 * Accept the unit characters in both lowercase and uppercase to be consistent
 * with the undocumented behaviour of fill_tm().  Do not check whether the
 * amount is valid for the unit.  Return the advanced pointer on success or
 * NULL otherwise.
 */
static const char *
parse_token(const char *str, struct parseable_token_t *token)
{
	enum { START, AMOUNT, UNIT } fsm_state = START;
	uint64_t amount = 0; /* Initialize to squelch a warning. */
	char char_unit = 0; /* Initialize to squelch a warning. */

	while (1) {
		switch (fsm_state) {
		case START: /* Have not seen anything yet. */
			if (! isdigit((u_char)*str))
				return NULL;
			amount = *str - '0';
			fsm_state = AMOUNT;
			break;
		case AMOUNT: /* Have seen one or more digits for the amount. */
			if (isalpha((u_char)*str)) {
				token->amount = amount;
				char_unit = tolower((u_char)*str);
				fsm_state = UNIT;
				break;
			}
			if (! isdigit((u_char)*str) ||
			    (amount = amount * 10 + *str - '0') > INT32_MAX)
				return NULL;
			break;
		case UNIT: /* Have seen a character, could be a valid unit. */
			switch (char_unit) {
			case 'y':
				token->unit = YEAR;
				break;
			/* no month */
			case 'd':
				token->unit = DAY;
				break;
			case 'h':
				token->unit = HOUR;
				break;
			case 'm':
				token->unit = MINUTE;
				break;
			case 's':
				token->unit = SECOND;
				break;
			case 'u':
				token->unit = MICROSECOND;
				break;
			default:
				return NULL;
			} /* switch (char_unit) */
			return str;
		default:
			error("invalid FSM state in %s()", __func__);
		} /* switch (fsm_state) */
		str++;
	} /* while (1) */
}

/* Test if the string conforms to the "ymdhmsu" format (as discussed in the
 * man page).  Do not test individual amounts to be valid for their time units
 * or the date to be a valid date or the time to be a valid time.  Return 1 on
 * good and 0 on bad.
 */
static unsigned char
timestamp_parseable_format_correct(const char *str)
{
	struct parseable_token_t token[TS_PARSEABLE_MAX_TOKENS];
	unsigned numtokens = 0;

	/* Try to tokenize the full string, fail as early as possible. */
	while (*str != '\0') {
		if (numtokens == TS_PARSEABLE_MAX_TOKENS ||
		    (str = parse_token(str, token + numtokens)) == NULL)
			return 0;
		numtokens++;
	}

	if (numtokens > 1) {
		unsigned i;
		/* Disambiguate "m". */
		for (i = 0; i < numtokens - 1; i++)
			if (token[i].unit == MINUTE && token[i + 1].unit == DAY)
				token[i].unit = MONTH;
		/* Require each time unit in the vector to appear at most once
		 * and in the order of strictly decreasing magnitude.
		 */
		for (i = 0; i < numtokens - 1; i++)
			if (token[i].unit <= token[i + 1].unit)
				return 0;
	}

	return numtokens > 0;
}

/* Test if the string conforms to a valid input time format (with an optional
 * leading "+").  Return 1 on good and 0 on bad.
 */
static unsigned char
timestamp_input_format_correct(const char *str)
{
	if (*str == '+')
		str++;
	return timestamp_parseable_format_correct(str) ||
	       timestamp_raw_format_correct(str);
}

/* No-op iff the date and the time in the given broken-down time are valid
 * and the year is within the [1970, 2069] range declared in the man page.
 */
static void
assert_valid_tm(const struct tm t)
{
	int year, maxdays;

	/* yy: [70, 99] in tm_year means [1970, 1999]
	 * yy: [0, 69] in tm_year means [2000, 2069]
	 * yyyy: [70, 99] in tm_year means [1970, 1999].
	 * yyyy: [100, 169] in tm_year means [2000, 2069].
	 */
	year = 1900 + t.tm_year;
	if (year < 1970)
		year += 100;
	if (year < 1970 || year > 2069)
		error("year %d is not valid\n", year);

	if (t.tm_mon < 0 || t.tm_mon > 11) /* 11 is December */
		error("month %d is not valid\n", t.tm_mon + 1);

	maxdays = days_in_month[t.tm_mon];
	if (t.tm_mon == 1 && IS_LEAP_YEAR(year)) /* 1 is February */
		maxdays++;
	if (t.tm_mday < 1 || t.tm_mday > maxdays)
		error("day %d is not valid\n", t.tm_mday);

	if (t.tm_hour < 0 || t.tm_hour > 23)
		error("hour %d is not valid\n", t.tm_hour);

	if (t.tm_min < 0 || t.tm_min > 59)
		error("minute %d is not valid\n", t.tm_min);

	if (t.tm_sec < 0 || t.tm_sec > 59)
		error("second %d is not valid\n", t.tm_sec);
}

/* Given a string specifying a time (or a time offset) and a "base time"
 * from which to compute offsets and fill in defaults, returns a timeval
 * containing the specified time.
 */
static struct timeval
parse_time(const char *time_string, struct timeval base_time)
{
	struct tm *bt = localtime((time_t *) &base_time.tv_sec);
	struct tm t;
	struct timeval result;
	time_t usecs = 0;
	int is_delta = (time_string[0] == '+');

	if ( is_delta )
		++time_string;	/* skip over '+' sign */

	if (timestamp_raw_format_correct(time_string))
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
			timeradd(&result, &base_time, &result);

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

	/* Terminate the program on error. */
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

	assert_valid_tm(t); /* Terminate the program on error. */
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
static void
fill_tm(const char *time_string, const int is_delta, struct tm *t, time_t *usecs_addr)
{
	const char *t_start, *t_stop;

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
		if (! isdigit((u_char)*t_start))
			error("bad date format %s, problem starting at %s",
			      time_string, t_start);

		while (isdigit((u_char)*t_stop))
			++t_stop;
		if (! (*t_stop))
			error("bad date format %s, problem starting at %s",
			      time_string, t_start);

		int val = atoi(t_start);

		char format_ch = *t_stop;
		if (isupper((u_char)format_ch))
			format_ch = tolower((u_char)format_ch);

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
static struct timeval
lowest_start_time(const struct state *states, int numfiles)
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
static struct timeval
latest_end_time(const struct state *states, int numfiles)
{
	struct timeval max_time = states->file_stop_time;

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
static void
get_next_packet(struct state *s)
{
	struct timeval tvbuf;

	do {
		s->pkt = pcap_next(s->p, &s->hdr);
		if (! s->pkt) {
			s->done = 1;
			if (track_sessions)
				sessions_exit();
			pcap_close(s->p);
		}
		TIMEVAL_FROM_PKTHDR_TS(tvbuf, s->hdr.ts);
	} while ((! s->done) &&
		 sf_timestamp_less_than(&tvbuf, &s->last_pkt_time));

	s->last_pkt_time = tvbuf;
}

static struct state *
open_files(char *filenames[], const int numfiles)
{
	struct state *states;
	struct state *s;
	char errbuf[PCAP_ERRBUF_SIZE];
	int i;

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
			error( "bad pcap file %s: %s", s->filename, errbuf );
		if (track_sessions)
			sessions_nids_init(s->p);

		int this_snap = pcap_snapshot( s->p );
		if (this_snap > snaplen) {
			snaplen = this_snap;
		}

		s->start_pos = ftell64( pcap_file( s->p ) );

		if (pcap_next(s->p, &s->hdr) == NULL)
			error( "error reading packet in %s: %s",
				s->filename, pcap_geterr( s->p ) );

		TIMEVAL_FROM_PKTHDR_TS(s->file_start_time, s->hdr.ts);

		if ( ! sf_find_end( s->p, &s->file_start_time,
					  &s->file_stop_time ) )
			error( "problems finding end packet of file %s",
				s->filename );

		s->stop_pos = ftell64( pcap_file( s->p ) );
	}

	return states;
}

/* Return 0 on no errors. */
static u_char
validate_files(struct state states[], const int numfiles)
{
	u_char ret = 0;
	int i, first_dlt, this_dlt;

	for (i = 0; i < numfiles; i++) {
		this_dlt = pcap_datalink(states[i].p);
		if (i == 0)
			first_dlt = this_dlt;
		else if (first_dlt != this_dlt) {
			warning("file '%s' uses DLT %d, and the first file '%s' uses DLT %d",
			        states[i].filename, this_dlt, states[0].filename, first_dlt);
			ret = 1;
		}

		/* Do a minimal sanity check of the timestamps. */
		if (sf_timestamp_less_than(&states[i].file_stop_time,
		                           &states[i].file_start_time)) {
			warning("'%s' has the last timestamp before the first timestamp",
			        states[i].filename);
			ret = 1;
		}
	}
	return ret;
}

static void
close_files(struct state states[], const int numfiles)
{
	int i;

	for (i = 0; i < numfiles; i++)
		if (!states[i].done)
			pcap_close(states[i].p);
	free(states);
}

/*
 * Extract from a given set of files all packets with timestamps between
 * the two time values given (inclusive).  These packets are written
 * to the save file given by write_file_name.
 *
 * Upon return, start_time is adjusted to reflect a time just after
 * that of the last packet written to the output.
 */
static void
extract_slice(struct state *states, const int numfiles, const char *write_file_name,
		const struct timeval *start_time, struct timeval *stop_time,
		const int keep_dups, const int relative_time_merge,
		const struct timeval *base_time)
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

	timersub(start_time, base_time, &relative_start);
	timersub(stop_time, base_time, &relative_stop);

	/* Always write the output file, use the first input file's DLT. */
	global_dumper = pcap_dump_open(states[0].p, write_file_name);
	if (!global_dumper) {
		error("error creating output file '%s': %s",
		      write_file_name, pcap_geterr(states[0].p));
	}

	for (i = 0; i < numfiles; ++i) {
		s = &states[i];

		/* compute the first packet time within *this* file */
		if (relative_time_merge) {
			/* relative time within this file */
			timeradd(&s->file_start_time, &relative_start, &temp1);
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


	/*
	 * Now, loop through all the packets in all the files,
	 * putting packets out in timestamp order.
	 *
	 * Quite often, the files will not have overlapping
	 * timestamps, so it would be nice to try to deal
	 * efficiently with that situation. (XXX)
	 */

	while (1) {
		struct timeval tvbuf;

		min_state = 0;
		for (i = 0; i < numfiles; ++i) {
			s = &states[i];
			if (! s->done) {
				if (! min_state)
					min_state = s;

				if (relative_time_merge) {
					/* compare *relative* times */
					timersub(&s->hdr.ts,
						&s->file_start_time, &temp1);
					timersub(&min_state->hdr.ts,
						&min_state->file_start_time, &temp2);
				} else {
					/* compare *absolute* times */
					TIMEVAL_FROM_PKTHDR_TS(temp1, s->hdr.ts);
					TIMEVAL_FROM_PKTHDR_TS(temp2, min_state->hdr.ts);
				}
				if (sf_timestamp_less_than( &temp1, &temp2))
					min_state = s;
			}
		}

		if (! min_state)
			break;	/* didn't find any !done files */

		if (relative_time_merge) {
			/* relative time w/in this file */
			timeradd(&min_state->file_start_time, &relative_stop, &temp1);
		} else
			/* take absolute times */
			temp1 = *stop_time;

		TIMEVAL_FROM_PKTHDR_TS(tvbuf, min_state->hdr.ts);
		if (sf_timestamp_less_than(&temp1, &tvbuf)) {
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
			timersub(&min_state->hdr.ts, &min_state->file_start_time, &temp1);
			timeradd(&temp1, base_time, &min_state->hdr.ts);
		}

#ifdef HAVE_LIBNIDS
		/* Keep track of sessions, if specified by the user */
		if (track_sessions && min_state->hdr.caplen) {
			/*
			 * Copy the packet buffer to deconstify it for the function.
			 */
			u_char *pkt_copy = malloc(min_state->hdr.caplen);

			if (!pkt_copy)
				error("malloc() failed in %s()", __func__);
			memcpy(pkt_copy, min_state->pkt, min_state->hdr.caplen);
			nids_pcap_handler((u_char *)min_state->p, &min_state->hdr, pkt_copy);
			free(pkt_copy);
		}
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

	pcap_dump_close(global_dumper);
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
timestamp_to_string(const struct timeval *timestamp)
{
	struct tm *t;
#define NUM_BUFFERS 2
#define DATEBUFSIZE 128
	static char buffers[NUM_BUFFERS][DATEBUFSIZE];
	static int buffer_to_use = 0;
	char *buf;

	buf = buffers[buffer_to_use];
	buffer_to_use = (buffer_to_use + 1) % NUM_BUFFERS;

	switch ( timestamp_style ) {

	    case TIMESTAMP_RAW:
		snprintf( buf, DATEBUFSIZE, "%u.%06u",
		    (u_int32_t)timestamp->tv_sec,
		    (u_int32_t)timestamp->tv_usec );
		break;

	    case TIMESTAMP_READABLE:
		t = localtime((const time_t *) &timestamp->tv_sec);
		/* Mimic asctime() with C99 format specifiers. */
		strftime(buf, DATEBUFSIZE, "%a %b %e %T %Y", t);
		break;

	    case TIMESTAMP_PARSEABLE:
		t = localtime((const time_t *) &timestamp->tv_sec);
		snprintf( buf, DATEBUFSIZE, "%04dy%02dm%02dd%02dh%02dm%02ds%06uu",
			t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
			t->tm_hour, t->tm_min, t->tm_sec,
			(u_int32_t)timestamp->tv_usec );
		break;

	}

	return buf;
}

/* Given a pcap save filename, reports on the times of the first
 * and last packets in the file.
 */
static void
dump_times(const struct state *states, int numfiles)
{
	for (; numfiles--; states++) {
		printf( "%s\t%s\t%s\n",
			states->filename,
			timestamp_to_string( &states->file_start_time ),
			timestamp_to_string( &states->file_stop_time ) );
	}
}

static void
print_usage(FILE *f)
{
#ifndef HAVE_PCAP_LIB_VERSION
  #ifdef HAVE_PCAP_VERSION
	extern char pcap_version[];
  #else /* HAVE_PCAP_VERSION */
	static char pcap_version[] = "unknown";
  #endif /* HAVE_PCAP_VERSION */
#endif /* HAVE_PCAP_LIB_VERSION */

	(void)fprintf(f, "tcpslice version %s\n", PACKAGE_VERSION);
#ifdef HAVE_PCAP_LIB_VERSION
	(void)fprintf(f, "%s\n", pcap_lib_version());
#else /* HAVE_PCAP_LIB_VERSION */
	(void)fprintf(f, "libpcap version %s\n", pcap_version);
#endif /* HAVE_PCAP_LIB_VERSION */

#ifdef HAVE_LIBNIDS
	(void)fprintf(f, "libnids version %u.%u\n", NIDS_MAJOR, NIDS_MINOR);

#ifdef HAVE_LIBOSIPPARSER2
	(void)fprintf(f, "libosip2 unknown version\n");
#endif /* HAVE_LIBOSIPPARSER2 */

#ifdef HAVE_LIBOOH323C
	(void)fprintf(f, "libooh323c %s\n", OOH323C_VERSION);
#endif /* HAVE_LIBOOH323C */

#endif /* HAVE_LIBNIDS */

	(void)fprintf(f,
	              "Usage: tcpslice [-DdhlRrtv] [-w file]\n"
	              "                [ -s types [ -e seconds ] [ -f format ] ]\n"
	              "                [start-time [end-time]] file ... \n");
}

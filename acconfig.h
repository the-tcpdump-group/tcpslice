/* DO NOT EDIT config.h.in */
@TOP@
/* If you have both fseeko and ftello, change both of these. */
#define	FSEEK	fseek
#define	FTELL	ftell

/* If there is an LBL-supplied header with additional prototypes
 * for your system, define this.
 */
#undef	HAVE_OS_PROTO_H

/* If you have <pcap-int.h> that goes with your libpcap, define this. */
#undef	HAVE_PCAP_INT_H

/* Secret configure stuff */
#undef	_HPUX_SOURCE

/* If you don't have sized types, define these to be the correct sizes. */
#undef	int32_t
#undef	u_int32_t

/*
 * captivednsd
 * 
 * Mini DNS server, which returns the same answer to all requests.
 *
 * Copyright (C) 2008 Nicholas J Humfrey
 * Copyright (C) 2005 Roberto A. Foglietta (me@roberto.foglietta.name)
 * Copyright (C) 2005 Odd Arild Olsen (oao at fibula dot no)
 * Copyright (C) 2003 Paul Sheer
 *
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 *
 * Based on Busybox's dnsd, which in-turn is based on scdns.
 *
 */


// Function prototypes
void convname(char *cstr, char *dnsstr);
int process_packet(uint8_t *buf);
int listen_socket(char *bind_addr, int listen_port);
void interrupt(int sig);
void setup_signals();
void usage();

#define HOST_FILE_PATH	"/etc/hosts"
#define MAX_HOST_LEN	(16)     // longest host name allowed is 15
#define	IP_STRING_LEN	(18)     // .xxx.xxx.xxx.xxx\0
#define REQ_A			(1)
#define REQ_PTR			(12)

//must be strlen('.in-addr.arpa') larger than IP_STRING_LEN
#define  MAX_NAME_LEN  (IP_STRING_LEN + 13)


/* Cannot get bigger packets than 512 per RFC1035
   In practice this can be set considerably smaller:
   Length of response packet is  header (12B) + 2*type(4B) + 2*class(4B) + 
   ttl(4B) + rlen(2B) + r (MAX_NAME_LEN =21B) + 
   2*querystring (2 MAX_NAME_LEN= 42B), all together 90 Byte
*/
#define  MAX_PACK_LEN (512 + 1)

#define DEFAULT_TTL			(30)		// increase this when not testing?
#define DEFAULT_PORT		(53)		// Default port to listen on
#define DEFAULT_BIND_ADDR	"0.0.0.0"	// Default port to listen on


struct dns_head {		// the message from client and first part of response mag
	uint16_t id;
	uint16_t flags;
	uint16_t nquer;		// accepts 0
	uint16_t nansw;		// 1 in response
	uint16_t nauth;		// 0
	uint16_t nadd;		// 0
};

struct dns_prop {
	uint16_t type;
	uint16_t class;
};

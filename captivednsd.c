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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>

#include "captivednsd.h"

/* Globals */
struct in_addr captive_ip;
char captive_host[MAX_HOST_LEN];
uint32_t ttl = DEFAULT_TTL;
int verbose = 0;


/*
 * Convert host name from C-string to DNS length/string.
 */
void convname(char *cstr, char *dnsstr)
{
	int i = (cstr[0] == '.') ? 0 : 1;
	for (; i < MAX_HOST_LEN-1 && *cstr; i++, cstr++)
		dnsstr[i] = tolower(*cstr);
	dnsstr[0] = i - 1;
	dnsstr[i] = 0;
}


/*
 * Display a DNS length/string
 */
void display_query_string(uint8_t *qstr)
{
	while(1) {
		uint8_t i=0, len = qstr[0];
		if (len == 0) break;
		for(i=1; i<=len; i++) {
			printf("%c", qstr[i]);
		}
		printf(".");
		qstr=&qstr[i];
	}
	printf("\n");
}


/*
 * Decode message and generate answer
 */
int process_packet(uint8_t *buf)
{
	uint8_t answstr[MAX_NAME_LEN + 1];
	struct dns_head *head;
	struct dns_prop *qprop;
	uint8_t *querystr, *answb;
	uint16_t outr_rlen;
	uint16_t outr_flags;
	uint16_t flags;
	int type, packet_len;
	int querystr_len;

	answstr[0] = '\0';

	head = (struct dns_head *)buf;
	if (head->nquer == 0) {
		fprintf(stderr, "warning: packet contained no queries");
		return -1;
	}

	if (head->flags & 0x8000) {
		fprintf(stderr, "warning: ignoring response packet");
		return -1;
	}

	querystr = (void *)&head[1];		//  end of header / start of query string
	// FIXME: strlen of untrusted data??!
	querystr_len = strlen((char *)querystr) + 1 + sizeof(struct dns_prop);
	answb = querystr + querystr_len;   // where to append answer block

	outr_rlen = 0;
	outr_flags = 0;

	// class INET ?
	qprop = (struct dns_prop *)(answb - 4);
	if (ntohs(qprop->class) != 1 ) { 
		fprintf(stderr, "warning: non-INET class requests unsupported\n");
		outr_flags = 4; // not supported
		goto empty_packet;
	}

	// We only support standard queries
	if ((ntohs(head->flags) & 0x7800) != 0) {
		fprintf(stderr, "warning: non-standard query received\n");
		goto empty_packet;
	}

	// Check the query type
	type = ntohs(qprop->type);
	if (type == REQ_A) {
		// Return a IP address
		memcpy(answstr, &captive_ip.s_addr, 4);
		outr_rlen = 4;	// uint32_t IPv4 address
		printf("Recieved A record query for: ");
	} else if (type == REQ_PTR) {
		// Return a hostname
		outr_rlen = strlen(captive_host) + 1;
		memcpy(answstr, captive_host, outr_rlen);
		printf("Recieved PTR record query for: ");
	} else {
		fprintf(stderr, "warning: we only support A and PTR queries not type: 0x%x\n", type);
		goto empty_packet;	// we can't handle the query type
	}

	// Display the DNS query string	
	display_query_string(querystr);
	
	// Set the authority-bit
	outr_flags |= 0x0400;
	// we have an answer
	head->nansw = htons(1);
	// copy query block to answer block
	memcpy(answb, querystr, querystr_len);
	answb += querystr_len;

	// and append answer rr
	// FIXME: unaligned accesses??
	*(uint32_t *) answb = htonl(ttl);
	answb += 4;
	*(uint16_t *) answb = htons(outr_rlen);
	answb += 2;
	memcpy(answb, answstr, outr_rlen);
	answb += outr_rlen;

 empty_packet:

	flags = ntohs(head->flags);
	// clear rcode and RA, set response bit and our new flags
	flags |= (outr_flags & 0xff80) | 0x8000;
	head->flags = htons(flags);
	head->nauth = head->nadd = 0;
	head->nquer = htons(1);

	packet_len = answb - buf;
	return packet_len;
}


/*
 *  Create a UDP socket
 */
int listen_socket(char *bind_addr, int listen_port)
{
	struct sockaddr_in a;
	int s;
	int yes = 1;
	if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket() failed");
		exit(-1);
	}

#ifdef SO_REUSEADDR
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, sizeof(yes)) < 0) {
		perror("setsockopt() failed");
		exit(-1);
	}
#endif

	memset(&a, 0, sizeof(a));
	a.sin_port = htons(listen_port);
	a.sin_family = AF_INET;
	if (!inet_aton(bind_addr, &a.sin_addr)) {
		perror("bad interface address");
		exit(-1);
	}
	
	if (bind(s, (struct sockaddr *)&a, sizeof(a)) < 0) {
		perror("bind() failed");
		exit(-1);
	}
	
	listen(s, 50);
	
	if (verbose)
		printf("Accepting UDP packets on %s:%d\n", bind_addr, (int)listen_port);

	return s;
}

/* 
 *  Interrupt handler
 */
void interrupt(int sig)
{
	fprintf(stderr, "interrupt, exiting\n");
	exit(2);
}

void setup_signals()
{
	signal(SIGINT, interrupt);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
#ifdef SIGTSTP
	signal(SIGTSTP, SIG_IGN);
#endif
#ifdef SIGURG
	signal(SIGURG, SIG_IGN);
#endif
}


/* 
 *  Usage message
 */
void usage()
{
	printf("usage: captivednsd [options] <ip> <host>\n");
	printf("          -t <ttl>   Set the TTL for DNS responses (default %d).\n", DEFAULT_TTL);
	printf("          -p <port>  Port number to listen on (default %d).\n", DEFAULT_PORT);
	printf("          -b <addr>  Address to bind socket to (default %s).\n", DEFAULT_BIND_ADDR);
	exit(-1);
}



int main(int argc, char **argv)
{
	uint16_t port = DEFAULT_PORT;
	char *bind_addr = DEFAULT_BIND_ADDR;
	uint8_t buf[MAX_PACK_LEN];
	int sock;
	int opt;

	// Parse Switches
	while ((opt = getopt(argc, argv, "t:p:i:v")) != -1) {
		switch (opt) {
			case 't':  ttl = (uint32_t) atoi(optarg); break;
			case 'p':  port = (uint16_t) atoi(optarg); break;
			case 'i':  bind_addr = optarg; break;
			case 'v':  verbose = 1; break;
			default:   usage(); break;
		}
	}
	
	// Check remaining arguments
	argc -= optind;
	argv += optind;
	if (argc!=2) usage();
    
    // Parse the captive IP address
	if (!inet_aton(argv[0], &captive_ip)) {
		fprintf(stderr, "error: invalid IPv4 address: %s\n", argv[0]);
		exit(-1);
	}
	
	// Convert host name from C-string to dns length/string
	convname( argv[1], captive_host);

	// Setup signal handlers
	setup_signals();

	// Create socket
	sock = listen_socket(bind_addr, port);
	if (sock < 0) exit(1);

	while (1) {
		fd_set fdset;
		int r;
	
		FD_ZERO(&fdset);
		FD_SET(sock, &fdset);
		// Block until a message arrives
		if((r = select(sock + 1, &fdset, NULL, NULL, NULL)) < 0) {
			perror("select error");
			exit(-1);
		} else if (r == 0) {
			perror("select spurious return");
			exit(-1);
		}

		// Can this test ever be false?
		if (FD_ISSET(sock, &fdset)) {
			struct sockaddr_in from;
			int fromlen = sizeof(from);
			r = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&from, (void *)&fromlen);
			
			if (verbose) {
				printf("--- Got %d byte UDP packet from %s:%d\n",
						r, inet_ntoa(from.sin_addr), from.sin_port);
			}
			
			if (r < 12 || r > 512) {
				fprintf(stderr, "invalid DNS packet size");
				continue;
			}
			if (r > 0) {
				r = process_packet(buf);
				if (r > 0) sendto(sock, buf, r, 0, (struct sockaddr *)&from, fromlen);
			}
		}
	}
	
	return 0;
}

/*
	captivednsd
	Copyright (C) 2008 Nicholas J Humfrey
	Copyright (C) 2005 Odd Arild Olsen (oao at fibula dot no)
	Copyright (C) 2003 Paul Sheer
	Copyright (C) 2001 Levent Karakas
	
	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.
	
	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.
	
	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>

#include "captivednsd.h"


struct dns_entry *dnsentry = NULL;
static uint32_t ttl = DEFAULT_TTL;


void bb_perror_msg_and_die(const char *s) 
{
	perror(s);
	exit(1);
}

void bb_error_msg_and_die(const char *s) 
{
	fprintf(stderr,"%s\n",s);
	exit(1);
}

/* 
   Read one line of hostname/IP from file
   Returns 0 for each valid entry read, -1 at EOF
   Assumes all host names are lower case only
   Hostnames with more than one label is not handled correctly.
   Presently the dot is copied into name without
   converting to a length/string substring for that label.
*/
int getfileentry(FILE * fp, struct dns_entry *s)
{
	static char line[100];
	unsigned int a,b,c,d;
	char *r, *name;

	while(1) {
		if(!(r = fgets(line, 100, fp)))
				return -1;

		while(*r == ' ' || *r == '\t') {
			r++;
			if(!*r || *r == '#' || *r == '\n') 
				continue; // skipping empty/blank and commented lines
		}
		name = r;
		while(*r != ' ' && *r != '\t')
			r++;
		*r++ = 0;
		if(sscanf(r,"%u.%u.%u.%u",&a,&b,&c,&d) != 4)
				continue; // skipping wrong lines
	
		sprintf(s->ip,"%u.%u.%u.%u",a,b,c,d);
		sprintf(s->rip,".%u.%u.%u.%u",d,c,b,a);
		undot((uint8_t*)s->rip);
			convname(s->name,(uint8_t*)name);
		//fprintf(stderr,"ip:%s\tname:%s\trip:%s\n\n",s->ip,&(s->name[1]),s->rip); //DEBUG
		break;
	}

	return 0;
}

/*
  Read hostname/IP records from file
*/
void dnsentryinit(void)
{
	FILE *fp;
	struct dns_entry *m, *prev;
	prev = dnsentry = NULL;

	if(!(fp = fopen(HOST_FILE_PATH, "r")))
		bb_perror_msg_and_die("open /etc/hosts");

	while (1) {
		if(!(m = (struct dns_entry *)malloc(sizeof(struct dns_entry))))
			bb_perror_msg_and_die("malloc dns_entry");

		m->next = NULL;
		if (getfileentry(fp, m))
			break;

		if (prev == NULL)
			dnsentry = m;
		else
			prev->next = m;
		prev = m;
	}
	fclose(fp);
}


/*
  Set up UDP socket
*/
int listen_socket(char *iface_addr, int listen_port)
{
		struct sockaddr_in a;
		int s;
		int yes = 1;
		if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0) 
				bb_perror_msg_and_die("socket() failed");
#ifdef SO_REUSEADDR
		if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, sizeof(yes)) < 0) 
				bb_perror_msg_and_die("setsockopt() failed");
#endif
		memset(&a, 0, sizeof(a));
		a.sin_port = htons(listen_port);
		a.sin_family = AF_INET;
		if (!inet_aton(iface_addr, &a.sin_addr)) 
				bb_perror_msg_and_die("bad iface address");
		if (bind(s, (struct sockaddr *)&a, sizeof(a)) < 0)
				bb_perror_msg_and_die("bind() failed");
		listen(s, 50);
		printf("accepting UDP packets on addr:port %s:%d\n",
				iface_addr, (int)listen_port);
		return s;
}

/* 
  Exit on signal
*/
void interrupt(int x)
{
		write(2, "interrupt exiting\n", 18);
		exit(2);
}

/* 
  Decode message and generate answer
*/
#define eret(s) do { fprintf (stderr, "%s\n", s); return -1; } while (0)
int process_packet(uint8_t * buf)
{
		struct dns_head *head;
		struct dns_prop *qprop;
		struct dns_repl outr;
		void *next, *from, *answb;

		uint8_t answstr[MAX_NAME_LEN + 1];
		int lookup_result, type, len, packet_len;
		uint16_t flags;

		answstr[0] = '\0';

		head = (struct dns_head *)buf;
		if (head->nquer == 0)
				eret("no queries");

		if ((head->flags & 0x8000))
				eret("ignoring response packet");

		from = (void *)&head[1];		//	start of query string
		next = answb = from + strlen((char *)&head[1]) + 1 + sizeof(struct dns_prop);	// where to append answer block

		outr.rlen = 0;			// may change later
		outr.r = NULL;
		outr.flags = 0;

		qprop = (struct dns_prop *)(answb - 4);
		type = ntohs(qprop->type);

		// only let REQ_A and REQ_PTR pass
		if (!(type == REQ_A || type == REQ_PTR)) {
				goto empty_packet;		// we can't handle the query type
		}

		// class INET ?
		if (ntohs(qprop->class) != 1 ) { 
				outr.flags = 4; // not supported
				goto empty_packet;
		}

		// we only support standard queries
		if ((ntohs(head->flags) & 0x7800) != 0)
				goto empty_packet;

		// We have a standard query
		//log_message(LOG_FILE, (char *)head);
		lookup_result = table_lookup(type, answstr, (uint8_t*)(&head[1]));
		if (lookup_result != 0) {
				outr.flags = 3 | 0x0400;		//name do not exist and auth
				goto empty_packet;
		}
		if (type == REQ_A) {	// return an address
				struct in_addr a;
				if (!inet_aton((char*)answstr, &a)) {//dotted dec to long conv
						outr.flags = 1; // Frmt err
						goto empty_packet;
				}
				memcpy(answstr, &a.s_addr, 4);	// save before a disappears
				outr.rlen = 4;	// uint32_t IP
		}
		else
				outr.rlen = strlen((char *)answstr) + 1;	// a host name
		outr.r = answstr;		// 32 bit ip or a host name
		outr.flags |= 0x0400;	// authority-bit
		// we have an answer
		head->nansw = htons(1);

		// copy query block to answer block 
		len = answb - from;
		memcpy(answb, from, len);
		next += len;

		// and append answer rr
		*(uint32_t *) next = htonl(ttl);
		next += 4;
		*(uint16_t *) next = htons(outr.rlen);
		next += 2;
		memcpy(next, (void *)answstr, outr.rlen);
		next += outr.rlen;

	  empty_packet:

		flags = ntohs(head->flags);
		// clear rcode and RA, set responsebit and our new flags
		flags |= (outr.flags & 0xff80) | 0x8000;
		head->flags = htons(flags);
		head->nauth = head->nadd = htons(0);
		head->nquer = htons(1);

		packet_len = next - (void *)buf;
		return packet_len;
}

/*
  Look query up in dns records and return answer if found 
  qs is the query string, first byte the string length
*/ 
int table_lookup(uint16_t type, uint8_t * as, uint8_t * qs)
{
		struct dns_entry *d;
		char *p,*q;
		int len;
		d = dnsentry;
		do {
		// DEBUG
		q = (char *)&(qs[1]); // we modify the returned record if we modify *q
		p = &(d->name[1]);
		len = strlen(p);
				fprintf(stderr, "\ntest: %d <%s> <%s> %d", len, p, q, (int)strlen(q));
				if (type == REQ_A) { // search by name
			q = (char *)qs;
			p = d->name;
						//fprintf(stderr, " p/q: %x/%x ", *p, *q);
			while(tolower(*++q) == *++p) {
							//fprintf(stderr, " p/q: %x/%x ", *p, *q);
				if(!*q) {
					fprintf(stderr, " OK");
					strcpy((char *)as, d->ip);
					fprintf(stderr, " %s ", as);
					return 0;
				}	
				//q++;
				//p++;
			}
				}
				else if (type == REQ_PTR) { // search by IP-address
			if (!strncmp((char*)&d->rip[1], 
					 (char*)&qs[1], strlen(d->rip)-1)) {
								strcpy((char *)as, d->name);
								return 0;
						}
				}
		} while ((d = d->next) != NULL);
		return -1;
}

/*
  Convert host name from C-string to dns length/string. 
*/
void convname(char *a, uint8_t *q)
{
	int i = (q[0] == '.')?0:1;
	for(; i < MAX_HOST_LEN-1 && *q; i++, q++)
		a[i] = tolower(*q);
		a[0] = i - 1;
	a[i] = 0;
}


/*
  Insert length of substrings insetad of dots
*/
void undot(uint8_t * rip)
{
	int i=0, s=0;
	while(rip[i]) i++;
	for(--i; i >= 0; i--) {
		if(rip[i] == '.') {
			rip[i] = s;
			s = 0;
		} else s++;
	}
}


void usage()
{
	printf("Usage:\n");
	printf("\tscdns [-ttl <seconds>] [-p <port>] [-i <iface-ip>]\n");
	exit(-1);
}

int main(int argc, char **argv)
{
	int udps;
	uint16_t port = 53;
	uint8_t buf[MAX_PACK_LEN];
	char *listen_interface = "0.0.0.0";

	if (argc > 1) {
		int k;
		for (k = 1; k < argc; k++) {
			if (argv[k][0] == '-' && k > argc - 2)
				usage();
			if (!strncmp(argv[k], "-ttl", 4))		//time to live
				ttl = (uint32_t) atol(argv[++k]);
			else if (!strncmp(argv[k], "-p", 2))
				port = (uint16_t) atol(argv[++k]);
			else if (!strncmp(argv[k], "-i", 2))
				listen_interface = argv[++k];
			else if (argv[k][0] == '-')
				usage();

		}				// end for
	}						// end if
	dnsentryinit();

	signal(SIGINT, interrupt);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
#ifdef SIGTSTP
	signal(SIGTSTP, SIG_IGN);
#endif
#ifdef SIGURG
	signal(SIGURG, SIG_IGN);
#endif

	udps = listen_socket(listen_interface, port);
	if (udps < 0)
		exit(1);

	while (1) {
		fd_set fdset;
		int r;
	
		FD_ZERO(&fdset);
		FD_SET(udps, &fdset);
		// Block until a message arrives
		if((r = select(udps + 1, &fdset, NULL, NULL, NULL)) < 0)
			bb_perror_msg_and_die("select error");
		else if(r == 0) 
			bb_perror_msg_and_die("select spurious return");

		// Can this test ever be false?
		if (FD_ISSET(udps, &fdset)) {
			struct sockaddr_in from;
			int fromlen = sizeof(from);
			r = recvfrom(udps, buf, sizeof(buf), 0,
						 (struct sockaddr *)&from,
						 (void *)&fromlen);
			fprintf(stderr, "\n--- Got UDP	");

			if (r < 12 || r > 512) {
				fprintf(stderr, "invalid packet size");
				continue;
			}
			if (r > 0) {
				r = process_packet(buf);
				if (r > 0) sendto(udps, buf, r, 0, (struct sockaddr *)&from, fromlen);
			}
		}
	}
}


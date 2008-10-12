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

#ifndef isblank
# define isblank isspace
#endif

// Function prototypes
int process_packet(uint8_t * buf);
int table_lookup(uint16_t type, uint8_t * as, uint8_t * qs);
void convname(char *a, uint8_t * q);
void dnsentryinit(void);
void undot(uint8_t * rip);
void interrupt(int x);

#define HOST_FILE_PATH "/etc/hosts"
#define MAX_HOST_LEN   (16)     // longest host name allowed is 15
#define IP_STRING_LEN  (18)     // .xxx.xxx.xxx.xxx\0

//must be strlen('.in-addr.arpa') larger than IP_STRING_LEN
#define  MAX_NAME_LEN  (IP_STRING_LEN + 13)

/* Cannot get bigger packets than 512 per RFC1035
   In practice this can be set considerably smaller:
   Length of response packet is  header (12B) + 2*type(4B) + 2*class(4B) + 
   ttl(4B) + rlen(2B) + r (MAX_NAME_LEN =21B) + 
   2*querystring (2 MAX_NAME_LEN= 42B), all together 90 Byte
*/
#define  MAX_PACK_LEN (512 + 1)

#define  DEFAULT_TTL (30)        // increase this when not testing?
#define  REQ_A       (1)
#define  REQ_PTR     (12)


struct dns_repl {               // resource record, add 0 or 1 to accepted dns_msg in resp
        uint16_t rlen;
        uint8_t *r;             // resource
        uint16_t flags;
};

struct dns_head {               // the message from client and first part of response mag
        uint16_t id;
        uint16_t flags;
        uint16_t nquer;         // accepts 0
        uint16_t nansw;         // 1 in response
        uint16_t nauth;         // 0 
        uint16_t nadd;          // 0
};

struct dns_prop {
        uint16_t type;
        uint16_t class;
};

struct dns_entry {              // element of known name, ip address and reversed ip address
        struct dns_entry *next;
        char ip[IP_STRING_LEN]; 	// dotted decimal IP
        char rip[IP_STRING_LEN];        // length decimal reversed IP 
	char name[MAX_HOST_LEN];
};

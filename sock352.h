/* Copyright (c) 2015 Rutgers University and Richard P. Martin.
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose, without fee, and without written agreement is
 * hereby granted, provided that the following conditions are met:
 *
 *    1. Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 *    3. Neither the name of the University nor the names of its
 *       contributors may be used to endorse or promote products derived from
 *       this software without specific prior written permission.
 *
 * IN NO EVENT SHALL RUTGERS UNIVERSITY BE LIABLE TO ANY PARTY FOR DIRECT,
 * INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES ARISING OUT
 * OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF RUTGERS
 * UNIVERSITY HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * RUTGERS UNIVERSITY SPECIFICALLY DISCLAIMS ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS
 * ON AN "AS IS" BASIS, AND RUTGERS UNIVERSITY HAS NO OBLIGATION TO
 * PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.
 *
 *
 * Author:                      Richard P. Martin
 * Version:                     1
 * Creation Date:				Wed Jan 28 12:29:20 EST 2015
 * Filename:					client.c
 */

/* this is the CS 352 spring 2015 socket library definition for the project part 1
 * Students must complete the this library for the client and server to work
 */

#ifndef SOCK352_H
#define SOCK352_H 1

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* Structure describing a CS 352 socket address.  */
struct sockaddr_sock352 {
	__SOCKADDR_COMMON (sin_);
	uint32_t cs352_port; /* CS 352 socket port number */
	in_port_t sin_port; /* UDP Port number.  */
	struct in_addr sin_addr; /* Internet address.  */

	/* Pad to size of `struct sockaddr'.  */
	unsigned char sin_zero[sizeof(struct sockaddr) -
	__SOCKADDR_COMMON_SIZE - sizeof(uint32_t) - sizeof(in_port_t)
			- sizeof(struct in_addr)];
};
typedef struct sockaddr_sock352 sockaddr_sock352_t;  /* add type shortcut */

extern int sock352_init(int udp_port);
extern int sock352_init2(int remote_port, int local_port);
extern int sock352_init3(int remote_port, int local_port, char **envp);
extern int sock352_socket(int domain, int type, int protocol);
extern int sock352_bind(int fd, sockaddr_sock352_t *addr, socklen_t len);
extern int sock352_connect(int fd, sockaddr_sock352_t *addr, socklen_t len);
extern int sock352_listen(int fd, int n);
extern int sock352_accept(int _fd, sockaddr_sock352_t *addr, int *len);
extern int sock352_close(int fd);
extern int sock352_read(int fd, void *buf, int count);
extern int sock352_write(int fd, void *buf, int count);

/* the protocol and address families for CS 352 sockets */
#define PF_CS352 (0x1F)
#define AF_CS352 PF_CS352

#define SOCK352_SUCCESS (0)
#define SOCK352_FAILURE (-1)

/* these are the options, set int the flags
 * field, for the packet
 * */

#define SOCK352_VER_1 (0x01)
#define SOCK352_SYN  (0x01)
#define SOCK352_FIN  (0x02)
#define SOCK352_ACK  (0x04)
#define SOCK352_RESET (0x08)
#define SOCK352_HAS_OPT (0xA0)

#define SOCK352_DEFAULT_UDP_PORT (27182)  /* first digits of the number e */

/* a CS 352 RDP protocol packet header */
struct __attribute__ ((__packed__)) sock352_pkt_hdr {
	uint8_t version;        /* version number */
	uint8_t flags;          /* for connection set up, tear-down, control */
	uint8_t opt_ptr;        /* option type between the header and payload */
	uint8_t protocol;       /* higher-level protocol */
	uint16_t header_len;    /* length of the header */
	uint16_t checksum;      /* checksum of the packet */
	uint32_t source_port;   /* source port */
	uint32_t dest_port;     /* destination port */
	uint64_t sequence_no;   /* sequence number */
	uint64_t ack_no;        /* acknowledgement number */
	uint32_t window;        /* receiver advertised window in bytes*/
	uint32_t payload_len;   /* length of the payload */
};
typedef struct sock352_pkt_hdr sock352_pkt_hdr_t;

#endif /* sock352.h */

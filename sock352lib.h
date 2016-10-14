/*
 * Copyright (c) 2015 Rutgers University and Richard P. Martin.
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
 * Creation Date:				Wed Jan 28 15:41:32 EST 2015
 * Filename:					sock352lib.h
 */
#ifndef SOCK352LIB_H_
#define SOCK352LIB_H_

#include <sys/types.h>
#include <pthread.h>
#include <endian.h>
#include "sock352.h"
#include "uthash.h"

#define DEBUG//turn on trace messages for program

#ifdef DEBUG
unsigned int debug_lvl;
#define TRACEMSG(lvl, fmt, args...) lvl < debug_lvl ? 0 : printf(fmt, ##args)
#else
#define TRACEMSG(lvl, fmt, args...)
#endif

#define MAXPAYLOAD (65000) //approx 64kb of max data to send in one packet (might reduce)
#define WINDOW_SIZE (0x100000) //1024KB or 1MB max # of unacknowledged bytes
#define TIMEOUT_DURATION (200000000) //in nanoseconds = 0.2 seconds

#define SUCCESS (0)
#define FAILURE (1)
#define MAX_RETRY (5)

//socket states
typedef enum {
	CLOSED,
	SYN_SENT,
	SYN_RECVD,
	LISTEN,
	ESTABLISHED,
	FIN_WAIT_1,
	FIN_WAIT_2,
	CLOSING,
	TIME_WAIT,
	CLOSE_WAIT,
	LAST_ACK,
} conn_states;

//packet is just packet header with payload after it
struct packet {
	sock352_pkt_hdr_t header;
	char data[MAXPAYLOAD];
	struct packet *prev;
	struct packet *next;
} ;
typedef struct packet pckt_t;

//globals
struct connection_mng {
	conn_states conn_status;
	struct sockaddr_in remote_addr;
	socklen_t sock_len;
	int local_port;
	int remote_port;
	int listen_fd;
	uint64_t ack_recv; //highest ack received by client
	uint64_t curr_seqno; //current seq number on client
	pckt_t *tx_unack;
	pckt_t *rx_unread;
};
typedef struct connection_mng conn_mng_t;

void init_globals(void);
void cleanup(void);
sock352_pkt_hdr_t create_header(uint32_t payload_len, uint8_t flags, uint64_t ack_no);

#endif /* SOCK352LIB_H_ */

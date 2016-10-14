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
 * Creation Date:				Wed Jan 28 15:39:42 EST 2015
 * Filename:					sock352lib.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include "uthash.h"
#include "utlist.h"

#include "sock352.h"
#include "sock352lib.h"

/**
** Global connection manager that handles everything connection related between client and server
**/
conn_mng_t conn_manager;

/**
** Debug level can be tweeked to get more or less debug messages
**/
unsigned int debug_lvl;

void init_globals(void)
{
	bzero(&conn_manager.remote_addr, sizeof(conn_manager.remote_addr));

	//Set default to closed
	conn_manager.conn_status = CLOSED;

	//initialize packetlist
	conn_manager.tx_unack = NULL;
	conn_manager.rx_unread = NULL;

	//init random seed
	srand(time(NULL));

	//print all debug msgs of mid priority or higher
	//if another lvl is specified through environment variable, this will be overriden
	debug_lvl = 4;
}

void cleanup(void)
{
	//add anything here to free before close
}

sock352_pkt_hdr_t create_header(uint32_t payload_len, uint8_t flags, uint64_t ack_no)
{
	sock352_pkt_hdr_t temp_hdr;

	temp_hdr.version = SOCK352_VER_1;
	temp_hdr.flags = flags;
	temp_hdr.opt_ptr = 0;
	temp_hdr.protocol = 0;
	temp_hdr.header_len = sizeof(sock352_pkt_hdr_t);
	temp_hdr.source_port = 0;
	temp_hdr.dest_port = 0;
	temp_hdr.sequence_no = conn_manager.curr_seqno++;
	temp_hdr.ack_no = ack_no;
	temp_hdr.window = WINDOW_SIZE;
	temp_hdr.payload_len = payload_len;

	return temp_hdr;
}

int sock352_init(int port) 
{
	//port not within valid range
	if(port < 0 || port > 65535){
		return SOCK352_FAILURE;
	}

	if(port == 0){
		conn_manager.local_port = conn_manager.remote_port = SOCK352_DEFAULT_UDP_PORT;
	}
	else{
		conn_manager.local_port = conn_manager.remote_port = port;
	}

	init_globals();

	return SOCK352_SUCCESS;
}

int sock352_init2(int remote_port,int local_port) 
{
	//ports not within valid range
	if(remote_port < 0 || remote_port > 65535 || local_port < 0 || local_port > 65535){
		return SOCK352_FAILURE;
	}

	conn_manager.remote_port = remote_port;
	conn_manager.local_port = local_port; 

	init_globals();

	return SOCK352_SUCCESS;
}

int sock352_init3(int remote_port,int local_port, char *envp[] )
{
	int result = sock352_init2(remote_port, local_port);

	//if there is a debug level specified
	if(getenv("SOCK352_DEBUG_LEVEL")) {
		debug_lvl = atoi(getenv("SOCK352_DEBUG_LEVEL"));
	}

    return result;
}

int sock352_socket(int domain, int type, int protocol) 
{
	TRACEMSG(0, "SOCK352_SOCKET CALLED \n");

	if(domain != AF_CS352 || type != SOCK_STREAM){
		return SOCK352_FAILURE;
	}

	return socket(AF_INET, SOCK_DGRAM, 0);
}

int sock352_bind (int fd, struct sockaddr_sock352 *addr, socklen_t len)
{
	TRACEMSG(0, "SOCK352_BIND CALLED \n");

	/*socket to bind*/
	struct sockaddr_in bindaddr;
	bzero(&bindaddr,sizeof(bindaddr));
	bindaddr.sin_family = AF_INET;
	bindaddr.sin_addr.s_addr = htonl(INADDR_ANY); //take any incoming address
	bindaddr.sin_port = conn_manager.local_port;

	//store server listening sockfd
	conn_manager.listen_fd = fd;
	conn_manager.sock_len = len;

	int err = bind(fd, (struct sockaddr *) &bindaddr, conn_manager.sock_len);
	if(err){
		return SOCK352_FAILURE;
	}

	TRACEMSG(7, "Server binded socket to port %d\n", conn_manager.local_port);

	return SOCK352_SUCCESS;
}

int sock352_listen (int fd, int n)
{
	TRACEMSG(0, "SOCK352_LISTEN CALLED \n");

	return SOCK352_SUCCESS;
}

int sock352_accept (int fd, sockaddr_sock352_t *addr, int *len) 
{
	TRACEMSG(0, "SOCK352_ACCEPT CALLED \n");

	sock352_pkt_hdr_t req;
	sock352_pkt_hdr_t res;
	int br, bw, err;

	TRACEMSG(5, "Waiting for incoming connections\n");

	/*Server receives client's request for a connection (Step 1)*/
	if((recvfrom(fd, &req, sizeof(req), 0, (struct sockaddr *) &conn_manager.remote_addr, &conn_manager.sock_len) == sizeof(req)) && (req.flags & SOCK352_SYN)){

		TRACEMSG(5, "Connection request received from client\n");

		/*Send SYN and ACK flag back to client (step 2)*/
		res = create_header(0, SOCK352_SYN | SOCK352_ACK, req.sequence_no + 1);
		
		if(sendto(fd, &res, sizeof(res), 0, (struct sockaddr *) &conn_manager.remote_addr, conn_manager.sock_len) == sizeof(res)){

			/*Receive final ACK from client (step 3)*/
			if((recvfrom(fd, &res, sizeof(res), 0, (struct sockaddr *) &conn_manager.remote_addr, &conn_manager.sock_len) == sizeof(res)) && (res.flags & SOCK352_ACK)){

				conn_manager.ack_recv = res.ack_no;
				
				TRACEMSG(5, "Final ACK received from client for connection\n");

				//create new socket for client
				int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

				if(sockfd < 0){
					return SOCK352_FAILURE;
				}
				
				bind(sockfd, (struct sockaddr *) addr, *len);
				conn_manager.conn_status = ESTABLISHED;

				//return sockfd;
				return fd;

			}
		}
	}

	//case where server returns RESET?

	return SOCK352_FAILURE;
}

int sock352_connect(int fd, sockaddr_sock352_t *addr, socklen_t len) 
{
	TRACEMSG(0, "SOCK352_CONNECT CALLED \n");

	/*Store remote information*/
	conn_manager.remote_addr.sin_family = AF_INET;
	conn_manager.remote_addr.sin_addr.s_addr = addr->sin_addr.s_addr;
	conn_manager.remote_addr.sin_port = conn_manager.remote_port;
	conn_manager.sock_len = len;

	sock352_pkt_hdr_t req;
	sock352_pkt_hdr_t res;
	sock352_pkt_hdr_t established;
	int br, bw, err;

	/*client sends connection request with SYN bit set to server host (step 1)*/
	req = create_header(0, SOCK352_SYN, conn_manager.ack_recv);

	if(sendto(fd, &req, sizeof(req), 0, (struct sockaddr *) &conn_manager.remote_addr, conn_manager.sock_len) == sizeof(sock352_pkt_hdr_t)){

		TRACEMSG(5, "Connection request sent to server\n");
			
		if(recvfrom(fd, &res, sizeof(res), 0, (struct sockaddr *) &conn_manager.remote_addr, &conn_manager.sock_len) == sizeof(sock352_pkt_hdr_t)){
			
			TRACEMSG(5, "Connection response received from server\n");

			/*server responds with SYN and ACK flags set saying it is ready to establish connection (step 2)*/
			if((res.flags & SOCK352_SYN) && (res.flags & SOCK352_ACK) && (res.ack_no == req.sequence_no + 1)){
				//conn_manager.ack_recv = res.ack_no;

				TRACEMSG(5, "Server acknowledged connection request\n");

				/*client sends final acknowledgement saying it received server's SYN (step 3)*/
				established = create_header(0, SOCK352_ACK, res.sequence_no + 1);

				if(sendto(fd, &established, sizeof(req), 0, (struct sockaddr *) &conn_manager.remote_addr, conn_manager.sock_len) == sizeof(sock352_pkt_hdr_t)){
					TRACEMSG(5, "Client sent final ACK for connection\n");
					conn_manager.conn_status = ESTABLISHED;
					return SOCK352_SUCCESS;
				}
			}
			//if server sends RESET flag, it is already serving a client
			else if((res.flags & SOCK352_RESET)){
				TRACEMSG(9, "Server is busy\n");
				//handle case where server is already serving a client, failure for now
				return SOCK352_FAILURE;
			}

			//if none of two cases above and timeout packet will be sent again by server

		}
	}

	return SOCK352_FAILURE;
}

extern int sock352_close(int fd) 
{
	TRACEMSG(0, "SOCK352_CLOSE CALLED \n");

	sock352_pkt_hdr_t req;
	sock352_pkt_hdr_t res;

	while(1){

		switch (conn_manager.conn_status){

			case(ESTABLISHED):
				TRACEMSG(4, "In ESTABLISHED state\n");

				// Create header with FIN FLAG
				req = create_header(0, SOCK352_FIN, conn_manager.ack_recv);

				if(sendto(fd, &req, sizeof(req), 0, (struct sockaddr *) &conn_manager.remote_addr, conn_manager.sock_len) == sizeof(req)){
					conn_manager.conn_status = FIN_WAIT_1;
				}
				break;


			case(FIN_WAIT_1):
				TRACEMSG(4, "In FIN_WAIT_1 state\n");
				
				if(recvfrom(fd, &res, sizeof(res), 0, (struct sockaddr *) &conn_manager.remote_addr, &conn_manager.sock_len) == sizeof(res)){
					TRACEMSG(0, "FIN_WAIT_1: Recieved Response \n");

					if ((res.flags & SOCK352_FIN) && (res.flags & SOCK352_ACK)){
						req = create_header(0, SOCK352_ACK, res.sequence_no + 1);

						if(sendto(fd, &req, sizeof(req), 0, (struct sockaddr *) &conn_manager.remote_addr, conn_manager.sock_len) == sizeof(req)){
							conn_manager.conn_status = TIME_WAIT;
						}
					}
					else if (res.flags & SOCK352_FIN){
						req = create_header(0, SOCK352_ACK, res.sequence_no + 1);

						if(sendto(fd, &req, sizeof(req), 0, (struct sockaddr *) &conn_manager.remote_addr, conn_manager.sock_len) == sizeof(req)){
							conn_manager.conn_status = CLOSING;
						}
					}	
					else if (res.flags & SOCK352_ACK){
						conn_manager.conn_status = FIN_WAIT_2;
					}
				}
				break;

			case(FIN_WAIT_2):
				TRACEMSG(4, "In FIN_WAIT_2 state\n");
				
				if(recvfrom(conn_manager.listen_fd, &res, sizeof(res), 0, (struct sockaddr *) &conn_manager.remote_addr, &conn_manager.sock_len) == sizeof(res)){
					if (res.flags & SOCK352_FIN){
						req = create_header(0, SOCK352_ACK, res.sequence_no + 1);

						if(sendto(fd, &req, sizeof(req), 0, (struct sockaddr *) &conn_manager.remote_addr, conn_manager.sock_len) == sizeof(req)){
							conn_manager.conn_status = TIME_WAIT;
						}
					}	
				}

				break;

			case(CLOSING):
				TRACEMSG(4, "In CLOSING state\n");

				// if(recvfrom(conn_manager.listen_fd, &res, sizeof(res), 0, (struct sockaddr *) &conn_manager.remote_addr, &conn_manager.sock_len) == sizeof(res)){
				// 	if (res.flags & SOCK352_ACK){
						conn_manager.conn_status = TIME_WAIT;
				// 	}	
				// }

				break;

			case(TIME_WAIT):
				TRACEMSG(4, "In TIME_WAIT state\n");

				//sleep for 200ms
				struct timespec t_req = {0, TIMEOUT_DURATION};
				struct timespec t_rem = {0, 0};
				nanosleep(&t_req, &t_rem);

				conn_manager.conn_status = CLOSED;
				break;

			case(CLOSED):
				close(fd);
				cleanup();
				return SOCK352_SUCCESS;

			default:
				TRACEMSG(9, "ERROR: NO STATE");
				return SOCK352_FAILURE;
		}
	}
}

int sock352_read(int fd, void *buf, int count) 
{
	TRACEMSG(0, "SOCK352_READ CALLED \n");

	int br = 0;
	sock352_pkt_hdr_t res;

	//Read packet
	pckt_t packet;

	recvfrom(fd, &packet, sizeof(pckt_t), 0, (struct sockaddr *) &conn_manager.remote_addr, &conn_manager.sock_len);
	TRACEMSG(3, "READ SUCCESS \n");
	memcpy (buf, packet.data, packet.header.payload_len);

	//only return packet if it has not been reciv
	if (packet.header.sequence_no > conn_manager.ack_recv) {
		br = packet.header.payload_len;
	}

	//Send ACK back to client
	res = create_header(0, SOCK352_ACK, packet.header.sequence_no + 1);

	TRACEMSG(3, "SEND ACK - #%lu\n", res.ack_no);

	if (sendto(fd, &res, sizeof(res), 0, (struct sockaddr *) &conn_manager.remote_addr, conn_manager.sock_len) < 0) {
		perror("Send failure");
	}

	if (res.ack_no < conn_manager.ack_recv) {
		conn_manager.ack_recv = res.ack_no;
	}
	
	TRACEMSG(3, "read %d bytes\n", br);
	TRACEMSG(3, "SENT SEQ# = %lu \n", res.sequence_no);
	TRACEMSG(3, "RCVD SEQ# = %lu \n\n", packet.header.sequence_no);

	return br;
}

int sock352_write(int fd, void *buf, int count)
{
	TRACEMSG(0, "SOCK352_WRITE CALLED \n");

	TRACEMSG(3, "Attempting to send - %i bytes \n", count);
	int total_bytes = 0;
	int bytes_written;
	int bytes_left = count;
	sock352_pkt_hdr_t pkt_head;

	while(bytes_left != 0) {
		if (bytes_left > MAXPAYLOAD) {
			bytes_written = MAXPAYLOAD;
		}
		else {
			bytes_written = bytes_left;
		}
		
		pkt_head = create_header(bytes_written, 0, conn_manager.ack_recv);

		conn_manager.curr_seqno += (pkt_head.header_len + pkt_head.payload_len);
		
		if( (conn_manager.ack_recv + WINDOW_SIZE) > (conn_manager.curr_seqno + bytes_written) ) {

			TRACEMSG(3, "Requested Bytes %i, Bytes sent %i\n", bytes_written, count);
			int retry = 0;

			//Timeout & ACK Handling
			struct timeval tv;
			tv.tv_sec = 0;
			tv.tv_usec = 200000;
			sock352_pkt_hdr_t res;
			int response;
			if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
				perror("Error: could not set timout\n");
			}

			
			pckt_t pack;
			pack.header = pkt_head;
			memcpy(pack.data, buf + total_bytes, bytes_written);

			int IS_ACK = FAILURE;

			while(IS_ACK) {
				TRACEMSG(3, "Sending (%i Bytes) of Requested Bytes %i\n", bytes_written, count);
				retry++;
				TRACEMSG(3, "Retry Count: %i \n", retry);

				sendto(fd, &pack, sizeof(pckt_t), 0, (struct sockaddr *) &conn_manager.remote_addr, conn_manager.sock_len);

				TRACEMSG(3, "Client sent %d bytes\n", bytes_written);
				TRACEMSG(3, "CX SEQ# = %lu \n", pack.header.sequence_no);

				if ( (response = recvfrom(fd, &res, sizeof(res), 0, (struct sockaddr *) &conn_manager.remote_addr, &conn_manager.sock_len) ) < 0 ) {
					TRACEMSG(5, "TIME OUT, response %i\n", response);
					if (retry > MAX_RETRY) {
						TRACEMSG(5, "REACHED MAX TRY ATTEMPTS \n");
						return total_bytes;
					}
				}
				else {
					if ((res.ack_no == pack.header.sequence_no + 1) && (res.flags & SOCK352_ACK)){
						TRACEMSG(3, "ACK SUCCESS, ACK CX RVD - #%lu\n", res.ack_no);
						total_bytes += bytes_written;
						bytes_left -= bytes_written;
						conn_manager.ack_recv = res.ack_no;
						IS_ACK = SUCCESS;
					}
				}
			}

			TRACEMSG(0, "RETURN\n\n\n");

		}
	}

	return total_bytes;
}



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
 * Creation Date:				Wed Jan 28 12:31:10 EST 2015
 * Filename:					server.c
 */

/* this is the CS 352 spring 2015 server program for the project part 2
 * Students must complete the sock352 calls for this library for this server to work
 * with the corresponding client. See sock352.h for the definition
 */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/md5.h>

#include "sock352.h"

#define BUFFER_SIZE 8192
#define MAX_ZERO_BYTE_READS 1000000

void usage() {
		printf("server2: usage: -o <output-file> -u <udp-port> -l <local-port> -r <remote-port> \n");
}

/* this returns the lapsed number of micro-seconds given timestamps since epoch
 * (epoch is Jan 1, 1970 */
uint64_t lapsed_usec(struct timeval * start, struct timeval *end){
	uint64_t bt, be;  /* start, end times as 64 bit integers */

	bt =  (uint64_t) start->tv_sec *  (uint64_t)(1000000) + (uint64_t )start->tv_usec;
	be =  (uint64_t) end->tv_sec *  (uint64_t)(1000000) + (uint64_t ) end->tv_usec;

	if (be >= bt) { /* make sure we don't return a negative time */
		return (be-bt);
	}
	else {
		printf("server2: lapsed_usec: warning, negative time interval\n");
		return 0;
	}
}

int main(int argc, char *argv[], char **envp) {
		char *output_filename; /* name of the output file sent by the client */
		int file_fd;           /* file descriptor for above  input file */
		uint32_t file_size;
		uint32_t file_size_network;
		struct stat file_stat; /* used to get the size of the file */
		int client_error;  /* flag if the clients file request is an error */

		sockaddr_sock352_t server_addr,client_addr; /*  address of the server and client*/
		uint32_t cs352_port;
		uint32_t udp_port,local_port,remote_port;  /* ports used for remote library */
		int retval;  /* return code */
		int listen_fd, connection_fd;

		char buffer[BUFFER_SIZE]; /* read/write buffer */
		char command_string[BUFFER_SIZE]; /* holds the command string to our server */
		char *token_p, *command_s, *file_name_s, *protocol_s; /* used the parse the command string */

		int end_of_file, total_bytes, bytes_read; /* for reading the input file */

		/* set defaults */
		udp_port = SOCK352_DEFAULT_UDP_PORT;
		local_port = remote_port =0 ;
		int client_addr_len;
		int socket_closed;
		int zero_bytes,bw;

		struct timeval begin_time, end_time; /* start, end time to compute bandwidth */
		uint64_t lapsed_useconds;
		double lapsed_seconds;

		MD5_CTX md5_context;
		unsigned char md5_out[MD5_DIGEST_LENGTH];

		int c,i; /* index counters */
		/* Parse the arguments to get: */
		opterr = 0;

		while ((c = getopt (argc, argv, "c:u:l:r:")) != -1) {
			switch (c) {
		      case 'c':
		        cs352_port = atoi(optarg);
		        break;
		      case 'u':
		        udp_port = atoi(optarg);
		        break;
		      case 'l':
		    	  local_port =  atoi(optarg);
		    	  break;
		      case 'r':
		    	  remote_port =  atoi(optarg);
		    	  break;
		      case '?':
		    	  usage();
		    	  exit(-1);
		    	  break;
		      default:
		        printf("server2: unknown option: ");
		        usage();
		        exit(-1);
		        break;
			}
		}

		/* change which init function to use based on the arguments */
		/* if BOTH the local and remote ports are set, use the init2 function */

		if ( (remote_port > 0) && (local_port > 0) ) {
			retval =  sock352_init3(remote_port, local_port,envp);
		} else {
			retval = sock352_init(udp_port);
		}
		if (retval != SOCK352_SUCCESS < 0) {
			printf("server2: initialization of 352 sockets on UDP port %d failed\n",udp_port);
			exit(-1);
		}
		listen_fd = sock352_socket(AF_CS352,SOCK_STREAM,0);

		/* the destination port overrides the udp port setting */
		if (remote_port != 0) {
			udp_port = remote_port;
		}

		memset(&server_addr,0,sizeof(server_addr));
		server_addr.sin_family = AF_CS352;
		server_addr.sin_addr.s_addr=htonl(INADDR_ANY);
		server_addr.sin_port=htons(udp_port);

		if ( sock352_bind(listen_fd,(sockaddr_sock352_t *) &server_addr,
				sizeof(server_addr)) != SOCK352_SUCCESS) {
			printf("server2: bind failed \n");
			exit(-1);
		}

		if ( (sock352_listen(listen_fd,5)) != SOCK352_SUCCESS) {
			printf("server2: listen failed \n");
			exit(-1);
		}
		client_addr_len = sizeof(client_addr);
		connection_fd  = sock352_accept(listen_fd,(sockaddr_sock352_t *)&client_addr,
										&client_addr_len);

		if (connection_fd == SOCK352_FAILURE) {
			printf("server2: accept failed");
			exit(-1);
		}

		socket_closed = zero_bytes = total_bytes = 0;

		/* the first string is the command and the name of the file as an ASCII string */
		bytes_read = sock352_read(connection_fd,command_string,BUFFER_SIZE-1);

		/* start timing from when we get the command string */
		MD5_Init(&md5_context);
		gettimeofday(&begin_time, (struct timezone *) NULL);
		command_string[BUFFER_SIZE] = '\0'; /* make sure the string is null-terminated */

		/* use strtok to parse the command and name of the file */
		token_p = strtok(command_string," ");
		command_s = token_p;
		file_name_s = strtok(NULL," ");
		protocol_s = strtok(NULL," ");

		client_error = 0; /* assume all is well */
		/* check for errors, if an error, send a zero for the length of the
		 * the file.
		 */
		if (strcmp(command_s,"GET") != 0) {
			printf("server2: bad command \n");
			client_error =1;
		}
		if (strcmp(protocol_s,"CS352/1.0") != 0) {
			printf("server2: bad protocol \n");
			client_error = 1;
		}

		/* open the local file */
		/* check the file exists */
		if (file_name_s == NULL) {
			printf("server2: no input file specified: ");
			client_error = 1;
		}
		/* open for reading */
		if ( (file_fd = open(file_name_s, O_RDONLY) ) < 0) {
			printf("server2: error: open of file %s failed: %s \n", file_name_s,
			strerror(errno));
			client_error =1;
		}

		file_size = 0;
		/* get the size of the file */
		if (stat(file_name_s, &file_stat) < 0) {
			printf("server2: stat of %s failed %s\n", file_name_s, strerror(errno));
			client_error =1;
		}
		if (! client_error )
			file_size = (uint32_t) file_stat.st_size;

		/* send the size of the file */

		/* the server first sends the size of the file, then the file */
		/* first send the size of the file as a 32 bit integer in network byte order */
		file_size_network = htonl(file_size);
		bw = sock352_write(connection_fd,&file_size_network,sizeof(file_size_network));
		if (bw != sizeof(file_size_network)) {
			printf("server2: write of file size failed \n");
			exit(-1);
		}

		/* now send the file proper */
		total_bytes = end_of_file = 0;
		while ( (total_bytes < file_size) &&   /* the main loop checks both if we've sent the whole file*/
				(! end_of_file) ) {            /* or there is some other error */

				bytes_read = read(file_fd,buffer,BUFFER_SIZE);  /* read from the file */
				if (bytes_read > 0) {                      /* check we sent something */
					total_bytes += bytes_read ;
					if ( (bw = sock352_write(connection_fd,buffer,bytes_read)) != bytes_read) {
						printf("server2: error writing byte at count %d bytes written %d \n",total_bytes,bw);
					} else {
						MD5_Update(&md5_context, buffer, bytes_read);  /* update the checksum */
					}
				} else {
					end_of_file =1;   /* we got either zero bytes or and error, so finish the loop */
				}
		}
		if ( sock352_close(connection_fd) != SOCK352_SUCCESS) {
			printf("server2: error with socket close \n");
		}
		gettimeofday(&end_time, (struct timezone *) NULL);
		MD5_Final(md5_out, &md5_context);

		/* make sure to clean up! */
		close(file_fd);
		sock352_close(listen_fd);

		if (total_bytes == 0) {
			printf("server2: no file sent\n");
			exit(-1);
		}

		lapsed_useconds = lapsed_usec(&begin_time, &end_time);
		lapsed_seconds = (double) lapsed_useconds / (double) 1000000;
		printf("server2: sent %d bytes in %lf sec, bandwidth %8.4lf Mb/s \n", total_bytes,lapsed_seconds,
				( (double) total_bytes/ (double) (1048576*8)) /lapsed_seconds );
		printf("server2: MD5-checksum: ");
		for(i=0; i < MD5_DIGEST_LENGTH; i++)
			printf("%02x", md5_out[i]);
		printf("\n");

return 0;

}

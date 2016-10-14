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
 * Creation Date:				Tue Mar 10 12:09:54 EDT 2015
 * Filename:					client2.c
 */

/* this is the CS 352 spring 2015 client program for the project part 2
 * Students must complete the sock352 calls for this library for this client to work
 * with the corresponding server. See sock352.h for the definition
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <fcntl.h>
#include <time.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/md5.h>

#include "sock352.h"

#define BUFFER_SIZE 8192
#define MAX_ZERO_BYTE_READS 1000000

void usage() {
		printf("client2: usage: -f <remote filename>  -o <output file> -d <destination> -u <udp-port> -l <local-port> -r <remote-port> \n");
}

/* timer function that returns the lapsed number of micro-seconds since epoch
 * (epoch is Jan 1, 1970 ) */
uint64_t lapsed_usec(struct timeval * start, struct timeval *end){
	uint64_t bt, be;  /* start, end times as 64 bit integers */

	bt =  (uint64_t) start->tv_sec *(1000000) + (uint64_t )start->tv_usec;
	be =  (uint64_t) end->tv_sec *(1000000) + (uint64_t ) end->tv_usec;
	/* make sure we don't return a negative time */
	if (be >= bt) {
		return (be-bt);
	}
	else {
		printf("client2: lapsed_usec: warning, negative time interval\n");
		return 0;
	}
} /* end lapsed_usec */

int main(int argc, char *argv[], char *envp[]) {
	char *server_filename; /* name of file to give to the server */
	char *output_filename;  /* name of file to write locally */

	int output_fd;        /* file descriptor for the output file (downloaded from the server) */
	uint32_t file_size;    /* size of the file, in bytes */
	uint32_t file_size_network;  /* size of the file in network byte order */

	char *destination;    /* name of the server, or server's IP address */
	sockaddr_sock352_t dest_addr;  /* destination address as a CS 352 socket address */
	int dest_sock;        /* destination socket address */
	uint32_t cs352_port;  /* CS 352 port space port */
	uint32_t udp_port;    /* UDP to run the CS 352 sockets over */
	uint32_t local_port; /* UDP port to use as the local listen  address */
	uint32_t remote_port;   /* UDP port to use as the remote destination address */
	struct hostent *hp;   /* the host pointer for resolving names */

	char buffer[BUFFER_SIZE]; /* read/write buffer */
	static const char command_name_s[] = "GET ";  /* these are the command and protocol strings used to download the file */
	static const char protocol_name_s[] = "CS352/1.0 \n";
	int command_len, protocol_len,filename_len; /* lengths of the command and protocol strings */
	char *server_command_s; /* string to send to the server with the command name, filename and protocol name */

	int end_of_file, total_bytes, bytes_read,zero_bytes,socket_closed;
	int bw;                   /* bytes written */
	struct timeval begin_time, end_time; /* start, end time to compute bandwidth */
	uint64_t lapsed_useconds;   /* micro-seconds since epoch */
	double lapsed_seconds;      /* difference from start and stop of the timer */

    server_filename = output_filename = NULL;
	/* set defaults */
	udp_port = SOCK352_DEFAULT_UDP_PORT;
	local_port = remote_port = 0;
	/* these support computing the file checksum */
	MD5_CTX md5_context;
	unsigned char md5_out[MD5_DIGEST_LENGTH];

	int retval;  /* return code for library operations */
	int c,i; /* index pointers */

	/* Parse the arguments to get the input file name, port, and destination  */
	opterr = 0;
	while ((c = getopt (argc, argv, "f:o:d:u:l:r:")) != -1) {
		switch (c) {
	      case 'f':
	        server_filename = optarg;
	        break;
	      case 'o':
	    	output_filename = optarg;
	    	break;
	      case 'c':
	        cs352_port = atoi(optarg);
	        break;
	      case 'u':
	        udp_port = atoi(optarg);
	        break;
	      case 'd':
	    	  destination = optarg;
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
	        printf("client2: unknown option: ");
	        usage();
	        exit(-1);
	        break;
		}
	}

	/* check that we have a filename to give to the server */
	if (server_filename == NULL) {
		printf("client2: no remote file  name specified: ");
			usage();
			exit(-1);
	}
	/* check that we have a filename to write the above locally */
	if (output_filename == NULL) {
		printf("client2: no local output file  name specified: ");
		usage();
		exit(-1);
	}

	/* open the local file for writing  */
	if ( (output_fd = open(output_filename,O_CREAT|O_WRONLY) ) < 0) {
		printf("client2: error: open of output file %s failed: %s \n", output_filename,
			strerror(errno));
		exit(-1);
	}

	/* check that we have a server */
	if (destination == NULL) {
		printf("client2: no remote host name or IP address specified\n");
		usage();
		exit(-1);
	}

	/* set the destination address */
	  dest_addr.sin_family = AF_CS352;
	  dest_addr.sin_port = htons(udp_port);
	  /* If an internet "a.d.c.d" address is specified, use inet_addr()
	   * to convert it into real address.  If host name is specified,
	   * use gethostbyname() to resolve its address */
	  dest_addr.sin_addr.s_addr = inet_addr(destination); /* if a decimal "a.b.c.d" format */
	  if (dest_addr.sin_addr.s_addr == -1) {
	    hp = gethostbyname(destination);    /* if DNS name, e.g. x.y.com */
	    if (hp == NULL) {
	      printf("client2: host name %s not found\n", destination);
	      exit(-1);
	    }
	    memcpy(&(dest_addr.sin_addr),hp->h_addr, hp->h_length);
	  }

    /* change which init function to use based on the arguments */
	/* if BOTH the local and remote ports are set, use the init2 function */
	if ( (remote_port > 0) && (local_port > 0) ) {
		retval =  sock352_init3(remote_port, local_port, envp);
	} else {
		retval = sock352_init(udp_port);
	}
	if (retval == SOCK352_FAILURE) {
			fprintf(stderr,"client2: initialization of 352 sockets on UDP port %d failed\n",udp_port);
			exit(-1);
	}
	  /* Create a CS 352 stream socket */
	if ( (dest_sock = sock352_socket(AF_CS352, SOCK_STREAM, 0)) == -1 ) {
		printf("client2: sock called failed \n");
		exit(-1);
	}

	/* construct the string that tells the server what file to get and what protocol we are using */
	server_command_s = buffer;
	command_len = strlen(command_name_s);
	protocol_len = strlen(protocol_name_s);
	/* truncate filename length if too long */
	filename_len = (strlen(server_filename) < BUFFER_SIZE-(command_len+protocol_len+2)) ?
					strlen(server_filename) : BUFFER_SIZE-(command_len+protocol_len+2);

	strcpy(server_command_s,command_name_s);
	server_command_s += command_len;
	strncpy(server_command_s,server_filename,filename_len);
	server_command_s += filename_len;
	server_command_s[0] = ' '; server_command_s++; /* add a whitespace */
	strcpy(server_command_s,protocol_name_s);

	/* begin the sending process*/
	MD5_Init(&md5_context);
	gettimeofday(&begin_time, (struct timezone *) NULL); /* get a start timestamp */

	if ( sock352_connect(dest_sock, &dest_addr, sizeof(dest_addr)) != SOCK352_SUCCESS) {
		printf("client2: connect failed");
		exit(-1);
	}

	/* write the name of the file */
	sock352_write(dest_sock,buffer,strlen(buffer));

	/* read the size of the file*/
	sock352_read(dest_sock,&file_size_network,sizeof(file_size_network));
	file_size = htonl((int) file_size_network);

	/* initialize test variables correctly */
	total_bytes = zero_bytes = socket_closed = 0;
	/* loop until we either get the whole file or there is an error */
	while ( (total_bytes < file_size) && (! socket_closed)) {
		bytes_read = sock352_read(dest_sock,buffer,BUFFER_SIZE);
		if (bytes_read > 0) {
			total_bytes += bytes_read;
				bw = write(output_fd,buffer,bytes_read);
				if (bw != bytes_read) {
					printf("client2: error writing to file at byte %d \n", total_bytes);
				} else {
					MD5_Update(&md5_context, buffer, bytes_read);
				}
		} else {
			if (bytes_read == 0) {
				zero_bytes++;
			} else {
				if (bytes_read < 0 ){
					socket_closed = 1;
				}
			}
		}
		if (zero_bytes > MAX_ZERO_BYTE_READS) {
			printf("server: too many zero byte returns, closing connection\n");
			socket_closed = 1;
		}
	} /* end while socket not closed */
	if ( zero_bytes > 0) printf("client2: zero byte calls is %d \n",zero_bytes);
	sock352_close(dest_sock);
	gettimeofday(&end_time, (struct timezone *) NULL); /* end time-stamp */
	MD5_Final(md5_out, &md5_context);

	if ( close(output_fd) < 0) { /* clean up the file descriptor */
		printf("client2: error closing the file \n");
	}

	lapsed_useconds = lapsed_usec(&begin_time, &end_time);
	lapsed_seconds = (double) lapsed_useconds / (double) 1000000;
	if (total_bytes == 0) {
			printf("client2: no file received\n");
			exit(-1);
	}
	printf("client2: received %d bytes in %lf sec, bandwidth %8.4lf Mb/s \n", total_bytes,lapsed_seconds,
				( (double) total_bytes/ (double) (1048576*8)) /lapsed_seconds );
	printf("client2: MD5-checksum: ");
    for(i=0; i < MD5_DIGEST_LENGTH; i++)
            printf("%02x", md5_out[i]);
    printf("\n");

return 0;

}

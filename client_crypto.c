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
 * Creation Date:               Thu Apr 16 10:08:34 EDT 2015
 * Filename:			client_crypto.c
 */

/* this is the CS 352 spring 2015 client program for the project part 3
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

#include <sodium.h>
#include "sock352.h"

#define BUFFER_SIZE 8192
#define MAX_BUFFER_SIZE 49152
#define MAX_ZERO_BYTE_READS 1000000
#define MAX_MSG_SIZE 32768  /* maximum for a encrypted message */

void usage() {
		printf("client_crypto: usage: -f <remote filename>  -o <output file> -d <destination> -u <udp-port> -l <local-port> -r <remote-port> -k <key-file> \n");
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
		printf("client_crypto: lapsed_usec: warning, negative time interval\n");
		return 0;
	}
} /* end lapsed_usec */

/* convert a hex character 0-A or 0-a to a 4 bit nybble */ 
int hexchar_to_int(char c) {
  int val; 
  val = -1;
  if (c >= '0' && c <= '9') 
    val = (c-'0');
  if (c >= 'A' && c <= 'F') 
    val =  10 + (c-'A');
  if (c >= 'a' && c <= 'f') 
    val = 10 + (c-'a');

  return val;
}

/* convert a hexadecimal string to a binary array */
int hexstr_to_bin(uint8_t *dest, char *str, int numdigits) { 
  int i,j; 
  unsigned char val; 
  int numbin, count; 

  if ( (numdigits % 2 ) != 0) { /* need an even # of characters */
    return -1;  
  }
  count =0;
  /* loop for each binary, inc char index by 2 each time*/
  for (i =0 , j=0 ; i < numdigits; i++, j+=2) { 
    val = ( (hexchar_to_int(str[j])) <<4 ) | (hexchar_to_int(str[j+1])) ;

    if (val == -1) {  /* if we get non-hex character abort */
      return -1;
    }
    count++;
    dest[i]=val; 
  }
  return count;
} /* end hexstr_to_bin */


/* read a key from a line in the key file */
int read_key(FILE *file_p,char *name_s, uint8_t *key, int keylen) {
  unsigned char key_s[crypto_box_PUBLICKEYBYTES*2+2]; 
  char buffer[256]; 
  int val; 

  fread(buffer,1,strlen(name_s),file_p); 
  if (strncmp(buffer,name_s,strlen(name_s)) != 0) { 
    printf("client_crypto: error: parsing %s key failed \n", name_s);    
    return -1; 
  }

  if (fgets(key_s,2*keylen+2,file_p) == NULL) { 
    printf("client_crypto: error: parsing %s key failed:\n", name_s);
    return -1; 
  }

  val = hexstr_to_bin(key,key_s,keylen);
  if (val == -1) {  
    printf("client_crypto: error parsing binary %s key failed.\n", name_s);   
    return -1; 
  }

  return val; 
}

/* a key file contains a public and private key */ 
int get_keys(char *keys_file, uint8_t* public_key, uint8_t *secret_key,int8_t *remote_key) {
  FILE *file_fd; 
  int val; 
  int keycount; 
  char *public_name_s = "public: "; 
  char *secret_name_s = "secret: "; 
  char *remote_name_s = "remote: ";
  char buffer[32]; 

  /* check the key file exists */
  if (keys_file == NULL) {
    printf("client_crypto: null key file specified \n ");
    usage();
    return -1; 
  }

  /* open public key file for reading */
  if ( (file_fd = fopen(keys_file, "r") ) == NULL ) {
    printf("client_crypto: error: open of key file %s failed: %s \n", keys_file,
	   strerror(errno));
    return -1; 
  }

  keycount =0;
  if ( read_key(file_fd,public_name_s,public_key,crypto_box_PUBLICKEYBYTES) > 0) { 
    keycount ++; 
  } 
  if ( read_key(file_fd,secret_name_s,secret_key,crypto_box_SECRETKEYBYTES) > 0) { 
    keycount ++; 
  }
  if ( read_key(file_fd,remote_name_s,remote_key,crypto_box_PUBLICKEYBYTES) > 0) { 
    keycount ++; 
  }

  return keycount; 
}

/* return if a memory region is all zeros */
int is_zero( const uint8_t *data, int len ) {
  int i;
  int rc;

  rc = 0;
  for(i = 0; i < len; ++i) {
    rc |= data[i];
  }

  return rc;
}

/* wrapper for simple encryption of a message */ 
/* code taken from crypt_box example in the sodium library */ 
int encrypt(uint8_t encrypted[], const uint8_t pk[], const uint8_t sk[], 
	    const uint8_t nonce[], const uint8_t plain[], int length) {
  uint8_t temp_plain[MAX_MSG_SIZE];
  uint8_t temp_encrypted[MAX_MSG_SIZE];
  int rc;

  if(length+crypto_box_ZEROBYTES >= MAX_MSG_SIZE) {
    return -2;
  }

  memset(temp_plain, '\0', crypto_box_ZEROBYTES);
  memcpy(temp_plain + crypto_box_ZEROBYTES, plain, length);

  rc = crypto_box(temp_encrypted, temp_plain, crypto_box_ZEROBYTES + length, nonce, pk, sk);

  if( rc != 0 ) {
    return -1;
  }

  if( is_zero(temp_plain, crypto_box_BOXZEROBYTES) != 0 ) {
    return -3;
  }
  
  memcpy(encrypted, temp_encrypted + crypto_box_BOXZEROBYTES, crypto_box_ZEROBYTES + length);

  return crypto_box_ZEROBYTES + length - crypto_box_BOXZEROBYTES;
}

/* wrapper for simple decryption of a message */ 
/* code taken from crypt_box example in the sodium library */ 
int decrypt(uint8_t plain[], const uint8_t pk[], const uint8_t sk[],
	    const uint8_t nonce[], const uint8_t encrypted[], int length) {
  uint8_t temp_encrypted[MAX_MSG_SIZE];
  uint8_t temp_plain[MAX_MSG_SIZE];
  int rc;

  if(length+crypto_box_BOXZEROBYTES >= MAX_MSG_SIZE) {
    return -2;
  }

  memset(temp_encrypted, '\0', crypto_box_BOXZEROBYTES);
  memcpy(temp_encrypted + crypto_box_BOXZEROBYTES, encrypted, length);

  rc = crypto_box_open(temp_plain, temp_encrypted, crypto_box_BOXZEROBYTES + length, nonce, pk, sk);

  if( rc != 0 ) {
    return -1;
  }

  if( is_zero(temp_plain, crypto_box_ZEROBYTES) != 0 ) {
    return -3;
  }

  memcpy(plain, temp_plain + crypto_box_ZEROBYTES, crypto_box_BOXZEROBYTES + length);

  return crypto_box_BOXZEROBYTES + length - crypto_box_ZEROBYTES;
}

/* package up a write into an encrypt followed by a write */
int encrypted_write(int fd, uint8_t *buffer, int size, uint8_t *public_key,
		    uint8_t *secret_key, uint8_t *nonce)  { 
  int count; 
  char encrypted_buf[MAX_BUFFER_SIZE];
  
  count = encrypt(encrypted_buf,public_key,secret_key, nonce, buffer, size);
  if( count < 0 ) { 
    printf("encryption write failed \n");
    return -1; 
  }

  count = sock352_write(fd,encrypted_buf,count);	
  return count; 

} /* end encrypted_write */

/* package up a read into a read followed by a decrypt */
int decrypted_read(int fd, uint8_t *buffer, int size,
		   int8_t *public_key, uint8_t *secret_key,uint8_t *nonce) { 
  int bytes_read; 
  int count;
  char tmp_buffer[2*MAX_BUFFER_SIZE];
  char tmp_buffer_plain[2*MAX_BUFFER_SIZE];

  /* the first string is the command and the name of the file as an ASCII string */
  bytes_read = sock352_read(fd,tmp_buffer,MAX_BUFFER_SIZE);
  if (bytes_read <= 0) { 
    return bytes_read; 
  }
  
  /* decrypt the message  */ 
  memset(buffer,0,size);
  memset(tmp_buffer_plain,0,2*MAX_BUFFER_SIZE);
  count = decrypt(tmp_buffer_plain, public_key, secret_key, nonce, 
			     tmp_buffer, bytes_read);  
  if (count <= 0 ) { 
    printf("decryption in read failed \n");
  }

  if (count <= size) {
    memcpy(buffer,tmp_buffer_plain,count);
    return count;
  } else { 
    memcpy(buffer,tmp_buffer_plain,size);
    printf("warning, decrypted text too large for buffer! \n");
    return size;
  }

} /* end decrypted_read */


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
	char encrypted_buf[2*BUFFER_SIZE]; /* encrypted read/write buffer */
	char decrypted_buf[2*BUFFER_SIZE]; /* decrypted read/write buffer */
	int count; /* size of the encrypted buffer */ 

	static const char command_name_s[] = "GET ";  /* these are the command and protocol strings used to download the file */
	static const char protocol_name_s[] = "CS352/2.0 \n";
	int command_len, protocol_len,filename_len; /* lengths of the command and protocol strings */
	char *server_command_s; /* string to send to the server with the command name, filename and protocol name */

	/* cryptography variables */
	char *my_keys_fn, *public_key_fn; /* filenames to find the keys */
	int my_keys_fd, public_key_fd;  /* file descriptors of the keys */
	unsigned char nonce[crypto_box_NONCEBYTES];
	unsigned char my_public_key[crypto_box_PUBLICKEYBYTES];  
	unsigned char my_secret_key[crypto_box_SECRETKEYBYTES];
	unsigned char remote_public_key[crypto_box_PUBLICKEYBYTES];  

	int end_of_file, total_bytes, bytes_read,zero_bytes,socket_closed;
	int bw;                   /* bytes written */
	struct timeval begin_time, end_time; /* start, end time to compute bandwidth */
	uint64_t lapsed_useconds;   /* micro-seconds since epoch */
	double lapsed_seconds;      /* difference from start and stop of the timer */

	/* these support computing the file checksum */
	MD5_CTX md5_context;
	unsigned char md5_out[MD5_DIGEST_LENGTH];

	int retval;  /* return code for library operations */
	int c,i; /* index pointers */


	/* set defaults */
	my_keys_fn = public_key_fn = NULL;
	server_filename = output_filename = NULL;
	udp_port = SOCK352_DEFAULT_UDP_PORT;
	local_port = remote_port = 0;

	/* Parse the arguments to get the input file name, port, and destination  */
	opterr = 0;
	while ((c = getopt (argc, argv, "f:o:d:u:l:r:k:")) != -1) {
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
	      case 'k':
		my_keys_fn = optarg; 
		break;
	      case '?':
		usage();
		exit(-1);
		break;
	      default:
	        printf("client_crypto: unknown option: ");
	        usage();
	        exit(-1);
	        break;
		}
	}


	if (my_keys_fn == NULL) { 
	  printf("client_crypto: no keys file specified \n");
	  usage();
	  return -1; 		  
	}

	if ( get_keys(my_keys_fn,my_public_key,my_secret_key,remote_public_key) != 3 ) { 
	  printf("client_crypto: getting all keys from file %s failed \n", my_keys_fn);
	  return -1; 
	}
	
	/* check that we have a filename to give to the server */
	if (server_filename == NULL) {
		printf("client_crypto: no remote file  name specified: ");
			usage();
			exit(-1);
	}
	/* check that we have a filename to write the above locally */
	if (output_filename == NULL) {
		printf("client_crypto: no local output file  name specified: ");
		usage();
		exit(-1);
	}

	/* open the local file for writing  */
	if ( (output_fd = open(output_filename,O_CREAT|O_WRONLY|O_TRUNC,777) ) < 0) {
		printf("client_crypto: error: open of output file %s failed: %s \n", output_filename,
			strerror(errno));
		exit(-1);
	}

	/* check that we have a server */
	if (destination == NULL) {
		printf("client_crypto: no remote host name or IP address specified\n");
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
	      printf("client_crypto: host name %s not found\n", destination);
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
			fprintf(stderr,"client_crypto: initialization of 352 sockets on UDP port %d failed\n",udp_port);
			exit(-1);
	}
	  /* Create a CS 352 stream socket */
	if ( (dest_sock = sock352_socket(AF_CS352, SOCK_STREAM, 0)) == -1 ) {
		printf("client_crypto: sock called failed \n");
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
		printf("client_crypto: connect failed");
		exit(-1);
	}

	/* get the nonce for this connection */ 
	count = sock352_read(dest_sock,nonce,crypto_box_NONCEBYTES);
	if (count != crypto_box_NONCEBYTES) {
	  printf("client_crypto: reading nonce failed \n");
	  return -1; 
	}
	
	/* send the encrypted the name of the file */
	count = encrypted_write(dest_sock,buffer,strlen(buffer), 
				remote_public_key, my_secret_key, nonce);
	if( count < 0 ) { 
	  printf("client_crypto: encryption failed \n");
	  return -1; 
	}

	/* read the size of the file*/
	count = decrypted_read(dest_sock,(uint8_t *)&file_size_network,sizeof(file_size_network), 
			       remote_public_key, my_secret_key,nonce);
	if (count != sizeof(file_size_network)) { 
	  printf("client_crypto: receive of file size failed \n");	  
	  return -1;
	}
	file_size = htonl((int) file_size_network);

	/* initialize test variables correctly */
	total_bytes = zero_bytes = socket_closed = 0;
	/* loop until we either get the whole file or there is an error */
	while ( (total_bytes < file_size) && (! socket_closed)) {
	  bytes_read = decrypted_read(dest_sock,buffer,BUFFER_SIZE,
				      remote_public_key,my_secret_key,nonce);
		if (bytes_read > 0) {
			total_bytes += bytes_read;
				bw = write(output_fd,buffer,bytes_read);
				if (bw != bytes_read) {
					printf("client_crypto: error writing to file at byte %d \n", total_bytes);
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
	if ( zero_bytes > 0) printf("client_crypto: zero byte calls is %d \n",zero_bytes);
	sock352_close(dest_sock);
	gettimeofday(&end_time, (struct timezone *) NULL); /* end time-stamp */
	MD5_Final(md5_out, &md5_context);

	if ( close(output_fd) < 0) { /* clean up the file descriptor */
		printf("client_crypto: error closing the file \n");
	}

	lapsed_useconds = lapsed_usec(&begin_time, &end_time);
	lapsed_seconds = (double) lapsed_useconds / (double) 1000000;
	if (total_bytes == 0) {
			printf("client_crypto: no file received\n");
			exit(-1);
	}
	printf("client_crypto: received %d bytes in %lf sec, bandwidth %8.4lf Mb/s \n", total_bytes,lapsed_seconds,
				( (double) total_bytes/ (double) (1048576*8)) /lapsed_seconds );
	printf("client_crypto: MD5-checksum: ");
    for(i=0; i < MD5_DIGEST_LENGTH; i++)
            printf("%02x", md5_out[i]);
    printf("\n");

return 0;

}

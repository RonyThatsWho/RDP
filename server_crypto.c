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
 * Creation Date:	        Thu Apr 16 10:02:41 EDT 2015
 * Filename:		        server_crypto.c
 */

/* this is the CS 352 spring 2015 server program for the project part 3
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

#include "sodium.h"  
#include "sock352.h"

#define BUFFER_SIZE 8192
#define MAX_BUFFER_SIZE 49152
#define MAX_ZERO_BYTE_READS 1000000
#define MAX_MSG_SIZE 32768  /* maximum for a encrypted message */

void usage() {
		printf("server_crypto: usage -u <udp-port> -l <local-port> -r <remote-port> -k <key_file> -p <print_keypair> \n");
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
		printf("server_crypto: lapsed_usec: warning, negative time interval\n");
		return 0;
	}
}


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
    printf("server_crypto: error: parsing %s key failed \n", name_s);    
    return -1; 
  }

  if (fgets(key_s,2*keylen+2,file_p) == NULL) { 
    printf("server_crypto: error: parsing %s key failed:\n", name_s);
    return -1; 
  }

  val = hexstr_to_bin(key,key_s,keylen);
  if (val == -1) {  
    printf("server_crypto: error parsing binary %s key failed.\n", name_s);   
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
    printf("server_crypto: null key file specified \n ");
    usage();
    return -1; 
  }

  /* open public key file for reading */
  if ( (file_fd = fopen(keys_file, "r") ) == NULL ) {
    printf("server_crypto: error: open of key file %s failed: %s \n", keys_file,
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

/* package up a read into a read followed by a decrypt */
int decrypted_read(int fd, uint8_t *buffer, int size,
		   int8_t *public_key, uint8_t *secret_key,uint8_t *nonce) { 
  int bytes_read; 
  int count;
  char tmp_buffer[2*MAX_BUFFER_SIZE];  /* deal with zero-byte pads here */
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

/* print out a binary byte array into hexadecimal */
char* to_hex( char hex[], uint8_t bin[], size_t length ) {
  int i;
  uint8_t *p0 = (uint8_t *)bin;
  char *p1 = hex;

  for( i = 0; i < length; i++ ) {
    snprintf( p1, 3, "%02x", *p0 );
    p0 += 1;
    p1 += 2;
  }
  return hex;
}

/* print a public/private key pair for use by the client and server */ 
/* the client requires 1 keypair and the server another */
int print_new_keys() { 
  char phexbuf[2*crypto_box_PUBLICKEYBYTES+1];
  char shexbuf[2*crypto_box_SECRETKEYBYTES+1];
  unsigned char public_key[crypto_box_PUBLICKEYBYTES];
  unsigned char secret_key[crypto_box_SECRETKEYBYTES];

  crypto_box_keypair(public_key, secret_key);

  printf("public: %s\n", to_hex(phexbuf, public_key, crypto_box_PUBLICKEYBYTES ));
  printf("secret: %s\n\n", to_hex(shexbuf, secret_key, crypto_box_SECRETKEYBYTES ));

  return 0;
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

		/* cryptography variables */
		char *my_keys_fn; /* filenames to find the keys */
		int my_keys_fd, print_key_pair; /* file descriptors of the keys */
		unsigned char nonce[crypto_box_NONCEBYTES];
		uint8_t my_public_key[crypto_box_PUBLICKEYBYTES];  
		uint8_t my_secret_key[crypto_box_SECRETKEYBYTES];
		uint8_t remote_public_key[crypto_box_PUBLICKEYBYTES];  
		int count;  /* bytes from decryption */

		char buffer[BUFFER_SIZE]; /* read/write buffer */
		char command_string_encrypt[BUFFER_SIZE]; /* holds the command string to our server */
		char command_string_decrypt[BUFFER_SIZE]; /* holds the decrypted string */
		char *token_p, *command_s, *file_name_s, *protocol_s; /* used the parse the command string */

		int end_of_file, total_bytes, bytes_read; /* for reading the input file */

		int client_addr_len;
		int socket_closed;
		int zero_bytes,bw;

		struct timeval begin_time, end_time; /* start, end time to compute bandwidth */

		uint64_t lapsed_useconds;
		double lapsed_seconds;

		MD5_CTX md5_context;
		unsigned char md5_out[MD5_DIGEST_LENGTH];

		int c,i; /* index counters */

		/* set defaults */
		my_keys_fn = NULL;
		print_key_pair = 0;
		udp_port = SOCK352_DEFAULT_UDP_PORT;
		local_port = remote_port =0 ;

		/* Parse the arguments to get: */
		opterr = 0;

		while ((c = getopt (argc, argv, "pk:c:u:l:r:")) != -1) {
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
		      case 'k':
			my_keys_fn = optarg; 
			break;
                      case 'p': 
			print_key_pair = 1; 
			break;
		      case '?':
			usage();
			exit(-1);
			break;
		      default:
		        printf("server_crypto: unknown option: ");
		        usage();
		        exit(-1);
		        break;
			}
		}

		if (print_key_pair == 1) { 

		  print_new_keys(); 
		  exit(-1);
		}
		
		/* get the cryptography parameters - the nonce and the keys */
		randombytes(nonce, crypto_box_NONCEBYTES);

		if (my_keys_fn == NULL) { 
		  printf("server_crypto: no keys file specified \n");
		  usage();
		  return -1; 		  
		}

		if ( get_keys(my_keys_fn,my_public_key,my_secret_key,remote_public_key) != 3 ) { 
		  printf("server_crypto: getting all keys from file %s failed \n", my_keys_fn);
		  return -1; 
		}

		/* change which init function to use based on the arguments */
		/* if BOTH the local and remote ports are set, use the init2 function */

		if ( (remote_port > 0) && (local_port > 0) ) {
			retval =  sock352_init3(remote_port, local_port,envp);
		} else {
			retval = sock352_init(udp_port);
		}
		if (retval != SOCK352_SUCCESS < 0) {
			printf("server_crypto: initialization of 352 sockets on UDP port %d failed\n",udp_port);
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
			printf("server_crypto: bind failed \n");
			exit(-1);
		}

		if ( (sock352_listen(listen_fd,5)) != SOCK352_SUCCESS) {
			printf("server_crypto: listen failed \n");
			exit(-1);
		}
		client_addr_len = sizeof(client_addr);
		connection_fd  = sock352_accept(listen_fd,(sockaddr_sock352_t *)&client_addr,
										&client_addr_len);

		if (connection_fd == SOCK352_FAILURE) {
			printf("server_crypto: accept failed");
			exit(-1);
		}


		socket_closed = zero_bytes = total_bytes = 0;

		/* start timing from when we return from accept */
		MD5_Init(&md5_context);
		gettimeofday(&begin_time, (struct timezone *) NULL);

		/* send back the nonce */
		bw = sock352_write(connection_fd,nonce, crypto_box_NONCEBYTES);		
		if (bw != crypto_box_NONCEBYTES) { 
		  printf("server_crypto: write of nonce failed \n");
		}
		
		count = decrypted_read(connection_fd,command_string_decrypt, BUFFER_SIZE,
				       remote_public_key, my_secret_key, nonce);
				     

		command_string_decrypt[BUFFER_SIZE] = '\0'; /* make sure the string is null-terminated */

		/* use strtok to parse the command and name of the file */
		token_p = strtok(command_string_decrypt," ");
		command_s = token_p;
		file_name_s = strtok(NULL," ");
		protocol_s = strtok(NULL," ");

		client_error = 0; /* assume all is well */
		/* check for errors, if an error, send a zero for the length of the
		 * the file.
		 */
		if (strcmp(command_s,"GET") != 0) {
			printf("server_crypto: bad command \n");
			client_error =1;
		}
		if (strcmp(protocol_s,"CS352/2.0") != 0) {
			printf("server_crypto: bad protocol \n");
			client_error = 1;
		}

		/* open the local file */
		/* check the file exists */
		if (file_name_s == NULL) {
			printf("server_crypto: no input file specified: ");
			client_error = 1;
		}
		/* open for reading */
		if ( (file_fd = open(file_name_s, O_RDONLY) ) < 0) {
			printf("server_crypto: error: open of file %s failed: %s \n", file_name_s,
			strerror(errno));
			client_error =1;
		}

		file_size = 0;
		/* get the size of the file */
		if (stat(file_name_s, &file_stat) < 0) {
			printf("server_crypto: stat of %s failed %s\n", file_name_s, strerror(errno));
			client_error =1;
		}
		if (! client_error )
			file_size = (uint32_t) file_stat.st_size;

		/* send the size of the file */
		/* the server first sends the size of the file, then the file */
		/* first send the size of the file as a 32 bit integer in network byte order */
		file_size_network = htonl(file_size);
		bw = encrypted_write(connection_fd, (uint8_t *)&file_size_network, sizeof(file_size_network),
				     remote_public_key, my_secret_key, nonce);
		if (bw <= 0) {
		  printf("server_crypto: write of file size failed \n");
		  exit(-1);
		}

		/* now send the file proper */
		total_bytes = end_of_file = 0;
		while ( (total_bytes < file_size) &&   /* the main loop checks both if we've sent the whole file*/
				(! end_of_file) ) {            /* or there is some other error */

				bytes_read = read(file_fd,buffer,BUFFER_SIZE);  /* read from the file */
				if (bytes_read > 0) {                      /* check we sent something */
					total_bytes += bytes_read ;
					if ( (bw = encrypted_write(connection_fd,buffer,bytes_read,
								   remote_public_key,my_secret_key,nonce)) <= 0) {
						printf("server_crypto: error writing byte at count %d bytes written %d \n",total_bytes,bw);
					} else {
						MD5_Update(&md5_context, buffer, bytes_read);  /* update the checksum */
					}
				} else {
					end_of_file =1;   /* we got either zero bytes or and error, so finish the loop */
				}
		}
		if ( sock352_close(connection_fd) != SOCK352_SUCCESS) {
			printf("server_crypto: error with socket close \n");
		}
		gettimeofday(&end_time, (struct timezone *) NULL);
		MD5_Final(md5_out, &md5_context);

		/* make sure to clean up! */
		close(file_fd);
		sock352_close(listen_fd);

		if (total_bytes == 0) {
			printf("server_crypto: no file sent\n");
			exit(-1);
		}

		lapsed_useconds = lapsed_usec(&begin_time, &end_time);
		lapsed_seconds = (double) lapsed_useconds / (double) 1000000;
		printf("server_crypto: sent %d bytes in %lf sec, bandwidth %8.4lf Mb/s \n", total_bytes,lapsed_seconds,
				( (double) total_bytes/ (double) (1048576*8)) /lapsed_seconds );
		printf("server_crypto: MD5-checksum: ");
		for(i=0; i < MD5_DIGEST_LENGTH; i++)
			printf("%02x", md5_out[i]);
		printf("\n");

return 0;

}

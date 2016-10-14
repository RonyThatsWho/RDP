# Copyright (c) 2015 Rutgers University and Richard P. Martin.
# All rights reserved.
#
# Permission to use, copy, modify, and distribute this software and its
# documentation for any purpose, without fee, and without written agreement is
# hereby granted, provided that the following conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#
#    2. Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#
#    3. Neither the name of the University nor the names of its
#       contributors may be used to endorse or promote products derived from
#       this software without specific prior written permission.
#
# IN NO EVENT SHALL RUTGERS UNIVERSITY BE LIABLE TO ANY PARTY FOR DIRECT,
# INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES ARISING OUT
# OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF RUTGERS
# UNIVERSITY HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# RUTGERS UNIVERSITY SPECIFICALLY DISCLAIMS ANY WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS FOR A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS
# ON AN "AS IS" BASIS, AND RUTGERS UNIVERSITY HAS NO OBLIGATION TO
# PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.
#
# A simple sample makefile for CS 352 Spring 2015
# You must create a client binary and server binary called client and server 
# these need to be created from source code with the 'make all' command 
# a 'make clean' command must remove these above binaries. 
# 
# Makefile tutorials you can use: 
# http://www.cs.colby.edu/maxwell/courses/tutorials/maketutor/
# https://www3.ntu.edu.sg/home/ehchua/programming/cpp/gcc_make.html 


CC=gcc
CFLAGS= -g -O0 -I. -I./include 
DEPS = sock352.h sock352-int.h 
CLIENT_OBJ = client.o sock352lib.o 
SERVER_OBJ = server.o sock352lib.o 
CLIENT2_OBJ = client2.o sock352lib.o 
SERVER2_OBJ = server2.o sock352lib.o 
CLIENT_CRYPTO_OBJ = client_crypto.o sock352lib.o 
SERVER_CRYPTO_OBJ = server_crypto.o sock352lib.o 
INCLUDES = -I sodium
LIBS =  -lssl -lcrypto -lm -lpthread 

all: client server client2 server2 client_crypto server_crypto 

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

client: $(CLIENT_OBJ) 
	gcc -o $@ $^ $(CFLAGS) $(INCLUDES) $(LIBS) 

server: $(SERVER_OBJ) 
	gcc -o $@ $^ $(CFLAGS) $(INCLUDES) $(LIBS)

client2: $(CLIENT2_OBJ)
	gcc -o $@ $^ $(CFLAGS) $(INCLUDES) $(LIBS) 

server2: $(SERVER2_OBJ) 
	gcc -o $@ $^ $(CFLAGS) $(INCLUDES) $(LIBS)

client_crypto: $(CLIENT_CRYPTO_OBJ)
	gcc -o $@ $^  libsodium.a $(CFLAGS) $(INCLUDES) $(LIBS)

server_crypto: $(SERVER_CRYPTO_OBJ) 
	gcc -o $@ $^  libsodium.a $(CFLAGS) $(INCLUDES) $(LIBS) 

.PHONY: clean

clean:
	rm -f client server client2 server2 client_crypto server_crypto *.o core  


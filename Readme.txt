
Notes on Heartbleed Project Files


To begin, unzip the ISA656_RESEARCH_PROJECT_JACOBS_BRANDON_G00895916.zip file which should result in the creation of a
large file tree in a directory called "ISA656_RESEARCH_PROJECT_JACOBS_BRANDON_G00895916". This ISA656_RESEARCH_PROJECT_JACOBS_BRANDON_G00895916 directory will be 
your main working directory.Change directory into ISA656_RESEARCH_PROJECT_JACOBS_BRANDON_G00895916 and follow all of the instructions below.

  cd ISA656_RESEARCH_PROJECT_JACOBS_BRANDON_G00895916

Before starting, execute the following shell script to create some links:

  sh -x create_links

This will create (or make sure they exist) 4 symbolic links needed for the 
compilation of the source files.

The set of files in the Heartbleed/SSL zip file contain the following:

- ssl_server.c (SSL server linked with OpenSSL with heartbleed vulnerability)
- ssl_client.c (SSL client that demonstrates SSL handshake with server)
- ssl_heartbleed.c (SSL client that demonstrates the heartbleed vulnerability)
- OpenSSL library (1.0.1 version of the library with heartbleed vulnerability)
- libsslfixed.a (version of OpenSSL library with heartbleed fix applied)
- Makefile (used to create binaries and symbolic links)
- client_cert.pem (private key and certificate file for ssl_client)
- server_cert.pem (private key and certificate file for ssl_server)

OpenSSL
The 1.0.1 version of the OpenSSL library is provided in a subdirectory named
openssl-1.0.1 and should be symbolically linked into the top level directory
where the files are unzipped. The symbolic link should have been created by
running the create_links scripts but if not, link it now:

  ln -s openssl-1.0.1 openssl

In the openssl directory is a Makefile in the event you need to recompile and
link the libraries but this should not be necessary. The libraries have already
been built and are ready for use. If you do need to compile OpenSSL, take care
that it is done on a FreeBSD release of 10.2 or you may run into issues. If you
are using a different version of FreeBSD to compile the library, you may need to
run a configuration utility first that will generate Makefiles specific to your
FreeBSD release before building the libraries. These are two libraries in the
openssl directory:

  libssl.a
  libcrypto.a

You should symbolically link these into your working directory although the 
create_links script should already have created these links. These links along
with the Makefile for the heartbleed files make sure the programs are linked
with the correct version of OpenSSL for your testing.

  ln -s openssl/libssl.a libssl.a
  ln -s openssl/libcrypto.a libcrypto.a

If for some reason you need to build the openssl libraries, you can go to the 
openssl directory and do:

  make clean; make

If the make fails for OpenSSL, it is probably related to a FreeBSD version
difference and your makefiles need to be configured and rebuilt. Also, the 
default compiler for OpenSSL is gcc (not cc) so you need to have gcc installed
on your FreeBSD system (it is a loadable package).

These is also a library in the main working directory that has been built for
you called:

  libsslfixed.a

This is a version of the openssl libssl.a library that has the heartbleed fix
applied. It is used to link a version of the ssl_server binary used to show
that the vulnerability has been repaired. The libssl.a version that is in the 
same working directory (and the library that is currently in the openssl tree)
have the heartbleed vulnerability since the openssl version is 1.0.1 in which
the problem first appeared.

To fix the vulnerability, you can examine the following file:

  openssl/ss/t1_lib.c

Look in this file for the define:

  #define HEARTBLEED_FIX	1

Depending on whether the define is active determines which block of code is used
in the compilation of t1_lib.c. When the define is enabled, the heartbleed code is
fixed so that it is no longer susceptible to the vulnerability. This is the same
or similar fix to what appears in versions of OpenSSL 1.0.1g and later which do
not have the problem. Without the #define active, the original code from 1.0.1 is
enabled and this code has the heartbleed vulnerability in it. The library named
libsslfixed.a has been created with the HEARTBLEED_FIX define enabled. Otherwise,
if you use the libssl.a in your local directory, the vulnerability exists in the 
heartbeat function.

  BUILDING FILES

You should be able to run the following:

  make

in the ISA656_RESEARCH_PROJECT_JACOBS_BRANDON_G00895916 directory and it will create the client and server files used in the 
discussions below. The OpenSSL libraries are already built and should not need
to be rebuilt. If there are any compilation errors and you are not running on
FreeBSD 10.2, you may have to adjust the header files used in the source files.

  DEMONSTRATIONS

1. Running the Client and Server

First, create two shell windows that you can use for executing the server and a
client. Execute the following commands, one from each of the shell windows:

  ./ssl_server
  ./ssl_client

  Defaults: server certificate file is server_cert.pem
	    client certificate file is client_cert.pem
	    Client and Server use port 2000
	    Client and Server use host 127.0.0.1 (loopback) for network connection

The programs should execute (the server does not terminate but continues to wait
for more client connections) and each will output information about its actions
and status. You will see the client and server perform an TLS/SSL handshake where
the server certificate is obtained by the client, the connection is encrypted and
MAC protected, they will exchange a simple message, and then the client exits. The 
server will continue to run.

Terminate the ssl_server using ^C.

2. Running the Client and Server (with client certificate)

In the first demonstration,only the server certificate was exchanged since the SSL 
server did not request the client certificate as part of the handshake. For this
demonstration, execute the following commands each in its own shell window:

  ./ssl_server -c
  ./ssl_client

The program will execute and again output information on their actions and status
with the main difference this time being that the server requests the certificate
from the client and the client sends it to the server. Both the server and client
will print out some identifying information from their respective certificates 
that are obtained during the handshake.

3. Demonstrating the Heartbleed Vulnerability

Execute the following programs in their own shell window:

  ./ssl_server
  ./ssl_heartbleed

The client and server will perform the SSL handshake and the client will obtain the 
server certificate. The client certificate is not requested in this demonstration. At
the end of the SSL handshake from the server side, before the connection is encrypted,
the client will send a HEARTBEAT request to the server. The request is malformed in
the sense that it requests 16K bytes of data but it does not send the equivalent amount
of data in the payload of the request which is how the HEARTBEAT request is specified
in the protocol. The result is that the server will return 16K of data to the client
and the client outputs the data received. All of this data comes from server memory
used for data/variables and not from the original HEARTBEAT request payload provided
by the client. The client, upon receiving the 16K bytes of data from the server, will
indicate that it has tested for and found the server to be vulnerable to heartbleed.

4. Demonstrating the Heartbleed Vulnerability Fix

Execute the following programs in their own shell window:

  ./ssl_server_fixed
  ./ssl_heartbleed

The client and server will perform the SSL handshake and the client will obtain the 
server certificate. The client certificate is not requested in this demonstration. At
the end of the SSL handshake from the server side, before the connection is encrypted,
the client will send a HEARTBEAT request to the server. The request is malformed in
the sense that it requests 16K bytes of data but it does not send the equivalent amount
of data in the payload of the request which is how the HEARTBEAT request is specified
in the protocol.In this example, the server which has the fix applied, will reject the 
HEARTBEAT request as being malformed and will return 0 bytes to the client as a result.
The client will determine that the server is not vulnerable to the heartbleed attack as
a result of how the server handled the malformed HEARTBEAT request.

  SUMMARY

The client and servers implemented demonstrate a basic knowledge of TLS/SSL concepts
and also an understanding of the heartbleed vulnerability, how to exploit it, and how
to fix it. The vulnerability, although it can be simply fixed, demonstrates how a
simple attack takes advantage of poor coding to reveal critical client/server data
which in this case could include passwords, private keys, account information, etc.
It is estimated that 800,000 to 1,000,000 web sites use OpenSSL and as a result of
this problem, many had to regenerate private keys and certificates for their servers
once they were able to apply the heartbleed patch.




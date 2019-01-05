

#include <errno.h>
#include <unistd.h>

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <openssl/err.h>
#include <signal.h>
 

static char *progName;
static int server;	// listener socket for client connections

#define PACKET_DUMP_COUNT	32

/*
 * PacketDump - output the contents of a data packet in hex format.
 */

void
DumpPacket(unsigned char *packet, int length)
{
    int n;

    printf("%s: packet [001-%03d]: ", progName, PACKET_DUMP_COUNT);

    for(n=0; n < length; n++)
    {
	int end;

	if((length - n) < PACKET_DUMP_COUNT)
	    end = n + (length - n);
	else
	    end = n + PACKET_DUMP_COUNT;

	if(n && ((n % PACKET_DUMP_COUNT) == 0))
	    printf("\n%s: packet [%03d-%03d]: ", progName, n+1, end);

	printf("%02x", packet[n]);
    }

    printf("\n");
}

/*
 * OpenListener - create a listener port for SSL client connections and
 * bind it to the specified (or default) port. The listen depth of the
 * queue is also set but practically speaking, for testing, only a single
 * client at a time is used.
 */

int OpenListener(int port)
{   int sd;
    struct sockaddr_in addr;
    int sockOpt, sockOptLen;

    /* Create the server socket on which to receive client connections */
    
    printf("%s: creating server SSL socket on port - %d\n", progName, port);
    
    sd = socket(PF_INET, SOCK_STREAM, 0);

    if(sd ==-1)
    {
      printf("%s: unable to create the server SSL socket - %d\n", progName, errno);
      exit(0);
    }
    
    /*
     * It is possible due to TIME_WAIT and other network conditions that the port used by
     * this program for packet diversion may remain bound even though the process that did
     * the bind(2) has terminated. This will result in the bind(2) below failing even though
     * our program is no longer able to receive diverted packets. Use the reuseport socket
     * option to allow the program to successfully bind to the same port.
     *
     * Note: option may not be supported on all versions of FreeBSD
     */

    if(setsockopt(sd, SOL_SOCKET, SO_REUSEPORT, &sockOpt, sockOptLen) == -1)
	    printf("%s: failed to set SO_REUSEPORT on SSL socket - %d\n", progName, errno);

    /* Bind the socket to the SSL server port for the client */
    
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    /* Bind the server socket to the specified (or default) port */

    if(bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        printf("%s: unable to bind() the server SSL socket - %d\n", progName, errno);
        exit(0);
    }

    /* Listen for client connections */

    if(listen(sd, 10) != 0 )
    {
        printf("%s: unable to listen() on server SSL socket - %d\n", progName, errno);
        exit(0);
    }

    return sd;
}
 
/*
 * VerifyCertificate - provides a simple routine that "verifies" the client's
 * certificate. If this routine is not used, the OpenSSL library uses an internal
 * validity check function on the client certificate which will fail since the
 * certificate is self-signed.This routine "verifies" the validity of the client
 * certificate since this is for demonstration purposes only.
 */

int VerifyCertificate(int preverifyOK, X509_STORE_CTX *x509ctx)
{
  printf("%s: verifying the SSL client certificate, self-signed, OK\n", progName);
  return 1;
}

/*
 * InitServerCTX - initialize the server's SSL context. load strings, cipers,
 * and methods to be used with TLS/SSL. If client certificate validation is 
 * requested on the command line, the context flag's are set that will require
 * the client to provide the server with its certificate during the handshake
 * or the connection will be rejected.
 */

SSL_CTX *InitServerCTX(int clientCert)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;
 
    printf("%s: initializing SSL\n", progName);
    
    OpenSSL_add_all_algorithms();  	/* load & register all cryptos, etc. */

    SSL_load_error_strings();   	/* load all error messages */

    method = TLSv1_2_server_method();  	/* create new server-method instance */

    ctx = SSL_CTX_new(method);   	/* create new context from method */
    
    printf("%s: SSL initialized & context created\n", progName);

    if(ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        exit(0);
    }

    /* Optionally require client certificate */
    
    if(clientCert)
    {
      SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, VerifyCertificate);
      SSL_CTX_set_verify_depth(ctx,1);
    }
    
    return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    printf("%s: loading SSL server certificate and private key\n", progName);
    
    /* set the local certificate from CertFile */

    if(SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        exit(0);
    }

    /* set the private key from KeyFile (may be the same as CertFile) */

    if(SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        exit(0);
    }

    /* verify private key */

    if(!SSL_CTX_check_private_key(ctx) )
    {
        printf("%s: private key does not match the public certificate\n", progName);
        exit(0);
    }
    
    printf("%s: successfully loaded SSL server certificate and private key\n", progName);
}
 
void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;
    long verify;
 
    /* Obtain the client certificate provided during handshake if requested */
    
    cert = SSL_get_peer_certificate(ssl); 	/* Get certificates (if available) */

    if(cert != NULL )
    {
	/* Check for certificate validity */
	
	verify = SSL_get_verify_result(ssl);
	
	if(verify == X509_V_OK || verify == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
	{
	    printf("%s: SSL client certificate\n", progName);
	    line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
	    printf("    Subject: %s\n", line);
	    free(line);
	    
	    line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
	    printf("    Issuer: %s\n", line);
	    free(line);
	    
	    X509_free(cert);
	}
	else
	    printf("%s: invalid SSL client certificate - %ld\n", progName, verify);
    }
    else
        printf("%s: no SSL client certificate\n", progName);
}
 
/*
 * Servlet - process SSL requests from the client
 */

void Servlet(SSL *ssl)
{
    char buf[1024];
    char reply[1024];
    int sd, bytes;
    char *response="Hello from SSL server";
 
    printf("%s: performing SSL_accept on new client connection\n", progName);
	
    if (SSL_accept(ssl) == -1)     /* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    else
    {
        ShowCerts(ssl);        			 /* get any certificates */

	while(1)
	{
	  printf("%s: reading from client SSL socket\n", progName);
	  
	  bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
	  
	  printf("%s: read [%d] client bytes from SSL socket\n", progName, bytes);
	  
	  if(bytes > 0)
	  {
	      DumpPacket((unsigned char *) buf, bytes);
	      buf[bytes] = 0;
	      printf("    Client msg: \"%s\"\n", buf);
	      sprintf(reply, "%s [%s]", response, buf);   	/* construct reply */
	      SSL_write(ssl, reply, strlen(reply)); 		/* send reply */
	      
	      printf("%s: SSL data sent to client\n", progName);
	  }
	  else
	  {
	      ERR_print_errors_fp(stderr);
	      break;
	  }
	}
    }

    sd = SSL_get_fd(ssl);       /* get socket connection */
    
    printf("%s: SSL server terminating client SSL connection - fd [%d]\n", progName, sd);

    SSL_free(ssl);         	/* release SSL state */

    close(sd);          	/* close connection */
}

/*
 * signalHandler - handle SIGTERM for orderly program termination
 */

void signalHandler(int sig)
{
    printf("%s: SSL server terminating\n", progName);
    
    close(server);          /* close server socket */

    exit(1);
}

/*
 * SSL Server/HEARTBLEED Vulnerability Demonstration
 * 
 * This SSL server can be used to demonstrate two concepts. When used with the
 * ssl_client program, it demonstrates the TLS/SSL handshake between the client
 * and server including the exchange of certificates, negotiation of servers,
 * and the encrypted/authenticated exchange of a message.
 * 
 * When used with the ssl_heartbeat client, the client will demonstrate that the
 * server is vulnerable to the HEARTBLEED attack where a significant amount of
 * server memory is returned to the client as the result of a memory leak. This
 * server is linked with the 1.0.1 version of OpenSSL that has the vulnerability
 * in the library.The fix for the vulnerability is also conditionally compiled
 * into the local copy of the OpenSSL library and if linked with the fixed version
 * of the OpenSSL library, the same client will not be able to obtain the data
 * via the Heartbeat request.
 * 
 * OpenSSL module fixed for Heartbleed:  ssl/t1_lib.c (see conditional code)
 *
 * Command line: ssl_server [-p port] [-s filename] [-c]
 * 
 * 	./ssl_server (no arguments, port=2000, key/cert file=server_cert.pem, no client cert)
 * 
 * SSL client certificate not requested by default, use -c option for client certificate
 * retrieval during handshake and for verification. Keep in mind that both server and
 * client certificates are generated by OpenSSL and self-signed so they will not pass
 * a standard SSL/TLS verification process (no valid Certificte Authority).
 * 
 * -p port is the server port on which to listen for client connections
 * -s file is the file name containing server key and certificate
 * -c flag used to specify client certificate required during handshake
 *
 * Default port is 2000 if not specified on command line
 * Default key/certificate file is "server_cert.pem" if no filename specified
 * Default client certificate is NOT required during handshake
 *
 */

int main(int argc, char *argv[])
{
    SSL_CTX *ctx;
    struct sigaction sigact;
    char *certfile;
    int clientCert;
    int portnum;
    int opt;
 
    /* Initialize default values for port and certificate/key file */

    progName = argv[0];
    portnum = 2000;			// default listener port
    certfile = "server_cert.pem";	// default certificate/key file
    clientCert = 0;			// default - no client certificate requird

    /* Process command line arguments */

    while((opt = getopt(argc, argv, "s:p:c")) != -1)
    {
	switch(opt)
	{
	    case 'p':
		portnum = atoi(optarg);
		break;

	    case 's':			// server certificate file
		certfile = optarg;
		break;
	    
	    case 'c':
		clientCert = 1;		// require client certificate
		printf("%s: *** configured to require SSL client certificate ***\n", progName);
		break;
	}
    }

    /* Must run as root to function correctly */
    
    if(getuid())
    {
        printf("%s: program must be run as root/sudo user!!", progName);
        exit(0);
    }

    /* Signal handler for graceful exit */

    sigact.sa_handler = signalHandler;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = 0;
    sigaction(SIGINT, &sigact, (struct sigaction *) NULL);

    /* Initialize SSL library and context for the server */

    SSL_library_init();
 
    ctx = InitServerCTX(clientCert);        		/* initialize SSL */

    LoadCertificates(ctx, certfile, certfile); 		/* load certs */

    printf("%s: SSL initialized & context created, creating listener socket\n", progName);
    
    server = OpenListener(portnum);    			/* create server socket */

    /* Listen and process client connections */

    while (1)
    {
	struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;
	int client_fd;
 
	printf("%s: waiting for SSL client connection\n", progName);
    
        client_fd = accept(server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */

	/* Print out IP address details of the client that conected */

        printf("%s: SSL client connection: %s:%d\n",progName, inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

        ssl = SSL_new(ctx);           /* get new SSL state with context */

        SSL_set_fd(ssl, client_fd);   /* set connection socket to SSL state */

        Servlet(ssl);         	      /* service connection */
    }

    printf("%s: SSL server terminating\n", progName);
    
    close(server);          /* close server socket */

    SSL_CTX_free(ctx);      /* release context */

    exit(1);
}

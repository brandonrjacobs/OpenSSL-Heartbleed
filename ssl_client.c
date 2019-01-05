

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/ssl3.h>
#include <openssl/tls1.h>
#include <openssl/err.h>
 
 

static char *progName;

/*
 * OpenConnection - convert the hostname into the socket structure,
 * create a local socket endpoint, and then connect to the SSL server
 * on the specified (or default) port.
 */

int OpenConnection(const char *hostaddr, int port)
{
    struct sockaddr_in addr;
    int sd;
 
    printf("%s: converting SSL server IP address [%s]\n", progName, hostaddr);
    
    /* Convert the host address in ASCII format */
    
    if(inet_aton(hostaddr, &addr.sin_addr) == -1)
    {
        printf("%s: error on inet_ntoa() - %d\n", progName, errno);
        exit(0);
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
	exit(0);
    }
    
    return sd;
}
 
/*
 * InitCTX - create and initialize an SSL context for the client, load
 * the necessary cipers, methods, and strings, and return the context to
 * the caller.
 */

SSL_CTX* InitCTX(void)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;
 
    printf("%s: initializing SSL\n", progName);
    
    OpenSSL_add_all_algorithms();  	/* Load cryptos, et.al. */
    
    SSL_load_error_strings();   	/* Bring in and register error messages */
    
    method = TLSv1_2_client_method();  	/* Create new client-method instance */
    
    ctx = SSL_CTX_new(method);   	/* Create new context */
    
    if(ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        exit(0);
    }
    
    printf("%s: SSL initialized and context created\n", progName);
    
    return ctx;
}

/*
 * LoadCertificates - load the client certificate into the SSL context
 * along with the private key and verify that the key matches the public
 * certificate. The key and certificate are in the same file for simple
 * convenience. OpenSSL was used to create the self-signed certificate
 * used by the client.
 */

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    printf("%s: loading SSL client certificate and private key - %s\n", progName, CertFile);
    
    /* set the local certificate from CertFile */

    if(SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(0);
    }

    /* set the private key from KeyFile (may be the same as CertFile) */

    if(SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(0);
    }

    /* verify private key */

    if(!SSL_CTX_check_private_key(ctx))
    {
        printf("%s: private key does not match the public certificate\n", progName);
        exit(0);
    }
    
    printf("%s: successfully loaded SSL client certificate and private key\n", progName);
}

/*
 * ShowCerts - display information from the server certificate returned
 * during the SSL handshake process.
 */

void ShowCerts(SSL* ssl)
{
    X509 *cert;
    char *line;
    long verify;
 
    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    
    if(cert != NULL )
    {
	/* Check for certificate validity */
	
	verify = SSL_get_verify_result(ssl);
	
	if(verify == X509_V_OK || verify == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
	{
	    printf("%s: SSL server certificate:\n", progName);
	    
	    line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
	    printf("    Subject: %s\n", line);
	    free(line);       	/* free the malloc'ed string */
	    
	    line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
	    printf("    Issuer: %s\n", line);
	    free(line);       	/* free the malloc'ed string */
	    
	    X509_free(cert);     	/* free the malloc'ed certificate copy */
	}
	else
	    printf("%s: invalid SSL server certificate - %ld\n", progName, verify); 
    }
    else
        printf("%s: no SSL server certificate\n", progName);
}
 
/*
 * main - invoke the SSL client which will connect to the SSL server using
 * TLS v1.2. Following the handshake with the SSL server, the client and
 * server exchange a simple message to demonstrate encryption/MAC protection
 * for the data connection based on the cipers/methods/policies negotiated
 * during the handshake. The SSl server may operate in two modes: one where
 * it does not request the client certificate and a second where the client
 * certificate is requested.
 * 
 * ./ssl_client [-p port] [-h host_IP] [-c certificate/key_file]
 * 
 * ./ssl_client (no arguments uses 127.0.0.1:2000 with client_cert.pem)
 * 
 * Arguments:
 * 	-h 	specifies the host IP address (default is localhost for testing)
 * 	-p	specifies the SSl server port (default 2000)
 * 	-c	specifies client key/certificate file (default is client_cert.pem)
 */

int main(int argc, char *argv[])
{
    SSL_CTX *ctx;
    int server;
    SSL *ssl;
    char buf[1024];
    int bytes;
    char *hostname;
    char *certfile;
    int portnum;
    int opt;
    char *msg = "Hello from SSL client";
 
    /* Initialize default values for port and certificate/key file */

    progName = argv[0];
    portnum = 2000;			// default listener port
    certfile = "client_cert.pem";	// default certificate/key file
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

	    case 'c':
		certfile = optarg;
		break;
	}
    }

    SSL_library_init();
 
    ctx = InitCTX();
    
    LoadCertificates(ctx, certfile, certfile); 		/* load certs */
    
    printf("%s: SSL initialized & context created, connecting to SSL server\n", progName);
    
    server = OpenConnection(hostname, portnum);
    
    ssl = SSL_new(ctx);      		/* create new SSL connection state */
    
    SSL_set_fd(ssl, server);    	/* attach the socket descriptor */
    
    printf("%s: SSL server fd [%d] opened, SSL context created\n", progName, server);
    
    if(SSL_connect(ssl) == -1)   	/* perform the connection */
    {
        ERR_print_errors_fp(stderr);
	exit(0);
    }
       
    printf("%s: connected to SSL server with %s encryption, version %s\n",
	   progName, SSL_get_cipher(ssl), SSL_get_version(ssl));
    
    ShowCerts(ssl);        				/* get any certs */
    SSL_write(ssl, msg, strlen(msg));   		/* encrypt & send message */
    bytes = SSL_read(ssl, buf, sizeof(buf)); 	/* get reply & decrypt */
    buf[bytes] = 0;
    
    printf("%s: SSL data received: \"%s\"\n", progName, buf);
    
    SSL_free(ssl);        	/* release connection state */
    
    printf("%s: SSL client terminating\n", progName);
    
    close(server);         	/* close socket */
    
    SSL_CTX_free(ctx);        	/* release context */
    
    exit(1);
}

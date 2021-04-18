#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "client.h"
#include "parse_opts.h"

#define GNUTLS_FAIL(x) do { \
        gnutls_perror(x); \
        ret = EXIT_FAILURE; \
        goto cleanup; \
    } while (0)
#define GNUTLS_CHECK(x) if ((ret = (x)) < 0) { \
        GNUTLS_FAIL(ret); \
    }
#define CUSTOM_FAIL(error) do { \
        ret = EXIT_FAILURE; \
        fprintf(stderr, "Error: %s", error); \
        goto cleanup; \
    } while (0)


int main(int argc, char **argv)
{   
    // final return value
    int ret = EXIT_SUCCESS;

    // options to get from argv
    struct tls_options opts = 
    {
        .check_crl = false,
        .check_ocsp = false,
        .check_ocsp_staple = false,
        .host = {0},
        .port = {0},
        .trust_anchor = {0},
    };

    // parse the command line options
    if (parse_opts(argc, argv, &opts) != PARSING_SUCCESS) {
        CUSTOM_FAIL("Parsing command line arguments failed.");
    }

    // TLS session
    gnutls_session_t session = NULL;

    // credentials variable needed to set trust anchors
    gnutls_certificate_credentials_t creds = NULL;

    // the socket descriptor to use for connection
    int sockfd = -1;
	
    // NOTE: might want to use gnutls_global_init (some precomputations to speed things up)

	// initialize a TLS session
	GNUTLS_CHECK(gnutls_init(&session, GNUTLS_CLIENT));
    
	// will use the SNI extension to indicate the address to connect to
	GNUTLS_CHECK(gnutls_server_name_set(session, GNUTLS_NAME_DNS, opts.host, strlen(opts.host)));
	
    // initialize the credentials structure
	GNUTLS_CHECK(gnutls_certificate_allocate_credentials(&creds));

	// set the trust anchor for certificate validation
	GNUTLS_CHECK(gnutls_certificate_set_x509_trust_file(creds, opts.trust_anchor, GNUTLS_X509_FMT_PEM));
	// NOTE: normally we would use `gnutls_certificate_set_x509_system_trust`

	// associate the credentials with the session
	GNUTLS_CHECK(gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, creds));

	// instruct GnuTLS to verify server certificate along with hostname verification
	gnutls_session_set_verify_cert(session, opts.host, 0);
    // TODO: move back opts.host

    // request a stapled OCSP response (TLS status request extension)
    if (opts.check_ocsp_staple) {
        GNUTLS_CHECK(gnutls_ocsp_status_request_enable_client(session, NULL, 0, NULL));
    }

	// set default cipher suite priorities
	GNUTLS_CHECK(gnutls_set_default_priority(session));

	// initialize the underlying TCP connection
	sockfd = tcp_connect((const char *) &(opts.host), (const char *) &(opts.port));
	if (sockfd == -1) {
        CUSTOM_FAIL("Could not establish TCP/IP connection to server.");
    }

    // associate the socket with the TLS session
    gnutls_transport_set_int(session, sockfd);

    // set default timeout for the handshake
    gnutls_handshake_set_timeout(session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

    // handshake return value
    int r;

    // try to do handshake until successful
    do {
    	r = gnutls_handshake(session);
    } while (r < 0 && gnutls_error_is_fatal(r) == 0);


    // print the certificate verification result
    unsigned status = gnutls_session_get_verify_cert_status(session);
    if (status != (unsigned int)-1) {
        gnutls_certificate_type_t cert_type = gnutls_certificate_type_get(session);
        gnutls_datum_t out = { 0 };
        gnutls_certificate_verification_status_print(status, cert_type, &out, 0);
        fprintf(stderr, "%s", out.data);
        gnutls_free(out.data);
    }
    else {
        GNUTLS_FAIL(r);
    }

	// TODO: do something useful here

    // alert server that we are closing connection
    GNUTLS_CHECK(gnutls_bye(session, GNUTLS_SHUT_RDWR));

cleanup:
	if (sockfd >= 0) {
        close(sockfd);
    }
    if (creds != NULL) {
        gnutls_certificate_free_credentials(creds);
    }
    if (session != NULL) {
        gnutls_deinit(session);
    }
    
    return ret;
}


int tcp_connect(const char *host, const char *port)
{   
    // TODO: move this function somewhere else

    /* TCP/IP socket descriptor */
    int sockfd = -1;

    /* Hints that we send to server with our preferences */
    struct addrinfo hints = {0};

    /* We allow both IPv4 and IPv6 */
    hints.ai_family = AF_UNSPEC;
    /* We want a stream socket, not a datagram one */
    hints.ai_socktype = SOCK_STREAM;
    /* We know the numeric port number beforehand */
    hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV;
    /* We want to use TCP */
    hints.ai_protocol = IPPROTO_TCP;

    struct addrinfo *result = NULL;

    /* Try to get the server addrinfo list */
    if (getaddrinfo(host, port, &hints, &result) != 0 || result == NULL) {
        return -1;
    }

    /* Try each address from the server list until successful */
    struct addrinfo *rr;
    for (rr = result; rr != NULL; rr = rr->ai_next) {
        sockfd = socket(rr->ai_family, rr->ai_socktype, rr->ai_protocol);
        if (sockfd == -1)
            continue;
        if (connect(sockfd, rr->ai_addr, rr->ai_addrlen) != -1)
            break;
        close(sockfd);
    }

    /* We don't need the server info anymore */
    freeaddrinfo(result);
    
    /* Fail if we didn't manage to connect to any server address */
    if (rr == NULL) {
        return -1;
    }

    return sockfd;
}
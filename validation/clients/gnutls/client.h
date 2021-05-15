#ifndef CLIENT_H
#define CLIENT_H

#include <stdbool.h>
#include <gnutls/gnutls.h>

/* Buffer lengths for command line arguments */
#define HOST_BUFFER_LENGTH 256
#define PORT_BUFFER_LENGTH 16
#define	PATH_BUFFER_LENGTH 4096

#define PARSING_SUCCESS 0
#define PARSING_ERROR 1

/* Macros for dealing with GnuTLS errors*/
#define GNUTLS_FAIL(x) do { \
        gnutls_perror(x); \
        ret = EXIT_FAILURE; \
        goto cleanup; \
    } while (0)
#define GNUTLS_CHECK(x) if ((ret = (x)) < 0) { \
        GNUTLS_FAIL(ret); \
    }

/* Macro for dealing with application errors */
#define CUSTOM_FAIL(error) do { \
        ret = EXIT_FAILURE; \
        fprintf(stderr, "Application error: %s", error); \
        goto cleanup; \
    } while (0)

/* Possible command line arguments */
struct tls_options
{
	/* Determines whether we want to check revocation */
	bool check_crl;
	/* Determines whether we want to check OCSP online */
	bool check_ocsp;
	/* Determines whether we want to check stapled OCSP */
	bool check_ocsp_staple;
	/* Hostname to connect to */
	char host[HOST_BUFFER_LENGTH];
	/* Port number to use for the connection */
	char port[PORT_BUFFER_LENGTH];
	/* Path to a trusted root certificate */
	char trust_anchor[PATH_BUFFER_LENGTH];
};

/* Function to parse the command line arguments */
int parse_opts(int argc, char **argv, struct tls_options *opts);

/* Function to establish a TCP/IP connection, returns a socket descriptor */
int tcp_connect(const char *host, const char *port);

/* Custom verify callback */
int verify_callback(gnutls_session_t session);

/* cURL write callback */
static size_t write_data(void *ptr, size_t size, size_t nmemb, void *stream);

#endif
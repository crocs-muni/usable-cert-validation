#ifndef CLIENT_H
#define CLIENT_H

#include <stdbool.h>

/* Buffer lengths for command line arguments */
#define HOST_BUFFER_LENGTH 256
#define PORT_BUFFER_LENGTH 16
#define	PATH_BUFFER_LENGTH 4096

#define PARSING_SUCCESS 0
#define PARSING_ERROR 1

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

#endif
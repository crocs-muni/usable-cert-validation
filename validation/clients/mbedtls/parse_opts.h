#ifndef PARSE_OPTS_H
#define PARSE_OPTS_H

#include <stdbool.h>

#define HOST_BUFFER_LENGTH 256
#define PORT_BUFFER_LENGTH 16
#define	PATH_BUFFER_LENGTH 4096

#define PARSING_SUCCESS 0
#define PARSING_ERROR 1

struct tls_options
{
	char crl_file[PATH_BUFFER_LENGTH];
	char host[HOST_BUFFER_LENGTH];
	char port[PORT_BUFFER_LENGTH];
	char trust_anchor[PATH_BUFFER_LENGTH];
};

int parse_opts(int argc, char **argv, struct tls_options *opts);

#endif
#ifndef PARSE_OPTS_H
#define PARSE_OPTS_H

#include <stdbool.h>

#define HOST_BUFFER_LENGTH 256
#define PORT_BUFFER_LENGTH 16
#define	PATH_BUFFER_LENGTH 4096
#define EMAIL_BUFFER_LENGTH 256
#define POLICY_BUFFER_LENGTH 256
#define IP_BUFFER_LENGTH 32
#define PURPOSE_BUFFER_LENGTH 32
#define TRUST_BUFFER_LENGTH 32

#define PARSING_SUCCESS 0
#define PARSING_ERROR 1

struct tls_options
{
	bool check_crl;
	bool check_ocsp;
	bool check_ocsp_staple;
	bool check_ct;
	bool strict;
	bool allow_proxy;
	bool check_policies;
	bool explicit_policy;
	bool inhibit_any_policy;
	bool inhibit_mapping;
	bool use_deltas;
	char host[HOST_BUFFER_LENGTH];
	char port[PORT_BUFFER_LENGTH];
	char trust_anchor[PATH_BUFFER_LENGTH];
	int max_depth;
	char email[EMAIL_BUFFER_LENGTH];
	char ip[IP_BUFFER_LENGTH];
	char policy[POLICY_BUFFER_LENGTH];
	char purpose[PURPOSE_BUFFER_LENGTH];
	char trust[TRUST_BUFFER_LENGTH];
};

int parse_opts(int argc, char **argv, struct tls_options *opts);

#endif
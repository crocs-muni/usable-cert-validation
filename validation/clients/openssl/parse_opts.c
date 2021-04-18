#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>

#include "parse_opts.h"

int parse_opts(int argc, char **argv, struct tls_options *opts)
{	
	int c;
	while(1) {
		static struct option long_options[] = 
		{
			{"check_crl", no_argument, NULL, 'c'},
			{"check_ocsp", no_argument, NULL, 'o'},
			{"check_ocsp_staple", no_argument, NULL, 's'},
			{"check_ct", no_argument, NULL, 'f'},
			{"strict", no_argument, NULL, 'r'},
			{"allow_proxy", no_argument, NULL, 'a'},
			{"check_policies", no_argument, NULL, 'k'},
			{"explicit_policy", no_argument, NULL, 'x'},
			{"inhibit_any_policy", no_argument, NULL, 'y'},
			{"inhibit_mapping", no_argument, NULL, 'b'},
			{"use_deltas", no_argument, NULL, 'u'},
			{"host", required_argument, NULL, 'h'},
			{"port", required_argument, NULL, 'p'},
			{"trust_anchor", required_argument, NULL, 't'},
			{"max_depth", required_argument, NULL, 'd'},
			{"email", required_argument, NULL, 'e'},
			{"ip", required_argument, NULL, 'i'},
			{"purpose", required_argument, NULL, 'j'},
			{"policy", required_argument, NULL, 'l'},
			{"trust", required_argument, NULL, 'w'},
			{NULL, 0, NULL, 0}
		};

		c = getopt_long(argc, argv, "", long_options, NULL);
		if (c == -1) {
			break;
		}

		switch(c) {
			case 'r':
				opts->strict = true;
				break;
			case 'a':
				opts->allow_proxy = true;
				break;
			case 'k':
				opts->check_policies = true;
				break;
			case 'x':
				opts->explicit_policy = true;
				break;
			case 'y':
				opts->inhibit_any_policy = true;
				break;
			case 'b':
				opts->inhibit_mapping = true;
				break;
			case 'u':
				opts->use_deltas = true;
				break;
			case 'o':
				opts->check_ocsp = true;
				break;
			case 'c':
				opts->check_crl = true;
				break;
			case 'f':
				opts->check_ct = true;
				break;
			case 's':
				opts->check_ocsp_staple = true;
				break;
			case 'h':
				strcpy(opts->host, optarg);
				break;
			case 'p':
				strcpy(opts->port, optarg);
				break;
			case 't':
				strcpy(opts->trust_anchor, optarg);
				break;
			case 'd':
				opts->max_depth = atoi(optarg);
				break;
			case 'e':
				strcpy(opts->email, optarg);
				break;
			case 'i':
				strcpy(opts->ip, optarg);
				break;
			case 'j':
				strcpy(opts->purpose, optarg);
				break;
			case 'l':
				strcpy(opts->policy, optarg);
				break;
			case 'w':
				strcpy(opts->trust, optarg);
				break;
			default:
				return PARSING_ERROR;
		}
	}

	return PARSING_SUCCESS;
}
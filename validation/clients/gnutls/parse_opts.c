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
			{"host", required_argument, NULL, 'h'},
			{"port", required_argument, NULL, 'p'},
			{"trust_anchor", required_argument, NULL, 't'},
			{NULL, 0, NULL, 0},
		};

		c = getopt_long(argc, argv, "", long_options, NULL);
		if (c == -1) {
			break;
		}

		switch(c) {
			case 'c':
				opts->check_crl = true;
				break;
			case 'o':
				opts->check_ocsp = true;
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
			default:
				return PARSING_ERROR;
		}
	}

	return PARSING_SUCCESS;
}
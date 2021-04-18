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
			{"crl_file", required_argument, NULL, 'c'},
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
				strcpy(opts->crl_file, optarg);
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
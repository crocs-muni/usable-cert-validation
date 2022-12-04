#ifndef OPTIONS_H
#define OPTIONS_H

#include <stdbool.h>
/* getopt_long function and structure option is declared here! */
#include <getopt.h>

struct short_options {
    char *port;
    bool print_cert_chain_info;
    bool is_crl_check_enabled;
    bool is_ocsp_check_enabled;
    bool is_ocsp_stapling_check_enabled;
    bool is_certificate_transparency_check_enabled;
};

void parse_options(int argc, char **argv, char **hostname, struct short_options *actual_options);
void print_help();

#endif

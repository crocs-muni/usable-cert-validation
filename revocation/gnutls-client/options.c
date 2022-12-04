#include "options.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void print_help() {
  printf(
      "Usage: gnutls_client [OPTION]... HOSTNAME \n\n"

      "Connect securely (by using TLS protocol) to the server specified by "
      "mandatory hostname argument, "
      "perform its certificate chain validation and if the validation passes "
      "successfully, "
      "perform X.509 certificate revocation check for each certificate from "
      "the chain.\n"
      "The selected revocation schemes from the CLI interface are used for the "
      "revocation check, "
      "where several revocation schemes can be selected at once.\n"
      "If no revocation scheme is specified, all are used by default.\n\n"

      "Mandatory arguments to long options are mandatory for short options "
      "too.\n"
      "  -p, --port=PORT                       explicitly specify the server's "
      "service to which this client attempts to connect, 443 for the https "
      "service is the default\n"
      "  -i, --print-cert-chain-info           print defail information about "
      "each certificate from the certificate chain\n"
      "      --crl-check                       perform CRL revocation check\n"
      "      --ocsp-check                      perform OCSP revocation check\n"
      "      --ocsp-stapling-check             perform OCSP-stapling "
      "revocation check\n"
      "      --certificate-transparency-check  perform SCTs validation check "
      "(CT policy)\n"
      "  -h, --help                            display this help and exit\n\n"

      "EXAMPLES: \n"
      "To securely connect to the x509errors.org server listening at port 443 "
      "with printing details "
      "about each certificate from the chain and checking the revocation "
      "status of these certificates with each revocation scheme possible.\n"
      " $ gnutls_client --print-cert-chain-info -p 443 x509errors.org\n\n"

      "To securely connect to google.com server at default port 443, checking "
      "the revocation status of "
      "the certificates from the certificate chain using only the CRL "
      "revocation scheme.\n"
      " $ gnutls_client --crl-check google.com\n\n");
}

static bool is_parameter_numeric(char *parameter) {
  for (int i = 0; i < strlen(parameter); i++) {
    if (!isdigit(parameter[i])) {
      return false;
    }
  }

  return true;
}

void parse_options(int argc, char **argv, char **hostname,
                   struct short_options *actual_options) {
  /* Set default values, in case particular option is not used. */
  actual_options->port = "443";  // default port number for HTTPS

  /* List of supported 'short' v  options, where the option that requires an
   * argument is followed by a colon. */
  /* The first colon in the string sets the "scan mode", in which the function
   * distinguishes the output ? (unknown option) and : (known option has no
   * required argument). */
  const char *optstring = ":hp:i";

  /* If flag is set not tu NULL in long_options, then the value will be stored
   * in this variable adress. */
  /* Function will return case 0 in this case. */
  int flag_adress = 0;

  /* List of supported 'long' options and their mappings to the 'short'
   * equivalent. */
  struct option long_options[] = {
      {.name = "help", .has_arg = 0, .flag = NULL, .val = 'h'},
      {.name = "port", .has_arg = 1, .flag = NULL, .val = 'p'},
      {.name = "print-cert-chain-info", .has_arg = 0, .flag = NULL, .val = 'i'},
      {.name = "crl-check", .has_arg = 0, .flag = &flag_adress, .val = 'a'},
      {.name = "ocsp-check", .has_arg = 0, .flag = &flag_adress, .val = 'b'},
      {.name = "ocsp-stapling-check",
       .has_arg = 0,
       .flag = &flag_adress,
       .val = 'c'},
      {.name = "certificate-transparency-check",
       .has_arg = 0,
       .flag = &flag_adress,
       .val = 'd'},
      {0},
  };

  int opt;
  while ((opt = getopt_long(argc, argv, optstring, long_options, NULL)) != -1) {
    switch (opt) {
      case 'h':
        print_help();
        exit(EXIT_SUCCESS);
      case 'p':
        if (!is_parameter_numeric(optarg)) {
          fprintf(stderr, "Supplied port is not in numeric format!\n");
          printf("Try 'gnutls_client --help' for more information.\n");
          exit(EXIT_FAILURE);
        }
        actual_options->port = optarg;
        break;

      case 'i':
        actual_options->print_cert_chain_info = true;
        break;

      case 0:
        if (flag_adress == 'a') {
          actual_options->is_crl_check_enabled = true;
        } else if (flag_adress == 'b') {
          actual_options->is_ocsp_check_enabled = true;
        } else if (flag_adress == 'c') {
          actual_options->is_ocsp_stapling_check_enabled = true;
        } else if (flag_adress == 'd') {
          actual_options->is_certificate_transparency_check_enabled = true;
        } else {
          fprintf(
              stderr,
              "Unexpected error occured while parsing the program options!\n");
          exit(EXIT_FAILURE);
        }
        break;

      case '?':
        fprintf(stderr, "gnutls_client: unrecognized option '%s'\n",
                argv[optind - 1]);
        printf("Try 'gnutls_client --help' for more information.\n");
        exit(EXIT_FAILURE);
        break;
      case ':':
        fprintf(stderr, "gnutls_client: option '%s' requires an argument\n",
                argv[optind - 1]);
        printf("Try 'gnutls_client --help' for more information.\n");
        exit(EXIT_FAILURE);
        break;

      default:
        fprintf(
            stderr,
            "Unexpected error occured while parsing the program options!\n");
    }
  }

  /* This will catch case, when the required argument HOSTNAME is missing. */
  if (optind == argc) {
    printf("gnutls_client: missing required hostname operand\n");
    printf("Usage: gnutls_client [OPTION]... HOSTNAME \n");
    printf("Try 'gnutls_client --help' for more information.\n");
    exit(EXIT_FAILURE);
  }

  /* If no revocation check is no explicitly selected, enable all of them. */
  if (!actual_options->is_crl_check_enabled &&
      !actual_options->is_ocsp_check_enabled &&
      !actual_options->is_ocsp_stapling_check_enabled &&
      !actual_options->is_certificate_transparency_check_enabled) {
    actual_options->is_crl_check_enabled = true;
    actual_options->is_ocsp_check_enabled = true;
    actual_options->is_ocsp_stapling_check_enabled = true;
    actual_options->is_certificate_transparency_check_enabled = true;
  }

  /* Parse the required HOSTNAME argument from the cli and set it to the
   * provided variable. */
  *hostname = argv[optind];
}

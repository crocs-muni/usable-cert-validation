#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"

#include "client.h"

int main(int argc, char **argv) {
  /* Final return value */
  int ret = EXIT_SUCCESS;

  /* List of possible arguments to parse */
  struct tls_options opts = {
      .crl_file = {0},
      .host = {0},
      .port = {0},
      .trust_anchor = {0},
  };

  /* Socket (file descriptor) wrapper */
  mbedtls_net_context server_fd;

  /* Entropy (randomness source) context */
  mbedtls_entropy_context entropy;

  /* Context for random number generation */
  mbedtls_ctr_drbg_context drbg;

  /* TLS context */
  mbedtls_ssl_context ssl;

  /* Configuration to use within TLS */
  mbedtls_ssl_config conf;

  /* Structure to load the trusted root cert into */
  mbedtls_x509_crt cacert;

  /* Structure to load the CRL into */
  mbedtls_x509_crl crl;

  /* Parse the command line options */
  if (parse_opts(argc, argv, &opts) != PARSING_SUCCESS) {
    CUSTOM_FAIL("Parsing command line arguments failed.");
  }

  /* Initialize all variables */
  mbedtls_net_init(&server_fd);
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&drbg);
  mbedtls_ssl_init(&ssl);
  mbedtls_ssl_config_init(&conf);
  mbedtls_x509_crt_init(&cacert);
  mbedtls_x509_crl_init(&crl);

  /* Seed the random number generator */
  MBEDTLS_CHECK(
      mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy, NULL, 0));

  /* Initiate the underlying TCP/IP connection */
  MBEDTLS_CHECK(mbedtls_net_connect(&server_fd, opts.host, opts.port,
                                    MBEDTLS_NET_PROTO_TCP));

  /* Set defaults for the TLS configuration */
  MBEDTLS_CHECK(mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                            MBEDTLS_SSL_TRANSPORT_STREAM,
                                            MBEDTLS_SSL_PRESET_DEFAULT));

  /* Assign the random number generator to the TLS config */
  mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &drbg);

  /* Accept only TLS 1.2 or higher */
  mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3,
                               MBEDTLS_SSL_MINOR_VERSION_3);

  /* Set server verify optional, normally we would use VERIFY_REQUIRED */
  mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);

  /* Load the trusted root, normally we would use "/etc/ssl/certs" */
  MBEDTLS_CHECK(mbedtls_x509_crt_parse_file(&cacert, opts.trust_anchor));

  /* If `crl_file` is present, load CRL too, and assign both to the config */
  if (strlen(opts.crl_file) != 0) {
    MBEDTLS_CHECK(mbedtls_x509_crl_parse_file(&crl, opts.crl_file));
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, &crl);
  } else {
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
  }

  /* Assign TLS config to the TLS context */
  MBEDTLS_CHECK(mbedtls_ssl_setup(&ssl, &conf));

  /* Set the SNI TLS extension (to enable "virtual hosting") */
  MBEDTLS_CHECK(mbedtls_ssl_set_hostname(&ssl, opts.host));

  /* Set the IO functions to use in the underlying connection */
  mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv,
                      NULL);

  /* Explicitly preform the handshake */
  int r = mbedtls_ssl_handshake(&ssl);
  if (r != 0) {
    MBEDTLS_FAIL(r);
  }

  /* Manually check the result of certificate verification */
  uint32_t res = mbedtls_ssl_get_verify_result(&ssl);

  /* Print the result of certificate verification as string */
  char message_buffer[2048];
  mbedtls_x509_crt_verify_info(message_buffer, 2048, "", res);
  fprintf(stderr, "%s", message_buffer);

  /* Gracefully close the connection, don't check for errors anymore */
  mbedtls_ssl_close_notify(&ssl);

/* Clean up all used resources and structures and exit */
cleanup:
  mbedtls_ssl_free(&ssl);
  mbedtls_x509_crt_free(&cacert);
  mbedtls_x509_crl_free(&crl);
  mbedtls_ssl_config_free(&conf);
  mbedtls_net_free(&server_fd);
  mbedtls_ctr_drbg_free(&drbg);
  mbedtls_entropy_free(&entropy);
  return ret;
}

int parse_opts(int argc, char **argv, struct tls_options *opts) {
  int c;
  while (1) {
    static struct option long_options[] = {
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

    switch (c) {
    case 'c':
      strncpy(opts->crl_file, optarg, PATH_BUFFER_LENGTH);
      break;
    case 'h':
      strncpy(opts->host, optarg, HOST_BUFFER_LENGTH);
      break;
    case 'p':
      strncpy(opts->port, optarg, PORT_BUFFER_LENGTH);
      break;
    case 't':
      strncpy(opts->trust_anchor, optarg, PATH_BUFFER_LENGTH);
      break;
    default:
      return PARSING_ERROR;
    }
  }

  return PARSING_SUCCESS;
}
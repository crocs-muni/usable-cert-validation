#ifndef CLIENT_H
#define CLIENT_H

#include <openssl/x509_vfy.h>
#include <stdbool.h>

/* Buffer lengths for command line arguments */
#define HOST_BUFFER_LENGTH 256
#define PORT_BUFFER_LENGTH 16
#define PATH_BUFFER_LENGTH 4096
#define EMAIL_BUFFER_LENGTH 256
#define POLICY_BUFFER_LENGTH 256
#define IP_BUFFER_LENGTH 32
#define PURPOSE_BUFFER_LENGTH 32
#define TRUST_BUFFER_LENGTH 32

#define PARSING_SUCCESS 0
#define PARSING_ERROR 1

/* Macros for dealing with OpenSSL errors*/
#define OPENSSL_FAIL()                                                         \
  do {                                                                         \
    ret = EXIT_FAILURE;                                                        \
    ERR_print_errors_fp(stderr);                                               \
    goto cleanup;                                                              \
  } while (0)

#define OPENSSL_CHECK(x)                                                       \
  if ((x) != 1) {                                                              \
    OPENSSL_FAIL();                                                            \
  }

/* Macro for dealing with application errors */
#define CUSTOM_FAIL(error)                                                     \
  do {                                                                         \
    ret = EXIT_FAILURE;                                                        \
    fprintf(stderr, "Application error: %s\n", error);                         \
    goto cleanup;                                                              \
  } while (0)

/* Return the OpenSSL ID for the given purpose string */
int get_purpose_id(const char *purpose);

/* Return the OpenSSL ID for the given trust string */
int get_trust_id(const char *trust);

/* Function to establish a TCP/IP connection, returns a socket descriptor */
int tcp_connect(const char *host, const char *port);

/* Possible command line arguments */
struct tls_options {
  /* Check revocation */
  bool check_crl;
  /* Check OCSP online */
  bool check_ocsp;
  /* Check stapled OCSP */
  bool check_ocsp_staple;
  /* Check certificate transparency */
  bool check_ct;
  /* Strict rules for certificate syntax */
  bool strict;
  /* Allow proxy certificates */
  bool allow_proxy;
  /* Check policies in the certificates */
  bool check_policies;
  /* Require explicit policy */
  bool explicit_policy;
  /* Inhibit the anyPolicy extension */
  bool inhibit_any_policy;
  /* Inhibit the policyMappings extension */
  bool inhibit_mapping;
  /* Enable the usage of deltas (Freshest CRL)*/
  bool use_deltas;
  /* Hostname to connect to */
  char host[HOST_BUFFER_LENGTH];
  /* Port to connect to */
  char port[PORT_BUFFER_LENGTH];
  /* Path to a trusted root CA */
  char trust_anchor[PATH_BUFFER_LENGTH];
  /* Max length of the certificate chain*/
  int max_depth;
  /* Email of the host to check */
  char email[EMAIL_BUFFER_LENGTH];
  /* IP of the host to check */
  char ip[IP_BUFFER_LENGTH];
  /* Required policy */
  char policy[POLICY_BUFFER_LENGTH];
  /* Required purpose */
  char purpose[PURPOSE_BUFFER_LENGTH];
  /* Required trust of the root CA */
  char trust[TRUST_BUFFER_LENGTH];
};

/* Function to parse the command line arguments */
int parse_opts(int argc, char **argv, struct tls_options *opts);

/* Set verification options */
int set_verify_params(X509_VERIFY_PARAM *vpm, struct tls_options *opts);

#endif
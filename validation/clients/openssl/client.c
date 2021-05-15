#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include "client.h"

int main(int argc, char **argv) {
  /* Final return value of the program */
  int ret = EXIT_SUCCESS;

  /* Default values of the command line arguments */
  struct tls_options opts = {.check_crl = false,
                             .check_ocsp = false,
                             .check_ocsp_staple = false,
                             .check_ct = false,
                             .strict = false,
                             .allow_proxy = false,
                             .check_policies = false,
                             .explicit_policy = false,
                             .inhibit_any_policy = false,
                             .inhibit_mapping = false,
                             .use_deltas = false,
                             .purpose = {0},
                             .policy = {0},
                             .host = {0},
                             .port = {0},
                             .trust_anchor = {0},
                             .max_depth = -1,
                             .ip = {0},
                             .email = {0},
                             .trust = {0}};

  /* TLS context structure */
  SSL_CTX *ctx = NULL;

  /* TLS connection structure */
  SSL *ssl = NULL;

  /* Socket descriptor to use in the underlying TCP/IP connection */
  int sockfd = -1;

  /* Parse command line arguments */
  if (parse_opts(argc, argv, &opts) != PARSING_SUCCESS) {
    CUSTOM_FAIL("Parsing command line arguments failed.");
  }

  /* Initialize the TLS context with a flexible negotiation method */
  ctx = SSL_CTX_new(TLS_client_method());
  if (ctx == NULL) {
    OPENSSL_FAIL();
  }

  /* Require at least TLS 1.2 */
  OPENSSL_CHECK(SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION));

  /* Enable certificate verification with a default callback */
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

  /* Retrieve the verification parameters for modification */
  X509_VERIFY_PARAM *vpm = SSL_CTX_get0_param(ctx);

  /* Set parameters according to command line options */
  int param_ret = set_verify_params(vpm, &opts);
  if (param_ret == 1) {
    OPENSSL_FAIL();
  }
  if (param_ret == -1) {
    CUSTOM_FAIL("Setting verification flags failed.");
  }

  /* TODO: specify security parameters here (ciphers, ...) */

  /* Set the trust anchor for certificate validation */
  OPENSSL_CHECK(SSL_CTX_load_verify_locations(ctx, opts.trust_anchor, NULL));
  /* NOTE: Normally we would use SSL_CTX_set_default_verify_paths() */

  /* Initialize the TLS connection structure */
  ssl = SSL_new(ctx);
  if (ssl == NULL) {
    OPENSSL_FAIL();
  }

  /* Establish the underlying TCP/IP connection */
  sockfd = tcp_connect((const char *)&(opts.host), (const char *)&(opts.port));
  if (sockfd == -1) {
    CUSTOM_FAIL("Could not establish TCP/IP connection to server.");
  }

  /* Bind the socket descriptor to the TLS connection structure */
  OPENSSL_CHECK(SSL_set_fd(ssl, sockfd));

  /* Set the SNI TLS extension to enable "virtual hosting" */
  OPENSSL_CHECK(SSL_set_tlsext_host_name(ssl, opts.host));

  /* Set hostname for verification */
  OPENSSL_CHECK(SSL_set1_host(ssl, opts.host));

  /* Perform the TLS handshake but don't fail immediately */
  int r = SSL_connect(ssl);

  /* Print the result of certificate verification */
  int verifyResult = SSL_get_verify_result(ssl);
  const char *message = X509_verify_cert_error_string(verifyResult);
  fprintf(stderr, "%s", message);

  /* Fail when the handshake failed but verification was OK */
  if (verifyResult == X509_V_OK && r != 1) {
    OPENSSL_FAIL();
  }

  /* Alert the server that we are closing connection */
  SSL_shutdown(ssl);

/* Clean up all resources and exit */
cleanup:
  if (ssl != NULL) {
    SSL_free(ssl);
  }
  if (ctx != NULL) {
    SSL_CTX_free(ctx);
  }
  if (sockfd >= 0) {
    close(sockfd);
  }
  return ret;
}

int tcp_connect(const char *host, const char *port) {
  /* TCP/IP socket descriptor */
  int sockfd = -1;

  /* Hints that we send to server with our preferences */
  struct addrinfo hints = {0};

  /* We allow both IPv4 and IPv6 */
  hints.ai_family = AF_UNSPEC;
  /* We want a stream socket, not a datagram one */
  hints.ai_socktype = SOCK_STREAM;
  /* We know the numeric port number beforehand */
  hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV;
  /* We want to use TCP */
  hints.ai_protocol = IPPROTO_TCP;

  struct addrinfo *result = NULL;

  /* Try to get the server addrinfo list */
  if (getaddrinfo(host, port, &hints, &result) != 0 || result == NULL) {
    return -1;
  }

  /* Try each address from the server list until successful */
  struct addrinfo *rr;
  for (rr = result; rr != NULL; rr = rr->ai_next) {
    sockfd = socket(rr->ai_family, rr->ai_socktype, rr->ai_protocol);
    if (sockfd == -1)
      continue;
    if (connect(sockfd, rr->ai_addr, rr->ai_addrlen) != -1)
      break;
    close(sockfd);
  }

  /* We don't need the server info anymore */
  freeaddrinfo(result);

  /* Fail if we didn't manage to connect to any server address */
  if (rr == NULL) {
    return -1;
  }

  return sockfd;
}

int get_purpose_id(const char *purpose) {
  if (strcmp(purpose, "SSL_CLIENT")) {
    return 1;
  }
  if (strcmp(purpose, "SSL_SERVER")) {
    return 2;
  }
  if (strcmp(purpose, "ANY")) {
    return 7;
  }
  if (strcmp(purpose, "CRL_SIGN")) {
    return 6;
  }
  return -1;
}

int get_trust_id(const char *trust) {
  if (strcmp(trust, "SSL_CLIENT")) {
    return 2;
  }
  if (strcmp(trust, "SSL_SERVER")) {
    return 3;
  }
  return -1;
}

int parse_opts(int argc, char **argv, struct tls_options *opts) {
  int c;
  while (1) {
    static struct option long_options[] = {
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
        {NULL, 0, NULL, 0}};

    c = getopt_long(argc, argv, "", long_options, NULL);
    if (c == -1) {
      break;
    }

    switch (c) {
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
      strncpy(opts->host, optarg, HOST_BUFFER_LENGTH);
      break;
    case 'p':
      strncpy(opts->port, optarg, PORT_BUFFER_LENGTH);
      break;
    case 't':
      strncpy(opts->trust_anchor, optarg, PATH_BUFFER_LENGTH);
      break;
    case 'd':
      opts->max_depth = atoi(optarg);
      break;
    case 'e':
      strncpy(opts->email, optarg, EMAIL_BUFFER_LENGTH);
      break;
    case 'i':
      strncpy(opts->ip, optarg, IP_BUFFER_LENGTH);
      break;
    case 'j':
      strncpy(opts->purpose, optarg, PURPOSE_BUFFER_LENGTH);
      break;
    case 'l':
      strncpy(opts->policy, optarg, POLICY_BUFFER_LENGTH);
      break;
    case 'w':
      strncpy(opts->trust, optarg, TRUST_BUFFER_LENGTH);
      break;
    default:
      return PARSING_ERROR;
    }
  }

  return PARSING_SUCCESS;
}

int set_verify_params(X509_VERIFY_PARAM *vpm, struct tls_options *opts) {
  if (opts->max_depth != -1) {
    X509_VERIFY_PARAM_set_depth(vpm, opts->max_depth);
  }

  if (strlen(opts->purpose) != 0) {
    int purpose_id = get_purpose_id(opts->purpose);
    if (purpose_id == -1) {
      return -1;
    }
    if (X509_VERIFY_PARAM_set_purpose(vpm, purpose_id) != 1) {
      return 1;
    };
  }

  if (strlen(opts->trust) != 0) {
    int trust_id = get_trust_id(opts->trust);
    if (trust_id == -1) {
      return -1;
    }
    if (X509_VERIFY_PARAM_set_trust(vpm, trust_id) != 1) {
      return 1;
    }
  }

  if (strlen(opts->email) != 0) {
    if (X509_VERIFY_PARAM_set1_email(vpm, opts->email, strlen(opts->email)) !=
        1) {
      return 1;
    }
  }

  if (strlen(opts->ip) != 0) {
    if (X509_VERIFY_PARAM_set1_ip_asc(vpm, opts->ip) != 1) {
      return 1;
    }
  }

  if (strlen(opts->policy) != 0) {
    STACK_OF(ASN1_OBJECT) *policies = sk_ASN1_OBJECT_new_null();
    if (policies == NULL) {
      return -1;
    }
    ASN1_OBJECT *policy = OBJ_txt2obj(opts->policy, 1);
    if (sk_ASN1_OBJECT_push(policies, policy) != 1) {
      return 1;
    }
    if (X509_VERIFY_PARAM_set1_policies(vpm, policies) != 1) {
      return 1;
    }
  }

  unsigned long flags = X509_VERIFY_PARAM_get_flags(vpm);

  if (opts->strict) {
    flags |= X509_V_FLAG_X509_STRICT;
  }

  if (opts->check_crl) {
    flags |= X509_V_FLAG_CRL_CHECK;
  }

  if (opts->allow_proxy) {
    flags |= X509_V_FLAG_ALLOW_PROXY_CERTS;
  }

  if (opts->check_policies) {
    flags |= X509_V_FLAG_POLICY_CHECK;
  }

  if (opts->explicit_policy) {
    flags |= X509_V_FLAG_EXPLICIT_POLICY;
  }

  if (opts->inhibit_any_policy) {
    flags |= X509_V_FLAG_INHIBIT_ANY;
  }

  if (opts->inhibit_mapping) {
    flags |= X509_V_FLAG_INHIBIT_MAP;
  }

  if (opts->use_deltas) {
    flags |= X509_V_FLAG_USE_DELTAS;
  }

  if (X509_VERIFY_PARAM_set_flags(vpm, flags) != 1) {
    return 1;
  }

  return 0;
}
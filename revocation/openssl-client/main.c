
#include <curl/curl.h>
#include <err.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/ocsp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "crl_revoc.h"
#include "ct_check.h"
#include "ocsp_revoc.h"
#include "ocsp_stapling_revoc.h"
#include "utils.h"

void unsecure_print_connection_info(struct addrinfo *act_node) {
  int ret_status;
  char hostname_domain[NI_MAXHOST];
  char hostname_adress[NI_MAXHOST];
  char service_text[NI_MAXSERV];
  char service_numeric[NI_MAXSERV];

  if ((ret_status =
           getnameinfo(act_node->ai_addr, act_node->ai_addrlen, hostname_domain,
                       NI_MAXHOST, service_text, NI_MAXSERV, 0)) != 0) {
    fprintf(stderr, "Function 'getnameinfo' has failed: %s\n",
            gai_strerror(ret_status));
    exit(EXIT_FAILURE);
  }

  if ((ret_status = getnameinfo(act_node->ai_addr, act_node->ai_addrlen,
                                hostname_adress, NI_MAXHOST, service_numeric,
                                NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV)) !=
      0) {
    fprintf(stderr, "Function 'getnameinfo' has failed: %s\n",
            gai_strerror(ret_status));
    exit(EXIT_FAILURE);
  }

  printf("\n");
  printf("Host's network adress: \n");
  printf("network adress: %s, %s\n", hostname_domain, hostname_adress);
  printf("service: %s, %s\n", service_text, service_numeric);
}

int unsecure_connect_to_server(char *hostname) {
  int ret_status;
  int client_fd;

  struct addrinfo hints = {0};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_CANONNAME;

  struct addrinfo *adresses;

  if ((ret_status = getaddrinfo(hostname, "https", &hints, &adresses)) != 0) {
    fprintf(stderr, "Function 'getaddrinfo' has failed: %s\n",
            gai_strerror(ret_status));
    exit(EXIT_FAILURE);
  }

  printf("Canonical name of the host: %s\n", adresses->ai_canonname);

  struct addrinfo *act_node;
  for (act_node = adresses; act_node != NULL; act_node = act_node->ai_next) {
    unsecure_print_connection_info(act_node);
    printf("Establishing TCP connection ... ");

    client_fd = socket(act_node->ai_family, act_node->ai_socktype,
                       act_node->ai_protocol);
    if (client_fd == -1) {
      printf(" [NOK] \n");
      fprintf(stderr, "Function 'socket' has failed!\n");
      continue;
    }

    if (connect(client_fd, act_node->ai_addr, act_node->ai_addrlen) != 0) {
      printf(" [NOK] \n");
      fprintf(stderr, "Function 'connect' has failed!\n");
      close(client_fd);
      continue;
    }

    printf(" [OK] \n");
    break;
  }

  freeaddrinfo(adresses);

  if (act_node == NULL) {
    printf(" [NOK] \n");
    fprintf(stderr,
            "A transport layer connection could not be established for the "
            "specified hostname on htpps!");
    exit(EXIT_FAILURE);
  }

  return client_fd;
}

int custom_callback(SSL *s_connection, void *arg) {
  printf("\n*** In Custom Callback ***\n");

  print_x509_certificate_chain_info(s_connection);

  int crl_status = crl_check(s_connection);

  int ocsp_status = ocsp_check(s_connection);

  int ocsp_stapling_status = ocsp_stapling_check(s_connection);

  ct_check(s_connection);

  printf("\n*** Custom callback finished ***\n");

  if (crl_status != REVOC_CHECK_SUCCESS || ocsp_status != REVOC_CHECK_SUCCESS ||
      ocsp_stapling_status != REVOC_CHECK_SUCCESS) {
    /* Revocation check failed, terminate the TLS handshake with returning
     * negative value from this callback function. */
    fprintf(stderr, "- custom callback has failed!\n");
    return -1;
  }

  /* Return value 0 would mean 'Response is not acceptable and handshake will
   * fail'. */

  return 1;
}

SSL_CTX *prepare_SSL_context(char *hostname, int client_fd) {
  SSL_CTX *context = NULL;

  /* Create the context. We will use the version-flexible TLS method to
  *negotiate.
  ** This means that we prefer the highest supported version, but agree with
  *downgrading. */
  context = SSL_CTX_new(TLS_client_method());
  if (context == NULL) {
    fprintf(stderr, "Function 'SSL_CTX_new' has failed!\n");
    goto cleanup;
  }

  /* However, we won't let the server downgrade to less than TLS v1.2, since
   * older TLS versions are deprecated. */
  if (SSL_CTX_set_min_proto_version(context, TLS1_2_VERSION) != 1) {
    fprintf(stderr, "Function 'SSL_CTX_set_min_proto_version' has failed!\n");
    goto cleanup;
  }

  /* We need to set the option to validate the peer certificate chain.
  ** If we skipped this step, an active attacker could impersonate the server.
 */
  SSL_CTX_set_verify(context, SSL_VERIFY_PEER, NULL);

  /* In certificate validation, we usually want to trust the system default
   * certificate authorities. */
  /* Other options: SSL_CTX_set_default_verify_dir() and
   * SSL_CTX_set_default_verify_file() */
  /* Other option: SSL_CTX_load_verify_locations(SSL_CTX, char *file, char *dir)
   */
  if (SSL_CTX_set_default_verify_paths(context) != 1) {
    fprintf(stderr,
            "Function 'SSL_CTX_set_default_verify_paths' has failed!\n");
    goto cleanup;
  }

  // - - - - - - - - - - - - - - - - - - - - - - - - -
  /* OPTIONAL: Enable OCSP-Stapling! */
  // - - - - - - - - - - - - - - - - - - - - - - - - -
  if (SSL_CTX_set_tlsext_status_type(context, TLSEXT_STATUSTYPE_ocsp) != 1) {
    fprintf(stderr, "Function 'SSL_CTX_set_tlsext_status_type' has failed!\n");
    goto cleanup;
  }

  // - - - - - - - - - - - - - - - - - - - - - - - - -
  /* OPTIONAL: Enable CT LOG (SCT) */
  // - - - - - - - - - - - - - - - - - - - - - - - - -
  /* Enables OCSP stapling as well because SCTs could be delivered through OCSP
   * Stapling, TLS Extensions or X509 Extensions. */
  /* Flag SSL_CT_VALIDATIOn_PERMISSIVE - handshake result is not affected by the
   * validation status of any SCT. */
  /* Flag SSL_CT_VALIDATIOn_STRICT - if verification mode was previously set to
   * SSL_VERIFY_PEER and the peer presents no valid SCT, then the handshake will
   * be aborted with X509_V_ERR_NO_VALID_SCTS error code. */
  if (SSL_CTX_enable_ct(context, SSL_CT_VALIDATION_PERMISSIVE) != 1) {
    fprintf(stderr, "Function 'SSL_enable_ct' has failed!\n");
    goto cleanup;
  }

  // - - - - - - - - - - - - - - - - - - - - - - - - -
  /* OPTIONAL: Set custom verification callback */
  // - - - - - - - - - - - - - - - - - - - - - - - - -
  /* Function callback called during the TLS handshake after the certificate
   * chain has been verified. */
  /* Mainly designed for checking the result of stapled OCSP Response. */
  int (*callback)(SSL *, void *) = &custom_callback;
  SSL_CTX_set_tlsext_status_cb(context, callback);

  // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  /* OPTIONAL: Custom certificate validation settings */
  // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

  /* Put additional constraing on certificate validation during the TLS
   * handshake */
  /* Putting additional constraints == modifying default X509_VERIFY_PARAM
   * structure! */

  /* Retrieve the verification parameters for modification. */
  X509_VERIFY_PARAM *verify_param_struct = SSL_CTX_get0_param(context);
  if (verify_param_struct == NULL) {
    fprintf(stderr, "Function 'SSL_CTX_get0_param' has failed!\n");
    goto cleanup;
  }

  /* Retrieve certificate validation flags from verify param structure/ */
  unsigned long verify_param_flags =
      X509_VERIFY_PARAM_get_flags(verify_param_struct);

  /* Modify (adding constraings by ORing them) the actual verification and after
   * modification, save them back. */
  /* Enable the strict certificate validation flag.
  ** Certificates with e.g. duplicate extensions, will now be rejected. */
  verify_param_flags |= X509_V_FLAG_X509_STRICT;

  /* Put the modified validation flags back into the params structure. */
  if (X509_VERIFY_PARAM_set_flags(verify_param_struct, verify_param_flags) !=
      1) {
    fprintf(stderr, "Function 'X509_VERIFY_PARAM_set_flags' has failed!\n");
    goto cleanup;
  }

  /* Manipulate the X509_VERIFY_PARAM structure directly with the functions
   * provided by OpenSSL */

  /* Server certificate will have to contain provided hostname in its Subject
   * Alternative name (SAN) or Subject CommonName (CN). */
  /* If hostname in the second argument is specified, hostname is checked during
   * certificate validation with X509_check_host function! */
  if (X509_VERIFY_PARAM_set1_host(verify_param_struct, hostname, 0) != 1) {
    fprintf(stderr, "Function 'X509_VERIFY_PARAM_set1_host' has failed!\n");
    goto cleanup;
  }

  /* Save the modified verify param structure back to the CTX context structure.
   */
  if (SSL_CTX_set1_param(context, verify_param_struct) != 1) {
    fprintf(stderr, "Function 'SSL_CTX_set1_param' has failed!\n");
    goto cleanup;
  }

  return context;

cleanup:
  if (context != NULL) {
    SSL_CTX_free(context);
  }
  close(client_fd);
  exit(EXIT_FAILURE);
}

SSL *secure_connect(SSL_CTX *context, int client_fd, char *hostname) {
  SSL *s_connection = NULL;

  /* Initialize a TLS connection structure. */
  /* Initialized connection structure inherits settings from the context
   * structure! */
  s_connection = SSL_new(context);
  if (s_connection == NULL) {
    fprintf(stderr, "Function 'SSL_new' has failed!\n");
    goto cleanup;
  }

  /* Bind the secure connection with the unsecure connected file descriptor */
  /* It will automatically create a BIO socket for SSL s_connection (from
   * client_fd unsecured descriptor). */
  if (SSL_set_fd(s_connection, client_fd) != 1) {
    fprintf(stderr, "Function 'SSL_set_fd' has failed!\n");
    goto cleanup;
  }

  /* Set the Server Name Indication TLS extension to specify the name of the
   * server. */
  /* This is required when multiple servers are running at the same IP address
   * (virtual hosting). */
  if (SSL_set_tlsext_host_name(s_connection, hostname) != 1) {
    fprintf(stderr, "Function 'set_tlsext_host_name' has failed!\n");
    goto cleanup;
  }

  /* Set hostname for verification. */
  /* Not setting the hostname would mean that we would accept a certificate of
   * any trusted server. */
  /* Other options: SSL_add1_host(connection, hostname) */
  if (SSL_set1_host(s_connection, hostname) != 1) {
    fprintf(stderr, "Function 'SSL_set1_host' has failed!\n");
    goto cleanup;
  }

  /* Connect to the server, this performs the TLS handshake. */
  /* During this procedure, the peer certificate is validated + hostname check.
   */

  printf("\nEstablishing the TLS connection ... ");

  /* Function returns <0 (fatal error occured), 0 (error from TLS/SSL protocol),
   * 1 (success). */
  // If <0 or 0 - not succesfull - we can call SSL_get_error() which returns int
  // as error code macro
  if (SSL_connect(s_connection) == 1) {
    printf(" [OK] \n");
    printf("Secure connected with %s encryption!\n",
           SSL_get_cipher_name(s_connection));
  } else {
    printf(" [NOK] \n");
    fprintf(stderr, "SSL_connect has failed!\n");
    ERR_print_errors_fp(stderr);

    /* Dont terminate the program yet, look at the verification result of the
     * certificate chain! */

    /* Retrieve the error code of the error that occured during certificate
     * validation. */
    int verifyResult = SSL_get_verify_result(s_connection);
    /* Convert the error code to a human-readable string. */
    const char *message = X509_verify_cert_error_string(verifyResult);
    /* Print the string to the standard error output. */
    fprintf(stderr, "%s\n", message);

    /* Now, terminate the program, since the connection is not secure. */
    goto cleanup;
  }

  return s_connection;

cleanup:
  if (s_connection != NULL) {
    SSL_free(s_connection);
  }
  if (context != NULL) {
    SSL_CTX_free(context);
  }
  close(client_fd);
  exit(EXIT_FAILURE);
}

void close_connection(int client_fd, SSL_CTX *context, SSL *s_connection) {
  printf("\nClosing connection ... ");

  /* To finish the connection properly, we send a "close notify" alert to the
   * server. */
  /* In most cases, we have to wait for the same message from the server, and
   * perform the call again. */
  int ret_value = SSL_shutdown(s_connection);
  if (ret_value < 0) {
    printf(" [NOK] \n");
    fprintf(stderr, "- SSL_shutdown with fatal error!\n");
    goto cleanup;
  }

  if (ret_value == 0) {
    if (SSL_shutdown(s_connection) != 1) {
      printf(" [NOK2] \n");
      goto cleanup;
    }
  }

  /* ret_value == 1 */
  printf(" [OK] \n");

  /* Free the TLS connection structure */
  SSL_free(s_connection);

  /* Free the TLS context structure */
  SSL_CTX_free(context);

  /* Close the underlying socket descriptor */
  close(client_fd);

  return;

cleanup:
  SSL_free(s_connection);
  SSL_CTX_free(context);
  close(client_fd);
  exit(EXIT_FAILURE);
}

int main(int argc, char **argv) {
  if (argc != 2) {
    printf("\nUsage: openssl_client [hostname]\n\n");
    exit(EXIT_FAILURE);
  }

  char *hostname = argv[1];

  printf("Received hostname from the command line: %s\n", hostname);

  int client_fd = unsecure_connect_to_server(hostname);

  SSL_CTX *context = prepare_SSL_context(hostname, client_fd);

  SSL *s_connection = secure_connect(context, client_fd, hostname);

  close_connection(client_fd, context, s_connection);
  return EXIT_SUCCESS;
}

#include <err.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <netdb.h>
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

/*
 * GNUTLS_E_* - macros for error codes, returned value of gnutls_* functions
 * (e.g GNUTLS_E_SUCCESS = 0 )
 *
 * gnutls_certificate_type_t -- GNUTLS_CRT_* (e.g GNUTLS_CRT_X509 )
 * gnutls_certificate_verify_flags -- GNUTLS_VERIFY_* (e.g
 * GNUTLS_VERIFY_DISABLE_CA_SIGN ) (4.1.1.8) gnutls_certificate_status_t --
 * GNUTLS_CERT_* (e.g GNUTLS_CERT_INVALID ) (4.1.1.7)
 *
 * gnutls_x509_crt_fmt_t -- GNUTLS_X509_FMT_DER or GNUTLS_X509_FMT_PEM
 * gnutls_certificate_print_formats_t -- GNUTLS_CRT_PRINT_* (e.g
 * GNUTLS_CRT_PRINT_FULL )
 *
 * gnutls_trust_list_flags_t -- GNUTLS_TR_* (e.g GNUTLS_TL_VERIFY_CRL )
 *
 * gnutls_x509_crl_reason_flags_t -- GNUTLS_CRL_REASON_* (e.g
 * GNUTLS_CRL_REASON_UNSPECIFIED )
 *
 * gnutls_ocsp_verify_reason_t -- GNUTLS_OCSP_VERIFY_* - verifying the ocsp
 * response of signer
 */

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

    printf(" [OK] \n\n");
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

/**
 * @brief revocation_check_callback
 * A callback function that checks the revocation status for all certificates in
 * the certificate chain. This function is configured before the TLS handshake,
 * so that it takes place during the TLS handshake, immediately after the
 * certification chain is verified. The GnuTLS library does not perform
 * revocation checks by default (excluding OCSP-Stapling) (only with leaf
 * server's certificate).
 * @param session
 * @return 0 if handshake should continue, non-zero if handshake should be
 * terminated
 */
int revocation_check_callback(gnutls_session_t session) {
  int ct_check_result;
  int crl_check_result;
  int ocsp_check_result;
  int ocsp_stapling_check_result;
  char *hostname;
  gnutls_certificate_type_t cert_type;
  /* ORed flags of enum gnutls_certificate_status_t (0 if trusted, non-zero if
   * problem) */
  unsigned int certificate_verification_status;
  gnutls_datum_t certificate_verification_status_pretty = {0};

  printf(
      "\nPerforming certificate verification during TLS handshake calback "
      "... ");

  /* Retrieve the hostname from the user pointer from the session, set
   * previously */
  hostname = gnutls_session_get_ptr(session);

  /* Verify the peer's certificate and the hostname */
  if (gnutls_certificate_verify_peers3(session, hostname,
                                       &certificate_verification_status) !=
      GNUTLS_E_SUCCESS) {
    errx(EXIT_FAILURE,
         "Function 'gnutls_certificate_verify_peers3' has failed during "
         "callback\n");
  }

  if ((cert_type = gnutls_certificate_type_get(session)) != GNUTLS_CRT_X509) {
    fprintf(stderr, "Certificate type used is not X509\n");
    exit(EXIT_FAILURE);
  }

  if ((gnutls_certificate_verification_status_print(
          certificate_verification_status, cert_type,
          &certificate_verification_status_pretty, 0)) != GNUTLS_E_SUCCESS) {
    errx(
        EXIT_FAILURE,
        "Function 'gnutls_certificate_verification_status_print has failed\n'");
  }

  if (certificate_verification_status == 0) {
    printf(" [OK] \n");
  } else {
    printf(" [NOK] \n");
  }
  printf("- %s\n", certificate_verification_status_pretty.data);

  gnutls_free(certificate_verification_status_pretty.data);

  if (certificate_verification_status != 0) {
    return GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR;
  }

  /* After performing certificate verification check, perform revocation check
   */

  /* Uncomment in order to print defails about every certificate from the chain
   */
  if (!print_certificate_chain_info(session)) {
    return GNUTLS_E_CERTIFICATE_ERROR;
  }

  /* Perform Certificate Transparency (SCT) check */
  ct_check_result = ct_check(session);

  /* Perform CRL revocation check (with usage of trusted list) */
  crl_check_result = crl_revoc_check(session);

  /* Perform OCSP revocation check */
  ocsp_check_result = ocsp_revoc_check(session);

  /* Perform OCSP-Stapling revocation check */
  ocsp_stapling_check_result = ocsp_stapling_check(session);

  if (!ct_check_result || !crl_check_result || !ocsp_check_result ||
      !ocsp_stapling_check_result) {
    return GNUTLS_E_CERTIFICATE_ERROR;
  }

  /* notify gnutls to continue handshake normally */
  return 0;
}

gnutls_session_t make_secure_connection(
    int client_fd, int *handshake_result,
    gnutls_certificate_credentials_t *credentials, char *hostname) {
  int ret_val;
  gnutls_certificate_credentials_t creds = {0};
  gnutls_session_t session = {0};

  /* Initialize the credentials structure. */
  if ((ret_val = gnutls_certificate_allocate_credentials(&creds)) < 0) {
    fprintf(
        stderr,
        "Function 'gnutls_certificate_allocate_credentials' has failed: %s\n",
        gnutls_strerror(ret_val));
    goto cleanup;
  }

  /* Add the system's default trusted CAs certificates (as trust anchors) in
   * order to verify the server's certificate. */
  /* Other options are: 'gnutls_certificate_set_x509_trust_dir',
   * 'gnutls_certificate_set_x509_trust_file'. */
  if ((ret_val = gnutls_certificate_set_x509_system_trust(creds)) < 0) {
    fprintf(
        stderr,
        "Function 'gnutls_certificate_set_x509_system_trust' has failed: %s\n",
        gnutls_strerror(ret_val));
    goto cleanup;
  }

  /* Uncomment in order to perform offline CRL check of server/client
   * certificates during the TLS handshake. */
  /* Requires the CRL list file to be stored locally. */
  //    if ((ret_val = gnutls_certificate_set_x509_crl_file(creds,
  //    "test_data/badssl_revoked_CRL.crl", GNUTLS_X509_FMT_DER)) <= 0)
  //    {
  //        fprintf(stderr, "Function 'gnutls_certificate_set_x509_crl_file' has
  //        failed: %s\n", gnutls_strerror(ret_val)); goto cleanup;
  //    }

  /* Initialize the TLS session context. */
  if ((ret_val = gnutls_init(&session, GNUTLS_CLIENT)) < 0) {
    fprintf(stderr, "Function 'gnutls_init' has failed: %s\n",
            gnutls_strerror(ret_val));
    goto cleanup;
  }

  /* Set the hostname to the session structure, so it can be available during
   * verification callback during TLS handshake */
  gnutls_session_set_ptr(session, (void *)hostname);

  /* Set default cipher suite priorities. These are the recommended option. */
  if ((ret_val = gnutls_set_default_priority(session)) < 0) {
    fprintf(stderr, "Function 'gnutls_set_default_priority' has failed: %s\n",
            gnutls_strerror(ret_val));
    goto cleanup;
  }

  /* Verify the server's certificate with the provided hostname during the TLS
   * handshake. */
  /* Not setting the verification of hostname would mean that we would accept a
   * certificate of any trusted server. */
  gnutls_session_set_verify_cert(session, hostname, 0);

  /* Set the Server Name Indication TLS extension to specify the name of the
   * server. */
  /* This is required when multiple servers are running at the same IP address
   * (virtual hosting). */
  if ((ret_val = gnutls_server_name_set(session, GNUTLS_NAME_DNS, hostname,
                                        strlen(hostname))) < 0) {
    fprintf(stderr, "Function 'gnutls_server_name_set' has failed: %s\n",
            gnutls_strerror(ret_val));
    goto cleanup;
  }

  /* Enable OCSP-Stapling, using 'status_request' TLS extension */
  /* If no OCSP staple is found, certificate verification during handshake will
   * fail */
  if ((ret_val = gnutls_ocsp_status_request_enable_client(session, NULL, 0,
                                                          NULL)) != 0) {
    fprintf(stderr, "Failed to enable OCSP-Stapling through TLS extension!");
    fprintf(
        stderr,
        "Function 'gnutls_ocsp_status_request_enable_client' has failed: %s\n",
        gnutls_strerror(ret_val));
    goto cleanup;
  }

  /* Associate the credentials structure with the session structure. */
  if ((ret_val = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE,
                                        creds)) < 0) {
    fprintf(stderr, "Function 'gnutls_credentials_set' has failed: %s\n",
            gnutls_strerror(ret_val));
    goto cleanup;
  }

  /* Bind the open unsecure socket to the TLS session. */
  gnutls_transport_set_int(session, client_fd);

  /* Set default timeout for the handshake. */
  gnutls_handshake_set_timeout(session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

  //    /* Set custom verification function, which will run immidiately after
  //    certificate chain has been received */
  int (*revocation_callback)(gnutls_session_t) = &revocation_check_callback;
  gnutls_session_set_verify_function(session, revocation_callback);

  /* Try to perform TLS handshake until successful (this is the standard way).
   */
  /* returned value ==0 - successful handshake (GNUTLS_E_SUCCESS is equal to 0)
   * returned value <0 - error occured, which could be classified as fatal or
   * non-fatal
   *   - non-fatal error - try to connect again
   *   - fatal error - session has to be terminated
   */
  int ret_handshake;
  printf("Establishing TLS connection ... \n");

  do {
    ret_handshake = gnutls_handshake(session);
  } while (ret_handshake < 0 && gnutls_error_is_fatal(ret_handshake) == 0);

  if (ret_handshake == GNUTLS_E_SUCCESS) {
    printf("\n[OK] - TLS connection was established successfully\n");
    // check_result_of_cert_validation(session);

    char *session_description = gnutls_session_get_desc(session);
    printf("'Current TLS session using': %s\n", session_description);
    gnutls_free(session_description);
  }

  if (ret_handshake < 0) {
    printf("\n[NOK] - failed to establish TLS connection\n");
    fprintf(stderr, "Fatal error occured during TLS handshake\n");
    /* Examine the returned code from function (GNUTLS_E_* code) */
    fprintf(stderr, "%s\n", gnutls_strerror(ret_handshake));
    /* Examine the gnutls_certificate_status_t enum, set up by verification
     * function (during handshake) */
    // check_result_of_cert_validation(session);
    printf("\n");
  }

  *handshake_result = ret_handshake;
  *credentials = creds;
  return session;

cleanup:
  if (creds != NULL) {
    gnutls_certificate_free_credentials(creds);
  }
  if (session != NULL) {
    gnutls_deinit(session);
  }
  exit(EXIT_FAILURE);
}

void close_connection(int client_fd, gnutls_session_t session,
                      gnutls_certificate_credentials_t creds) {
  printf("\nTerminating the TLS connection ... ");

  /* Send the "close notify" message to the server, alerting it that we are
   * closing the connection. */
  int bye_return = gnutls_bye(session, GNUTLS_SHUT_RDWR);

  if (bye_return != GNUTLS_E_SUCCESS) {
    printf(" [NOK] \n");
    fprintf(stderr, "Function 'gnutls_bye' has failed: %s\n",
            gnutls_strerror(bye_return));
  } else {
    printf(" [OK] \n");
  }

  /* Free the credentials structure! */
  gnutls_certificate_free_credentials(creds);

  /* Free the session structure! */
  gnutls_deinit(session);

  /* Close the underlying TCP unsecure socket! */
  printf("Closing underlying TCP socket ... ");
  if ((close(client_fd)) == 0) {
    printf(" [OK] \n");
  } else {
    printf(" [NOK] \n");
  }

  exit(EXIT_SUCCESS);
}

int main(int argc, char **argv) {
  if (argc != 2) {
    printf("Usage: gnutls_client [hostname]\n\n");
    exit(EXIT_FAILURE);
  }

  char *hostname = argv[1];

  printf("Received hostname from the command line: %s\n", hostname);

  int client_fd = unsecure_connect_to_server(hostname);

  int handshake_result;
  gnutls_certificate_credentials_t creds;
  gnutls_session_t session =
      make_secure_connection(client_fd, &handshake_result, &creds, hostname);

  // revocation_check_callback(session);

  close_connection(client_fd, session, creds);
}

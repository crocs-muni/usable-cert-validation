#include "ocsp_stapling_revoc.h"

#include <err.h>
#include <gnutls/gnutls.h>
#include <gnutls/ocsp.h>
#include <stdio.h>
#include <stdlib.h>

#include "ocsp_revoc.h"
#include "utils.h"

int verify_single_stapled_ocsp_response(gnutls_datum_t ocsp_response_datum) {
  int ret_err_val;
  int status = REVOC_CHECK_SUCCESS;

  /* Convert the stapled OCSP Response from gnutls_datum_t structure into
   * gnutls_ocsp_resp_t structure. */
  gnutls_ocsp_resp_t ocsp_response;
  if ((ret_err_val = gnutls_ocsp_resp_init(&ocsp_response)) !=
      GNUTLS_E_SUCCESS) {
    fprintf(stderr, "Function 'gnutls_ocsp_resp_init' has failed: %s\n",
            gnutls_strerror(ret_err_val));
    return REVOC_CHECK_INTERNAL_ERROR;
  }
  if ((ret_err_val = gnutls_ocsp_resp_import(
           ocsp_response, &ocsp_response_datum)) != GNUTLS_E_SUCCESS) {
    fprintf(stderr, "Function 'gnutls_ocsp_resp_import' has failed: %s\n",
            gnutls_strerror(ret_err_val));
    gnutls_ocsp_resp_deinit(ocsp_response);
    return REVOC_CHECK_INTERNAL_ERROR;
  }

  /* Now, we have a single OCSP Response. */
  print_ocsp_response_info(ocsp_response);

  /* TODO Signature verification! */

  /* Get the OCSP Revocation result for this response. */
  if ((status = ocsp_revocation_result(ocsp_response)) != REVOC_CHECK_SUCCESS) {
    gnutls_ocsp_resp_deinit(ocsp_response);
    return status;
  }

  /* Deinitialize. */
  gnutls_ocsp_resp_deinit(ocsp_response);
  return status;
}

int ocsp_stapling_check(gnutls_session_t session) {
  int status = REVOC_CHECK_SUCCESS;

  printf("\n--- Performing OCSP-Stapling verification! ---\n");

  /* Obtain information whether a valid stapled OCSP Response was included in
   * the TLS handshake. */
  /* Should be called after verification of the certificate chain. */
  if (gnutls_ocsp_status_request_is_checked(session, 0) != 0) {
    printf("- valid stapled OCSP response was included in the TLS handshake\n");
  } else {
    /* Invalid OCSP status == old, superseded or revoked. */
    fprintf(stderr, "- no valid stapled OCSP response found\n");
    return REVOC_CHECK_SUCCESS;
  }

  /* In case, TLS server sends revocation status for more than one certificate
   * (TLS server's certificate) in stapled OCSP Response. */
  gnutls_datum_t ocsp_response_datum = {0};
  unsigned int index = 0;
  int ret_val = 0;
  while (1) {
    ret_val =
        gnutls_ocsp_status_request_get2(session, index, &ocsp_response_datum);
    if (ret_val == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
      break;
    } else if (ret_val == GNUTLS_E_SUCCESS) {
      printf("\nVerifying the certificate at index %d\n", index);
      if ((status = verify_single_stapled_ocsp_response(ocsp_response_datum)) !=
          REVOC_CHECK_SUCCESS) {
        return status;
      }
      index++;
    } else {
      fprintf(stderr, "- error occured\n");
      exit(EXIT_FAILURE);
    }
  }

  return status;
}

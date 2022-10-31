#include <stdlib.h>
#include <stdio.h>
#include <err.h>

#include <gnutls/gnutls.h>
#include <gnutls/ocsp.h>

#include "ocsp_stapling_revoc.h"
#include "ocsp_revoc.h"
#include "utils.h"


bool verify_single_stapled_ocsp_response(gnutls_datum_t ocsp_response_datum)
{
    int ret_err_val;

    /* Convert the stapled OCSP Response from gnutls_datum_t structure into gnutls_ocsp_resp_t structure */
    gnutls_ocsp_resp_t ocsp_response;
    if ((ret_err_val = gnutls_ocsp_resp_init(&ocsp_response)) != GNUTLS_E_SUCCESS) {
        fprintf(stderr, "Function 'gnutls_ocsp_resp_init' has failed: %s\n", gnutls_strerror(ret_err_val));
        exit(EXIT_FAILURE);
    }
    if ((ret_err_val = gnutls_ocsp_resp_import(ocsp_response, &ocsp_response_datum)) != GNUTLS_E_SUCCESS) {
        fprintf(stderr, "Function 'gnutls_ocsp_resp_import' has failed: %s\n", gnutls_strerror(ret_err_val));
        gnutls_ocsp_resp_deinit(ocsp_response);
        exit(EXIT_FAILURE);
    }

    /* Now, we have a single OCSP Response */
    print_ocsp_response_info(ocsp_response);

    /* Signature verification */

    /* Get the OCSP Revocation result for this response */
    if (!ocsp_revocation_result(ocsp_response)) {
        gnutls_ocsp_resp_deinit(ocsp_response);
        return false;
    }

    /* Deinitialize */
    gnutls_ocsp_resp_deinit(ocsp_response);
    return true;
}


bool ocsp_stapling_check(gnutls_session_t session)
{
    printf("\n--- Performing OCSP-Stapling verification! ---\n");

    /* Obtain information whether a valid stapled OCSP Response was included inthe TLS handshake */
    /* Should be called after verification of the certificate chain */
    if (gnutls_ocsp_status_request_is_checked(session, 0) != 0)
    {
        printf("- valid stapled OCSP response was included in the TLS handshake\n");
    }
    else
    {
        /* Invalid OCSP status == old, superseded or revoked */
        fprintf(stderr, "- no valid stapled OCSP response found\n");
        return true;
    }

    /* Retrieve the stapled OCSP Response in DER format for each certificate from chain */
    gnutls_datum_t ocsp_response_datum = { 0 };
    unsigned int index = 0;
    int ret_val = 0;
    while (1) {
     ret_val = gnutls_ocsp_status_request_get2(session, index, &ocsp_response_datum);
     if (ret_val == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
         break;
     }
     else if (ret_val == GNUTLS_E_SUCCESS) {
         printf("\nVerifying the certificate at index %d\n", index);
         verify_single_stapled_ocsp_response(ocsp_response_datum);
         printf("\n");
         index++;
     }
     else {
        fprintf(stderr, "- error occured\n");
        exit(EXIT_FAILURE);
     }
    }

    return true;
}


#include <stdio.h>
#include <err.h>

#include <openssl/ssl.h>
#include <openssl/ocsp.h>

#include "ocsp_revoc.h"
#include "ocsp_stapling_revoc.h"
#include "utils.h"

int ocsp_stapling_check(SSL *s_connection) {
    int status = REVOC_CHECK_SUCCESS;
    OCSP_BASICRESP *stapled_ocsp_response_basic = NULL;

    printf("\n*** Performing OCSP-Stapling check! ***\n");

    if (SSL_get_tlsext_status_type(s_connection) == -1) {
        fprintf(stderr, "- client does not previously requested the OCSP-stapling!\n");
        return REVOC_CHECK_SUCCESS;
    }

    /* Retrieve the stapled OCSP response, after or during the TLS handshake. */
    char *ocsp_response_stapled_DER;
    long ocsp_response_stapled_size = SSL_get_tlsext_status_ocsp_resp(s_connection, &ocsp_response_stapled_DER);
    if (ocsp_response_stapled_size == -1) {
        fprintf(stderr, "- server did not send the stapled OCSP Response!\n");
        return REVOC_CHECK_SUCCESS;
    }

    /* Convert the retrieved stapled OCSP Response to the OpenSSL native structure. */
    OCSP_RESPONSE *stapled_ocsp_response = d2i_OCSP_RESPONSE(NULL, (const unsigned char **) &ocsp_response_stapled_DER, ocsp_response_stapled_size);
    if (stapled_ocsp_response == NULL) {
        fprintf(stderr, "Function 'd2i_OCSP_RESPONSE' has failed!\n");
        return REVOC_CHECK_INTERNAL_ERROR;
    }

    /* Save the retrieved stapled OCSP response to the file, possible to examine. */
    save_OCSP_response_to_file(stapled_ocsp_response, "ocsp_resp_stapled.der");

    /* Verify and parse the OCSP stapled Response! */

    /* Retrieve the server's certificate chain from the OpenSSL connection. */
    int cert_chain_stack_size;
    STACK_OF(X509) *cert_chain_stack = retrieve_server_certificate_chain(s_connection, &cert_chain_stack_size, false);
    if (cert_chain_stack == NULL) {
        status = REVOC_CHECK_FAILURE;
        goto cleanup;
    }

    /* Verify the signature of the retrieved Stapled OCSP Response. */
    status = verify_ocsp_response_signature(stapled_ocsp_response, cert_chain_stack, &stapled_ocsp_response_basic);
    if (status != REVOC_CHECK_SUCCESS) {
        goto cleanup;
    }

    /* Find out the revocation status for every certificate included in the stapled OCSP Response. */
    status = parse_revocation_check_from_basic_resp_through_single_resp(stapled_ocsp_response_basic);
    if (status != REVOC_CHECK_SUCCESS) {
        goto cleanup;
    }

    /* Deinitialize. */
    OCSP_RESPONSE_free(stapled_ocsp_response);
    OCSP_BASICRESP_free(stapled_ocsp_response_basic);

    return status;

cleanup:
    if (stapled_ocsp_response != NULL) {
        OCSP_RESPONSE_free(stapled_ocsp_response);
    }
    if (stapled_ocsp_response_basic != NULL) {
        OCSP_BASICRESP_free(stapled_ocsp_response_basic);
    }
    return status;
}

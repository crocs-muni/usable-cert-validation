
#include <stdbool.h>
#include <stdio.h>
#include <err.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/ocsp.h>

#include <curl/curl.h>

#include "ocsp_revoc.h"
#include "utils.h"

char *extract_ocsp_responder_uri(X509 *certificate, int *number_of_responders) {
    /* Retrieve all OCSP Responder's URIs in the array of type STACK_OF(TYPE). */
    /* Not documented function! */
    STACK_OF(OPENSSL_STRING) *ocsp_uris_stack = X509_get1_ocsp(certificate);

    /* Retrieve the number of all responder uris from the STACK_OF(TYPE) array. */
    int ocsp_uris_stack_size= sk_OPENSSL_STRING_num(ocsp_uris_stack);
    *number_of_responders = ocsp_uris_stack_size;

    printf("- number of OCSP Responder URIs: %d\n", ocsp_uris_stack_size);

    if (ocsp_uris_stack_size == 0) {
        fprintf(stderr, "- no OCSP Responder URL included in this certificate!\n");
        return NULL;
    }

    /* Print all the OCSP Responder URL's (in most cases, just 1). */
    for (int i = 0; i < sk_OPENSSL_STRING_num(ocsp_uris_stack); i++) {
        printf("  - OCSP Responder URL: %s\n", sk_OPENSSL_STRING_value(ocsp_uris_stack, i));
    }

    /* Retrieve the first (at index 0) OCSP Responder's uri entry from the STACK_OF(TYPE) array. */
    char *ocsp_uri = sk_OPENSSL_STRING_value(ocsp_uris_stack, 0);

    /* Deinitialize the STACK_OF() array */
    sk_OPENSSL_STRING_free(ocsp_uris_stack);

    return ocsp_uri;
}

int generate_ocsp_request(X509 *certificate, X509 *issuer_certificate, OCSP_CERTID **certid, OCSP_REQUEST **ocsp_request_in)
{
    /* Initialize new empty ocsp request structure. */
    OCSP_REQUEST *ocsp_request = OCSP_REQUEST_new();
    if (ocsp_request == NULL) {
        fprintf(stderr, "Function 'OCSP_REQUEST_new' has failed!\n");
        return REVOC_CHECK_INTERNAL_ERROR;
    }

//    /* Add certificate to the OCSP Request. */
//    if (OCSP_request_add1_cert(ocsp_request, certificate) != 1) {
//        errx(EXIT_FAILURE, "Function 'OCSP_request_add1_cert' has failed!\n");
//    }

    /* Create the new OCSP_CERTID structure with default SHA1 message digest (first argument) for given certificate and its issuer. */
    *certid = OCSP_cert_to_id(NULL, certificate, issuer_certificate);
    if (*certid == NULL)  {
        fprintf(stderr, "Function 'OCSP_cert_to_id' has failed!\n");
        OCSP_REQUEST_free(ocsp_request);
        return REVOC_CHECK_INTERNAL_ERROR;
    }

    /* Add the certificate ID (OCSP_CERTID structure) to the OCSP Request. */
    /* Structure OCSP_ONEREQ is returned so an application can add additional extensions to the request. */
    /* Another option: OCSP_request_add1_cert */
    OCSP_ONEREQ *ocsp_onereq = OCSP_request_add0_id(ocsp_request, *certid);
    if (ocsp_onereq == NULL) {
        fprintf(stderr, "Function 'OCSP_request_add0_id' has failed!\n");
        OCSP_REQUEST_free(ocsp_request);
        return REVOC_CHECK_INTERNAL_ERROR;
    }

    /* Add a random nonce value (NULL argument) as extension to the OCSP Request. */
    /* Default length of nonce, 16B, is used. */
    if (OCSP_request_add1_nonce(ocsp_request, NULL, 0) != 1) {
        fprintf(stderr, "Function 'OCSP_request_add1_nonce' has failed!\n");
        OCSP_REQUEST_free(ocsp_request);
        return REVOC_CHECK_INTERNAL_ERROR;
    }

    /* We have ocsp request filled with the server's, issuer's certificate and random nonce */
    *ocsp_request_in = ocsp_request;
    return REVOC_CHECK_SUCCESS;
}

int send_ocsp_request(OCSP_REQUEST *ocsp_request, char *ocsp_uri, OCSP_RESPONSE **ocsp_response_in)
{   
    CURL *handle = NULL;
    struct curl_slist *headers = NULL;

    /* Prepare the custom (datum_t) structure where the OCSP Response will be placed. */
    struct datum_t ocsp_response_DER = {0};

    /* Convert the previously generated OCSP Request from native OpenSSL structure to the plain DER format. */
    unsigned char *ocsp_request_DER = NULL;
    int ocsp_request_size = i2d_OCSP_REQUEST(ocsp_request, &ocsp_request_DER);
    if (ocsp_request_size < 0) {
        fprintf(stderr, "Function 'i2d_OCSP_REQUEST' has failed!\n");
        goto cleanup;
    }

    /* Prepare the cURL for making out-of-band connection. */
    curl_global_init(CURL_GLOBAL_ALL);
    handle = curl_easy_init();
    if (handle == NULL) {
        fprintf(stderr, "Function 'curl_easy_init' has failed!\n");
        goto cleanup;
    }

    /* Add ocsp header to the HTTP POST Request. */
    headers = curl_slist_append(headers, "Content-Type: application/ocsp-request");
    if (headers == NULL) {
        fprintf(stderr, "Function 'curl_slist_append' has failed!\n");
        goto cleanup;
    }

    /* Tell curl which data we want to send (in our case OCSP Request data). */
    curl_easy_setopt(handle, CURLOPT_POSTFIELDS, ocsp_request_DER);
    /* Tell curl the size of the data we want to send (size of the OCSP Request). */
    curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE, ocsp_request_size);
    /* Tell curl the URL, location where the data should be send. */
    curl_easy_setopt(handle, CURLOPT_URL, ocsp_uri);
    /* Add our custom HTTP headers. */
    curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers);
    /* Tell curl to write each chunk of data (our OCSP Response) with this function callback. */
    curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, get_data);
    /* Tell curl to write each chunk of data to the given location, in our case, to the variable in the memory. */
    curl_easy_setopt(handle, CURLOPT_WRITEDATA, &ocsp_response_DER);

    /* Send the request. */
    int ret_val = curl_easy_perform(handle);
    if (ret_val != 0) {
        fprintf(stderr, "Function 'curl_easy_perform' has failed!\n");
        goto cleanup;
    }

    /* OCSP Response has been retrieved! */

    /* Convert the retrieved OCSP Response from DER format to the native OpenSSL structure. */
    const char *ocsp_response_der_data = (const char *) ocsp_response_DER.data;
    int ocsp_response_der_size = ocsp_response_DER.size;
    OCSP_RESPONSE *ocsp_response = d2i_OCSP_RESPONSE(NULL, (const unsigned char **) &ocsp_response_der_data, ocsp_response_der_size);
    if (ocsp_response == NULL) {
        fprintf(stderr, "Function 'd2i_OCSP_RESPONSE' has failed!\n");
        goto cleanup;
    }

    /* Deinitialize no longer variables and structures */
    curl_slist_free_all(headers);
    curl_easy_cleanup(handle);
    free(ocsp_request_DER);  // unsigned char *
    free(ocsp_response_DER.data);  // struct datum_t

    free(ocsp_uri);

    *ocsp_response_in = ocsp_response;
    return REVOC_CHECK_SUCCESS;

cleanup:
    /* Always non-null. */
    free(ocsp_uri);

    if (ocsp_request_DER != NULL) {
        free(ocsp_request_DER);
    }
    if (handle != NULL) {
        curl_easy_cleanup(handle);
    }
    if (headers != NULL) {
        curl_slist_free_all(headers);
    }
    if (ocsp_response_DER.data != NULL) {
        free(ocsp_response_DER.data);
    }
    return REVOC_CHECK_INTERNAL_ERROR;
}

int verify_ocsp_response_signature(OCSP_RESPONSE *ocsp_response, STACK_OF(X509) *cert_chain_stack, OCSP_BASICRESP **ocsp_response_basic_in) {

    int status = REVOC_CHECK_SUCCESS;

    X509_STORE *store = NULL;

    /* Check the status of retrieved OCSP response, if it is not malformed or invalid for some other reason. */
    if (OCSP_response_status(ocsp_response) != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        fprintf(stderr, "- invalid status of OCSP Response!\n");
        return REVOC_CHECK_FAILURE;
    }

    /* Decode and return the OCSP_BASICRESP structure from OCSP_RESPONSE. */
    OCSP_BASICRESP *ocsp_response_basic = OCSP_response_get1_basic(ocsp_response);
    if (ocsp_response_basic == NULL) {
        fprintf(stderr, "Function 'OCSP_response_get1_basic' has failed!\n");
        status = REVOC_CHECK_INTERNAL_ERROR;
        goto cleanup;
    }

    /* Load default certificate store. */
    /* This will be required later when verifying signature of OCSP (basic) response and verifying the issuer's certificate as well. */
    store = X509_STORE_new();
    if (store == NULL) {
        fprintf(stderr, "Function 'X509_STORE_new' has failed!\n");
        status = REVOC_CHECK_INTERNAL_ERROR;
        goto cleanup;
    }
    if (X509_STORE_set_default_paths(store) != 1) {
        fprintf(stderr, "Function 'X509_STORE_set_default_paths' has failed!\n");
        status = REVOC_CHECK_INTERNAL_ERROR;
        goto cleanup;
    }

    /* Verify the signature of basic OCSP Response with validation of issuer's certificate. */
    /* If we want to just verify the signature of OCSP response and we dont want to validate the server's certificate, use flag OCSP_TRUSTOTHER and the X509_STORE wont be needed. */
    if (OCSP_basic_verify(ocsp_response_basic, cert_chain_stack, store, 0) != 1) {
        fprintf(stderr, "- verification of OCSP (basic) Response has failed!\n");
        status = REVOC_CHECK_FAILURE;
        goto cleanup;
    }

    /* Deinitialize */
    X509_STORE_free(store);

    *ocsp_response_basic_in = ocsp_response_basic;
    return status;

cleanup:
    if (ocsp_response_basic != NULL) {
        OCSP_BASICRESP_free(ocsp_response_basic);
    }
    if (store != NULL) {
        X509_STORE_free(store);
    }
    return status;
}

int parse_revocation_check_from_basic_resp_through_single_resp(OCSP_BASICRESP *ocsp_response_basic) {
    // - - - - - - - - - - - - - - - - - - - - - - - -
    /* ALTERNATIVE */
    // - - - - - - - - - - - - - - - - - - - - - - - -
    int status = REVOC_CHECK_SUCCESS;

    /* Retrieve the revocation status of the certificates included in the OCSP Basic response. */
    /* Revocation reason and time will be filled only if revocation_status == V_OCSP_CERTSTATUS_REVOKED. */
    int revocation_status;
    int revocation_reason;
    ASN1_GENERALIZEDTIME *rev_time;
    ASN1_GENERALIZEDTIME *thisupd;
    ASN1_GENERALIZEDTIME *nextupd;

    int number_of_single_responses = OCSP_resp_count(ocsp_response_basic);
    printf("- number of single responses in OCSP basic response: %d\n", number_of_single_responses);

    OCSP_SINGLERESP *one_response;
    for (int index = 0; index < number_of_single_responses; index ++) {
        printf("\nVerifying OCSP_SINGLERESP at index: %d ... ", index);

        one_response = OCSP_resp_get0(ocsp_response_basic, index);
        if (one_response == NULL) {
            fprintf(stderr, "Function 'OCSP_resp_get0' has failed!\n");
            return REVOC_CHECK_INTERNAL_ERROR;
        }

        /* Retrieve the revocation status, revocation_reason, revocation time and other info */
        /* Similar to functionOCSP_resp_find(), but this one operates on OCSP_SINGLERESP structure. */
        int rev_status = OCSP_single_get0_status(one_response, &revocation_reason, &rev_time, &thisupd, &nextupd);
        if (rev_status == V_OCSP_CERTSTATUS_GOOD) {
            printf("[OK]\n");
        }
        else if (rev_status == V_OCSP_CERTSTATUS_REVOKED) {
            printf("[NOK]\n");
            return REVOC_CHECK_FAILURE;
        }
        else if (rev_status == V_OCSP_CERTSTATUS_UNKNOWN) {
            printf("[UNKNOWN]\n");
        }
        else {
            /* Should not happen. */
            printf("[ERROR]\n");
            return REVOC_CHECK_INTERNAL_ERROR;
        }
    }

    return status;
}

int ocsp_response_verify_and_check(OCSP_RESPONSE *ocsp_response, OCSP_CERTID *certid, OCSP_REQUEST *ocsp_request, STACK_OF(X509) *cert_chain_stack) {
    int status = REVOC_CHECK_SUCCESS;

    OCSP_BASICRESP *ocsp_response_basic;
    status = verify_ocsp_response_signature(ocsp_response, cert_chain_stack, &ocsp_response_basic);
    if (status != REVOC_CHECK_SUCCESS) {
        return status;
    }

    /* Compare and check the nonces in OCSP Response (basic) and OCSP Request */
    int nonce_check_result = OCSP_check_nonce(ocsp_request, ocsp_response_basic);
    if (nonce_check_result == 1) {
        printf("- OK: nonce is present in both the request and the response, and they are equal!\n");
    }
    else if (nonce_check_result == 0) {
        fprintf(stderr, "- WARNING: nonce is present in both the request and the response, but they are not equal!\n");
    }
    else if (nonce_check_result == -1) {
        fprintf(stderr, "- WARNING: nonce is present only in the ocsp request, not in the ocsp response!\n");
    }
    else if (nonce_check_result == 2) {
        fprintf(stderr, "- WARNING: nonce is missing in both, the request and the response\n");
    }
    else if (nonce_check_result == 3) {
        fprintf(stderr, "- WARNING: nonce is present only in the ocsp response, not in the ocsp request!\n");
    }

    /* Get the revocation status of the provided certificate, represented with OCSP_CERTID (with issuer's certificate). */
    /* Revocation reason and time will be filled only if revocation_status == V_OCSP_CERTSTATUS_REVOKED. */
    int revocation_status;
    int revocation_reason;
    ASN1_GENERALIZEDTIME *rev_time;
    ASN1_GENERALIZEDTIME *thisupd;
    ASN1_GENERALIZEDTIME *nextupd;
    if (OCSP_resp_find_status(ocsp_response_basic, certid, &revocation_status, &revocation_reason, &rev_time, &thisupd, &nextupd) != 1) {
        fprintf(stderr, "- id of the provided certificate was not found in basic OCSP Response!\n");
        status = REVOC_CHECK_FAILURE;
        goto cleanup;
    }

    printf("- revocation status: ");
    if (revocation_status == V_OCSP_CERTSTATUS_GOOD) {
        printf("[OK] \n");
    }
    else if (revocation_status == V_OCSP_CERTSTATUS_REVOKED) {
        printf("[REVOKED]\n");
        status = REVOC_CHECK_FAILURE;
    }
    else if (revocation_status == V_OCSP_CERTSTATUS_UNKNOWN) {
        printf("[UNKNOWN]\n");
    }
    else {
        /* Should not happen. */
        printf("[ERROR]\n");
        status = REVOC_CHECK_INTERNAL_ERROR;
    }

    /* Check the validity of this update and next update fields retrieved from basic OCSP Response. */
    if (OCSP_check_validity(thisupd, nextupd, 0, -1) != 1) {
        fprintf(stderr, "- validity check of OCSP response has failed!\n");
        status = REVOC_CHECK_FAILURE;
    }

    /* Deinitialize */
    OCSP_REQUEST_free(ocsp_request);
    OCSP_RESPONSE_free(ocsp_response);
    OCSP_BASICRESP_free(ocsp_response_basic);

    return status;

cleanup:
    /* Always non-null. */
    OCSP_REQUEST_free(ocsp_request);

    if (ocsp_response != NULL) {
        OCSP_RESPONSE_free(ocsp_response);
    }
    if (ocsp_response_basic != NULL) {
        OCSP_BASICRESP_free(ocsp_response_basic);
    }
    return status;
}

int ocsp_check_single_certificate(X509 *certificate, X509 *issuer_certificate, STACK_OF(X509) *cert_chain_stack) {
    int ret;

    /* 1.) Extract and obtain the URL of the OCSP Responder for this certificate */
    int number_of_responders;
    char *ocsp_uri = extract_ocsp_responder_uri(certificate, &number_of_responders);
    if (ocsp_uri == NULL && number_of_responders == 0) {
        /* No responder found. */
        return REVOC_CHECK_SUCCESS;
    }

    /* 2.) Generate the OCSP Request. */
    OCSP_CERTID *certid;
    OCSP_REQUEST *ocsp_request = NULL;
    if ((ret = generate_ocsp_request(certificate, issuer_certificate, &certid, &ocsp_request)) != REVOC_CHECK_SUCCESS) {
        return ret;
    }

    /* Save the generated OCSP Request to the file. */
    /* The file can be inspected with command 'openssl ocsp -reqin ocsp_req.der -text' */
    save_OCSP_request_to_file(ocsp_request, "ocsp_req.der");

    /* 3.) Send the generated OCSP Request to the obtained OCSP Responder URL and immediately retrieve the OCSP Response. */
    OCSP_RESPONSE *ocsp_response;
    if ((ret = send_ocsp_request(ocsp_request, ocsp_uri, &ocsp_response)) != REVOC_CHECK_SUCCESS) {
        return ret;
    }

    /* Save the retrieved OCSP Response to the file. */
    /* The file can be inspected with command 'openssl ocsp -respin ocsp_resp.der -text -noverify' */
    save_OCSP_response_to_file(ocsp_response, "ocsp_resp.der");

    /* 4.) Verify the signature of the OCSP Response and check the revocation status of provided certificate. */
    if ((ret = ocsp_response_verify_and_check(ocsp_response, certid, ocsp_request, cert_chain_stack)) != REVOC_CHECK_SUCCESS) {
        return ret;
    }

    return REVOC_CHECK_SUCCESS;
}

int ocsp_check(SSL *s_connection)
{
    printf("\n*** Performing Online Certificate Status Protocol (OCSP) check! ***\n");

    /* Retrieve the server's certificate chain from the OpenSSL connection. */
    int cert_chain_stack_size;
    STACK_OF(X509) *cert_chain_stack = retrieve_server_certificate_chain(s_connection, &cert_chain_stack_size, false);
    if (cert_chain_stack == NULL) {
        return REVOC_CHECK_INTERNAL_ERROR;
    }

    if (cert_chain_stack_size < 2) {
        fprintf(stderr, "- certificate chain is smaller than 2\n");
        return REVOC_CHECK_INTERNAL_ERROR;
    }

    X509 *certificate;
    X509 *issuer_certificate;
    for (int index = 0; index < cert_chain_stack_size - 1; index++) {
        printf("\nCertificate at index %d\n", index);
        certificate = sk_X509_value(cert_chain_stack, index);
        issuer_certificate = sk_X509_value(cert_chain_stack, index+1);
        ocsp_check_single_certificate(certificate, issuer_certificate, cert_chain_stack);
    }

    return REVOC_CHECK_SUCCESS;
}

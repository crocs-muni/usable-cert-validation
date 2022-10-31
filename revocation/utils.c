#include <stdlib.h>
#include <stdio.h>
#include <err.h>
#include <limits.h>
#include <string.h>
#include <stdbool.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/ocsp.h>

#include "utils.h"

/**
 * @brief get_data
 * Callback function supplied to curl during its configuration (CURLOPT_WRITEFUNCTION). Curl calls this function whenever
 * it receives a new piece of a data to save. The data transfer does never takes place all at once, but gradually in parts.
 * @param buffer - pointer pointing to the new chunk of delivered data (not null terminated!)
 * @param size - a value that is equal to 1 each time this function is invoked
 * @param nmemb - the size of the new chunk of delivered data, pointing by the first argument
 * @param userp - old, already processed data from previous transfers
 * @return the number of bytes that were processed successfully
 */
size_t get_data(void *buffer, size_t size, size_t nmemb, void *userp)
{
    /* Already processed data from previous transfers */
    gnutls_datum_t *ud = (gnutls_datum_t *) userp;

    /* nmemb bytes of new data */
    size *= nmemb;

    /* Reallocate the buffer containing the previous data so that it can also accommodate nmemb of new data */
    ud->data = realloc(ud->data, ud->size + size);
    if (ud->data == NULL)
    {
        errx(EXIT_FAILURE, "Function 'realloc' has failed");
    }

    /* Append nmemb new bytes to the previous data */
    memcpy(&ud->data[ud->size], buffer, size);
    ud->size += size;

    return size;
}

/**
 * @brief check_result_of_cert_validation
 *  A function whose task is to examine the result, the status (either successful or unsuccessful) of
 *  the certificate verification after the TLS handshake.
 * @param session
 */
void check_result_of_cert_validation(gnutls_session_t session)
{
    /* Retrieve the certificate type used during negotiation within TLS handshake. */
    /* By default, expecting GNUTLS_CRT_X509 enum value (equals 1). */
    gnutls_certificate_type_t cert_type = gnutls_certificate_type_get(session);

    /* Retrieve the certificate validation status. */
    unsigned cert_verify_status = gnutls_session_get_verify_cert_status(session);

    /* Prepare a buffer for the error message, fill it, and print the message to the standard error output. */
    gnutls_datum_t datum = {0};
    gnutls_certificate_verification_status_print(cert_verify_status, cert_type, &datum, 0);
    fprintf(stderr, "%s\n", datum.data);
    gnutls_free(datum.data);
}

gnutls_x509_crt_t *retrieve_server_certificate_chain(gnutls_session_t session, size_t *chain_size)
{
    int ret_val;

    /* Receive the entire chain of certificates stored in an array where each certificate
     * is in DER format and stored in the gnutls_datum_t structure.
     * The server's certificate is at index 0, its issuer's certificate is at index 1, etc
    */
    unsigned int server_chain_size = 0;
    const gnutls_datum_t *server_chain_der = gnutls_certificate_get_peers(session, &server_chain_size);
    if (server_chain_der == NULL)
    {
        fprintf(stderr, "Function 'gnutls_certificate_get_peers' has failed");
        return NULL;
    }

    /* Convert certificate array in gnutls_datum_t structure to certificate array in gnutls_crt_t structure */
    gnutls_x509_crt_t *server_chain_crt = gnutls_calloc(server_chain_size, sizeof(gnutls_x509_crt_t));
    if (server_chain_crt == NULL)
    {
        fprintf(stderr, "Function 'gnutls_calloc' has failed");
        return NULL;
    }

    for (int i=0; i < server_chain_size; i++)
    {
        gnutls_x509_crt_init(&server_chain_crt[i]);
        if ((ret_val = gnutls_x509_crt_import(server_chain_crt[i], &server_chain_der[i], GNUTLS_X509_FMT_DER)) != GNUTLS_E_SUCCESS)
        {
            fprintf(stderr, "Function 'gnutls_x509_crt_import' at index %d has failed: %s\n", i, gnutls_strerror(ret_val));
            for (int index = 0; index < i; index ++) {
                gnutls_x509_crt_deinit(server_chain_crt[index]);
                gnutls_free(server_chain_crt);
            }
            return NULL;
        }
    }

    *chain_size = server_chain_size;
    return server_chain_crt;
}

void deinitialize_certificate_chain(gnutls_x509_crt_t *certificate_chain, size_t chain_size)
{
    for (int i = 0; i < chain_size; i++)
    {
        gnutls_x509_crt_deinit(certificate_chain[i]);
    }
    gnutls_free(certificate_chain);
}

bool print_x509_certificate_info(gnutls_x509_crt_t certificate) {
    int ret_err_code;

    /* Information about the X509 certificate will be stored in the gnutls_datum_t structure and then written to stdout. */
    gnutls_datum_t certificate_datum;
    if ((ret_err_code = gnutls_x509_crt_print(certificate, GNUTLS_CRT_PRINT_ONELINE, &certificate_datum)) != GNUTLS_E_SUCCESS)
    {
        fprintf(stderr, "Function 'gnutls_x509_crt_print' has failed: \n%s\n", gnutls_strerror(ret_err_code));
        return false;
    }
    printf("Certificate info: \n- %s\n", certificate_datum.data);
    gnutls_free(certificate_datum.data);

    /* Extract more information about the certificate */
    /* TODO: should always check the result of the function (if GNUTLS_E_SUCCESS) */
    time_t activation_time = gnutls_x509_crt_get_activation_time(certificate);
    time_t expiration_time = gnutls_x509_crt_get_expiration_time(certificate);

    char serial_number_bin[40] = { 0 };
    size_t serial_number_size = sizeof(serial_number_bin);
    gnutls_x509_crt_get_serial(certificate, serial_number_bin, &serial_number_size);

    int algorithm;
    unsigned int bits;
    algorithm = gnutls_x509_crt_get_pk_algorithm(certificate, &bits);

    int version = gnutls_x509_crt_get_version(certificate);

    char dn[256] = { 0 };
    size_t dn_size = sizeof(dn);
    gnutls_x509_crt_get_dn(certificate, dn, &dn_size);

    char issuer_dn[256] = { 0 };
    size_t issuer_dn_size = sizeof(issuer_dn);
    gnutls_x509_crt_get_issuer_dn(certificate, issuer_dn, &issuer_dn_size);

    printf("- activation time: %s", ctime(&activation_time));
    printf("- expiration time: %s", ctime(&expiration_time));
    printf("- bits: %d\n", bits);
    printf("- algorithm: %s\n", gnutls_pk_algorithm_get_name(algorithm));
    printf("- certificate version: %d\n", version);
    printf("- dn: %s\n", dn);
    printf("- issuer dn: %s\n", issuer_dn);

    return true;
}

bool print_certificate_chain_info(gnutls_session_t session)
{
    int ret_err_code;

    /* Check that the server is really using X509 certificate */
    if (gnutls_certificate_type_get(session) != GNUTLS_CRT_X509)
    {
        fprintf(stderr, "Server is not using X509 certificate!");
        return false;
    }

    printf("\nCerticate chain details: \n");

    /* Receive the entire chain of certificates stored in an array where each certificate
     * is in DER format and stored in the gnutls_datum_t structure.
     * The server's certificate is at index 0, its issuer's certificate is at index 1, etc
    */
    unsigned int cert_list_size = UINT_MAX;
    const gnutls_datum_t *datum_cert_list = gnutls_certificate_get_peers(session, &cert_list_size);
    printf("- chain size: %u\n", cert_list_size);
    if (cert_list_size < 1)
    {
        fprintf(stderr, "Certificate chain size is < 1!\n");
        return false;
    }

    gnutls_x509_crt_t certificate;
    gnutls_x509_crt_init(&certificate);
    for (int index = 0; index < cert_list_size; index ++) {
        printf("\nParsing the certificate at index: %d ... ", index);
        if ((gnutls_x509_crt_import(certificate, &datum_cert_list[index], GNUTLS_X509_FMT_DER)) == GNUTLS_E_SUCCESS) {
            printf(" [OK] \n");
            print_x509_certificate_info(certificate);
       }
    }
    gnutls_x509_crt_deinit(certificate);
    return true;
}

void print_ocsp_request_info(gnutls_ocsp_req_t ocsp_req)
{
    gnutls_datum_t ocsp_req_pretty_print = { 0 };
    if (gnutls_ocsp_req_print(ocsp_req, GNUTLS_OCSP_PRINT_FULL, &ocsp_req_pretty_print) != 0)
    {
        errx(EXIT_FAILURE, "Function 'gnutls_ocsp_req_print' has failed");
    }
    printf("- %s\n", ocsp_req_pretty_print.data);
    gnutls_free(ocsp_req_pretty_print.data);
}

void print_ocsp_response_info(gnutls_ocsp_resp_t ocsp_response)
{
    gnutls_datum_t ocsp_response_pretty_print;
    if (gnutls_ocsp_resp_print(ocsp_response, GNUTLS_OCSP_PRINT_COMPACT, &ocsp_response_pretty_print) != 0)
    {
        errx(EXIT_FAILURE, "Function 'gnutls_ocsp_resp_print' has failed");
    }
    printf("- %s\n", ocsp_response_pretty_print.data);
    gnutls_free(ocsp_response_pretty_print.data);
}


#ifndef GNUTLS_REVOC_UTILS_H
#define GNUTLS_REVOC_UTILS_H

#include <gnutls/gnutls.h>
#include <gnutls/ocsp.h>
#include <stdbool.h>

#define REVOC_CHECK_SUCCESS 0
#define REVOC_CHECK_FAILURE 1
#define REVOC_CHECK_INTERNAL_ERROR 2

void check_result_of_cert_validation(gnutls_session_t session);

gnutls_x509_crt_t *retrieve_server_certificate_chain(gnutls_session_t session,
                                                     size_t *chain_size);
void deinitialize_certificate_chain(gnutls_x509_crt_t *certificate_chain,
                                    size_t chain_size);

int print_certificate_chain_info(gnutls_session_t session);
int print_x509_certificate_info(gnutls_x509_crt_t certificate);

size_t get_data(void *buffer, size_t size, size_t nmemb, void *userp);

void print_ocsp_request_info(gnutls_ocsp_req_t ocsp_req);
void print_ocsp_response_info(gnutls_ocsp_resp_t ocsp_response);

#endif

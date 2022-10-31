#ifndef GNUTLS_REVOC_UTILS_H
#define GNUTLS_REVOC_UTILS_H

#include <stdbool.h>

#include <gnutls/gnutls.h>
#include <gnutls/ocsp.h>

void check_result_of_cert_validation(gnutls_session_t session);

gnutls_x509_crt_t *retrieve_server_certificate_chain(gnutls_session_t session, size_t *chain_size);
void deinitialize_certificate_chain(gnutls_x509_crt_t *certificate_chain, size_t chain_size);

bool print_certificate_chain_info(gnutls_session_t session);
bool print_x509_certificate_info(gnutls_x509_crt_t certificate);

size_t get_data(void *buffer, size_t size, size_t nmemb, void *userp);

void print_ocsp_request_info(gnutls_ocsp_req_t ocsp_req);
void print_ocsp_response_info(gnutls_ocsp_resp_t ocsp_response);

#endif

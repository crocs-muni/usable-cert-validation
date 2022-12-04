#ifndef OPENSSL_REVOC_UTILS_H
#define OPENSSL_REVOC_UTILS_H

#include <stdbool.h>

#include <openssl/x509.h>
#include <openssl/ocsp.h>

#define REVOC_CHECK_SUCCESS 0
#define REVOC_CHECK_FAILURE 1
#define REVOC_CHECK_INTERNAL_ERROR 2
#define REVOC_CHECK_NOT_PERFORMED 3

struct datum_t {
    unsigned char *data;
    unsigned int size;
};


void print_x509_certificate_info(X509 *certificate);
void print_x509_certificate_chain_info(SSL *s_connection);
size_t get_data(void *buffer, size_t size, size_t nmemb, void *userp);
STACK_OF(X509) *retrieve_server_certificate_chain(SSL *s_connection, int *cert_chain_stack_size, bool useVerified);
void save_OCSP_request_to_file(OCSP_REQUEST *ocsp_request, char *filename);
void save_OCSP_response_to_file(OCSP_RESPONSE *ocsp_response, char *filename);

#endif

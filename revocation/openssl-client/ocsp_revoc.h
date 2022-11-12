#ifndef OCSP_REVOC_H
#define OCSP_REVOC_H

#include <openssl/ocsp.h>
#include <openssl/ssl.h>

int ocsp_check(SSL *s_connection);
int parse_revocation_check_from_basic_resp_through_single_resp(
    OCSP_BASICRESP *ocsp_response_basic);
int verify_ocsp_response_signature(OCSP_RESPONSE *ocsp_response,
                                   STACK_OF(X509) * cert_chain_stack,
                                   OCSP_BASICRESP **ocsp_response_basic_in);

#endif

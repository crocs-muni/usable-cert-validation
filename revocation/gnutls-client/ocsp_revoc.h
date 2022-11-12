#ifndef OCSP_REVOC_H
#define OCSP_REVOC_H

#include <gnutls/gnutls.h>
#include <gnutls/ocsp.h>

int ocsp_revoc_check(gnutls_session_t session);
int verify_ocsp_response_signature(gnutls_ocsp_resp_t ocsp_response,
                                   gnutls_x509_crt_t certificate,
                                   gnutls_x509_crt_t issuer_certificate,
                                   gnutls_datum_t nonce_req);
int ocsp_revocation_result(gnutls_ocsp_resp_t ocsp_response);

#endif

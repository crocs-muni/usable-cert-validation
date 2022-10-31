#ifndef CRL_REVOC_H
#define CRL_REVOC_H

#include <gnutls/gnutls.h>
#include <stdbool.h>

bool crl_revoc_check(gnutls_session_t session);

#endif

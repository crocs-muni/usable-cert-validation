#ifndef CRL_REVOC_H
#define CRL_REVOC_H

#include <gnutls/gnutls.h>

int crl_revoc_check(gnutls_session_t session);

#endif

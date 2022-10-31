#ifndef CRL_REVOC_H
#define CRL_REVOC_H

#include <stdbool.h>

#include <gnutls/gnutls.h>

bool crl_revoc_check(gnutls_session_t session);

#endif

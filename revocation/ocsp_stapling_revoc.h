#ifndef OCSP_STAPLING_REVOC_H
#define OCSP_STAPLING_REVOC_H

#include <gnutls/gnutls.h>
#include <stdbool.h>

bool ocsp_stapling_check(gnutls_session_t session);

#endif

#ifndef CT_CHECK_H
#define CT_CHECK_H

#include <stdbool.h>

#include <gnutls/gnutls.h>

bool ct_check(gnutls_session_t session);

#endif

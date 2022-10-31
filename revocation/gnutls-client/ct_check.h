#ifndef CT_CHECK_H
#define CT_CHECK_H

#include <gnutls/gnutls.h>
#include <stdbool.h>

bool ct_check(gnutls_session_t session);

#endif

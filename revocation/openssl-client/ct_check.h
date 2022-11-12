#ifndef CT_CHECK_H
#define CT_CHECK_H

#include <openssl/ssl.h>

int ct_check(SSL *s_connection);

#endif

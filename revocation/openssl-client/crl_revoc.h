#ifndef CRL_REVOC_H
#define CRL_REVOC_H

#include <openssl/ssl.h>

int crl_check(SSL *s_connection);

#endif

#ifndef OCSP_STAPLING_REVOC_H
#define OCSP_STAPLING_REVOC_H

#include <openssl/ssl.h>

int ocsp_stapling_check(SSL *s_connection);

#endif

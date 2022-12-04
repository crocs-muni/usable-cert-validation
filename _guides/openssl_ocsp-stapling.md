---
layout:         default
title:          "OpenSSL: OCSP Stapling"
title-short:    "OCSP Stapling"
slug:           openssl-ocsp-stapling
library:        openssl
---

{% assign libraryData = site.data.libraries | where: "name", page.library | first %}
<div class="section"><div class="container" markdown="1">

{:#{{ page.slug }}}

# {{ page.title }}

{:.lead}
This guide covers the implementation of certificate revocation status checking using the Online Certificate Status Protocol (OCSP) Stapling revocation scheme.

{% include navigation-guides.html library=libraryData %}

</div></div>
<div class="section"><div class="container" markdown="1">

## Introduction

Online Certificate Status Protocol Stapling, better known as OCSP Stapling, is a modification of the OCSP protocol, where the TLS server (instead of the TLS client) contacts the OCSP responder at regular intervals to provide him with the revocation status of its certificate. After receiving the OCSP response from the OCP Responder, the TLS server stores this response for a defined fixed period during which the OCSP response is considered valid. Subsequently, when establishing a connection with the TLS client, the TLS server sends its certificate together with the stapled and cached response.

OCSP-Stapling is defined in [RFC 6066](https://www.rfc-editor.org/info/rfc6066).
OCSP-Stapling on [Wikipedia](https://en.wikipedia.org/wiki/OCSP_stapling).

**Summary of this guide:**

1. Enable OCSP-Stapling
   - This step is performed **before** the TLS handshake.
2. Verify that the stapled OCSP Response was sent together with the certificates
   - This step is performed **during** (recommended) or after the TLS handshake.
   - The `SSL_CTX_set_tlsext_status_cb` API call is used to set a custom callback, which will be called during the TLS handshake, and thus, the following steps should be performed in this custom callback.
3. Process the retrieved stapled OCSP Response
   - This includes verifying the status and signature of the stapled OCSP response and examining the revocation status of the certificates included in the OCSP response.
4. Deinitialize

</div></div>
<div class="section"><div class="container" markdown="1">

## 1. Enable OCSP-Stapling

A TLS client application can request a TLS server to send it an OCSP response (known as OCSP-Stapling) during the TLS handshake. Status request TLS extension is used.

This step must be performed before the TLS handshake is performed, during the SSL session or CTX context instance configuration. This configuration is mentioned in the introductory guide on how to initiate a secure TLS connection, which can be found [here](/guides/openssl).

```c
#include <openssl/ssl.h>

if (SSL_set_tlsext_status_type(s_connection, TLSEXT_STATUSTYPE_ocsp) != 1) {
    exit(EXIT_FAILURE);
}
```

### Relevant links

- [SSL_set_tlsext_status_type](https://www.openssl.org/docs/man1.1.1/man3/SSL_set_tlsext_status_type.html) (OpenSSL docs)

</div></div>
<div class="section"><div class="container" markdown="1">

## 2. Verify that the stapled OCSP Response was sent together with the certificates

This step should be performed during the TLS handshake. It is possible to verify it after the TLS handshake, however, it is not recommended. The OpenSSL also recommends that an additional callback function should be provided to process the returned stapled OCSP response. This callback function is set by calling the `SSL_CTX_set_tlsext_status_cb` API call and will be called during the TLS handshake after the certificate chain has been validated. More information can be found in our guide on how to initiate a secure connection [here](/guides/openssl) or in [official documentation](https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set_tlsext_status_cb.html) from OpenSSL.

```c
if (SSL_get_tlsext_status_type(s_connection) == -1) {
    /* Client was not previously set to request the stapled OCSP Response. */
    exit(EXIT_FAILURE);
}

/* Retrieve the stapled OCSP response, after or during the TLS handshake. */
char *ocsp_response_stapled_DER;
long ocsp_response_stapled_size = SSL_get_tlsext_status_ocsp_resp(s_connection, &ocsp_response_stapled_DER);
if (ocsp_response_stapled_size == -1) {
    /* Server did not sent the stapled OCSP Response. */
    exit(EXIT_FAILURE);
}
```

### Relevant links

- [SSL_get_tlsext_status_ocsp_resp](https://www.openssl.org/docs/man1.1.1/man3/SSL_get_tlsext_status_ocsp_resp.html) (OpenSSL docs)
- [SSL_get_tlsext_status_type](https://www.openssl.org/docs/manmaster/man3/SSL_get_tlsext_status_type.html) (OpenSSL docs)

</div></div>
<div class="section"><div class="container" markdown="1">

## 3. Process the retrieved stapled OCSP Response

After the stapled OCSP Response has been retrieved, validate the certificates included in this response by performing a standard OCSP revocation check. Our guide on how to perform an OCSP revocation check can be found [here](/guides/openssl-ocsp).

```c
#include <openssl/ocsp.h>

/* Convert the retrieved stapled OCSP Response to the OpenSSL native structure. */
OCSP_RESPONSE *stapled_ocsp_response = d2i_OCSP_RESPONSE(NULL, (const unsigned char **) &ocsp_response_stapled_DER, 
                                                         ocsp_response_stapled_size);
if (stapled_ocsp_response == NULL) {
    exit(EXIT_FAILURE);

    /* Process the obtained OCSP_RESPONSE structure according to the steps found in the OCSP guide. */
    /* That means verifying the status and signature of the stapled OCSP response. */
    /* In case of success, parsing the revocation status of the certificates included in this OCSP response. */
}
```

### Relevant links

- [d2i_OCSP_RESPONSE](https://www.openssl.org/docs/man1.1.1/man3/d2i_OCSP_RESPONSE.html) (OpenSSL docs)

</div></div>
<div class="section"><div class="container" markdown="1">

## 4. Deinitialize

After work, don't forget to free the structure holding the stapled OCSP response.

```c
OCSP_RESPONSE_free(stapled_ocsp_response);
```

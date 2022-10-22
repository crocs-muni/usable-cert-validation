---
layout:     default
title:      "Developer guide: OpenSSL, Revocation with OCSP-Stapling"
slug:       openssl-ocsp-stapling
---

<div class="section"><div class="container" markdown="1">

{:#{{ page.slug }}}
# {{ page.title }}

{:.lead}
This guide covers the implementation of certificate revocation status checking using the Online Certificate Status Protocol (OCSP) Stapling revocation scheme. Official documentation of OpenSSL can be found [here](https://www.openssl.org/docs/manpages.html).


</div></div>
<div class="section"><div class="container" markdown="1">


**Short description of revocation scheme:**
Online Certificate Status Protocol Stapling, better known as OCSP Stapling is a modification of the OCSP protocol, where the TLS server contacts the OCSP responder at regular intervals to provide him with the revocation status of its certificate. After receiving the OCSP response from the OCP Responder, TLS server stores this response for a defined fix period during which the OCSP response is considered valid. Subsequently, when establishing a connection with the TLS client, the TLS server sends its certificate along with stapled cached response from the OCSP responder. Thus, the TLS server contacts the OCSP responder instead of the TLS client.

OCSP-Stapling is defined in [RFC 6066](https://www.rfc-editor.org/info/rfc6066).
OCSP-Stapling on [Wikipedia](https://en.wikipedia.org/wiki/OCSP_stapling).

**Summary of this guide:**
1. Enable OCSP-Stapling
   - call API function to request OCSP response from the TLS server, must be performed **before** the TLS handshake
2. Retrieve the stapled OCSP Response
   - **after** the TLS handshake


</div></div>
<div class="section"><div class="container" markdown="1">


## 1.) Enable OCSP-Stapling

This step must be performed before the TLS Handshake. With this API function, client will request OCSP response from the server during the TLS handshake. Status request TLS extension is used.

```c
#include <openssl/ssl.h>

/* TLS client may request that a server send back an stapled OCSP Response with this call */
if (SSL_set_tlsext_status_type(s_connection, TLSEXT_STATUSTYPE_ocsp) != 1)
{
    exit(EXIT_FAILURE);
}
```

### Relevant links
* [SSL_set_tlsext_status_type](https://www.openssl.org/docs/man1.1.1/man3/SSL_set_tlsext_status_type.html) (OpenSSL docs)


</div></div>
<div class="section"><div class="container" markdown="1">


## 2.) Retrieve the stapled OCSP Response

This step must be performed after the TLS Handshake. This means that the TLS client-server communication has already been established and the server has sent its certificate along with the stapled OCSP response.

The variable `SSL *s_connection` represents an already established connection.


```c
#include <openssl/ocsp.h>

/* Get the stapled response after the TLS handshake! */
char *buffer;
long buffer_size = SSL_get_tlsext_status_ocsp_resp(s_connection, &buffer);
if (buffer == NULL && buffer_size == -1)
{
    /* Server did not send the stapled OCSP Response */
}

/* Convert the Stapled OCSP Response in DER format to the native response structure */
OCSP_RESPONSE *stapled_ocsp_response = d2i_OCSP_RESPONSE(NULL, (const unsigned char **) &buffer, buffer_size);
if (stapled_ocsp_response == NULL)
{
    exit(EXIT_FAILURE);
}
```

After this step, we should have a valid OCSP response stored in a native variable of type `OCSP_RESPONSE`. For a response processing, signature verification and revocation status parsing, see the chapter here.


### Relevant links
* [SSL_get_tlsext_status_ocsp_resp](https://www.openssl.org/docs/man1.1.1/man3/SSL_get_tlsext_status_ocsp_resp.html) (OpenSSL docs)
* [d2i_OCSP_RESPONSE](https://www.openssl.org/docs/man1.1.1/man3/d2i_OCSP_RESPONSE.html) (OpenSSL docs)
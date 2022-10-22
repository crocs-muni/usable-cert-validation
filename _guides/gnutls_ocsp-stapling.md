---
layout:     default
title:      "Developer guide: GnuTLS, Revocation with OCSP-Stapling"
slug:       gnutls-ocsp-stapling
---

<div class="section"><div class="container" markdown="1">

{:#{{ page.slug }}}
# {{ page.title }}

{:.lead}
This guide covers the implementation of certificate revocation status checking using the Online Certificate Status Protocol (OCSP) Stapling revocation scheme. Official documentation of GnuTLS dealing with this topic can be found [here](https://www.gnutls.org/manual/gnutls.html#OCSP-stapling).


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
3. Deinitialize


</div></div>
<div class="section"><div class="container" markdown="1">


## 1.) Enable OCSP-Stapling

This step must be performed before the TLS Handshake. With this API function, client will request OCSP response from the server during the TLS handshake. Status request TLS extension is used.

```c
/* Enable OCSP-Stapling, using TLS extension */
#include <gnutls/gnutls.h>

if (gnutls_ocsp_status_request_enable_client(session, NULL, 0, NULL) != 0)
{
    exit(EXIT_FAILURE);
}
```

### Relevant links

* [gnutls_ocsp_status_request_enable_client](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005focsp_005fstatus_005frequest_005fenable_005fclient) (GnuTLS docs)


</div></div>
<div class="section"><div class="container" markdown="1">


## 2.) Retrieve the stapled OCSP Response

This step must be performed after the TLS Handshake. This means that the TLS client-server communication has already been established and the server has sent its certificate along with the stapled OCSP response.

The variable `gnutls_session_t session` represents an already established connection.


```c
#include <gnutls/ocsp.h>

/* Helper function on the client side to decide whether the valid stapled OCSP Response was included in the TLS handshake! */
if (gnutls_ocsp_status_request_is_checked(session, 0) != 0)
{
    /* Valid stapled OCSP Response was included in the TLS Handshake */
}
else
{
    /* Stapled OCSP Response is invalid or was not included in the TLS Handshake */
    /* Invalid OCSP Response status == old, superseded or revoked */
    exit(EXIT_FAILURE)
}

/* Retrieve the stapled OCSP Response in DER format into a new gnutls_datum_t structure */
gnutls_datum_t ocsp_response_datum = { 0 };
if (gnutls_ocsp_status_request_get(session, &ocsp_response_datum) != 0)
{
    /* Failed to retrieve the stapled OCSP Response */
    exit(EXIT_FAILURE);
}

/* Convert the stapled OCSP Response in DER format from gnutls_datum_t structure into native gnutls_ocsp_resp_t structure */
gnutls_ocsp_resp_t ocsp_response;
if (gnutls_ocsp_resp_init(&ocsp_response) != 0)
{
    exit(EXIT_FAILURE);
}
if (gnutls_ocsp_resp_import(ocsp_response, &ocsp_response_datum) != 0)
{
    exit(EXIT_FAILURE);
}
```

After this step, we should have a valid OCSP response stored in a native variable of type `gnutls_ocsp_resp_t`. For a response printing, signature verification and revocation status parsing, see the chapter here.


### Relevant links

* [gnutls_ocsp_status_request_is_checked](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005focsp_005fstatus_005frequest_005fis_005fchecked) (GnuTLS docs)
* [gnutls_ocsp_status_request_get](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005focsp_005fstatus_005frequest_005fget) (GnuTLS docs)
* [gnutls_ocsp_resp_init](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005focsp_005fresp_005finit) (GnuTLS docs)
* [gnutls_ocsp_resp_import](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005focsp_005fresp_005fimport) (GnuTLS docs)


</div></div>
<div class="section"><div class="container" markdown="1">


## 3.) Deinitialize

After work, dont forget to deinitialize the stapled OCSP response.

```c
gnutls_ocsp_resp_deinit(ocsp_response);
```

### Relevant links

* [gnutls_ocsp_resp_deinit](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005focsp_005fresp_005fdeinit) (GnuTLS docs)
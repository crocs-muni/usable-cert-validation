---
layout:         default
title:          "GnuTLS: OCSP Stapling"
title-short:    "OCSP Stapling"
slug:           gnutls-ocsp-stapling
library:        gnutls
---

{% assign libraryData = site.data.libraries | where: "name", page.library | first %}
<div class="section"><div class="container" markdown="1">

{:#{{ page.slug }}}

# {{ page.title }}

{:.lead}
This guide covers the implementation of certificate revocation status checking using the Online Certificate Status Protocol (OCSP) Stapling revocation scheme. Official documentation of GnuTLS dealing with this topic can be found [here](https://www.gnutls.org/manual/gnutls.html#OCSP-stapling).

{% include navigation-guides.html library=libraryData %}

</div></div>
<div class="section"><div class="container" markdown="1">

## Introduction

Online Certificate Status Protocol Stapling, better known as OCSP Stapling, is a modification of the OCSP protocol, where the TLS server (instead of the TLS client) contacts the OCSP responder at regular intervals to provide him with the revocation status of its certificate. After receiving the OCSP response from the OCP Responder, the TLS server stores this response for a defined fixed period during which the OCSP response is considered valid. Subsequently, when establishing a connection with the TLS client, the TLS server sends its certificate together with the stapled and cached response.

OCSP-Stapling is defined in [RFC 6066](https://www.rfc-editor.org/info/rfc6066).
OCSP-Stapling on [Wikipedia](https://en.wikipedia.org/wiki/OCSP_stapling).

**Summary of this guide:**

1. Enable OCSP-Stapling
   - Enable OCSP stapling by calling the appropriate API call. It must be called during the session configuration and **before** the TLS handshake is performed.
   - After enabling, the TLS client should request the stapled OCSP response from the TLS server.
2. Verify that the stapled OCSP Response was sent together with the certificates
3. Retrieve the stapled OCSP Response
   - This can be done **during or after** the TLS handshake.
4. Deinitialize

</div></div>
<div class="section"><div class="container" markdown="1">

## 1. Enable OCSP-Stapling

This step must be performed before the TLS Handshake. With this API call, the client will request an OCSP response from the server during the TLS handshake. Status request TLS extension is used.

```c
/* Enable OCSP-Stapling, using TLS extension. */
#include <gnutls/gnutls.h>

/* Send the status request extension to the server during the TLS handshake. */
if (gnutls_ocsp_status_request_enable_client(session, NULL, 0, NULL) < 0) {
    exit(EXIT_FAILURE);
}
```

### Relevant links

- [gnutls_ocsp_status_request_enable_client](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005focsp_005fstatus_005frequest_005fenable_005fclient) (GnuTLS docs)

</div></div>
<div class="section"><div class="container" markdown="1">

## 2. Verify that the stapled OCSP Response was sent together with the certificates

This step can be performed after the certificate chain was received by the client. It is important to check that the stapled OCSP response was sent together with the certificate chain.

```c
#include <gnutls/ocsp.h>

/* Obtain information whether a valid stapled OCSP Response was included during the TLS handshake. */
/* Should be called after verification of the certificate chain. */
if (gnutls_ocsp_status_request_is_checked(session, 0) != 0) {
    /* Valid stapled OCSP response was included in the TLS handshake. */
}
else {
    /* None or invalid OCSP Response found. */
    exit(EXIT_FAILURE)
}
```

### Relevant links

- [gnutls_ocsp_status_request_is_checked](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005focsp_005fstatus_005frequest_005fis_005fchecked) (GnuTLS docs)

</div></div>
<div class="section"><div class="container" markdown="1">

## 3. Retrieve the stapled OCSP Responses

It is recommended to verify every stapled OCSP Response sent by the TLS server to the TLS client. In case of any invalid OCSP response, the connection should be immediately terminated.

The single OCSP Response can be verified, for example, according to our [OCSP guide](/guides/gnutls-ocsp).

```c
/* Retrieve the stapled OCSP Response in DER format for each certificate from the chain. */
gnutls_datum_t ocsp_response_datum = { 0 };

/* Convert the stapled OCSP Response from gnutls_datum_t structure into gnutls_ocsp_resp_t structure. */
gnutls_ocsp_resp_t ocsp_response;
if (gnutls_ocsp_resp_init(&ocsp_response) <0) {
    exit(EXIT_FAILURE);
}

unsigned int index = 0;
int ret;
while (1) {
    ret = gnutls_ocsp_status_request_get2(session, index, &ocsp_response_datum);

    if (ret < 0) {
        /* Error occured! */
        exit(EXIT_FAILURE);
    }

    if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
        /* No more stapled OCSP Responses. */
        break;
    }

    /* Import the stapled OCSP Response from DER format to the gnutls_ocsp_resp_t structure. */
    if (gnutls_ocsp_resp_import(ocsp_response, &ocsp_response_datum) <0) {
        exit(EXIT_FAILURE);
    }

    /* Verify this single stapled OCSP Response according to the OCSP guide we have covered. */
}
```

### Relevant links

- [gnutls_ocsp_status_request_get](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005focsp_005fstatus_005frequest_005fget) (GnuTLS docs)
- [gnutls_ocsp_resp_init](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005focsp_005fresp_005finit) (GnuTLS docs)
- [gnutls_ocsp_resp_import](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005focsp_005fresp_005fimport) (GnuTLS docs)

</div></div>
<div class="section"><div class="container" markdown="1">

## 4. Deinitialize

Deinitialize variables and structures, which are no longer required.

```c
gnutls_ocsp_resp_deinit(ocsp_response);
```

### Relevant links

- [gnutls_ocsp_resp_deinit](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005focsp_005fresp_005fdeinit) (GnuTLS docs)

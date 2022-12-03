---
layout:     default
title:      "Certificate Transparency"
slug:       gnutls-cert-transparency
library:    gnutls
---

{% assign libraryData = site.data.libraries | where: "name", page.library | first %}
<div class="section"><div class="container" markdown="1">

{:#{{ page.slug }}}

# {{ libraryData.title }}: {{ page.title }}

{:.lead}
This guide describes how to obtain a Signed Certificate Timestamp (SCT) from a certificate and its subsequent verification. The SCT serves as proof that the certificate was appended to the public log.

{% include navigation-guides.html library=libraryData %}

</div></div>
<div class="section"><div class="container" markdown="1">

## Introduction

Certificate Transparency is a project initiated by Google in 2013. The main goal of this project was to make all certificates on the Internet publicly visible and, therefore, accessible and verifiable by anyone. Publicly available log servers are used to achieve this goal. Anyone can upload their certificates to these log servers and view the certificates from there. Every certificate that wants to support Certificate Transparency must be added to one of the publicly available log servers. However, one such certificate is often added to several log servers. That is also because Google requires such a certificate to be added to multiple public log servers. After the public log is asked to add a certificate, it responds with the Signed Certificate Timestamp (SCT). This SCT serves as a promise that the certificate will be inserted into the log. If a TLS client wants to verify that the certificate has been inserted into the public log, it must verify the validity of the certificate's SCT. During the verification of the SCT, its signature and timestamp are verified. The signature is verified against the log's public key that signed the SCT. The timestamp is then verified against the current time to prevent the SCT from being issued in the future.

Certificate Transparency is defined in [RFC 6962](https://www.rfc-editor.org/info/rfc6962).
Certificate Transparency on [Wikipedia](https://en.wikipedia.org/wiki/Certificate_Transparency).

**Summary of this guide:**

1. Retrieve the server's certificate chain with its size
   - From the certificate chain, we can parse any certificate we want to verify with its issuer’s certificate.
2. Verify each certificate in the certificate chain
3. Retrieve the list of Signed Certificate Timestamps (SCTs) from the certificate
   - We will extract the SCTs from the certificate's extension, which is identified by the appropriate OID.
4. Verify each SCT from the SCT list
   - For each SCT from the list, its signature, signature algorithm, timestamp and ID of the public log are extracted.
   - The signature is verified against the public key of the public log when we know the id of this log and the signature algorithm which was used.
5. Deinitialize

The only prerequisite for this guide is that the `gnutls_session_t session` variable has already been initialized. This session variable represents the current TLS session, which could have already been established, or the session is currently in the TLS handshake phase. For more information, see our [guide](/guides/gnutls) on how to initiate a secure TLS connection.

</div></div>
<div class="section"><div class="container" markdown="1">

## 1. Retrieve the TLS server's certificate chain with its size

First, we need to obtain the certificate chain from the TLS connection.

```c
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

/* Retrieve the entire chain of certificates stored in array of gnutls_datum_t structures. */
/* Each certificate is stored in DER format. */
/* Leaf node certificate is placed at index 0, its issuer at index 1, etc. */
unsigned int server_chain_size = 0;
const gnutls_datum_t *server_chain_der = gnutls_certificate_get_peers(session, &server_chain_size);
if (server_chain_der == NULL) {
    exit(EXIT_FAILURE);
}

/* Convert the certificate array of gnutls_datum_t structures to certificate array of gnutls_crt_t structures. */
gnutls_x509_crt_t *server_chain_crt = gnutls_calloc(server_chain_size, sizeof(gnutls_x509_crt_t));
if (server_chain_crt == NULL) {
    exit(EXIT_FAILURE);
}

for (int i=0; i < server_chain_size; i++) {
    if (gnutls_x509_crt_init(&server_chain_crt[i]) < 0) {
        exit(EXIT_FAILURE);
    }
    if (gnutls_x509_crt_import(server_chain_crt[i], &server_chain_der[i], GNUTLS_X509_FMT_DER) < 0) {
        exit(EXIT_FAILURE);
    }
}
```

### Relevant links

- [gnutls_certificate_get_peers](https://gnutls.org/manual/gnutls.html#gnutls_005fcertificate_005fget_005fpeers) (GnuTLS docs)
- [gnutls_x509_crt_init](https://gnutls.org/manual/gnutls.html#index-gnutls_005fx509_005fcrt_005finit) (GnuTLS docs)
- [gnutls_x509_crt_import](https://gnutls.org/manual/gnutls.html#index-gnutls_005fx509_005fcrt_005finit) (GnuTLS docs)

</div></div>
<div class="section"><div class="container" markdown="1">

{:.text-success}

{:.text-success}

## Optional: Pretty print any certificate from the certificate chain

After obtaining the certificate chain, it is possible to print any certificate from the chain to the standard output. Possible printing options are `GNUTLS_CRT_PRINT_FULL`, `GNUTLS_CRT_PRINT_ONELINE`,   `GNUTLS_CRT_PRINT_UNSIGNED_FULL`, `GNUTLS_CRT_PRINT_COMPACT`, `GNUTLS_CRT_PRINT_FULL_NUMBERS`.

```c
/* For example, get the leaf server's certificate from the chain. */
gnutls_x509_crt_t server_certificate = server_chain_crt[0];

/* Print the server's certificate to stdout. */
gnutls_datum_t server_cert_pretty;
gnutls_x509_crt_print(server_chain_crt[0], GNUTLS_CRT_PRINT_ONELINE, &server_cert_pretty);
printf("%s\n", server_cert_pretty.data);
gnutls_free(server_cert_pretty.data);
```

### Relevant links

- [gnutls_x509_crt_print](https://gnutls.org/manual/gnutls.html#index-gnutls_005fx509_005fcrt_005fprint) (GnuTLS docs)

</div></div>
<div class="section"><div class="container" markdown="1">

## 2. Verify each certificate in the certificate chain

Verification of each certificate from the TLS server's certificate chain should be performed (except the root one).

```c
gnutls_x509_crt_t certificate;

/* Verify each certificate from the certificate chain by verifying its list of Signed Certificate Timestamps (SCT). */
for (int index = 0; index < chain_size; index++) {
    certificate = server_chain_crt[index];

    /* Perform verification of a single certificate according to the following steps. */
}
```

</div></div>
<div class="section"><div class="container" markdown="1">

## 3. Retrieve the list of Signed Certificate Timestamps (SCTs) from the certificate

After a single certificate was obtained, the SCT list is parsed from one of the certificate extensions.

```c
#include <gnutls/x509-ext.h>

/* This is the defined OID for Signed Certificate Timestamp (SCT) extension. */
char *CT_SCT_OID = "1.3.6.1.4.1.11129.2.4.2";

/* SCT list in DER encoded raw form. */
gnutls_datum_t sct_list_DER = { 0 };
/* STC list in native gnutls_x509_ct_scts_t structure. */
gnutls_x509_ct_scts_t sct_list = { 0 };

/* Index specifies the index of OID in case multiple same OIDs exist in certificate extensions, we are working only with index 0. */
int index = 0;
/* Information whether the required extension is marked as critical or not. */
unsigned int critical;

/* Retrieve the CT SCT list of the given certificate from SCT extension into gnutls_datum_t structure in DER format. */
int ret;

ret = gnutls_x509_crt_get_extension_by_oid2(certificate, CT_SCT_OID, index, &sct_list_DER, &critical);

if (ret < 0) {
    /* Error occured! */
    exit(EXIT_FAILURE);
}

if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
    /* Certificate does not contain specified extension. */
    exit(EXIT_FAILURE);
}

/* Convert the DER encoded CT SCT list from gnutls_datum_t structure to native gnutls_x509_ct_scts_t structure. */
if (gnutls_x509_ext_ct_scts_init(&sct_list) < 0) {
    exit(EXIT_FAILURE);
}
if (gnutls_x509_ext_ct_import_scts(&sct_list_DER, sct_list, 0) < 0) {
    exit(EXIT_FAILURE);
}
```

### Relevant links

- [gnutls_x509_crt_get_extension_by_oid2](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005fx509_005fcrt_005fget_005fextension_005fby_005foid2) (GnuTLS docs)
- [gnutls_x509_ext_ct_scts_init](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005fx509_005fext_005fct_005fscts_005finit) (GnuTLS docs)
- [gnutls_x509_ext_ct_import_scts](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005fx509_005fext_005fct_005fimport_005fscts) (GnuTLS docs)

</div></div>
<div class="section"><div class="container" markdown="1">

## 4. Verify each SCT from the SCT list

Parse the information for every Signed Certificate Timestamp (SCT) from the list of SCTS. Information such as the ID of the public log, the signature algorithm used when signing the SCT and the resulting signature.

```c
/* Information about one SCT from SCT list */
/* DER encoded ID of the public log that appended the given certificate to itself. */
gnutls_datum_t logid = { 0 };
/* Algorithm which was used for signing this SCT. */
gnutls_sign_algorithm_t sigalg = { 0 };
/* DER encoded signature. */
gnutls_datum_t signature = { 0 };
/* Timestamp, when was this SCT added to the public log. */
time_t timestamp;

/* Iterate the SCT List, to verify every single SCT entry. */
int ret;

for (int index=0; ; index++) {
    ret = gnutls_x509_ct_sct_get(sct_list, index, &timestamp, &logid, &sigalg, &signature);

    if (ret < 0) {
        /* Error occured. */
        exit(EXIT_FAILURE);
    }

    if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
        /* No more items in the list. */
        break;
    }

    /* Got one SCT item from the list. */
    /* Process and verify single timestamp. */

    /* The logid and signature fields from SCT in gnutls_datum_t structure need to be freed on each cycle. */
    gnutls_free(logid.data);
    gnutls_free(signature.data);
}
```

During this step, all information required to successfully verify the signature of a single Signed Certificate Timestamp (SCT) was obtained. However, this guide does not cover the verification of a single SCT yet.

### Relevant links

- [gnutls_x509_ct_sct_get](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005fx509_005fct_005fsct_005fget) (GnuTLS docs)

</div></div>
<div class="section"><div class="container" markdown="1">

## 5. Deinitialize

Free the previously allocated structures, which are no longer required.

```c
for (int i = 0; i < chain_size; i++) {
    gnutls_x509_crt_deinit(server_chain_crt[i]);
}
gnutls_free(server_chain_crt);
gnutls_free(sct_list_DER.data);
gnutls_x509_ext_ct_scts_deinit(sct_list);
```

### Relevant links

- [gnutls_x509_crt_deinit](https://gnutls.org/manual/gnutls.html#gnutls_005fx509_005fcrt_005fdeinit) (GnuTLS docs)
- [gnutls_x509_ext_ct_scts_deinit](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005fx509_005fext_005fct_005fscts_005fdeinit) (GnuTLS docs)

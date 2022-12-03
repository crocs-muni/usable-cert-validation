---
layout:     default
title:      "CRL revocation"
slug:       openssl-crl
library:    openssl
---

{% assign libraryData = site.data.libraries | where: "name", page.library | first %}
<div class="section"><div class="container" markdown="1">

{:#{{ page.slug }}}

# {{ libraryData.title }}: {{ page.title }}

{:.lead}
This guide covers the implementation of certificate revocation status checking using the Certificate Revocation List (CRL) revocation scheme.

{% include navigation-guides.html library=libraryData %}

</div></div>
<div class="section"><div class="container" markdown="1">

**Short description of revocation scheme:**
A Certificate Revocation List (CRL) is a list of revoked certificates issued by a certification authority (CA). The CA can have multiple CRLs, each of which is signed with the private key of the corresponding CA. The CA then publishes its CRLs to HTTP or LDAP servers. Each X.509v3 certificate that supports CRL contains an extension called CRL distribution point, which stores a link to servers containing these CRLs in which the certificate should be located if it was previously revoked. When verifying the certificate with this scheme, the TLS client must look at the required extension of the certificate, obtain the address where the CRLs of the CA are located, download these lists and check their signatures. After the signature is validated, the TLS client can search the certificate against the CRL.

CRLs are defined in [RFC 5280](https://www.rfc-editor.org/info/rfc5280).
CRLs on [Wikipedia](https://en.wikipedia.org/wiki/Certificate_revocation_list).

**Summary of this guide:**

1. Retrieve the TLS server’s certificate chain with its size
   - after retrieving the whole TLS server's certificate chain from the SSL session instance, perform the revocation check on each certificate from the chain.
2. Initialize the structures and variables required to download the CRL
3. Download the CRL lists from all possible URL links found
   - parse all crl distribution point URLs for each certificate from the certificate chain
   - download all CRL lists for each certificate from found URLs
4. Verify the signature of single downloaded CRL
   - after each download of the CRL list, it is necessary to verify its signature
5. Check the revocation status of a single certificate
   - after successful verification of the downloaded CRL's signature, the revocation status of the provided certificate can be examined against the current CRL
6. Deinitialize

The only prerequisite for this guide is that the `SSL *s_connection` variable has already been initialized. This variable represents the current TLS session or connection, which could have already been established or is currently in the TLS handshake phase. For more information, see our [guide](/guides/openssl) on how to initiate a secure TLS connection.

</div></div>
<div class="section"><div class="container" markdown="1">

## 1.) Retrieve the TLS server's certificate chain with its size

First, we need to obtain the certificate chain from the TLS connection. After that, iterate through every certificate from the retrieved certificate chain (except the root one) and perform a revocation check for each certificate.

```c
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

/* Retrieve the server's certificate chain from the OpenSSL connection. */
/* Another option: SSL_get0_verified_chain() */
STACK_OF(X509) *cert_chain_stack = SSL_get_peer_cert_chain(s_connection);
if (cert_chain_stack == NULL) {
    exit(EXIT_FAILURE);
}
int cert_chain_stack_size = sk_X509_num(cert_chain_stack);

/* Check that the certificate chain contains at least 2 certificates. */
if (cert_chain_stack_size < 2) {
    exit(EXIT_FAILURE);
}

/* Check the revocation status for every certificate from the chain (except the root one). */
X509 *certificate;
X509 *issuer_certificate;
for (int index = 0; index < cert_chain_stack_size - 1; index++) {
    certificate = sk_X509_value(cert_chain_stack, index);
    issuer_certificate = sk_X509_value(cert_chain_stack, index+1);

    /* Download all the possible CRL lists for each certificate in the chain and verify that the certificate is not included in one of the downloaded CRLs. */
    /* This procedure is demonstrated in the following steps. */
}
```

### Relevant links

- [SSL_get_peer_cert_chain](https://www.openssl.org/docs/man1.1.1/man3/SSL_get_peer_cert_chain.html) (OpenSSL docs)
- [OpenSSL Stacks](https://man.openbsd.org/STACK_OF.3) (OpenBSD docs)

</div></div>
<div class="section"><div class="container" markdown="1">

## 2.) Initialize the structures and variables required to download the CRL

Before it is possible to start downloading CRL lists from crl distribution points, it is necessary to prepare some variables.

To store one CRL list after its download, we use a custom structure named `datum_t`.

```c
struct datum_t {
    unsigned char *data;
    unsigned int size;
};
```

To download the CRL, it is necessary to establish an out-of-band connection with the server on which the given CRL is located. In our example, the cURL library is used for this purpose. Curl is able to send HTTP GET Request to the server and save the downloaded CRL to the programs' memory.

```c
#include <curl/curl.h>

/* Prepare the custom datum_t structure, where the downloaded CRL in DER format will be stored. */
struct datum_t downloaded_crl_der = { 0 };

/* Prepare the cURL for making out-of-band connection, downloading the CRLs from distribution points. */
curl_global_init(CURL_GLOBAL_ALL);
handle = curl_easy_init();
if (handle == NULL) {
    exit(EXIT_FAILURE);
}

/* Tell curl to write each chunk of data (our CRL list during downloading) with this function callback */
curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, get_data);
/* Tell curl to write each chunk of data to the given location, in our case, to the variable in the memory. */
curl_easy_setopt(handle, CURLOPT_WRITEDATA, &downloaded_crl_der);

/* Get the STACK of all crl distribution point entries for this certificate. */
/* CRL_DIST_POINTS is typedef on STACK_OF(DIST_POINT). */
STACK_OF(DIST_POINT) *dist_points_stack = X509_get_ext_d2i(certificate, NID_crl_distribution_points, NULL, NULL);
if (dist_points_stack == NULL) {
    exit(EXIT_FAILURE);
}
```

We provide a simple example of a callback function used by curl (assigned to curl with the option `CURLOPT_WRITEFUNCTION`) during the download process of the CRLs. This function gets invoked whenever a new chunk of CRL data has been received and needs to be saved. More information can be found [here](https://curl.se/libcurl/c/CURLOPT_WRITEFUNCTION.html).

```c
size_t get_data(void *buffer, size_t size, size_t nmemb, void *userp) {
    /* Already processed data from previous transfers. */
    gnutls_datum_t *ud = (gnutls_datum_t *) userp;

    /* nmemb bytes of new data */
    size *= nmemb;

    /* Reallocate the buffer containing the previous data so that it can also accommodate nmemb of new data. */
    ud->data = realloc(ud->data, ud->size + size);
    if (ud->data == NULL) {
        exit(EXIT_FAILURE);
    }

    /* Append nmemb new bytes to the previous data. */
    memcpy(&ud->data[ud->size], buffer, size);
    ud->size += size;

    return size;
}
```

### Relevant links

- [X509_get_ext_d2i](https://www.openssl.org/docs/man1.1.1/man3/X509_get_ext_d2i.html) (OpenSSL docs)
- [cURL](https://curl.se/libcurl/c/libcurl-tutorial.html) (libcurl programming tutorial)

</div></div>
<div class="section"><div class="container" markdown="1">

## 3.) Download the CRL lists from all possible URL links found

After receiving a list containing URL links to crl distribution points (in the form of STACK_OF structure), iteration through this list is performed in order to download all the CRLs.

```c
/* Iterate through the stack of the distribution points. */
for (int index = 0; index < sk_DIST_POINT_num(dist_points_stack); index++) {

    DIST_POINT *dist_point = sk_DIST_POINT_value(dist_points_stack, index);

    GENERAL_NAMES *general_names = dist_point->distpoint->name.fullname;

    for (int index2 = 0; index 2 < sk_GENERAL_NAME_num(general_names); index2++) {
        int gtype;
        GENERAL_NAME *actual_general_name = sk_GENERAL_NAME_value(general_names, index2);
        ASN1_STRING *asn_string_uri = GENERAL_NAME_get0_value(actual_general_name, &gtype);

        if (gtype != GEN_URI || ASN1_STRING_length(asn_string_uri) <= 6) {
            printf("- control1 failed!\n");
        }

        /* Retrieve the URL link as string (char *). */
        const char *crl_dist_point_uri = (const char *) ASN1_STRING_get0_data(asn_string_uri);

        if (crl_dist_point_uri == NULL || strncmp(crl_dist_point_uri, "http://", sizeof("http://") - 1) != 0) {
            printf("- control2 failed!\n");
        }

        /* Tell curl the URL, location where the data should be send. */
        curl_easy_setopt(handle, CURLOPT_URL, crl_dist_point_uri);

        /* Start downloading. */
        if(curl_easy_perform(handle) != 0) {
            exit(EXIT_FAILURE);
        }

        /* The download has successfully finished. */

        /* Downloaded CRL should be stored in the prepared variable in DER format. */
        const unsigned char *downloaded_crl_der_data = (const unsigned char *) downloaded_crl_der.data;
        /* Downloaded CRL size. */
        unsigned int downloaded_crl_der_size = downloaded_crl_der.size;

        /* Import downloaded CRL from DER format to native OpenSSL structure. */
        X509_CRL *downloaded_crl = d2i_X509_CRL(NULL, &downloaded_crl_der_data, downloaded_crl_der_size);
        if (downloaded_crl == NULL) {
            exit(EXIT_FAILURE;
        }

        /* Continue processing the current downloaded CRL list according to the following steps. */
    }
}
```

### Relevant links

- [OpenSSL Stacks](https://man.openbsd.org/STACK_OF.3) (OpenBSD docs)
- [ASN1_STRING_length](https://www.openssl.org/docs/man1.1.1/man3/ASN1_STRING_length.html) (OpenSSL docs)
- [ASN1_STRING_get0_data](https://www.openssl.org/docs/man1.1.1/man3/ASN1_STRING_length.html) (OpenSSL docs)
- [d2i_X509_CRL](https://www.openssl.org/docs/man1.0.2/man3/d2i_X509_CRL.html) (OpenSSL docs)

</div></div>
<div class="section"><div class="container" markdown="1">

## 4.) Verify the signature of single downloaded CRL

After successfully downloading each CRL list, it is necessary to validate its signature. This signature is validated using the issuer's public key, which issued the certificate currently checking and, thus, signed the current CRL list.

```c
/* Retrieve the public key of the issuer. */
EVP_PKEY *issuer_public_key = X509_get0_pubkey(issuer_certificate);
if (issuer_public_key == NULL) {
    exit(EXIT_FAILURE);
}

/* Verify the signature of downloaded CRL. */
if (X509_CRL_verify(downloaded_crl, issuer_public_key) != 1) {
    /* Signature of the downloaded CRL does not match with the issuer's public key. */
}
else {
    /* Signature of the downloaded CRL passed the validation. */
}
```

### Relevant links

- [X509_get0_pubkey](https://www.openssl.org/docs/man1.1.1/man3/X509_get0_pubkey.html) (OpenSSL docs()
- [X509_CRL_verify](https://www.openssl.org/docs/man3.0/man3/X509_CRL_verify.html) (OpenSSL docs)

</div></div>
<div class="section"><div class="container" markdown="1">

## 5.) Check the revocation status of a single certificate

After successfully validating the signature of the currently downloaded CRL list, it is possible to receive the certificate's revocation status.

```c
/* Check the revocation status of the certificate. */
X509_REVOKED *revoked_certificate = NULL;
if (X509_CRL_get0_by_cert(downloaded_crl, &revoked_certificate, certificate) == 0) {
    /* Certificate is not revoked! */
    /* Pointer revoked_certificate is NULL. */
}
else {
    /* Certificate is revoked! */
    /* Pointer revoked_certificate is pointing to the revoked entry in CRL list. */
}
```

### Relevant links

- [X509_CRL_get0_by_cert](https://www.openssl.org/docs/man1.1.1/man3/X509_CRL_get0_by_cert.html) (OpenSSL docs)

</div></div>
<div class="section"><div class="container" markdown="1">

## 6.) Deinitialize

Deinitialize the previously allocated structures, which are no longer required.

```c
/* Deinitialize after each loop after downloading. */
free(downloaded_crl_der.data);
X509_CRL_free(downloaded_crl);
downloaded_crl_der.data = NULL;
downloaded_crl_der.size = 0;

/* Deinitialize other structures. */
sk_DIST_POINT_pop_free(dist_points_stack, DIST_POINT_free);
curl_easy_cleanup(handle);
```

### Relevant links

- [sk_DIST_POINT_pop_free / OpenSSL stacks](https://www.openssl.org/docs/manmaster/man3/sk_TYPE_pop_free.html) (OpenSSL docs)
- [X509_CRL_free](https://www.openssl.org/docs/man1.1.1/man3/X509_CRL_free.html) (OpenSSL docs)

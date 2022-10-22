---
layout:     default
title:      "Developer guide: OpenSSL, Revocation with CRL"
slug:       openssl-crl
---

<div class="section"><div class="container" markdown="1">

{:#{{ page.slug }}}
# {{ page.title }}

{:.lead}
This guide covers the implementation of certificate revocation status checking using the Certificate Revocation List (CRL) revocation scheme. Official documentation of OpenSSL can be found [here](https://www.openssl.org/docs/manpages.html).


</div></div>
<div class="section"><div class="container" markdown="1">


**Short description of revocation scheme:**
A Certificate Revocation List (CRL) is a list of revoked certificates previously issued by a CA. The CA can have multiple CRLs, each of which is signed with the private key of the corresponding CA. The CA authority then publishes its CRLs to HTTP or LDAP servers. Each X.509v3 certificate, that supports CRL, contains an extension called CRL distribution point, which stores a link to servers containing CRLs in which the certificate should be located. When verifying the TLS server’s certificate with this scheme, the TLS client must look at the required extension of the server’s certificate, obtain the address where the CRLs of the CA are located, and then download these lists and check their signatures. After the signature is validated, the TLS client can search the server’s certificate against the CRL.

CRLs are defined in [RFC 5280](https://www.rfc-editor.org/info/rfc5280).
CRLs on [Wikipedia](https://en.wikipedia.org/wiki/Certificate_revocation_list).

**Summary of this guide:**
1. Retrieve the TLS server's certificate chain
   - from the chain, we will parse the TLS server's certificate with the certificate of its issuer
2. Download the CRLs from the CRL distribution point extension, verify their signature and verify the server's certificate against them
   - extract the URLs of the CRL servers, the CRLs are located on these servers
   - from these retrieved URLs, download the corresponding CRLs
   - verify the signature of these CRLs
   - if the signature verification passed, verify the TLS server's certificate against each CRL

We assume that the TLS client-server connection has already been established, that is, the client has access to the TLS server's certificate. In other words, we assume that the variable `SSL *s_connection` represents an already established connection. TLS client-server initialization guide can be found [here](https://x509errors.org/guides/openssl).


</div></div>
<div class="section"><div class="container" markdown="1">


## 1.) Retrieve the TLS server's certificate chain

First, we need to obtain a server's certificate chain and then parse the TLS server's certificate together with the issuer's certificate from this chain. Issuer is the entity, who signed the TLS server's certificate.

```c
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

/* Retrieve the server's certificate chain from the openSSL connection */
STACK_OF(X509) *cert_chain_stack =  SSL_get_peer_cert_chain(s_connection);
if (cert_chain_stack == NULL)
{
    exit(EXIT_FAILURE);
}

/* Check if the chain contains at least two certificates (server and issuer) */
int cert_chain_stack_size = sk_X509_num(cert_chain_stack);
if (cert_chain_stack_size < 2)
{
    exit(EXIT_FAILURE);
}

/* Retrieve the server's and issuer's certificate from the chain */
X509 *server_certificate = sk_X509_value(cert_chain_stack, 0);
X509 *issuer_certificate = sk_X509_value(cert_chain_stack, 1);
if (server_certificate== NULL || issuer_certificate== NULL)
{
    exit(EXIT_FAILURE);
}
```

### Relevant links
* [SSL_get_peer_cert_chain](https://www.openssl.org/docs/man1.1.1/man3/SSL_get_peer_cert_chain.html) (OpenSSL docs)
* [OpenSSL Stacks](https://man.openbsd.org/STACK_OF.3) (OpenBSD docs)


</div></div>
<div class="section"><div class="container" markdown="1">


## 2.) Download the CRLs from the CRL distribution point extension, verify their signature and verify the TLS server's certificate against them

First, all URLs, where the CRLs of the issuer are located, are extracted from the TLS server certificate, which was retrieved in first step. CRLs are extracted from the X.509 certificate extension called `crl distribution points`. Subsequently, all CRLs are downloaded from these URLs, their signature is verified, and only then the revocation status of the TLS server's certificate is verified.

```c
struct datum_t {
    unsigned char *data;
    unsigned int size;
};
```

A downloaded CRL list is later stored in the variable of type struct datum_t. `*Data` will point to the DER encoded bytes of the CRL and in `size`, its legth will be stored. Variable of this type is assigned to the cURL handler with option called `CURLOPT_WRITEDATA`. Description can be found [here](https://curl.se/libcurl/c/CURLOPT_WRITEDATA.html).

```c
static size_t get_data(void *buffer, size_t size, size_t nmemb, void *userp)
{
struct datum_t *ud = (struct datum_t *) userp;

size *= nmemb;

ud->data = realloc(ud->data, ud->size + size);
if (ud->data == NULL)
{
    exit(EXIT_FAILURE);
}

memcpy(&ud->data[ud->size], buffer, size);
ud->size += size;

return size;
}
```

Function which will be used while downloading the CRLs. This function is assigned to the cURL handler with option called `CURLOPT_WRITEFUNCTION`. Description can be found [here](https://curl.se/libcurl/c/CURLOPT_WRITEFUNCTION.html).


```c
#include <curl/curl.h>

/* Variable for storing the type of the GENERAL_NAME structure */
int gtype;

int ret_error_val;

/* Prepare datum_t structure, where the downloaded CRL in DER format will be stored */
struct datum_t actual_one_CRL = { 0 };

/* Prepare the curl for making out-of-band connection and downloading CRLs from distribution point */
curl_global_init(CURL_GLOBAL_ALL);
CURL *handle = curl_easy_init();
if (handle == NULL)
{
    exit(EXIT_FAILURE);
}

curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, get_data);
curl_easy_setopt(handle, CURLOPT_WRITEDATA, &actual_one_CRL);


/* Get the STACK of all crl distribution point entries in the given server's certificate */
STACK_OF(DIST_POINT) *dist_points_stack = X509_get_ext_d2i(server_certificate, NID_crl_distribution_points, NULL, NULL);
if (dist_points_stack == NULL)
{
    exit(EXIT_FAILURE);
}

/* Iterate through the stack of the distribution points */
for (int index = 0; index < sk_DIST_POINT_num(dist_points_stack); index++)
{
    DIST_POINT *act_dist_point = sk_DIST_POINT_value(dist_points_stack, index);

    GENERAL_NAMES *general_names = act_dist_point->distpoint->name.fullname;

    for (int i = 0; i < sk_GENERAL_NAME_num(general_names); i++)
    {
        GENERAL_NAME *actual_general_name = sk_GENERAL_NAME_value(general_names, i);

        ASN1_STRING *asn_string_uri = GENERAL_NAME_get0_value(actual_general_name, &gtype);

        // Check the ASN1_STRING
        if (gtype != GEN_URI || ASN1_STRING_length(asn_string_uri) <= 6)
        {
            exit(EXIT_FAILURE);
        }

        const char *crl_dist_point_uri = (const char *) ASN1_STRING_get0_data(asn_string_uri);

        // Check the char * URI of the one of the CRL distribution points
        if (crl_dist_point_uri == NULL || strncmp(crl_dist_point_uri, "http://", sizeof("http://") - 1) != 0)
        {
            exit(EXIT_FAILURE);
        }

        curl_easy_setopt(handle, CURLOPT_URL, crl_dist_point_uri);

        ret_error_val = curl_easy_perform(handle);        // HTTP GET Request
        if (ret_error_val != 0)
        {
            exit(EXIT_FAILURE);
        }


        /* Downloaded CRL should be stored in the actual_one_CRL variable of type struct_datum_t */
        /* Downloaded CRL should be in DER format! */
        const unsigned char *CRL_data_der = (const unsigned char *) actual_one_CRL.data;

        /* Convert the DER encoded CRL list into the native type X509_CRL */
        X509_CRL *actual_crl = d2i_X509_CRL(NULL, &CRL_data_der, actual_one_CRL.size);
        if (actual_crl == NULL)
        {
            exit(EXIT_FAILURE);
        }

        /* Verify the signare of actual CRL */

        /* Get the public key of the issuer */
        EVP_PKEY *issuers_public_key = X509_get0_pubkey(issuer_certificate);
        if (issuers_public_key == NULL)
        {
            exit(EXIT_FAILURE);
        }

        /* Verify the signarue of actual CRL list against the retrieved public key of the issuer */
        if (X509_CRL_verify(actual_crl, issuers_public_key) != 1)
        {
            exit(EXIT_FAILURE);
        }

        /* Check the recovation status of TLS server's certificate against the actual CRL list */
        X509_REVOKED *revoked_certificate = NULL;
        if (X509_CRL_get0_by_cert(actual_crl, &revoked_certificate, server_certificate) == 0)
        {
            /* Certificate is not in this list */
            /* revoked_certificate is still set to the NULL */
        }
        else
        {
            /* Certificate is in the list -- REVOKED through this CRL from this crl distribution point */
            /* variable revoked_certificate is not NULL */
            fprintf(stderr, "CERTIFICATE is REVOKED!\n");
        }


        /* Deinitialize actual CRL */
        free(actual_one_CRL.data);
        X509_CRL_free(actual_crl);

        actual_one_CRL.data = NULL;
        actual_one_CRL.size = 0;
    }
}

/* Deinitialize curl */
curl_easy_cleanup(handle);

/* Deinitialize the STACK_OF(DIST_POINT) */
sk_DIST_POINT_pop_free(dist_points_stack, DIST_POINT_free);
```


### Relevant links
* [X509_get_ext_d2i](https://www.openssl.org/docs/man1.1.1/man3/X509_get_ext_d2i.html) (OpenSSL docs)
* [ASN1_STRING_length](https://www.openssl.org/docs/man1.1.1/man3/ASN1_STRING_length.html) (OpenSSL docs)
* [ASN1_STRING_get0_data](https://www.openssl.org/docs/man1.1.1/man3/ASN1_STRING_length.html) (OpenSSL docs)
* [d2i_X509_CRL](https://www.openssl.org/docs/man1.0.2/man3/d2i_X509_CRL.html) (OpenSSL docs)
* [X509_get0_pubkey](https://www.openssl.org/docs/man1.1.1/man3/X509_get0_pubkey.html) (OpenSSL docs()
* [X509_CRL_verify](https://www.openssl.org/docs/man3.0/man3/X509_CRL_verify.html) (OpenSSL docs)
* [X509_CRL_get0_by_cert](https://www.openssl.org/docs/man1.1.1/man3/X509_CRL_get0_by_cert.html) (OpenSSL docs)
* [X509_CRL_free](https://www.openssl.org/docs/man1.1.1/man3/X509_CRL_free.html) (OpenSSL docs)
* [OpenSSL Stacks](https://man.openbsd.org/STACK_OF.3) (OpenBSD docs)
* [cURL](https://curl.se/libcurl/c/libcurl-tutorial.html) (libcurl programming tutorial)


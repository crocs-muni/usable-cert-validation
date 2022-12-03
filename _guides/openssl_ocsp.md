---
layout:     default
title:      "OCSP revocation"
slug:       openssl-ocsp
library:    openssl
---

{% assign libraryData = site.data.libraries | where: "name", page.library | first %}
<div class="section"><div class="container" markdown="1">

{:#{{ page.slug }}}

# {{ libraryData.title }}: {{ page.title }}

{:.lead}
This guide covers the implementation of certificate revocation status checking using the Online Certificate Status Protocol (OCSP).

{% include navigation-guides.html library=libraryData %}

</div></div>
<div class="section"><div class="container" markdown="1">

## Introduction

OCSP is a separate protocol with which the TLS client and OCSP server called OCSP responder communicate. The TLS client contacts the OCSP responder, a trusted third party, to provide him with the revocation status of the certificates which the TLS client included in the OCSP request.

OCSP protocol is defined in [RFC 6960](https://www.rfc-editor.org/info/rfc6960).
OCSP on [Wikipedia](https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol).

**Summary of this guide:**

1. Retrieve the TLS server’s certificate chain with its size
   - From the certificate chain, we can parse any certificate we want to verify with its issuer’s certificate.
   - OCSP verification should be performed on all certificates present in the certificate chain (except the root one).
2. Extract the URL Address of the OCSP Responder
   - Extract the URL address of the OCSP Responder from the certificate’s extension called _authority information access_.
3. Generate the OCSP Request
   - In the OCSP request, we will include certificates for which the revocation status is needed.
   - Furthermore, a nonce extension should be added to the OCSP request as protection against replay attacks.
4. Send the OCSP Request and retrieve the OCSP Response
   - cURL library is used for sending the OCSP Request to the specified URL (from the previous steps).
   - The OCSP response is immediately retrieved.
5. Verify the status and signature of the OCSP Response
6. Extract the revocation status from the OCSP Response
   - If signature verification of the OCSP response from the previous step has successfully passed, we can extract the revocation status of the certificates we have included in the OCSP request.
7. Deinitialize

The only prerequisite for this guide is that the `SSL *s_connection` variable has already been initialized. This variable represents the current TLS session or connection, which could have already been established or is currently in the TLS handshake phase. For more information, see our [guide](/guides/openssl) on how to initiate a secure TLS connection.

</div></div>
<div class="section"><div class="container" markdown="1">

## 1. Retrieve the TLS server's certificate chain with its size

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

    /* Perform OCSP revocation check for each certificate from the certificate chain. */
    /* That includes parsing the URL address of OCSP Responder from the certificate's extension. */
    /* Generating the OCSP Request, sending it and retrieving the OCSP Response. */
    /* After the OCSP Response is retrieved, its signature is verified, and the certificate's revocation status is obtained. */
}
```

### Relevant links

- [SSL_get_peer_cert_chain](https://www.openssl.org/docs/man1.1.1/man3/SSL_get_peer_cert_chain.html) (OpenSSL docs)
- [OpenSSL Stacks](https://man.openbsd.org/STACK_OF.3) (OpenBSD docs)

</div></div>
<div class="section"><div class="container" markdown="1">

## 2. Extract the URL Address of the OCSP Responder

After obtaining a single certificate with the certificate of its issuer, extract the URL address of OCSP Responder from the certificate's authority information access extension.

```c
include <openssl/ocsp.h>

/* Retrieve all OCSP Responder's URIs in the array of type STACK_OF(TYPE). */
STACK_OF(OPENSSL_STRING) *ocsp_uris_stack = X509_get1_ocsp(certificate);

/* Retrieve the number of all responder uris from the STACK_OF(TYPE) array. */
int ocsp_uris_stack_size= sk_OPENSSL_STRING_num(ocsp_uris_stack);

if (ocsp_uris_stack_size == 0) {
    /* The given certificate does not contain any URL to the OCSP Responder. */
    exit(EXIT_SUCCESS);
}

/* Retrieve the first (at index 0) OCSP Responder's uri entry from the STACK_OF(TYPE) array. */
char *ocsp_uri = sk_OPENSSL_STRING_value(ocsp_uris_stack, 0);
```

### Relevant links

- [X509_get1_ocsp](https://abi-laboratory.pro/index.php?view=symbol_view&l=openssl&v=1.0.2e&obj=c93f7&s=X509_get1_ocsp) (not officially documented)
- [OpenSSL Stacks](https://man.openbsd.org/STACK_OF.3) (OpenBSD docs)

</div></div>
<div class="section"><div class="container" markdown="1">

## 3. Generate the OCSP Request

Generate the OCSP Request for the certificates we want to verify. In this case, it is the single certificate retrieved from the certificate chain.

```c
/* Initialize new empty ocsp request structure. */
OCSP_REQUEST *ocsp_request = OCSP_REQUEST_new();
if (ocsp_request == NULL) {
    exit(EXIT_FAILURE);
}

/* Create the new OCSP_CERTID structure with default SHA1 message digest (first argument) for given certificate and its issuer. */
OCSP_CERTID *certid = OCSP_cert_to_id(NULL, certificate, issuer_certificate);
if (*certid == NULL)  {
    exit(EXIT_FAILURE);
}

/* Add the certificate ID (OCSP_CERTID structure) to the OCSP Request. */
/* Structure OCSP_ONEREQ is returned so an application can add additional extensions to the request. */
/* Another option: OCSP_request_add1_cert */
OCSP_ONEREQ *ocsp_onereq = OCSP_request_add0_id(ocsp_request, *certid);
if (ocsp_onereq == NULL) {
    exit(EXIT_FAILURE);
}

/* Add a random nonce value (NULL argument) as extension to the OCSP Request. */
/* Default length of nonce, 16B, is used. */
if (OCSP_request_add1_nonce(ocsp_request, NULL, 0) != 1) {
    exit(EXIT_FAILURE);
}
```

### Relevant links

- [OCSP_REQUEST_new](https://www.openssl.org/docs/man3.0/man3/OCSP_REQUEST_new.html) (OpenSSL docs)
- [OCSP_cert_to_id](https://www.openssl.org/docs/man1.1.1/man3/OCSP_cert_to_id.html) (OpenSSL docs)
- [OCSP_request_add0_id](https://www.openssl.org/docs/man1.1.1/man3/OCSP_request_add0_id.html) (OpenSSL docs)
- [OCSP_request_add1_nonce](https://www.openssl.org/docs/man1.1.1/man3/OCSP_request_add1_nonce.html) (OpenSSL docs)

</div></div>
<div class="section"><div class="container" markdown="1">

{:.text-success}

## Optional: Print the OCSP Request in DER format into a file

The created DER encoded file containing the OCSP request can be inspected with the shell command `openssl ocsp -reqin ocsp_req.der -text`.

```c
BIO *file = BIO_new_file("ocsp_req.der", "wb");
/* From internal OpenSSL native structure to DER encoding. */
i2d_OCSP_REQUEST_bio(file, ocsp_request);
BIO_free(file);
```

### Relevant links

- [BIO_new_file](https://www.openssl.org/docs/man1.1.1/man3/BIO_new_file.html) (OpenSSL docs)
- [i2d_OCSP_REQUEST_bio](https://www.openssl.org/docs/man1.1.1/man3/i2d_OCSP_REQUEST.html) (OpenSSL docs)
- [BIO_free](https://www.openssl.org/docs/man1.1.1/man3/BIO_free.html) (OpenSSL docs)

</div></div>
<div class="section"><div class="container" markdown="1">

## 4. Send the OCSP Request and retrieve the OCSP Response

Send the generated OCSP Request to the OCSP Responder's URL. Subsequently, the OCSP Response sent from the OCSP Responder will be received. The response is stored in the program's memory.

This step establishes an out-of-band connection with the OCSP Responder.

In our example, the cURL library is used to establish such a connection. cURL can send an HTTP POST Request with the OCSP Request header.

To store the OCSP Response, we use a custom structure named `datum_t`. `*Data` will point to the DER encoded bytes of the retrieved OCSP Response, while `size` will hold the size of the OCSP Response.

```c
struct datum_t {
    unsigned char *data;
    unsigned int size;
};
```

```c
#include <curl/curl.h>

/* Prepare the custom (datum_t) structure where the OCSP Response will be placed. */
struct datum_t ocsp_response_DER = {0};

/* Convert the previously generated OCSP Request from native OpenSSL structure to the plain DER format. */
unsigned char *ocsp_request_DER = NULL;
int ocsp_request_size = i2d_OCSP_REQUEST(ocsp_request, &ocsp_request_DER);
if (ocsp_request_size < 0) {
    exit(EXIT_FAILURE);
}

/* Prepare the cURL for making out-of-band connection. */
curl_global_init(CURL_GLOBAL_ALL);
CURL *handle = curl_easy_init();
if (handle == NULL) {
    exit(EXIT_FAILURE);
}

/* Add ocsp header to the HTTP POST Request. */
headers = curl_slist_append(headers, "Content-Type: application/ocsp-request");
if (headers == NULL) {
    exit(EXIT_FAILURE);
}

/* Tell curl which data we want to send (in our case OCSP Request data). */
curl_easy_setopt(handle, CURLOPT_POSTFIELDS, ocsp_request_DER);
/* Tell curl the size of the data we want to send (size of the OCSP Request). */
curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE, ocsp_request_size);
/* Tell curl the URL, location where the data should be send. */
curl_easy_setopt(handle, CURLOPT_URL, ocsp_uri);
/* Add our custom HTTP headers. */
curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers);
/* Tell curl to write each chunk of data (our OCSP Response) with this function callback. */
curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, get_data);
/* Tell curl to write each chunk of data to the given location, in our case, to the variable in the memory. */
curl_easy_setopt(handle, CURLOPT_WRITEDATA, &ocsp_response_DER);

/* Send the request. */
int ret_val = curl_easy_perform(handle);
if (ret_val != 0) {
    exit(EXIT_FAILURE);
}

/* OCSP Response has been retrieved. */

/* Convert the retrieved OCSP Response from DER format to the native OpenSSL structure. */
const char *ocsp_response_der_data = (const char *) ocsp_response_DER.data;
int ocsp_response_der_size = ocsp_response_DER.size;
OCSP_RESPONSE *ocsp_response = d2i_OCSP_RESPONSE(NULL, (const unsigned char **) &ocsp_response_der_data, ocsp_response_der_size);
if (ocsp_response == NULL) {
    exit(EXIT_FAILURE);
}
```

We provide a simple example of a callback function used by cURL (assigned to cURL with the option `CURLOPT_WRITEFUNCTION`) during the process of receiving the OCSP Response. This function gets invoked whenever a new chunk of data has been received and needs to be saved. More information can be found [here](https://curl.se/libcurl/c/CURLOPT_WRITEFUNCTION.html).

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

- [cURL](https://curl.se/libcurl/c/libcurl-tutorial.html) (libcurl programming tutorial)
- [i2d_OCSP_REQUEST](https://www.openssl.org/docs/man1.1.1/man3/i2d_OCSP_REQUEST.html) (OpenSSL docs)
- [d2i_OCSP_RESPONSE](https://www.openssl.org/docs/man1.1.1/man3/d2i_OCSP_RESPONSE.html) (OpenSSL docs)

</div></div>
<div class="section"><div class="container" markdown="1">

{:.text-success}

## Optional: Print the received OCSP Response in DER format into a file

The created DER encoded file containing the OCSP Response can be inspected with the shell command `openssl ocsp -respin ocsp_resp.der -text -noverify`.

```c
BIO *file = BIO_new_file("ocsp_resp.der", "wb");
/* From internal OpenSSL native structure to DER encoding. */
i2d_OCSP_RESPONSE_bio(file, ocsp_response);
BIO_free(file);
```

### Relevant links

- [BIO_new_file](https://www.openssl.org/docs/man1.1.1/man3/BIO_new_file.html) (OpenSSL docs)
- [i2d_OCSP_RESPONSE_bio](https://www.openssl.org/docs/man1.1.1/man3/i2d_OCSP_RESPONSE.html) (OpenSSL docs)
- [BIO_free](https://www.openssl.org/docs/man1.1.1/man3/BIO_free.html) (OpenSSL docs)

</div></div>
<div class="section"><div class="container" markdown="1">

## 5. Verify the status and signature of the OCSP Response

The OCSP Response needs to be verified against some set of trust anchors before it can be relied upon.
It is also important to check whether the received OCSP Response corresponds to the certificate being checked.

```c
/* Check the status of retrieved OCSP response, if it is not malformed or invalid for some other reason. */
if (OCSP_response_status(ocsp_response) != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
    exit(EXIT_FAILURE);
}

/* Decode and return the OCSP_BASICRESP structure from OCSP_RESPONSE. */
OCSP_BASICRESP *ocsp_response_basic = OCSP_response_get1_basic(ocsp_response);
if (ocsp_response_basic == NULL) {
    exit(EXIT_FAILURE);
}

/* Compare and check the nonces in OCSP Response (basic) and OCSP Request */
int nonce_check_result = OCSP_check_nonce(ocsp_request, ocsp_response_basic);
if (nonce_check_result == 1) {
    /* Nonce is present in both the request and the response, and they are equal! */
}
else if (nonce_check_result == 0) {
    /* Nonce is present in both the request and the response, but they are not equal! */
}
else if (nonce_check_result == -1) {
    /* Nonce is present only in the ocsp request, not in the ocsp response! */
}
else if (nonce_check_result == 2) {
    /* Nonce is missing in both, the request and the response! */
}
else if (nonce_check_result == 3) {
    /* Nonce is present only in the ocsp response, not in the ocsp request! */
}

/* Load default certificate store. */
/* This will be required later when verifying signature of OCSP (basic) response and verifying the issuer's certificate as well. */
X509_STORE *store = X509_STORE_new();
if (store == NULL) {
    exit(EXIT_FAILURE);
}
if (X509_STORE_set_default_paths(store) != 1) {
    exit(EXIT_FAILURE);
}

/* Verify the signature of basic OCSP Response with validation of issuer's certificate. */
/* If we want to just verify the signature of OCSP response and we dont want to validate the server's certificate, */
/* use flag OCSP_TRUSTOTHER and the X509_STORE wont be needed. */
if (OCSP_basic_verify(ocsp_response_basic, cert_chain_stack, store, 0) != 1) {
    /* Verification of signature of the OCSP Response has failed. */
}
```

### Relevant links

- [OCSP_response_status](https://www.openssl.org/docs/man1.1.1/man3/OCSP_response_status.html) (OpenSSL docs)
- [OCSP_response_get1_basic](https://www.openssl.org/docs/man1.1.1/man3/OCSP_response_get1_basic.html) (OpenSSL docs)
- [OCSP_check_nonce](https://www.openssl.org/docs/man1.1.1/man3/OCSP_check_nonce.html) (OpenSSL docs)
- [X509_STORE_new](https://www.openssl.org/docs/man1.1.1/man3/X509_STORE_new.html) (OpenSSL docs)
- [X509_STORE_set_default_paths](https://www.openssl.org/docs/man1.1.1/man3/X509_STORE_set_default_paths.html) (OpenSSL docs)
- [OCSP_basic_verify](https://www.openssl.org/docs/man1.1.1/man3/OCSP_basic_verify.html) (OpenSSL docs)

</div></div>
<div class="section"><div class="container" markdown="1">

## 6. Extract the revocation status from the OCSP Response

After the signature of the OCSP Response has been verified, the revocation status of the certificates included in the response can be safely examined. Except for the revocation status of the certificates, the OCSP Response also contains some other useful information.

```c
/* Get the revocation status of the provided certificate, represented with OCSP_CERTID (with issuer's certificate). */
/* Revocation reason and time will be filled only if revocation_status == V_OCSP_CERTSTATUS_REVOKED. */
int revocation_status;
int revocation_reason;
ASN1_GENERALIZEDTIME *rev_time;
ASN1_GENERALIZEDTIME *thisupd;
ASN1_GENERALIZEDTIME *nextupd;
if (OCSP_resp_find_status(ocsp_response_basic, certid, &revocation_status, &revocation_reason, &rev_time, &thisupd, &nextupd) != 1) {
    /* Internal error occured, function has failed. */
    exit(EXIT_FAILURE);
}

if (revocation_status == V_OCSP_CERTSTATUS_GOOD) {
    /* Certificate is not revoked. */
}
else if (revocation_status == V_OCSP_CERTSTATUS_REVOKED) {
    /* Certificate is revoked. */
    /* Can further inspect the time and reason of the revocation. */
}
else if (revocation_status == V_OCSP_CERTSTATUS_UNKNOWN) {
    /* Status of the provided certificate is unknown. */
}

/* Check the validity of this update and next update fields retrieved from basic OCSP Response. */
if (OCSP_check_validity(thisupd, nextupd, 0, -1) != 1) {
    /* Validity check has failed. */
}
```

### Relevant links

- [OCSP_resp_find_status](https://www.openssl.org/docs/man1.1.1/man3/OCSP_resp_find_status.html) (OpenSSL docs)
- [OCSP_check_validity](https://www.openssl.org/docs/man1.1.1/man3/OCSP_check_validity.html) (OpenSSL docs)

</div></div>
<div class="section"><div class="container" markdown="1">

{:.text-danger}

## Alternative: Multiple single responses in one basic response

The native response structure `OCSP_BASICRESP` can contain the revocation status for more than one certificate (if more certificates were added to the request). It is possible to iterate through each revocation status for the single certificate (represented by the `OCSP_SINGLERESP` structure).

```c
/* Retrieve the revocation status of the certificates included in the OCSP Basic response. */
/* Revocation reason and time will be filled only if revocation_status == V_OCSP_CERTSTATUS_REVOKED. */
int revocation_status;
int revocation_reason;
ASN1_GENERALIZEDTIME *rev_time;
ASN1_GENERALIZEDTIME *thisupd;
ASN1_GENERALIZEDTIME *nextupd;

int number_of_single_responses = OCSP_resp_count(ocsp_response_basic);

OCSP_SINGLERESP *one_response;
int rev_status;
for (int index = 0; index < number_of_single_responses; index ++) {
    one_response = OCSP_resp_get0(ocsp_response_basic, index);
    if (one_response == NULL) {
        /* Internal error occured, function has failed. */
    }

    /* Retrieve the revocation status, revocation_reason, revocation time and other information. */
    /* Similar to function OCSP_resp_find(), but this one operates on OCSP_SINGLERESP structure. */
    rev_status = OCSP_single_get0_status(one_response, &revocation_reason, &rev_time, &thisupd, &nextupd);
    if (rev_status == V_OCSP_CERTSTATUS_GOOD) {
        /* Certificate is not revoked. */
    }
    else if (rev_status == V_OCSP_CERTSTATUS_REVOKED) {
        /* Certificate is revoked. */
    }
    else if (rev_status == V_OCSP_CERTSTATUS_UNKNOWN) {
        /* Status of the provided certificate is unknown. */
    }
}
```

### Relevant links

- [OCSP_resp_count](https://www.openssl.org/docs/man1.1.1/man3/OCSP_resp_count.html) (OpenSSL docs)

- [OCSP_resp_get0](https://www.openssl.org/docs/man1.1.1/man3/OCSP_resp_get0.html) (OpenSSL docs)
- [OCSP_single_get0_status](https://www.openssl.org/docs/man1.1.1/man3/OCSP_single_get0_status.html) (OpenSSL docs)

</div></div>
<div class="section"><div class="container" markdown="1">

## 7. Deinitialize

Free the previously allocated structures and variables, which are no longer required.

```c
sk_OPENSSL_STRING_free(ocsp_uris_stack);
free(ocsp_uri);
free(ocsp_request_DER);
OCSP_REQUEST_free(ocsp_request);
curl_easy_cleanup(handle);
curl_slist_free_all(headers);
free(ocsp_response_DER.data);
OCSP_RESPONSE_free(ocsp_response);
OCSP_BASICRESP_free(ocsp_response_basic);
X509_STORE_free(store);
```

### Relevant links

- [OCSP_REQUEST_free](https://www.openssl.org/docs/man1.1.1/man3/OCSP_REQUEST_free.html) (OpenSSL docs)
- [OCSP_RESPONSE_free](https://www.openssl.org/docs/man1.1.1/man3/OCSP_RESPONSE_free.html) (OpenSSL docs)
- [OCSP_BASICRESP_free](https://www.openssl.org/docs/man1.1.1/man3/OCSP_BASICRESP_free.html) (OpenSSL docs)
- [X509_STORE_free](https://www.openssl.org/docs/man1.1.1/man3/X509_STORE_free.html) (OpenSSL docs)
- [OpenSSL Stacks](https://man.openbsd.org/STACK_OF.3) (OpenBSD docs)

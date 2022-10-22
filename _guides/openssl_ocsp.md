---
layout:     default
title:      "Developer guide: OpenSSL, Revocation with OCSP"
slug:       openssl-ocsp
---

<div class="section"><div class="container" markdown="1">

{:#{{ page.slug }}}
# {{ page.title }}

{:.lead}
This guide covers the implementation of certificate revocation status checking using the Online Certificate Status Protocol (OCSP) revocation scheme. Official documentation of OpenSSL can be found [here](https://www.openssl.org/docs/manpages.html).


</div></div>
<div class="section"><div class="container" markdown="1">


**Short description of revocation scheme:**
A separate protocol with which the TLS client and OCSP server called OCSP responder communicate. The TLS client contacts the OCSP responder, trusted third party, to provide him with the revocation status of the TLS server’s certificate with which the TLS client communicates.

OCSP protocol is defined in [RFC 6960](https://www.rfc-editor.org/info/rfc6960).
OCSP on [Wikipedia](https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol).

**Summary of this guide:**
1. Retrieve the server's certificate chain
   - from the chain, we will parse the TLS server's certificate with the certificate of its issuer
2. Extract the URL Adress of OCSP Responder
   - extract the URL adress of the OCSP Responder from the TLS server's certificate from step 1. The X.509v3 extension `authority information access` stores these URLs.
3. Generate the OCSP Request
   - in the OCSP request, we will include certificates whose revocation status we are interested in
   - also, we will include nonce into the OCSP request extension as a protection against replay attacks
4. Send the OCSP Request and retrieve the OCSP Response
   - cURL library is used for sending the OCSP Request to the specified URL from step 2
   - the OCSP response is immidiately retrieved
5. Verify the signature of the OCSP Response
6. Extract the revocation status from the OCSP Response
   - if signature verification of the OCSP response from step 5 passed, we can extract the revocation status of the certificates we have included into the OCSP request
7. Deinitialize

We assume that the TLS client-server connection has already been established, that is, the client has access to the TLS server's certificate. In other words, we assume that the variable `SSL *s_connection` represents an already established connection. TLS client-server initialization guide can be found [here](https://x509errors.org/guides/openssl).


</div></div>
<div class="section"><div class="container" markdown="1">


## 1.) Retrieve the server's certificate chain

First, we need to obtain a server's certificate chain and then parse the TLS server's certificate together with the issuer's certificate from this chain. Issuer is the entity, who signed the TLS server's certificate.

```c
#include <openssl/ssl.h>
#include <openssl/x509.h>

/* Retrieve the server's certificate chain from the openSSL connection */
STACK_OF(X509) *cert_chain_stack =  SSL_get_peer_cert_chain(s_connection);
if (cert_chain_stack == NULL)
{
    exit(EXIT_FAILURE;
}

/* Check if the chain contains at least two certificates (server and issuer) */
int cert_chain_stack_size = sk_X509_num(cert_chain_stack);
if (cert_chain_stack_size < 2)
{
    exit(EXIT_FAILURE);
}

/* Retrieve the server's and issuer's certificate from the chain */
X509 *server_certificate= sk_X509_value(cert_chain_stack, 0);
X509 *issuer_certificate= sk_X509_value(cert_chain_stack, 1);
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


## 2.) Extract the URL Adress of OCSP Responder

After obtaining the TLS server's certificate, we need to obtain the OCSP Responder's URL adress from the authority information access extension.


```c
include <openssl/ocsp.h>

/* Retrieve all OCSP Responder's URIs in the array of type STACK_OF(TYPE) */
STACK_OF(OPENSSL_STRING) *ocsp_uris_stack = X509_get1_ocsp(server_certificate);

/* Retrieve the number of all responder uris from the STACK_OF() array */
int ocsp_uris_stack_len = sk_OPENSSL_STRING_num(ocsp_uris_stack);

if (ocsp_uris_stack_len == 0)
{
    exit(EXIT_FAILURE);
}

char *ocsp_uri;
for (int i = 0; i < sk_OPENSSL_STRING_num(ocsp_uris_stack); i++)
{
    ocsp_uri = sk_OPENSSL_STRING_value(ocsp_uris_stack, i);
    /* Obtained one entry of the OCSP Responder's URI */
}

/* Retrieve the first OCSP Responder's uri entry from the STACK_OF(TYPE) array */
ocsp_uri = sk_OPENSSL_STRING_value(ocsp_uris_stack, 0);
```

### Relevant links
* [X509_get1_ocsp]() (not oficially documented)
* [OpenSSL Stacks](https://man.openbsd.org/STACK_OF.3) (OpenBSD docs)


</div></div>
<div class="section"><div class="container" markdown="1">


## 3.) Generate the OCSP Request

Generate the OCSP Request for the certificates we want to verify. In this case, it is just the TLS server's certificate.


```c
/* Allocate new empty ocsp request structure */
OCSP_REQUEST *ocsp_request = OCSP_REQUEST_new();

/* Create the OCSP_CERTID structure with default SHA1 message digest and fill it with the server's and issuer's certificate */
OCSP_CERTID *certid = OCSP_cert_to_id(NULL, server_certificate, issuer_certificate);
if (*certid == NULL)
{
    exit(EXIT_FAILURE);
}

/* Add the server's and issuer's certificate ID into the ocsp request structure using the previously created OCSP_CERTID structure */
/* NOTE: OCSP_request_add1_cert can be used instead */
OCSP_ONEREQ *ocsp_onereq = OCSP_request_add0_id(ocsp_request, *certid);
if (ocsp_onereq == NULL)
{
    exit(EXIT_FAILURE);
}

/* Add a random nonce value to OCSP request. We are using default length of nonce, 16B */
if (OCSP_request_add1_nonce(ocsp_request, NULL, 0) != 1)
{
    exit(EXIT_FAILURE);
}
```

### Relevant links
* [OCSP_REQUEST_new](https://www.openssl.org/docs/man3.0/man3/OCSP_REQUEST_new.html) (OpenSSL docs)
* [OCSP_cert_to_id](https://www.openssl.org/docs/man1.1.1/man3/OCSP_cert_to_id.html) (OpenSSL docs)
* [OCSP_request_add0_id](https://www.openssl.org/docs/man1.1.1/man3/OCSP_request_add0_id.html) (OpenSSL docs)
* [OCSP_request_add1_nonce](https://www.openssl.org/docs/man1.1.1/man3/OCSP_request_add1_nonce.html) (OpenSSL docs)


</div></div>
<div class="section"><div class="container" markdown="1">


{:.text-success}
## Optional: Print the OCSP Request in DER format into file

The created file with DER encoded OCSP request can be inspected with the shell command `openssl ocsp -reqin ocsp_req.der -text`.

```c
BIO *file = BIO_new_file("ocsp_req.der", "wb");

/* From internal native structure to DER encoding */
i2d_OCSP_REQUEST_bio(file, ocsp_request);

BIO_free(file);
```

### Relevant links
* [BIO_new_file](https://www.openssl.org/docs/man1.1.1/man3/BIO_new_file.html) (OpenSSL docs)
* [i2d_OCSP_REQUEST_bio](https://www.openssl.org/docs/man1.1.1/man3/i2d_OCSP_REQUEST.html) (OpenSSL docs)
* [BIO_free](https://www.openssl.org/docs/man1.1.1/man3/BIO_free.html) (OpenSSL docs)


</div></div>
<div class="section"><div class="container" markdown="1">


## 4.) Send the OCSP Request and retrieve the OCSP Response

Send the generated OCSP Request to the OCSP Responder's URL. Subsequently, we will also receive an OCSP Response from the OCSP Responder. The response is stored in the program's memory.

This step establishes an out-of-band connection with the OCSP Responder.

The cURL library is used to establish the connection. curL sends a HTTP Request with the OCSP Request header.


```c
struct datum_t {
    unsigned char *data;
    unsigned int size;
};
```

A downloaded CRL list is later stored in the variable of type struct datum_t. `*Data` will point to the DER encoded bytes of the CRL and in `size`, its legth will be stored. Varible of this type is assigned to the cURL handler with option called `CURLOPT_WRITEDATA`. Description can be found [here](https://curl.se/libcurl/c/CURLOPT_WRITEDATA.html).


```c
static size_t get_data(void *buffer, size_t size, size_t nmemb, void *userp)
{
struct datum_t *ud = (struct datum_t *) userp; // moje stare data

size *= nmemb;      // doslo nmemb B novych dat, na prvy ukazuje buffer

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

/* Prepare the buffer, the OCSP Response will be placed here */
/* For this purpose, we are using our own declared structure */
struct datum_t ocsp_response_datum = {0};

// From internal OCSP_REQUEST structure into DER format into allocated buffer with returned size
/* Convert the OCSP Request data from internal structure into DER format, which will be in char pointer */
unsigned char *ocsp_request_buffer_DER = NULL;
int ocsp_request_size = i2d_OCSP_REQUEST(ocsp_request, &ocsp_request_buffer_DER);
if (ocsp_request_size < 0)
{
    exit(EXIT_FAILURE);
}

curl_global_init(CURL_GLOBAL_ALL);
CURL *handle = curl_easy_init();
if (handle == NULL)
{
    exit(EXIT_FAILURE);
}

struct curl_slist *headers = NULL;
headers = curl_slist_append(headers, "Content-Type: application/ocsp-request");
if (headers == NULL)
{
    exit(EXIT_FAILURE);
}

/* binary data to POST */
curl_easy_setopt(handle, CURLOPT_POSTFIELDS, ocsp_request_buffer_DER);

/* set the size of binary data to POST */
curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE, ocsp_request_size);

/* set the URL - where to send ocsp request DER data */
curl_easy_setopt(handle, CURLOPT_URL, ocsp_uri);

/* pass our list of custom headers */
curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers);

/* instead of stdout, transfer data with get_data function inside our structure! */
curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, get_data);
curl_easy_setopt(handle, CURLOPT_WRITEDATA, &ocsp_response_datum);

int ret_val = curl_easy_perform(handle);   // post the data!
if (ret_val != 0)
{
    exit(EXIT_FAILURE);
}

/* Convert the data from datum_t structure into native OCSP_RESPONSE structure */
const char *data_der = (const char *) ocsp_response_datum.data;
OCSP_RESPONSE *ocsp_response = d2i_OCSP_RESPONSE(NULL, (const unsigned char **) &data_der, ocsp_response_datum.size);
if (ocsp_response == NULL)
{
    exit(EXIT_FAILURE);
}


/* Deinitialize cURL */
curl_slist_free_all(headers);
curl_easy_cleanup(handle);
```

### Relevant links
* [cURL](https://curl.se/libcurl/c/libcurl-tutorial.html) (libcurl programming tutorial)
* [i2d_OCSP_REQUEST](https://www.openssl.org/docs/man1.1.1/man3/i2d_OCSP_REQUEST.html) (OpenSSL docs)
* [d2i_OCSP_RESPONSE](https://www.openssl.org/docs/man1.1.1/man3/d2i_OCSP_RESPONSE.html) (OpenSSL docs)



</div></div>
<div class="section"><div class="container" markdown="1">


{:.text-success}
## Optional: Print the received OCSP Response in DER format into file

The created file with DER encoded OCSP response can be inspected with the shell command `openssl ocsp -respin ocsp_resp.der -text -noverify`.

```c
BIO *file = BIO_new_file("ocsp_resp.der", "wb");

/* From internal native structure to DER encoding */
i2d_OCSP_RESPONSE_bio(file, ocsp_response);

BIO_free(file);
```

### Relevant links
* [BIO_new_file](https://www.openssl.org/docs/man1.1.1/man3/BIO_new_file.html) (OpenSSL docs)
* [i2d_OCSP_RESPONSE_bio](https://www.openssl.org/docs/man1.1.1/man3/i2d_OCSP_RESPONSE.html) (OpenSSL docs)
* [BIO_free](https://www.openssl.org/docs/man1.1.1/man3/BIO_free.html) (OpenSSL docs)


</div></div>
<div class="section"><div class="container" markdown="1">


## 5.) Verify the signature of the OCSP Response

The OCSP Response needs to be verified against some set of trust anchors before it can be relied upon.
It is also important to check whether the received OCSP Response corresponds to the certificate being checked.


```c
// can return OCSP_RESPONSE_STATUS_* (SUCCESFULL, MALFORMED, TRYLATER, INTERNALERROR, SIGREQUIRED, UNAUTHORIZED)
/* Check the status of the OCSP response - if the OCSP Response is not malformed or other problem */
if (OCSP_response_status(ocsp_response) != OCSP_RESPONSE_STATUS_SUCCESSFUL)
{
    exit(EXIT_FAILURE);
}

/* Convert from OCSP_RESPONSE to OCSP_BASICRESP (extract response information) */
OCSP_BASICRESP *ocsp_response_basic = OCSP_response_get1_basic(ocsp_response);
if (ocsp_response_basic == NULL)
{
    exit(EXIT_FAILURE);
}

/* Check the nonce in OCSP Response by comparing the nonce from request and response (basic resp) */
/* different return values! */
int nonce_check = OCSP_check_nonce(ocsp_request, ocsp_response_basic);
if (nonce_check == 1)
{
    printf("Nonce present in req and in resp and they are equal!\n");
}
else if (nonce_check == 0)
{
    fprintf(stderr, "WARNING: nonces are present in both but not equal!\n");
}
else if (nonce_check == -1)
{
    fprintf(stderr, "WARNING: nonce present only in ocsp request, not in response!\n");
}
else if (nonce_check == 2)
{
    fprintf(stderr, "WARNING: nonces are absent in both\n");
}
else if (nonce_check == 3)
{
    fprintf(stderr, "WARNING: nonce present only in ocsp response, not in request!\n");
}


/* Load default certificate store */
/* This will be required later when verifying signature of response and verifying the issuer's certificate as well */
X509_STORE *store = X509_STORE_new();
if (store == NULL)
{
    exit(EXIT_FAILURE);
}
if (X509_STORE_set_default_paths(store) != 1)
{
    exit(EXIT_FAILURE);
}

/* Verify the signature with OCSP_basic_verify() */
/* If we want to just verify the signature of OCSP response and we dont want to validate the server's certificate, use flag OCSP_TRUSTOTHER and the X509_STORE wont be needed */
if (OCSP_basic_verify(ocsp_response_basic, cert_chain_stack, store, 0) != 1)
{
    exit(EXIT_FAILURE);
}
```

### Relevant links
* [OCSP_response_status](https://www.openssl.org/docs/man1.1.1/man3/OCSP_response_status.html) (OpenSSL docs)
* [OCSP_response_get1_basic](https://www.openssl.org/docs/man1.1.1/man3/OCSP_response_get1_basic.html) (OpenSSL docs)
* [OCSP_check_nonce](https://www.openssl.org/docs/man1.1.1/man3/OCSP_check_nonce.html) (OpenSSL docs)
* [X509_STORE_new](https://www.openssl.org/docs/man1.1.1/man3/X509_STORE_new.html) (OpenSSL docs)
* [X509_STORE_set_default_paths](https://www.openssl.org/docs/man1.1.1/man3/X509_STORE_set_default_paths.html) (OpenSSL docs)
* [OCSP_basic_verify](https://www.openssl.org/docs/man1.1.1/man3/OCSP_basic_verify.html) (OpenSSL docs)


</div></div>
<div class="section"><div class="container" markdown="1">


## 6.) Extract the revocation status from the OCSP Response


After we have checked the signature of the OCSP Response, we can extract information about the revocation status of our TLS server's certificate along with various other useful information from the response.


```c
// Get the revocation status of server's certificate and some info around it (optionally)
int revocation_status;
int revocation_reason;   // only if revocation_status will be revoked!
ASN1_GENERALIZEDTIME *rev_time;   // only if revocation_status will be revoked!
ASN1_GENERALIZEDTIME *thisupd;
ASN1_GENERALIZEDTIME *nextupd;
if (OCSP_resp_find_status(ocsp_response_basic, certid, &revocation_status, &revocation_reason, &rev_time, &thisupd, &nextupd) != 1)
{
    exit(EXIT_FAILURE);
}

if (rev_status != V_OCSP_CERTSTATUS_GOOD  )
{
    /* Certificate is GOOD and not REVOKED */
}
else if (rev_status == V_OCSP_CERTSTATUS_REVOKED)
{
    /* Certificate is REVOKED */
}
else if (rev_status == V_OCSP_CERTSTATUS_UNKNOWN)
{
    /* Certificate revocation status is UNKNOWN */
}


/* Check the validity of OCSP Response */
if (OCSP_check_validity(thisupd, nextupd, 0, 0) != 0)
{
    exit(EXIT_FAILURE);
}
```

### Relevant links
* [OCSP_resp_find_status](https://www.openssl.org/docs/man1.1.1/man3/OCSP_resp_find_status.html) (OpenSSL docs)
* [OCSP_check_validity](https://www.openssl.org/docs/man1.1.1/man3/OCSP_check_validity.html) (OpenSSL docs)


</div></div>
<div class="section"><div class="container" markdown="1">


{:.text-danger}
## Alternative: Using multiple single responses in one basic response

Native structure `OCSP_BASICRESP` can contain multiple OCSP Responses. That is why we must also specify the index of the OCSP Response, which we are interested in. However, in our case, the structure contains only one OCSP Response (to the TLS server's certificate).


```c
int number_of_single_responses = OCSP_resp_count(ocsp_response_basic);  // 1

for (int index = 0; index < number_of_single_responses; index++)
{
    OCSP_SINGLERESP *one_response = OCSP_resp_get0(ocsp_response_basic, index);
    if (one_response == NULL)
    {
        exit(EXIT_FAILURE)
    }

    /* Retrieve the revocation status, revocation_reason, revocation time and other similar info like with OCSP_resp_find() */
    int rev_status = OCSP_single_get0_status(one_response, &revocation_reason, &rev_time, &thisupd, &nextupd);
    if (rev_status != V_OCSP_CERTSTATUS_GOOD  )
    {
        /* Certificate is GOOD and not REVOKED */
    }
    else if (rev_status == V_OCSP_CERTSTATUS_REVOKED)
    {
        /* Certificate is REVOKED */
    }
    else if (rev_status == V_OCSP_CERTSTATUS_UNKNOWN)
    {
        /* Certificate revocation status is UNKNOWN */
    }
}
```

### Relevant links
* [OCSP_resp_count](https://www.openssl.org/docs/man1.1.1/man3/OCSP_resp_count.html) (OpenSSL docs)
* [OCSP_resp_get0](https://www.openssl.org/docs/man1.1.1/man3/OCSP_resp_get0.html) (OpenSSL docs)
* [OCSP_single_get0_status](https://www.openssl.org/docs/man1.1.1/man3/OCSP_single_get0_status.html) (OpenSSL docs)


</div></div>
<div class="section"><div class="container" markdown="1">


## 7.) Deinitialize

Free the previously allocated structures, which are no longer required.

```c
sk_OPENSSL_STRING_free(ocsp_uris_stack);
free(ocsp_uri);
OCSP_REQUEST_free(ocsp_request);
free(ocsp_request_buffer_DER);
free(ocsp_response_datum.data);
OCSP_RESPONSE_free(ocsp_response);
OCSP_BASICRESP_free(ocsp_response_basic);
X509_STORE_free(store);
```

### Relevant links
* [OCSP_REQUEST_free](https://www.openssl.org/docs/man1.1.1/man3/OCSP_REQUEST_free.html) (OpenSSL docs)
* [OCSP_RESPONSE_free](https://www.openssl.org/docs/man1.1.1/man3/OCSP_RESPONSE_free.html) (OpenSSL docs)
* [OCSP_BASICRESP_free](https://www.openssl.org/docs/man1.1.1/man3/OCSP_BASICRESP_free.html) (OpenSSL docs)
* [X509_STORE_free](https://www.openssl.org/docs/man1.1.1/man3/X509_STORE_free.html) (OpenSSL docs)
* [OpenSSL Stacks](https://man.openbsd.org/STACK_OF.3) (OpenBSD docs)
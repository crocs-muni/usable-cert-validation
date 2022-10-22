---
layout:     default
title:      "Developer guide: GnuTLS, Revocation with OCSP"
slug:       gnutls-ocsp
---

<div class="section"><div class="container" markdown="1">

{:#{{ page.slug }}}
# {{ page.title }}

{:.lead}
This guide covers the implementation of certificate revocation status checking using the Online Certificate Status Protocol (OCSP) revocation scheme. Official documentation of GnuTLS dealing with this topic can be found [here](https://www.gnutls.org/manual/gnutls.html#OCSP-certificate-status-checking) and similar example from GnuTLS can be found [here](https://www.gnutls.org/manual/gnutls.html#OCSP-example).


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

We assume that the TLS client-server connection has already been established, that is, the client has access to the server's certificate. In other words, we assume that the variable `gnutls_session_t session` represents an already established connection. TLS client-server initialization guide can be found [here](https://x509errors.org/guides/gnutls).


</div></div>
<div class="section"><div class="container" markdown="1">


## 1.) Retrieve the TLS server's certificate chain along with it's size

First, we need to obtain a server's certificate chain and then parse the TLS server's certificate together with the issuer's certificate from this chain. Issuer is the entity, who signed the TLS server's certificate.

```c
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

/* Retrieve the server's certificate chain together with the size of this chain. */
/* Server's certificate chain is represented as array of gnutls_datum_t type, where each certificate is in DER format. */
/* The first certificate in the array, at index 0, is server's certificate and the last certificate, at index size-1, is root CA certificate */
unsigned int server_chain_size = 0;
const gnutls_datum_t *server_chain_der = gnutls_certificate_get_peers(session, &server_chain_size);
if (server_chain_der == NULL)
{
    exit(EXIT_FAILURE);
}

/* Convert the certificate chain from array of gnutls_datum_t type into the array of native gnutls_x509_crt_t type! */
/* Again, the first certificate, at index 0, is the certificate of the server and the last certificate, at index size-1, is the certificate belonging to the Root CA. */
gnutls_x509_crt_t *server_chain_crt = gnutls_calloc(server_chain_size, sizeof(gnutls_x509_crt_t));
if (server_chain_crt == NULL)
{
    errx(EXIT_FAILURE, "gnutls_calloc failed!");
}
for (int i=0; i < server_chain_size; i++)
{
    gnutls_x509_crt_init(&server_chain_crt[i]);
    if ((gnutls_x509_crt_import(server_chain_crt[i], &server_chain_der[i], GNUTLS_X509_FMT_DER)) != 0)
    {
        exit(EXIT_FAILURE);
    }
}

/* Get the server's certificate from the chain */
gnutls_x509_crt_t server_certificate_crt = server_chain_crt[0];

/* Get the issuer's certificate from the chain */
gnutls_x509_crt_t issuer_certificate_crt = server_chain_crt[1];
```

### Relevant links

* [gnutls_certificate_get_peers](https://gnutls.org/manual/gnutls.html#gnutls_005fcertificate_005fget_005fpeers) (GnuTLS docs)
* [gnutls_x509_crt_init](https://gnutls.org/manual/gnutls.html#index-gnutls_005fx509_005fcrt_005finit) (GnuTLS docs)
* [gnutls_x509_crt_import](ihttps://gnutls.org/manual/gnutls.html#index-gnutls_005fx509_005fcrt_005finit) (GnuTLS docs)



</div></div>
<div class="section"><div class="container" markdown="1">


{:.text-success}
## Optional: Pretty print the server's certificate from the chain

After obtaining the TLS server's certificate, we can print the certificate to stdout.
Possible obtions are `GNUTLS_CRT_PRINT_FULL`, `GNUTLS_CRT_PRINT_ONELINE`,   `GNUTLS_CRT_PRINT_UNSIGNED_FULL`, `GNUTLS_CRT_PRINT_COMPACT`, `GNUTLS_CRT_PRINT_FULL_NUMBERS`.

```c
/* Print the server's certificate from the chain to stdout */
gnutls_datum_t server_cert_pretty;
gnutls_x509_crt_print(server_certificate_crt, GNUTLS_CRT_PRINT_ONELINE, &server_cert_pretty);
printf("%s\n", server_cert_pretty.data);
gnutls_free(server_cert_pretty.data);
```

### Relevant links

* [gnutls_x509_crt_print](https://gnutls.org/manual/gnutls.html#index-gnutls_005fx509_005fcrt_005fprint) (GnuTLS docs)


</div></div>
<div class="section"><div class="container" markdown="1">


## 2.) Extract the URL Adress of OCSP Responder

After obtaining the TLS server's certificate, we need to obtain the OCSP Responder's URL adress from the authority information access extension.

```c
/* This is the structure, where the URL adress will be placed */
gnutls_datum_t ocsp_responder_uri_datum = { 0 };

int ret_val;
int act_index = 0;

while (1)
{
    /* Parse the URL adress from the server's certificate from information authority access extension */
    ret_val = gnutls_x509_crt_get_authority_info_access(server_certificate_crt, act_index, GNUTLS_IA_OCSP_URI, &ocsp_responder_uri_datum, NULL);
    if (ret_val == GNUTLS_E_UNKNOWN_ALGORITHM)
    {
        act_index++;
        continue;
    }
    if (ret_val == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)    // out of band
    {
        /* No more OCSP URL in Authority Info Access extension was found */
        exit(EXIT_FAILURE);
    }
    if (ret_val < 0)
    {
        /* Another error occured */
        exit(EXIT_FAILURE);
    }

    /* No error occured, we have succesfully parsed the URL adress from aia extension */
    break;
}

/* Convert the OCSP Responder's URL to string (from gnutls_datum_t structure) */
char *ocsp_responder_uri = (char *) gnutls_malloc((ocsp_responder_uri_datum.size + 1) * sizeof(char));
if (ocsp_responder_uri == NULL)
{
    exit(EXIT_FAILURE);
}
memcpy(ocsp_responder_uri, ocsp_responder_uri_datum.data, ocsp_responder_uri_datum.size);
ocsp_responder_uri[ocsp_responder_uri_datum.size] = 0;
```

### Relevant links

* [gnutls_x509_crt_get_authority_info_access](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005fx509_005fcrt_005fget_005fauthority_005finfo_005faccess) (GnuTLS docs)



</div></div>
<div class="section"><div class="container" markdown="1">


## 3.) Generate the OCSP Request

Generate the OCSP Request for the certificates we want to verify. In this case, it is just the TLS server's certificate.

```c
/* Initialize empty native OCSP Request structure */
gnutls_ocsp_req_t ocsp_req;
if (gnutls_ocsp_req_init(&ocsp_req) < 0)
{
    exit(EXIT_FAILURE);
}

/* Add the certificate, which revocation status we want to get with its issuer's certificate to the OCSP Request structure */
if (gnutls_ocsp_req_add_cert(ocsp_req, GNUTLS_DIG_SHA1, issuer_certificate_crt, server_certificate_crt) < 0)
{
    exit(EXIT_FAILURE);
}

/* Add or update a nonce extension to the OCSP request with newly generated random value */
if (gnutls_ocsp_req_randomize_nonce(ocsp_req) != 0)
{
    exit(EXIT_FAILURE);
}

/* Retrieve the added or updated nonce */
gnutls_datum_t nonce_req = { 0 };
if (gnutls_ocsp_req_get_nonce(ocsp_req, NULL, &nonce_req) != 0)
{
    exit(EXIT_FAILURE);
}

/* Export from the native gnutls_ocsp_req_t structure to a new gnutls_datum_t structure */
gnutls_datum_t ocsp_req_datum_DER;
if (gnutls_ocsp_req_export(ocsp_req, &ocsp_req_datum_DER) != 0)
{
    exit(EXIT_FAILURE)
}
```

### Relevant links

* [gnutls_ocsp_req_init](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005focsp_005freq_005finit) (GnuTLS docs)
* [gnutls_ocsp_req_add_cert](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005focsp_005freq_005fadd_005fcert) (GnuTLS docs)
* [gnutls_ocsp_req_export](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005focsp_005freq_005fexport) (GnuTLS docs)
* [gnutls_ocsp_req_randomize_nonce](https://gnutls.org/manual/gnutls.html#index-gnutls_005focsp_005freq_005frandomize_005fnonce) (GnuTLS docs)
* [gnutls_ocsp_req_get_nonce](https://gnutls.org/manual/gnutls.html#index-gnutls_005focsp_005freq_005fget_005fnonce) (GnuTLS docs)


</div></div>
<div class="section"><div class="container" markdown="1">


{:.text-success}
## Optional: Pretty print information about the OCSP Request

After generating the OCSP Request, we can print the request to stdout.
Possible obtions are `GNUTLS_OCSP_PRINT_FULL`, `GNUTLS_OCSP_PRINT_COMPACT`.

```c
gnutls_datum_t ocsp_req_pretty_print = { 0 };
if (gnutls_ocsp_req_print(ocsp_req, GNUTLS_OCSP_PRINT_FULL, &ocsp_req_pretty_print) != 0)
{
    exit(EXIT_FAILURE);
}
printf("%s\n", ocsp_req_pretty_print.data);
gnutls_free(ocsp_req_pretty_print.data);
```

### Relevant links

* [gnutls_ocsp_req_print](index-gnutls_005focsp_005freq_005fprint) (GnuTLS docs)


</div></div>
<div class="section"><div class="container" markdown="1">


## 4.) Send the OCSP Request and retrieve the OCSP Response

Send the generated OCSP Request to the OCSP Responder's URL. Subsequently, we will also receive the OCSP Response from the OCSP Responder. The response is stored in the program's memory.

This step establishes an out-of-band connection with the OCSP Responder.

The cURL library is used to establish the connection. curL sends a HTTP Request with the OCSP Request header.

```c
/* Function used for transporting the data within cURL from CRL distribution point */
static size_t get_data(void *buffer, size_t size, size_t nmemb, void *userp)
{
    gnutls_datum_t *ud = (gnutls_datum_t *) userp;

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

int ret_val;

/* This is the structure, where we will retrieve the OCSP Response */
gnutls_datum_t ocsp_response_datum;
ocsp_response_datum.data = NULL;
ocsp_response_datum.size = 0;

/* Prepare cURL */
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

/* post binary data */
curl_easy_setopt(handle, CURLOPT_POSTFIELDS, ocsp_req_datum_DER.data);

/* set the size of the binary postfields data */
curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE, ocsp_req_datum_DER.size);

/* set the url */
curl_easy_setopt(handle, CURLOPT_URL, ocsp_responder_uri);

/* pass our list of custom made headers */
curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers);

/* Function used while receiving data within the cURL */
curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, get_data);

/* Instead of stdout, save the receiving data with the function above into variable */
curl_easy_setopt(handle, CURLOPT_WRITEDATA, &ocsp_response_datum);

/* Send the request and retrieve the response */
ret_val = curl_easy_perform(handle);        // post away!
if (ret_val != 0)
{
    exit(EXIT_FAILURE);
}

/* Initialize empty native OCSP Response structure */
gnutls_ocsp_resp_t ocsp_response;
if (gnutls_ocsp_resp_init(&ocsp_response) < 0)
{
    exit(EXIT_FAILURE);
}

/* Import from DER gnutls_datum_t structure into the native gnutls_ocsp_resp_t structure */
if (gnutls_ocsp_resp_import(ocsp_response, &ocsp_response_datum) < 0)
{
    exit(EXIT_FAILURE);
}

/* Deinitialize cURL */
curl_slist_free_all(headers);       // free the header list
curl_easy_cleanup(handle);
```

### Relevant links

* [cURL](https://curl.se/libcurl/c/libcurl-tutorial.html) (libcurl programming tutorial)
* [gnutls_ocsp_resp_init](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005focsp_005fresp_005finit) (GnuTLS docs)
* [gnutls_ocsp_resp_import](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005focsp_005fresp_005fimport) (GnuTLS docs)


</div></div>
<div class="section"><div class="container" markdown="1">


{:.text-success}
## Optional: Pretty print information about the OCSP Response

After obtaining the OCSP Response, we can print the response to stdout.
Possible obtions are `GNUTLS_OCSP_PRINT_FULL`, `GNUTLS_OCSP_PRINT_COMPACT`.

```c
gnutls_datum_t ocsp_response_pretty_print;
if (gnutls_ocsp_resp_print(ocsp_response, GNUTLS_OCSP_PRINT_COMPACT, &ocsp_response_pretty_print) != 0)
{
    exit(EXIT_FAILURE);
}
printf("%s\n", ocsp_response_pretty_print.data);
gnutls_free(ocsp_response_pretty_print.data);
```

### Relevant links

* [gnutls_ocsp_resp_print](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005focsp_005fresp_005fprint) (GnuTLS docs)


</div></div>
<div class="section"><div class="container" markdown="1">


## 5.) Verify the signature of the OCSP Response

The OCSP Response needs to be verified against some set of trust anchors before it can be relied upon.
It is also important to check whether the received OCSP Response corresponds to the certificate being checked.


```c
/* Check whether the OCSP Response is about the provided certificate */
if (gnutls_ocsp_resp_check_crt(ocsp_response, 0, server_certificate_crt) < 0)
{
    exit(EXIT_FAILURE);
}

/* Extract the nonce from the OCSP response */
gnutls_datum_t nonce_resp = { 0 };
if (gnutls_ocsp_resp_get_nonce(ocsp_response, NULL, &nonce_resp) != 0)
{
    /* Nonce extension is not present in the OCSP response */
}

/* Check that the nonces from the OCSP request and response are the same */
if (nonce_req.size != nonce_resp.size || memcmp(nonce_req.data, nonce_resp.data, nonce_resp.size) != 0)
{
    exit(EXIT_FAILURE);
}

/* Check whether OCSP Response is signed by given signer */
unsigned int verify_result;   // gnutls_ocsp_verify_reason_t enum
if (gnutls_ocsp_resp_verify_direct(ocsp_response, issuer_certificate_crt, &verify_result, 0) != GNUTLS_E_SUCCESS)
{
    exit(EXIT_FAILURE);
}

if (verify_result & GNUTLS_OCSP_VERIFY_SIGNER_NOT_FOUND)
{
    /* signature verification failed */
}
else if (verify_result & GNUTLS_OCSP_VERIFY_SIGNER_KEYUSAGE_ERROR)
{
    /* signature verification failed */
}
else if (verify_result & GNUTLS_OCSP_VERIFY_UNTRUSTED_SIGNER)
{
    /* signature verification failed */
}
else if (verify_result & GNUTLS_OCSP_VERIFY_INSECURE_ALGORITHM)
{
    /* signature verification failed */
}
else if (verify_result & GNUTLS_OCSP_VERIFY_SIGNATURE_FAILURE)
{
    /* signature verification failed */
}
else if (verify_result & GNUTLS_OCSP_VERIFY_CERT_NOT_ACTIVATED)
{
    /* signature verification failed */
}
else if (verify_result & GNUTLS_OCSP_VERIFY_CERT_EXPIRED)
{
    /* signature verification failed */
}
else
{
    /* signature verification passed */
}
```

### Relevant links

* [gnutls_ocsp_resp_check_crt](index-gnutls_005focsp_005fresp_005fcheck_005fcrt) (GnuTLS docs)
* [gnutls_ocsp_resp_get_nonce](https://gnutls.org/manual/gnutls.html#index-gnutls_005focsp_005fresp_005fget_005fnonce) (GnuTLS docs)
* [gnutls_ocsp_resp_verify_direct](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005focsp_005fresp_005fverify_005fdirect) (GnuTLS docs)



</div></div>
<div class="section"><div class="container" markdown="1">


## 6.) Extract the revocation status from the OCSP Response

After we have checked the signature of the OCSP Response, we can extract information about the revocation status of our TLS server's certificate along with various other useful information from the response.

Note: Native structure `gnutls_ocsp_resp_t` can contain multiple OCSP Responses. That is why we must also specify the index of the OCSP Response, which we are interested in. However, in our case, the structure contains only one OCSP Response (to the TLS server's certificate).

```c
/* Retrieve the revocation status from the OCSP response at given index */
unsigned int cert_status;    // gnutls_ocsp_cert_status_t enumeration
int index = 0;              // specify the response index to get
time_t revocation_time;     // if cert_status is GNUTLS_OCSP_CERT_REVOKED
unsigned int revocation_reason; // gnutls_x509_crl_reason_t enumeration

if (gnutls_ocsp_resp_get_single(ocsp_response, index, NULL, NULL, NULL, NULL, &cert_status, NULL, NULL, &revocation_time, &revocation_reason) != GNUTLS_E_SUCCESS)
{
    exit(EXIT_FAILURE);
}

if (cert_status & GNUTLS_OCSP_CERT_GOOD)
{
    /* Certificate is not Revoked */
}

else if (cert_status & GNUTLS_OCSP_CERT_UNKNOWN)
{
    /* Unknown status of the certificate */
}

else if (cert_status & GNUTLS_OCSP_CERT_REVOKED)
{
    /* Certificate is Revoked */
    /* Can further inspect the revocation reason */
}
```

### Relevant links

* [gnutls_ocsp_resp_get_single](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005focsp_005fresp_005fget_005fsingle-1) (GnuTLS docs)
* [gnutls_x509_crl_reason_t enumeration](https://www.gnutls.org/manual/gnutls.html#gnutls_005fx509_005fcrl_005freason_005ft) (GnuTLS docs)


</div></div>
<div class="section"><div class="container" markdown="1">


## 7.) Deinitialize

Free the previously allocated structures, which are no longer required.

```c
// Free the used memory and variables
for (int i = 0; i < chain_size; i++)
{
    gnutls_x509_crt_deinit(server_chain_crt[i]);
}
gnutls_free(server_chain_crt);
gnutls_free(ocsp_responder_uri_datum.data);
gnutls_free(ocsp_responder_uri);
gnutls_free(ocsp_req_datum_DER.data);
gnutls_ocsp_req_deinit(ocsp_req);
gnutls_free(ocsp_response_datum_DER.data);
gnutls_ocsp_resp_deinit(ocsp_response);
gnutls_free(nonce_req.data)
gnutls_free(nonce_resp.data)
```

### Relevant links

* [gnutls_x509_crt_deinit](https://gnutls.org/manual/gnutls.html#gnutls_005fx509_005fcrt_005fdeinit) (GnuTLS docs)
* [gnutls_ocsp_req_deinit](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005focsp_005freq_005fdeinit) (GnuTLS docs)
* [gnutls_ocsp_resp_deinit](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005focsp_005fresp_005fdeinit) (GnuTLS docs)


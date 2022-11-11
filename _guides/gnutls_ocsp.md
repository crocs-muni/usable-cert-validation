---
layout:     default
title:      "Developer guide: GnuTLS, Revocation with OCSP"
slug:       gnutls-ocsp
---

<div class="section"><div class="container" markdown="1">

{:#{{ page.slug }}}

# {{ page.title }}

{:.lead}
This guide covers the implementation of certificate revocation status checking using the Online Certificate Status Protocol (OCSP). Official documentation of GnuTLS dealing with this topic can be found [here](https://www.gnutls.org/manual/gnutls.html#OCSP-certificate-status-checking), and a similar example from GnuTLS can be found [here](https://www.gnutls.org/manual/gnutls.html#OCSP-example).

</div></div>
<div class="section"><div class="container" markdown="1">

**Short description of revocation scheme**:
OCSP is a separate protocol with which the TLS client and OCSP server called OCSP responder communicate. The TLS client contacts the OCSP responder, a trusted third party, to provide him with the revocation status of the certificates which the TLS client included in the OCSP request.

OCSP protocol is defined in [RFC 6960](https://www.rfc-editor.org/info/rfc6960).
OCSP on [Wikipedia](https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol).

**Summary of this guide:**

1. Retrieve the server's certificate chain
   - from the certificate chain, we can parse any certificate we want to verify with its issuer's certificate.
2. Verify each certificate in the certificate chain
   - OCSP verification should be performed on all certificates present in the certificate chain (except the root one)
3. Extract the URL Address of the OCSP Responder
   - extract the URL address of the OCSP Responder from the certificate's extension called 'authority information access'.
4. Generate the OCSP Request
   - in the OCSP request, we will include certificates whose revocation status we are interested in
   - also, a nonce extension should be added to the OCSP request as a protection against replay attacks
5. Send the OCSP Request and retrieve the OCSP Response
   - cURL library is used for sending the OCSP Request to the specified URL (from the previous steps)
   - the OCSP response is immediately retrieved
6. Verify the status and signature of the OCSP Response
7. Extract the revocation status from the OCSP Response
   - if signature verification of the OCSP response from the previous step has successfully passed, we can extract the revocation status of the certificates we have included into the OCSP request
8. Deinitialize

The only prerequisite for this guide is that the `gnutls_session_t session` variable has already been initialized. This session variable represents the current TLS session, which could have already been established, or the session is currently in the TLS handshake phase. For more information, see our [guide](/guides/gnutls) on how to initiate a secure TLS connection.

</div></div>
<div class="section"><div class="container" markdown="1">

## 1.) Retrieve the TLS server's certificate chain with its size

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

/* Convert the array of certificates in gnutls_datum_t structures to the array of certificates in gnutls_crt_t structures. */
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

After obtaining the certificate chain, it is possible to print any certificate from the chain to the stdout. Possible printing options are `GNUTLS_CRT_PRINT_FULL`, `GNUTLS_CRT_PRINT_ONELINE`,   `GNUTLS_CRT_PRINT_UNSIGNED_FULL`, `GNUTLS_CRT_PRINT_COMPACT`, `GNUTLS_CRT_PRINT_FULL_NUMBERS`.

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

## 2.) Verify each certificate in the certificate chain

Verification of each certificate from TLS server's certificate chain should be performed (except the root one).

```c
/* For each certificate in certificate chain (except the root one), perform OCSP revocation check. */
/* That includes finding the URL address of OCSP Responder for each certificate, generating and sending OCSP Request,
* retrieving and processing OCSP Response, verifying the signature of OCSP Response and finally checking the
* revocation status for each certificate.
*/
gnutls_x509_crt_t certificate;
gnutls_x509_crt_t issuer_certificate;
for (int index = 0; index < chain_size - 1; index++) {
    certificate = server_chain_crt[index];
    issuer_certificate = server_chain_crt[index + 1];

    /* Perform verification of a single certificate according to the following steps. */
}
```

</div></div>
<div class="section"><div class="container" markdown="1">

## 3.) Extract the URL Adress of OCSP Responder

After obtaining a single certificate with the certificate of its issuer, extract the URL address of OCSP Responder from the certificate's authority information access extension.

```c
/* The received OCSP Responder URL will be stored in this variable. */
gnutls_datum_t ocsp_responder_uri_datum = { 0 };

/* If there are multiple records with the same extension specified. */
int act_index = 0;
int ret;

while (1) {
    /* Parse the URL adress from the certificate's extension called authority information access. */
    ret = gnutls_x509_crt_get_authority_info_access(certificate, act_index, GNUTLS_IA_OCSP_URI, &ocsp_responder_uri_datum, NULL);

    /* Requested OID of the Authorify Info Access extension does not match, call again with another index. */
    if (ret == GNUTLS_E_UNKNOWN_ALGORITHM)
    {
        act_index++;
        continue;
    }

    /* Index out of bounds. */
    if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
    {
        break;
    }
    if (ret < 0)
    {
        /* Error occured! */
        exit(EXIT_FAILURE);
    }

    /* No error occured, we have succesfully parsed the URL from AIA extension. */
    break;
}

/* No URL of OCSP Responder has been found. */
if (ocsp_responder_uri_datum == NULL) {
    exit(EXIT_SUCCESS);
}

/* Convert the received URL of OCSP Responder to string (char *). */
char *ocsp_responder_uri = (char *) gnutls_malloc((ocsp_responder_uri_datum.size + 1) * sizeof(char));
if (ocsp_responder_uri == NULL) {
    exit(EXIT_FAILURE);
}

memcpy(ocsp_responder_uri, ocsp_responder_uri_datum.data, ocsp_responder_uri_datum.size);
ocsp_responder_uri[ocsp_responder_uri_datum.size] = 0;
```

### Relevant links

- [gnutls_x509_crt_get_authority_info_access](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005fx509_005fcrt_005fget_005fauthority_005finfo_005faccess) (GnuTLS docs)

</div></div>
<div class="section"><div class="container" markdown="1">

## 4.) Generate the OCSP Request

Generate the OCSP Request for the certificates we want to verify. In this case, it is the single certificate retrieved from the certificate chain.

```c
/* Initialize empty ocsp_req_t structure for storing the OCSP Request. */
gnutls_ocsp_req_t ocsp_req;
if (gnutls_ocsp_req_init(&ocsp_req) < 0) {
    exit(EXIT_FAILURE);
}

/* Add the serial number of the certificate we want to check, its issuer' name and issuer' key. */
/* Serial number and issuer's name and key are parsed from the supplied certificates. */
/* Fields are hashed with the supplied hashing algorithm (gnutls_digest_algorithm_t enum). */
if (gnutls_ocsp_req_add_cert(ocsp_req, GNUTLS_DIG_SHA1, issuer_certificate, certificate) < 0) {
    exit(EXIT_FAILURE);
}

/* Add or update a nonce extension of the OCSP request with newly generated random value. */
if (gnutls_ocsp_req_randomize_nonce(ocsp_req) < 0) {
    exit(EXIT_FAILURE);
}

/* Retrieve value of the nonce from the OCSP request.  */
/* This value will be later compared to the nonce value sent from OCSP Responder. */
gnutls_datum_t nonce_req = { 0 };
if (gnutls_ocsp_req_get_nonce(ocsp_req, NULL, &nonce_req) < 0) {
    exit(EXIT_FAILURE);
}
```

### Relevant links

- [gnutls_ocsp_req_init](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005focsp_005freq_005finit) (GnuTLS docs)
- [gnutls_ocsp_req_add_cert](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005focsp_005freq_005fadd_005fcert) (GnuTLS docs)
- [gnutls_ocsp_req_randomize_nonce](https://gnutls.org/manual/gnutls.html#index-gnutls_005focsp_005freq_005frandomize_005fnonce) (GnuTLS docs)
- [gnutls_ocsp_req_get_nonce](https://gnutls.org/manual/gnutls.html#index-gnutls_005focsp_005freq_005fget_005fnonce) (GnuTLS docs)

</div></div>
<div class="section"><div class="container" markdown="1">

{:.text-success}

## Optional: Pretty print information about the OCSP Request

After generating the OCSP Request, we can print the request to stdout.
Possible obtions are `GNUTLS_OCSP_PRINT_FULL`, `GNUTLS_OCSP_PRINT_COMPACT`.

```c
gnutls_datum_t ocsp_req_pretty_print = { 0 };
if (gnutls_ocsp_req_print(ocsp_req, GNUTLS_OCSP_PRINT_FULL, &ocsp_req_pretty_print) < 0) {
    exit(EXIT_FAILURE);
}
printf("%s\n", ocsp_req_pretty_print.data);
gnutls_free(ocsp_req_pretty_print.data);
```

### Relevant links

- [gnutls_ocsp_req_print](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005focsp_005freq_005fprint) (GnuTLS docs)

</div></div>
<div class="section"><div class="container" markdown="1">

## 5.) Send the OCSP Request and retrieve the OCSP Response

Send the generated OCSP Request to the OCSP Responder's URL. Subsequently, the OCSP Response sent from the OCSP Responder will be received. The response is stored in the program's memory.

This step establishes an out-of-band connection with the OCSP Responder.

In our example, the cURL library is used to establish such a connection. Curl is able to send an HTTP POST Request with the OCSP Request header.

```c
/* Export OCSP Request from gnutls_ocsp_req_t structure to gnutls_datum_t structure. */
gnutls_datum_t ocsp_req_datum_DER = { 0 };
if (gnutls_ocsp_req_export(ocsp_req, &ocsp_req_datum_DER) < 0) {
    exit(EXIT_FAILURE);
}

/* Initialize the structure where the retrieved OCSP Response will be placed. */
gnutls_datum_t ocsp_response_datum = { 0 };

/* Initialize the curl. */
curl_global_init(CURL_GLOBAL_ALL);
CURL *handle = curl_easy_init();
if (handle == NULL) {
    exit(EXIT_FAILURE);
}

/* Add ocsp header to the HTTP POST Request. */
struct curl_slist *headers = curl_slist_append(headers, "Content-Type: application/ocsp-request");
if (headers == NULL) {
    exit(EXIT_FAILURE);
}

/* Tell curl which data we want to send (in our case OCSP Request data). */
curl_easy_setopt(handle, CURLOPT_POSTFIELDS, ocsp_req_datum_DER.data);
/* Tell curl the size of the data we want to send (size of the OCSP Request). */
curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE, ocsp_req_datum_DER.size);
/* Tell curl the URL, location where the data should be send. */
curl_easy_setopt(handle, CURLOPT_URL, ocsp_responder_uri);
/* Add our custom HTTP headers. */
curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers);
/* Tell curl to write each chunk of data (our OCSP Response) with this function callback. */
curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, get_data);
/* Tell curl to write each chunk of data to the given location, in our case, to the variable in the memory. */
curl_easy_setopt(handle, CURLOPT_WRITEDATA, &ocsp_response_datum);

/* Send the request. */
if (curl_easy_perform(handle) != 0) {
    exit(EXIT_FAILURE);
}

/* Convert the retrieved OCSP Response from gnutls_datum_t structure to gnutls_ocsp_resp_t structure. */
if (gnutls_ocsp_resp_init(&ocsp_response) < 0) {
    exit(EXIT_FAILURE);
}
if (gnutls_ocsp_resp_import(ocsp_response, &ocsp_response_datum) < 0) {
    exit(EXIT_FAILURE);
}
```

We provide a simple example of a callback function used by curl (assigned to curl with the option `CURLOPT_WRITEFUNCTION`) during the process of receiving the OCSP Response. This function gets invoked whenever a new chunk of data has been received and needs to be saved. More information can be found [here](https://curl.se/libcurl/c/CURLOPT_WRITEFUNCTION.html).

```c
size_t get_data(void *buffer, size_t size, size_t nmemb, void *userp) {
    /* Already processed data from previous transfers. */
    gnutls_datum_t *ud = (gnutls_datum_t *) userp;

    /* nmemb bytes of new data. */
    size *= nmemb;

    /* Reallocate the buffer containing the previous data so that it can also accommodate nmemb bytes of new data. */
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
- [gnutls_ocsp_req_export](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005focsp_005freq_005fexport) (GnuTLS docs)
- [gnutls_ocsp_resp_init](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005focsp_005fresp_005finit) (GnuTLS docs)
- [gnutls_ocsp_resp_import](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005focsp_005fresp_005fimport) (GnuTLS docs)

</div></div>
<div class="section"><div class="container" markdown="1">

{:.text-success}

## Optional: Pretty print information about the OCSP Response

After obtaining the OCSP Response, we can print the response to stdout.
Possible obtions are `GNUTLS_OCSP_PRINT_FULL`, `GNUTLS_OCSP_PRINT_COMPACT`.

```c
gnutls_datum_t ocsp_response_pretty_print;
if (gnutls_ocsp_resp_print(ocsp_response, GNUTLS_OCSP_PRINT_COMPACT, &ocsp_response_pretty_print) < 0) {
    exit(EXIT_FAILURE);
}
printf("%s\n", ocsp_response_pretty_print.data);
gnutls_free(ocsp_response_pretty_print.data);
```

### Relevant links

- [gnutls_ocsp_resp_print](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005focsp_005fresp_005fprint) (GnuTLS docs)

</div></div>
<div class="section"><div class="container" markdown="1">

## 6.) Verify the signature of the OCSP Response

The OCSP Response needs to be verified against some set of trust anchors before it can be relied upon.
It is also important to check whether the received OCSP Response corresponds to the certificate being checked.

```c
/* Check the status of OCSP response (as gnutls_ocsp_resp_status_t enum). */
if (gnutls_ocsp_resp_get_status(ocsp_response) != GNUTLS_OCSP_RESP_SUCCESSFUL) {
    exit(EXIT_FAILURE);
}

/* Check whether the OCSP response is about the provided certificate. */
if (gnutls_ocsp_resp_check_crt(ocsp_response, 0, certificate) < 0) {
    exit(EXIT_FAILURE);
}

/* Extract the nonce extension from the OCSP response. */
gnutls_datum_t nonce_resp = { 0 };
if (gnutls_ocsp_resp_get_nonce(ocsp_response, NULL, &nonce_resp) != 0) {
    /* Nonce extension is not present in the OCSP response */
    exit(EXIT_FAILURE);
}

/* Check that the nonces from the OCSP request and the OCSP response are the same. */
if (nonce_req.size != nonce_resp.size || memcmp(nonce_req.data, nonce_resp.data, nonce_resp.size) != 0) {
    exit(EXIT_FAILURE);
}

/* Verify signature of the Basic OCSP Response against the public key in the issuer's certificate. */
/* Output variable (0 if signature matches) as gnutls_ocsp_verify_reason_t enum. */
unsigned int verify_result;
if (gnutls_ocsp_resp_verify_direct(ocsp_response, issuer_certificate_crt, &verify_result, 0) < 0) {
    exit(EXIT_FAILURE);
}

if (verify_result != 0) {
    /* Verification of signature of the OCSP Response has failed. */
    exit(EXIT_FAILURE);
}
```

### Relevant links

- [gnutls_ocsp_resp_get_status](https://gnutls.org/manual/gnutls.html#gnutls_005focsp_005fresp_005fget_005fstatus-1) (GnuTLS docs)
- [gnutls_ocsp_resp_check_crt](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005focsp_005fresp_005fcheck_005fcrt) (GnuTLS docs)
- [gnutls_ocsp_resp_get_nonce](https://gnutls.org/manual/gnutls.html#index-gnutls_005focsp_005fresp_005fget_005fnonce) (GnuTLS docs)
- [gnutls_ocsp_resp_verify_direct](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005focsp_005fresp_005fverify_005fdirect) (GnuTLS docs)

</div></div>
<div class="section"><div class="container" markdown="1">

{:.text-success}

## Optional: Checking the result of OCSP Response signature verification

If OCSP Response verification has failed, it is possible to examine exact reason why the verification failed.

```c
if (verify_result & GNUTLS_OCSP_VERIFY_SIGNER_NOT_FOUND) {
    /* Signer cert not found. */
}
if (verify_result & GNUTLS_OCSP_VERIFY_SIGNER_KEYUSAGE_ERROR) {
    /* Signer keyusage bits incorrect. */
}
if (verify_result & GNUTLS_OCSP_VERIFY_UNTRUSTED_SIGNER) {
    /* Signer is not trusted. */
}
if (verify_result & GNUTLS_OCSP_VERIFY_INSECURE_ALGORITHM) {
    /* Signature using insecure algorithm. */
}
if (verify_result & GNUTLS_OCSP_VERIFY_SIGNATURE_FAILURE) {
    /* Signature mismatch. */
}
if (verify_result & GNUTLS_OCSP_VERIFY_CERT_NOT_ACTIVATED) {
    /* Signer cert is not yet activated. */
}
if (verify_result & GNUTLS_OCSP_VERIFY_CERT_EXPIRED) {
    /* Signer cert has expired. */
}
```

</div></div>
<div class="section"><div class="container" markdown="1">

## 7.) Extract the revocation status from the OCSP Response

After the signature of the OCSP Response has been verified, the revocation status of the certificates included in the response can be safely examined. Except for the revocation status of the certificates, the OCSP Response also contains some other useful information.

Note: Native structure `gnutls_ocsp_resp_t` can contain multiple OCSP Responses. That is why we must also specify the index of the OCSP Response, which we are interested in. However, in our case, the structure contains only one OCSP Response.

```c
/* Retrieve the revocation status of the certificate. */
/* Specifies response number to get, 0 means the first one. */
unsigned int index = 0;
/* Hash algoritm used when hashing issuer's name and key. */
gnutls_digest_algorithm_t hash_algorithm;
/* Hash of the issuer's name will be stored here. */
gnutls_datum_t issuer_name_hash;
/* Hash of the issuer's key will be stored here. */
gnutls_datum_t issuer_key_hash;
/* Serial number of the certificate that was checked. */
gnutls_datum_t serial_number;
/* Certificate status as gnutls_ocsp_cert_status_t enum. */
unsigned int cert_status;
/* If cert_status is GNUTLS_OCSP_CERT_REVOKED, then this variable holds time of revocation. */
time_t revocation_time;
/* If cert_status is GNUTLS_OCSP_CERT_REVOKED, then this variable holds gnutls_x509_crl_reason_t enum value. */
unsigned int revocation_reason;

if (gnutls_ocsp_resp_get_single(ocsp_response, index, &hash_algorithm, &issuer_name_hash, &issuer_key_hash, &serial_number, &cert_status, NULL, NULL, &revocation_time, &revocation_reason) < 0) {
    exit(EXIT_FAILURE);
}

if (cert_status & GNUTLS_OCSP_CERT_GOOD) {
    /* Certificate is not Revoked. */
}

if (cert_status & GNUTLS_OCSP_CERT_UNKNOWN) {
    /* Unknown status of the certificate. */
}

if (cert_status & GNUTLS_OCSP_CERT_REVOKED) {
    /* Certificate is Revoked. */
    /* Can further inspect the revocation reason. */
}
```

### Relevant links

- [gnutls_ocsp_resp_get_single](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005focsp_005fresp_005fget_005fsingle-1) (GnuTLS docs)
- [gnutls_x509_crl_reason_t enumeration](https://www.gnutls.org/manual/gnutls.html#gnutls_005fx509_005fcrl_005freason_005ft) (GnuTLS docs)

</div></div>
<div class="section"><div class="container" markdown="1">

## 8.) Deinitialize

Free the previously allocated structures, which are no longer required.

```c
/* Deinitialize. */
for (int i = 0; i < chain_size; i++) {
    gnutls_x509_crt_deinit(server_chain_crt[i]);
}
gnutls_free(server_chain_crt);
gnutls_free(ocsp_responder_uri_datum.data);
curl_easy_cleanup(handle);
curl_slist_free_all(headers);
gnutls_free(ocsp_responder_uri);
gnutls_free(ocsp_req_datum_DER.data);
gnutls_free(ocsp_response_datum.data);
gnutls_free(nonce_req.data)
gnutls_free(nonce_resp.data)
gnutls_free(issuer_name_hash.data);
gnutls_free(issuer_key_hash.data);
gnutls_free(serial_number.data);
gnutls_ocsp_req_deinit(ocsp_req);
gnutls_ocsp_resp_deinit(ocsp_response);
```

### Relevant links

- [gnutls_x509_crt_deinit](https://gnutls.org/manual/gnutls.html#gnutls_005fx509_005fcrt_005fdeinit) (GnuTLS docs)
- [gnutls_ocsp_req_deinit](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005focsp_005freq_005fdeinit) (GnuTLS docs)
- [gnutls_ocsp_resp_deinit](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005focsp_005fresp_005fdeinit) (GnuTLS docs)

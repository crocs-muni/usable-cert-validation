---
layout:     default
title:      "Developer guide: GnuTLS, Revocation with CRL"
slug:       gnutls-crl
---

<div class="section"><div class="container" markdown="1">

{:#{{ page.slug }}}

# {{ page.title }}

{:.lead}
This guide covers the implementation of certificate revocation status checking using the Certificate Revocation List (CRL) revocation scheme. Official documentation of GnuTLS dealing with this topic can be found [here](https://www.gnutls.org/manual/html_node/Verifying-X_002e509-certificate-paths.html#Verifying-X_002e509-certificate-paths), and a similar example from GnuTLS can be found [here](https://www.gnutls.org/manual/html_node/Advanced-certificate-verification-example.html#Advanced-certificate-verification-example).

</div></div>
<div class="section"><div class="container" markdown="1">

**Short description of revocation scheme:**
A Certificate Revocation List (CRL) is a list of revoked certificates issued by a certification authority (CA). The CA can have multiple CRLs, each of which is signed with the private key of the corresponding CA. The CA then publishes its CRLs to HTTP or LDAP servers. Each X.509v3 certificate that supports CRL contains an extension called CRL distribution point, which stores a link to servers containing these CRLs in which the certificate should be located if it was previously revoked. When verifying the certificate with this scheme, the TLS client must look at the required extension of the certificate, obtain the address where the CRLs of the CA are located, download these lists and check their signatures. After the signature is validated, the TLS client can search the certificate against the CRL.

CRLs are defined in [RFC 5280](https://www.rfc-editor.org/info/rfc5280).
CRLs on [Wikipedia](https://en.wikipedia.org/wiki/Certificate_revocation_list).

**Summary of this guide:**

1. Retrieve the TLS server's certificate chain with its size
2. Initialize an empty trusted list
   - `gnutls_x509_trust_list_t` structure is used to represent the trusted list
   - general structure, which should be filled with **trusted** CA certificates and **trusted** CRLs.
   - one of its tasks is to validate that the given certificate is not present in one of the CRLs which were added to the trusted list
3. Fill the trusted list with trusted CA certificates
   - in our example, default system trusted CA certificates are used
4. Fill the trusted list with trusted CRLs
   - in our example, CRLs are downloaded from the distribution point extensions for each certificate in the chain
   - for each downloaded CRL, its signature should be verified, so the CRL can be considered trusted and subsequently added to the trusted list
5. Verify the TLS server's certificate chain against the filled trusted list
6. Deinitialize

The only prerequisite for this guide is that the `gnutls_session_t session` variable has already been initialized. This session variable represents the current TLS session, which could have already been established, or the session is currently in the TLS handshake phase. For more information, see our [guide](https://x509errors.org/guides/gnutls) on how to initiate a secure TLS connection.

</div></div>
<div class="section"><div class="container" markdown="1">

## 1.) Retrieve the TLS server's certificate chain with its size

First, we need to obtain the certificate chain from the TLS connection.

```c
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

/* Retrieve the entire chain of certificates stored in array of gnutls_datum_t structures */
/* Each certificate is stored in DER format */
/* Leaf node certificate is placed at index 0, its issuer at index 1, etc. */
unsigned int server_chain_size = 0;
const gnutls_datum_t *server_chain_der = gnutls_certificate_get_peers(session, &server_chain_size);
if (server_chain_der == NULL) {
    exit(EXIT_FAILURE);
}

/* Convert the certificate array of gnutls_datum_t structures to certificate array of gnutls_crt_t structures */
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

## Optional: Pretty print any certificate from the certificate chain

After obtaining the certificate chain, it is possible to print any certificate from the chain to the stdout. Possible printing options are `GNUTLS_CRT_PRINT_FULL`, `GNUTLS_CRT_PRINT_ONELINE`,   `GNUTLS_CRT_PRINT_UNSIGNED_FULL`, `GNUTLS_CRT_PRINT_COMPACT`, `GNUTLS_CRT_PRINT_FULL_NUMBERS`.

```c
/* For example, get the leaf server's certificate from the chain */
gnutls_x509_crt_t server_certificate = server_chain_crt[0];

/* Print the server's certificate to stdout */
gnutls_datum_t server_cert_pretty;
gnutls_x509_crt_print(server_chain_crt[0], GNUTLS_CRT_PRINT_ONELINE, &server_cert_pretty);
printf("%s\n", server_cert_pretty.data);
gnutls_free(server_cert_pretty.data);
```

### Relevant links

- [gnutls_x509_crt_print](https://gnutls.org/manual/gnutls.html#index-gnutls_005fx509_005fcrt_005fprint) (GnuTLS docs)

</div></div>
<div class="section"><div class="container" markdown="1">

## 2.) Initialize an empty trusted list

We initialize an empty structure called a trusted list. During the next steps, this trusted list will be filled with the trusted certificates of Certificate Authorities (CAs) and with the CRLs issued by these authorities. The certificate chain is subsequently verified by this filled trusted list. This will perform a CRL revocation check.

```c
/* Trusted list is in GnuTls represented with the gnutls_x509_trust_list_t structure */
gnutls_x509_trust_list_t trusted_list;
gnutls_x509_trust_list_init(&trusted_list, 0);
```

### Relevant Links

- [gnutls_509_trust_list_init](https://gnutls.org/manual/gnutls.html#index-gnutls_005fx509_005ftrust_005flist_005finit) (GnuTLS docs)

</div></div>
<div class="section"><div class="container" markdown="1">

## 3.) Fill the trusted list with trusted CA's certificates

Fill the trusted list with the certificates of trusted certificate authorities (CAs). For this purpose, the default system certificates are used.

```c
/* Add the system's default trusted certificate authorities to the trusted list. */
/* Function returns number of added elements or negative error code on failure. */
if (gnutls_x509_trust_list_add_system_trust(trusted_list, 0, 0) <= 0) {
    exit(EXIT_FAILURE);
}
```

### Relevant links

- [gnutls_x509_trust_list_add_system_trust](https://gnutls.org/manual/gnutls.html#index-gnutls_005fx509_005ftrust_005flist_005fadd_005fsystem_005ftrust-1) (GnuTLS docs)

</div></div>
<div class="section"><div class="container" markdown="1">

## 4.) Fill the trusted list with trusted CRLs

During this step, the trusted list should be filled with trusted CRLs. These trusted CRLs are downloaded from URLs that are stored in the crl distribution point extension of X509 certificate. Downloading takes place through all certificates in the certification chain (excluding the root one), where each certificate could contain multiple distribution points. After downloading each CRL, it is necessary to verify its signature.

```c
gnutls_x509_crt_t certificate;
gnutls_x509_crt_t issuer_certificate

for (int index = 0; index < server_chain_size - 1; index++) {
    certificate = server_chain_crt[index];
    issuer_certificate = server_chain_crt[index + 1];

    download_crls_single_certificate(trusted_list, certificate, issuer_certificate);
}
```

To download the CRL, it is necessary to establish an out-of-band connection with the server on which the given CRL is located. In our example, the cURL library is used for this purpose. Curl is able to send HTTP GET Request to the server and save the downloaded CRL to the programs' memory.

```c
#include <curl/curl.h>

void download_crls_single_certificate(gnutls_x509_trust_list_t trusted_list, gnutls_x509_crt_t certificate, gnutls_x509_crt_t issuer_certificate) {

    /* Prepare buffer for storing the URL adress for one CRL distribution point */
    size_t buffer_crl_dist_point_size = 1024;
    char *buffer_crl_dist_point = (char *) calloc(buffer_crl_dist_point_size, sizeof(char));
    if (buffer_crl_dist_point == NULL) {
        exit(EXIT_FAILURE);
    }

    /* Prepare gnutls_datum_t structure, where the downloaded CRL in DER format will be stored */
    gnutls_datum_t downloaded_crl_DER = { 0 };

    /* Prepare the native gnutls_x509_crl_t structure where the downloaded CRL will be imported */
    gnutls_x509_crl_t downloaded_crl = { 0 };
    if (gnutls_x509_crl_init(&downloaded_crl) < 0) {
        exit(EXIT_FAILURE);
    }

    /* Prepare and initialize the curl for making out-of-band connection and downloading CRLs from distribution point. */
    curl_global_init(CURL_GLOBAL_ALL);
    CURL *handle = curl_easy_init();
    if (handle == NULL) {
        exit(EXIT_FAILURE);
    }

    /* Tell curl to write each chunk of data (our CRL list during downloading) with this function callback */
    curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, get_data);
    /* Tell curl to write each chunk of data to the given location, in our case, to the variable in the memory */
    curl_easy_setopt(handle, CURLOPT_WRITEDATA, &downloaded_crl_DER);

    /* Each certificate can have more than one CRL distribution point entry */
    /* This cycle will iterate through every distribution point, until GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE will be returned */
    unsigned int revocation_reasons;
    int dist_points_index= 0;
    int ret;
    while (1) {
        ret = gnutls_x509_crt_get_crl_dist_points(certificate, dist_points_index, buffer_crl_dist_point, &buffer_crl_dist_point_size, &revocation_reasons, NULL);

        if (ret == GNUTLS_E_SHORT_MEMORY_BUFFER) {
            /* If buffer for storing URL of Distribution point is not big enough, reallocate it with returned required size */
            buffer_crl_dist_point = (char *) realloc(buffer_crl_dist_point, buffer_crl_dist_point_size);
            if (buffer_crl_dist_point == NULL)
            {
                exit(EXIT_FAILURE);
            }
            continue;
        }

        if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
            break;
        }

        /* Other error occured */
        if (ret < 0) {
            exit(EXIT_FAILURE);
        }

        /* Successfully parsed the distribution point (at actual index) */

        /* Tell curl to download CRL from the retrieved distribution point URL */
        curl_easy_setopt(handle, CURLOPT_URL, buffer_crl_dist_point);

        /* Start downloading */
        if (curl_easy_perform(handle) != 0) {
            exit(EXIT_FAILURE);
        }

        /* Download finished and successful */

        /* Convert the downloaded CRL from structure gnutls_datum_t to structure gnutls_crl_t */
        if (gnutls_x509_crl_import(downloaded_crl, &downloaded_crl_DER, GNUTLS_X509_FMT_DER) < 0) {
            exit(EXIT_FAILURE);
        }

        /* Verify the signature of the downloaded CRL against issuer's certificate */
        if (gnutls_x509_crl_check_issuer(downloaded_crl, issuer_certificate) != 1) {
            exit(EXIT_FAILURE);
        }

        /* Add downloaded DER encoded CRL to the trusted list */
        /* Function returns the number of added elements */
        if (gnutls_x509_trust_list_add_trust_mem(trusted_list, NULL, &downloaded_crl_DER, GNUTLS_X509_FMT_DER, 0, 0) <= 0 {
            exit(EXIT_FAILURE);
        }

        /* Deinitialize and set variables after each loop */
        gnutls_free(downloaded_crl_DER.data);
        downloaded_crl_DER.data = NULL;
        downloaded_crl_DER.size = 0;

        memset(buffer_crl_dist_point, 0, buffer_crl_dist_point_size);
        dist_points_index++;
    }

    /* If the current certificate has no CRL distribution point entry in its extensions, CRL revocation check could not be performed */
    /* If server's certificate has not a single CRL distribution point, we can not provide CRL revocation check */
    if (dist_points_index == 0) {
        fprintf(stderr, "No distribution point has been found\n");
        exit(EXIT_SUCCESS);
    }

    /* Deinitialize before leaving function */
    free(buffer_crl_dist_point);
    gnutls_x509_crl_deinit(downloaded_crl);
    curl_easy_cleanup(handle);
}
```

We provide a simple example of a callback function used by curl (assigned to curl with the option `CURLOPT_WRITEFUNCTION`) during the download process of the CRLs. This function gets invoked whenever a new chunk of CRL data has been received and needs to be saved. More information can be found [here](https://curl.se/libcurl/c/CURLOPT_WRITEFUNCTION.html).

```c
size_t get_data(void *buffer, size_t size, size_t nmemb, void *userp) {
    /* Already processed data from previous transfers */
    gnutls_datum_t *ud = (gnutls_datum_t *) userp;

    /* nmemb bytes of new data */
    size *= nmemb;

    /* Reallocate the buffer containing the previous data so that it can also accommodate nmemb of new data */
    ud->data = realloc(ud->data, ud->size + size);
    if (ud->data == NULL) {
        exit(EXIT_FAILURE);
    }

    /* Append nmemb new bytes to the previous data */
    memcpy(&ud->data[ud->size], buffer, size);
    ud->size += size;

    return size;
}
```

After this step, our trusted list should be filled with trusted CA certificates and CRLs.

### Relevant links

- [cURL](https://curl.se/libcurl/c/libcurl-tutorial.html) (libcurl programming tutorial)
- [gnutls_x509_crl_init](https://gnutls.org/manual/gnutls.html#index-gnutls_005fx509_005fcrl_005finit) (GnuTLS docs)
- [gnutls_x509_crt_get_crl_dist_points](https://gnutls.org/manual/gnutls.html#index-gnutls_005fx509_005fcrt_005fget_005fcrl_005fdist_005fpoints) (GnuTLS docs)
- [gnutls_x509_crl_import](https://gnutls.org/manual/gnutls.html#index-gnutls_005fx509_005fcrl_005fimport) (GnuTLS docs)
- [gnutls_x509_crl_check_issuer](https://gnutls.org/manual/gnutls.html#index-gnutls_005fx509_005fcrl_005fcheck_005fissuer) (GnuTLS docs)
- [gnutls_x509_trust_list_add_trust_mem](https://gnutls.org/manual/gnutls.html#index-gnutls_005fx509_005ftrust_005flist_005fadd_005ftrust_005fmem-1) (GnuTLS docs)

</div></div>
<div class="section"><div class="container" markdown="1">

## 5.) Verify the certificate chain against the filled trusted list

Verify the certificate chain against the filled trusted list. When a certificate chain with more than one certificate is provided, and the verification fails, the verification result is applied to the first certificate in the chain that failed verification.

```c
/* Verify the server's chain against filled trusted list */
unsigned int verify_output;
if (gnutls_x509_trust_list_verify_crt(trusted_list, server_chain_crt, server_chain_size, 0, &verify_output, NULL) != 0) {
    exit(EXIT_FAILURE);
}

/* The GNUTLS_CERT_INVALID flag is always set on a verification error */
/* More detailed flags (gnutls_certificate_status_t) will also be set when appropriate */
if (verify_output & GNUTLS_CERT_INVALID) {
    if (verify_output & GNUTLS_CERT_REVOKED) {
        /* Certificate chain is revoked */
    }
    else {
        /* Other verification error */
    }
}
else {
    /* No verification error */
}
```

### Relevant link

- [gnutls_x509_trust_list_verify_crt](https://gnutls.org/manual/gnutls.html#index-gnutls_005fx509_005ftrust_005flist_005fverify_005fcrt-1) (GnuTLS docs)
- [gnutls_certificate_status_t enumeration](https://www.gnutls.org/manual/gnutls.html#gnutls_005fcertificate_005fstatus_005ft) (GnuTLS docs)

</div></div>
<div class="section"><div class="container" markdown="1">

## 6.) Deinitialize

Free the previously allocated structures, which are no longer required.

```c
for (int i=0; i < server_chain_size; i++) {
    gnutls_x509_crt_deinit(server_chain_crt[i]);
}
gnutls_free(server_chain_crt);
gnutls_x509_trust_list_deinit(trusted_list, 1);
```

### Relevant links

- [gnutls_x509_crt_deinit](https://gnutls.org/manual/gnutls.html#gnutls_005fx509_005fcrt_005fdeinit) (GnuTLS docs)
- [gnutls_x509_crl_deinit](https://gnutls.org/manual/gnutls.html#index-gnutls_005fx509_005fcrl_005fdeinit) (GnuTLS docs)

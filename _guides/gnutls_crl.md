---
layout:     default
title:      "Developer guide: GnuTLS, Revocation with CRL"
slug:       gnutls-crl
---

<div class="section"><div class="container" markdown="1">

{:#{{ page.slug }}}
# {{ page.title }}

{:.lead}
This guide covers the implementation of certificate revocation status checking using the Certificate Revocation List (CRL) revocation scheme. Official documentation of GnuTLS dealing with this topic can be found [here](https://www.gnutls.org/manual/html_node/Verifying-X_002e509-certificate-paths.html#Verifying-X_002e509-certificate-paths) and similar example from GnuTLS can be found [here](https://www.gnutls.org/manual/html_node/Advanced-certificate-verification-example.html#Advanced-certificate-verification-example).


</div></div>
<div class="section"><div class="container" markdown="1">


**Short description of revocation scheme:**
A Certificate Revocation List (CRL) is a list of revoked certificates previously issued by a CA. The CA can have multiple CRLs, each of which is signed with the private key of the corresponding CA. The CA authority then publishes its CRLs to HTTP or LDAP servers. Each X.509v3 certificate, that supports CRL, contains an extension called CRL distribution point, which stores a link to servers containing CRLs in which the certificate should be located. When verifying the TLS server’s certificate with this scheme, the TLS client must look at the required extension of the server’s certificate, obtain the address where the CRLs of the CA are located, and then download these lists and check their signatures. After the signature is validated, the TLS client can search the server’s certificate against the CRL.

CRLs are defined in [RFC 5280](https://www.rfc-editor.org/info/rfc5280).
CRLs on [Wikipedia](https://en.wikipedia.org/wiki/Certificate_revocation_list).


**Summary of this guide:**
1. Retrieve the server's certificate chain with its size
   - from the chain, we will parse the TLS server's certificate with the certificate of its issuer
2. Initialize empty trusted list
   - `gnutls_x509_trust_list_t` structure is used to represent the trusted list
   - general structure, which should be filled with **trusted** CA certificates and **trusted** CRLs and its main task is to validate the given certificate and verify it against the provided trusted CRLs
3. Fill trusted list with trusted CA's certificates
   - default system trusted CA's certificates are used
4. Fill trusted list with trusted CRLs
   - we will download all CRLs found in the CRL distribution point extension from the TLS server's certificate
   - we will validate their signature and thus, they can be considered trusted and added to the trusted list
5. Verify the TLS server's certificate against the filled trusted list
6. Deinitialize

We assume that the TLS client-server connection has already been established, that is, the client has access to the TLS server's certificate. In other words, we assume that the variable `gnutls_session_t session` represents an already established connection. TLS client-server initialization guide can be found [here](https://x509errors.org/guides/gnutls).


</div></div>
<div class="section"><div class="container" markdown="1">


## 1.) Retrieve the TLS server's certificate chain with its size

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
    exit(EXIT_FAILURE);
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
gnutls_x509_crt_print(server_chain_crt[0], GNUTLS_CRT_PRINT_ONELINE, &server_cert_pretty);
printf("%s\n", server_cert_pretty.data);
gnutls_free(server_cert_pretty.data);
```

### Relevant links

* [gnutls_x509_crt_print](https://gnutls.org/manual/gnutls.html#index-gnutls_005fx509_005fcrt_005fprint) (GnuTLS docs)


</div></div>
<div class="section"><div class="container" markdown="1">


## 2.) Initialize empty trusted list

We initialize an empty so-called 'trusted list'. Later, we will fill this trusted list with trusted certificates of certificate authorities and with their trusted CRL lists. The TLS server's certificate is then verified against these trusted CA's certificates and the supplied CRLs. This will perform a CRL revocation check.

```c
/* Trusted list is in GnuTls represented with the gnutls_x509_trust_list_t structure */
gnutls_x509_trust_list_t trusted_list;
gnutls_x509_trust_list_init(&trusted_list, 0);
```

### Relevant Links

* [gnutls_509_trust_list_init](https://gnutls.org/manual/gnutls.html#index-gnutls_005fx509_005ftrust_005flist_005finit) (GnuTLS docs)


</div></div>
<div class="section"><div class="container" markdown="1">


## 3.) Fill trusted list with trusted CA's certificates

Fill empty trusted list with the certificates of trusted CAs. For this purpose, we will use system certificates, which are stored locally.

```c
if (gnutls_x509_trust_list_add_system_trust(trusted_list, 0, 0) <= 0)
{
    exit(EXIT_FAILURE);
}
```

### Relevant links

* [gnutls_x509_trust_list_add_system_trust](https://gnutls.org/manual/gnutls.html#index-gnutls_005fx509_005ftrust_005flist_005fadd_005fsystem_005ftrust-1) (GnuTLS docs)


</div></div>
<div class="section"><div class="container" markdown="1">


## 4.) Fill trusted list with trusted CRLs

Fill the trusted list with CRLs that a TLS server's certificate has in the crl distribution point extension. The CRL's signature is verified against the issuer's certificate.

One certificate can easily have multiple entries in the crl distribution point extension.

In this step, an out-of-band connection is always made to a different CRL server for each crl distribution point. From the CRL server, the CRL file is downloaded and stored into the program's memory.

The cURL library is used for out-of-band connection to the CRL server, which sends a HTTP Get Request.

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

/* Prepare the buffer for storing one URL adress parsed from CRL distribution point */
size_t buffer_crl_dist_point_size = 1024;
char *buffer_crl_dist_point = (char *) calloc(buffer_crl_dist_point_size, sizeof(char));
if (buffer_crl_dist_point == NULL)
{
    exit(EXIT_FAILURE);
}

/* Prepare gnutls_datum_t structure, where the downloaded CRL in DER format will be stored */
gnutls_datum_t actual_one_CRL = { 0 };

/* Prepare the native gnutls_x509_crl_t structure where the downloaded CRL from DER format will be imported */
gnutls_x509_crl_t actual_one_CRL_crl;
if (gnutls_x509_crl_init(&actual_one_CRL_crl) != 0)
{
    exit(EXIT_FAILURE);
}

/* Prepare the curl for making out-of-band connection and downloading CRLs from distribution point */
curl_global_init(CURL_GLOBAL_ALL);
CURL *handle = curl_easy_init();
if (handle == NULL)
{
    exit(EXIT_FAILURE);
}

/* Pass the data from CRL distribution point to this function and save the data into prepared variable */
curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, get_data);
curl_easy_setopt(handle, CURLOPT_WRITEDATA, &actual_one_CRL);

int ret_error_val;
unsigned int revocation_reasons;    // flags from gnutls_x509_crl_reason_flags_t
int dist_points_index= 0;

/* Server's certificate can have more than one CRL distribution point entry */
/* This cycle will iterate through every distribution point entry, download the CRL from there and add it to the trusted list */
while (1)
{
    /* Store the CRL distribution point at given index into the prepared buffer */
    ret_error_val = gnutls_x509_crt_get_crl_dist_points(server_certificate_crt, dist_points_index, buffer_crl_dist_point, &buffer_crl_dist_point_size, &revocation_reasons, NULL);

    if (ret_error_val == GNUTLS_E_SHORT_MEMORY_BUFFER)
    {
        buffer_crl_dist_point = (char *) realloc(buffer_crl_dist_point, buffer_crl_dist_point_size);
        if (buffer_crl_dist_point == NULL)
        {
            exit(EXIT_FAILURE);
        }
        continue;
    }
    if (ret_error_val == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
    {
        /* No more crl distribution point entries */
        free(buffer_crl_dist_point);
        break;
    }

    curl_easy_setopt(handle, CURLOPT_URL, buffer_crl_dist_point);
    ret_error_val = curl_easy_perform(handle);        // HTTP GET Request
    if (ret_error_val != 0)
    {
        exit(EXIT_FAILURE);
    }

    /* Check whether the downloaded CRL was issued by the issuer of the TLS server's certificate */
    if (gnutls_x509_crl_import(actual_one_CRL_crl, &actual_one_CRL, GNUTLS_X509_FMT_DER) != 0)
    {
        exit(EXIT_FAILURE);
    }

    if (gnutls_x509_crl_check_issuer(actual_one_CRL_crl, issuer_certificate_crt) != 1)
    {
        exit(EXIT_FAILURE);
    }

    /* Add retrieved DER encoded CRL from actual distribution point entry into the trusted list */
    if (gnutls_x509_trust_list_add_trust_mem(trusted_list, NULL, &actual_one_CRL, GNUTLS_X509_FMT_DER, 0, 0) <= 0)
    {
        exit(EXIT_FAILURE);
    }

    /* Deinitialize and clean actual CRL distribution point entry */
    gnutls_free(actual_one_CRL.data);
    actual_one_CRL.data = NULL;
    actual_one_CRL.size = 0;
    memset(buffer_crl_dist_point, 0, buffer_crl_dist_point_size);

    dist_points_index++;
}

/* Server's certificate has not a single CRL distribution point entry */
if (dist_points_index == 0)
{
    fprintf(stderr, "Cannot use CRL revocation, no CRLs defined in CRL distribution points in server's certificate!\n");
    exit(EXIT_FAILURE);
}

/* Deinitialize curl */
curl_easy_cleanup(handle);
```

After this step, our trusted list should be filled with certification authority certificates and CRLs.

### Relevant links

* [cURL](https://curl.se/libcurl/c/libcurl-tutorial.html) (libcurl programming tutorial)
* [gnutls_x509_crl_init](https://gnutls.org/manual/gnutls.html#index-gnutls_005fx509_005fcrl_005finit) (GnuTLS docs)
* [gnutls_x509_crt_get_crl_dist_points](https://gnutls.org/manual/gnutls.html#index-gnutls_005fx509_005fcrt_005fget_005fcrl_005fdist_005fpoints) (GnuTLS docs)
* [gnutls_x509_crl_import](https://gnutls.org/manual/gnutls.html#index-gnutls_005fx509_005fcrl_005fimport) (GnuTLS docs)
* [gnutls_x509_crl_check_issuer](https://gnutls.org/manual/gnutls.html#index-gnutls_005fx509_005fcrl_005fcheck_005fissuer) (GnuTLS docs)
* [gnutls_x509_trust_list_add_trust_mem](https://gnutls.org/manual/gnutls.html#index-gnutls_005fx509_005ftrust_005flist_005fadd_005ftrust_005fmem-1) (GnuTLS docs)


</div></div>
<div class="section"><div class="container" markdown="1">


## 5.) Verify the TLS server's certificate against the filled trusted list

Verify the received TLS server's certificate and the whole chain against the filled trusted list.

The verification function will verify a given certificate chain against a list of certificate authorities and certificate revocation lists

```c
/* Verify the server's chain against the trusted list */
unsigned int verify_output;     // ORed sequence of gnutls_certificate_status_t enum
if (gnutls_x509_trust_list_verify_crt(trusted_list, server_chain_crt, server_chain_size, 0, &verify_output, NULL) != 0)
{
    exit(EXIT_FAILURE);
}

/* The GNUTLS_CERT_INVALID flag is always set on a verification error */
/* More detailed flags (gnutls_certificate_status_t) will also be set when appropriate */
if (verify_output & GNUTLS_CERT_INVALID)
{
    if (verify_output & GNUTLS_CERT_REVOKED)  //
    {
        /* Certificate chain is revoked */
    }
    else
    {
        /* Other verification error */
    }
}
else
{
    /* No verification error */
}
```

### Relevant link

* [gnutls_x509_trust_list_verify_crt](https://gnutls.org/manual/gnutls.html#index-gnutls_005fx509_005ftrust_005flist_005fverify_005fcrt-1) (GnuTLS docs)
* [gnutls_certificate_status_t enumeration](https://www.gnutls.org/manual/gnutls.html#gnutls_005fcertificate_005fstatus_005ft) (GnuTLS docs)


</div></div>
<div class="section"><div class="container" markdown="1">


## 6.) Deinitialize

Free the previously allocated structures, which are no longer required.

```c
for (int i=0; i < server_chain_size; i++)
{
        gnutls_x509_crt_deinit(server_chain_crt[i]);
}
gnutls_free(server_chain_crt);
gnutls_x509_crl_deinit(actual_one_CRL_crl);
gnutls_x509_trust_list_deinit(trusted_list, 1);
```

### Relevant links

* [gnutls_x509_crt_deinit](https://gnutls.org/manual/gnutls.html#gnutls_005fx509_005fcrt_005fdeinit) (GnuTLS docs)
* [gnutls_x509_crl_deinit](https://gnutls.org/manual/gnutls.html#index-gnutls_005fx509_005fcrl_005fdeinit) (GnuTLS docs)


</div></div>
<div class="section"><div class="container" markdown="1">


{:.text-danger}
## Alternative: Using local CRL

This is the case when we have a local CRL file. In this case, we don't need to make an out-of-band connection to the third party (CRL server). We will supply the CRL file to the `gnutls_certificate_credentials_t` structure before the TLS handshake. Subsequently, the certificate will be verified against this trusted CRL file during the TLS handshake.

```c
/* Initialize a credentials structure */
gnutls_certificate_credentials_t creds;
if (gnutls_certificate_allocate_credentials(&creds) < 0)
{
    exit(EXIT_FAILURE);
}

/* Add the trusted CRL file into credentials structure, function can be called multiple times */
/* Use GNUTLS_X509_FMT_PEM if file is in PEM format */
if (gnutls_certificate_set_x509_crl_file(creds, "crl_file.crl", GNUTLS_X509_FMT_DER) < 0)
{
    exit(EXIT_FAILURE);
}

```

### Relevant links

* [gnutls_certificate_allocate_credentials](https://gnutls.org/manual/gnutls.html#index-gnutls_005fcertificate_005fallocate_005fcredentials) (GnuTLS docs)
* [gnutls_certificate_set_x509_crl_file](https://gnutls.org/manual/gnutls.html#index-gnutls_005fcertificate_005fset_005fx509_005fcrl_005ffile) (GnuTLS docs)
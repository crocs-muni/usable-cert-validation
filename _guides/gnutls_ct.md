
This guide describes how to obtain a Signed Certificate Timestamp (SCT) from a certificate and then verify it. The SCT serves as proof that the certificate has been appended into a public log. In our guide, we will validate the TLS server's certificate.


**Short description:**
Certificate Transparency is a project initiated by Google in 2013. The main goal of this project was to make all certificates on the Internet publicly visible and therefore accessible and verifiable by anyone. Publicly available log servers are used to achieve this goal. Anyone can upload their certificates to these log servers and view their certificates from there. Every certificate that wants to support Certificate Transparency must be added to one of the publicly available logs. However, one such certificate is often added to several log servers. That is also because Google requires such a certificate to be added to multiple public logs. After the public log is asked to add a certificate, it responds with the Signed Certificate Timestamp (SCT). This SCT serves as a promise that the certificate will be inserted into the log. If a TLS client wants to verify that the TLS server’s certificate, with which the TLS client communicates, has been inserted to the public log, it must verify the validity of its SCT. During the verification of the SCT, its signature and timestamp are verified. The signature is verified against the log’s public key that signed the SCT. The timestamp is then verified against the current time to prevent the SCT from being issued in the future.

Certificate Transparency is defined in [RFC 6962](https://www.rfc-editor.org/info/rfc6962).  
Certificate Transparency on [Wikipedia](https://en.wikipedia.org/wiki/Certificate_Transparency).

**Summary of this guide:**
1. Retrieve the server's certificate chain with its size
   - from the chain, we will parse the TLS server's certificate
2. Retrieve the list of Signed Certificate Timestamps (SCTs) from the TLS server's certificate
   - we will extract the SCTs from the extension of the TLS server's certificate, extension is identified by its OID
3. Retrieve the information from the Signed Certificate Timestamp (SCT)
   - for each SCT from the list of the SCTs from step 2, we will extract its timestamp, signature, signature algorithm, public log id
   - signature is verified against the public key of the public log, when we know the id of this log and signature algorithm which was used
4. Deinitialize

---
   

We assume that the TLS client-server connection has already been established, that is, the client has access to the server's certificate. In other words, we assume that the variable `gnutls_session_t session` represents an already established connection. TLS client-server initialization guide can be found [here](https://x509errors.org/guides/gnutls).


## 1.) Retrieve the TLS server's certificate chain with it's size

First, we need to obtain a server's certificate chain and then parse the TLS server's certificate from the chain.

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
```

### Relevant links

* [gnutls_certificate_get_peers](https://gnutls.org/manual/gnutls.html#gnutls_005fcertificate_005fget_005fpeers) (GnuTLS docs)
* [gnutls_x509_crt_init](https://gnutls.org/manual/gnutls.html#index-gnutls_005fx509_005fcrt_005finit) (GnuTLS docs)
* [gnutls_x509_crt_import](ihttps://gnutls.org/manual/gnutls.html#index-gnutls_005fx509_005fcrt_005finit) (GnuTLS docs)


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
  


## 2.) Retrieve the list of Signed Certificate Timestamps (SCTs) from the TLS server's certificate

After we have obtained the TLS server's certificate, we parse the SCT list from it. The SCT list of a given certificate is stored in one of the certificate extensions.


```c
#include <gnutls/x509-ext.h>

int ret_err_val;

/* This is the defined OID for Signed Certificate Timestamp (SCT) extension */
char *oid_of_ct_sct_extension = "1.3.6.1.4.1.11129.2.4.2";

/* Retrieve the SCT list from certificate into the gnutls_datum_t structure */
/* Each SCT from the list is in DER format */
unsigned int critical;   // information whether the extension is critical will be placed here 
gnutls_datum_t scts_extension_datum_DER = { 0 };
ret_err_val = gnutls_x509_crt_get_extension_by_oid2(server_certificate_crt, oid_of_ct_sct_extension, 0, &scts_extension_datum_DER, &critical);
if (ret_err_val != GNUTLS_E_SUCCESS)
{
    if (ret_err_val == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
    {   
        /* Certificate does not contain the specified extension (SCT in this case) */
    }

    /* Other error occured */
    exit(EXIT_FAILURE);

/* Convert the SCT List of the server certificate from the gnutls_datum_t structure into a new native gnutls_x509_ct_scts_t structure */
gnutls_x509_ct_scts_t scts_extension_internal;
if (gnutls_x509_ext_ct_scts_init(&scts_extension_internal) != 0)
{
    exit(EXIT_FAILURE);
}
if (gnutls_x509_ext_ct_import_scts(&scts_extension_datum_DER, scts_extension_internal, 0) != 0)
{
    exit(EXIT_FAILURE);
}
```

### Relevant links

* [gnutls_x509_crt_get_extension_by_oid2](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005fx509_005fcrt_005fget_005fextension_005fby_005foid2) (GnuTLS docs)
* [gnutls_x509_ext_ct_scts_init](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005fx509_005fext_005fct_005fscts_005finit) (GnuTLS docs)
* [gnutls_x509_ext_ct_import_scts](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005fx509_005fext_005fct_005fimport_005fscts) (GnuTLS docs)


## 3.) Retrieve the information from the Signed Certificate Timestamp (SCT)

Parse the informations for every SCT from the list of SCTs. Informations such as ID of public log, signature algorithm which was used to sign the SCT and the signature itself.

```c
int ret_err_val;

/* DER encoded structure with the information about the public log, which signed the SCT */
gnutls_datum_t logid = { 0 }; 
/* DER encoded structure containing the signature of the SCT */
gnutls_datum_t signature = { 0 };   
/* Native structure containing which algoritm was used when signing the SCT */
gnutls_sign_algorithm_t sigalg = { 0 };
/* The timestamp of the SCT */
time_t timestamp;

/* Iterate the SCT List, to verify every single SCT entry */
for (int index=0; ; index++)
{
    ret_err_val = gnutls_x509_ct_sct_get(scts_extension_internal, index, &timestamp, &logid, &sigalg, &signature);
    if (ret_err_val != GNUTLS_E_SUCCESS)
    {
        if (ret_err_val == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
        {   
            /* No more items in the list */
            break;
        }

        /* Error occured */
        exit(EXIT_FAILURE);
    }

    /* Got one SCT item from the list */
    /* Process and verify the SCT */

    /* The logid and signature fields from SCT in gnutls_datum_t structure need to be freed */
    gnutls_free(logid.data);
    gnutls_free(signature.data);
}
```

After this step, we have obtained ID of the publicly known log that signed the SCT. We have also got the signature and the algorithm, which was used for signing the corresponding SCT. The public key of the log is publicly available as well. It means, we have all the information required to verify the given SCT. However, this guide does not cover the verification yet.


### Relevant links

* [gnutls_x509_ct_sct_get](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005fx509_005fct_005fsct_005fget) (GnuTLS docs)


## 4.) Deinitialize

Free the previously allocated structures, which are no longer required.

```c
for (int i = 0; i < chain_size; i++)
{
    gnutls_x509_crt_deinit(server_chain_crt[i]);
}
gnutls_free(server_chain_crt);
gnutls_free(scts_extension_datum_DER.data);
gnutls_x509_ext_ct_scts_deinit(scts_extension_internal);
```


### Relevant links

* [gnutls_x509_crt_deinit](https://gnutls.org/manual/gnutls.html#gnutls_005fx509_005fcrt_005fdeinit) (GnuTLS docs)
* [gnutls_x509_ext_ct_scts_deinit](https://www.gnutls.org/manual/gnutls.html#index-gnutls_005fx509_005fext_005fct_005fscts_005fdeinit) (GnuTLS docs)
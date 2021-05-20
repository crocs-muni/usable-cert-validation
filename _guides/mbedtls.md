---
layout:     default
title:      "Developer guide: Mbed TLS"
slug:       mbedtls
---
<div class="section"><div class="container" markdown="1">

# {{ page.title }}

{:.lead}
This guide describes the implementation of a TLS client in [Mbed TLS](https://tls.mbed.org/).

{:.lead}
The guide covers basic aspects of initiating a secure TLS connection, including certificate validation and hostname verification. When various alternative approaches are possible, the guide presents each of them and specifies their use cases to help you choose which approach suits your needs best.

* We work with the API in C of Mbed TLS, version 2.16.9.
* We assume the server to communicate with is at `x509errors.org` and accepts TLS connections on a standard port `443`.

{% include alert.html type="warning"
    content="Note: For now, the guide _does not_ cover revocation checking and advanced techniques that may follow after the connection is already established, e.g. session resumption."
%}

{% include alert.html type="danger"
    content="Note: Mbed TLS does not support _online_ revocation checking of any kind. Use another library if that is your requirement."
%}

</div></div>
<div class="section"><div class="container" markdown="1">

## Preparing necessary data structures

Mbed TLS requires quite a lot of structures to be initialized before we start.

```c
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"

/* Wrapper of the socket descriptor.
** This will take care of the underlying TCP/IP connection. */
mbedtls_net_context server_fd;
mbedtls_net_init(&server_fd);

/* Entropy (randomness source) context.
** Necessary to produce random data during the TLS handshake. */
mbedtls_entropy_context entropy;
mbedtls_entropy_init(&entropy);

/* Context for random number generation.
** Again, needed to produce random data during the handshake. */
mbedtls_ctr_drbg_context drbg;
mbedtls_ctr_drbg_init(&drbg);

/* TLS context which represents our session. */
mbedtls_ssl_context ssl;
mbedtls_ssl_init(&ssl);

/* Configuration to use within TLS. */
mbedtls_ssl_config conf;
mbedtls_ssl_config_init(&conf);

/* Seed the random number generator. */
if (mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy, NULL, 0) != 0) {
    exit(EXIT_FAILURE);
}

/* Assign the random number generator to the TLS config. */
if (mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &drbg) != 0) {
    exit(EXIT_FAILURE);
}

/* Assign the TLS config to the TLS context. */
if (mbedtls_ssl_setup(&ssl, &conf) != 0) {
    exit(EXIT_FAILURE);
}
```

### Relevant links

* [`mbedtls_net_init`](https://tls.mbed.org/api/net__sockets_8h.html#aed7458e19fc1b4794f3a23aa3df49543) (Mbed TLS docs)
* [`mbedtls_entropy_init`](https://tls.mbed.org/api/entropy_8h.html#aa901e027093c6fe65dee5760db78aced) (Mbed TLS docs)
* [`mbedtls_ctr_drbg_init`](https://tls.mbed.org/api/ctr__drbg_8h.html#a70dbec5e03601bf437ec488f2645743b) (Mbed TLS docs)
* [`mbedtls_ssl_init`](https://tls.mbed.org/api/ssl_8h.html#a8560dea66d7830a11874188727ec4c45) (Mbed TLS docs)
* [`mbedtls_ssl_config_init`](https://tls.mbed.org/api/ssl_8h.html#aba55bcda50a47e83803e31a8db7c9a86) (Mbed TLS docs)
* [`mbedtls_ctr_drbg_seed`](https://tls.mbed.org/api/ctr__drbg_8h.html#ad93d675f998550b4478c1fe6f4f34ebc) (Mbed TLS docs)
* [`mbedtls_ssl_conf_rng`](https://tls.mbed.org/api/ssl_8h.html#a469cd1c64bbba4be22347bf8874a017e) (Mbed TLS docs)
* [`mbedtls_ssl_setup`](https://tls.mbed.org/api/ssl_8h.html#af79cb539a0ee6ac20cf9c574f4c3b343) (Mbed TLS docs)

</div></div>
<div class="section"><div class="container" markdown="1">

## Configuring the session settings

For the connection to be functional and secure, we must set multiple options beforehand.

```c
/* Set defaults for the TLS configuration.
** This is the recommended setting. */
if (mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                        MBEDTLS_SSL_TRANSPORT_STREAM,
                                        MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
    exit(EXIT_FAILURE);
}

/* However, we accept only TLS 1.2 and higher. */
mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3,
                                    MBEDTLS_SSL_MINOR_VERSION_3);
/* We need to set the option to validate the peer certificate chain.
** If we skipped this step, an active attacker could impersonate the server. */
mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);

/* Set hostname for verification.
** Not setting the hostname would mean that we would accept a certificate of any trusted server.
** It also sets the Server Name Indication TLS extension.
** This is required when multiple servers are running at the same IP address (virtual hosting). */
if (mbedtls_ssl_set_hostname(&ssl, "x509errors.org") != 0) {
    exit(EXIT_FAILURE);
}
```

### Relevant links

* [`mbedtls_ssl_config_defaults`](https://tls.mbed.org/api/ssl_8h.html#aa1335b65ba57e81accc91ef95454d5a6) (Mbed TLS docs)
* [`mbedtls_ssl_conf_min_version`](https://tls.mbed.org/api/ssl_8h.html#a0eade5c83cc08001672061c5925caaaa) (Mbed TLS docs)
* [`mbedtls_ssl_conf_authmode`](https://tls.mbed.org/api/ssl_8h.html#a5695285c9dbfefec295012b566290f37) (Mbed TLS docs)
* [`mbedtls_ssl_set_hostname`](https://tls.mbed.org/api/ssl_8h.html#aa659024cf89e20d6d2248c0626db7ef2) (Mbed TLS docs)
* [Server Name Indication](https://datatracker.ietf.org/doc/html/rfc6066#section-3) (RFC 6066)

</div></div>
<div class="section"><div class="container" markdown="1">

## Specifying trusted root authority certificates

Trusted root certs are usually found within a directory such as `/etc/ssl/certs`. If they are not concatenated, concatenate them using e.g. the `cat` command. We will now assume that a file `trusted_certs.pem` contains all trusted root certificates.

{% include alert.html type="info"
    content="When using Mbed TLS, it is necessary to concatenate all trusted CA certificates into one file in the PEM format."
%}

In some cases, it might be useful to trust an arbitrary certificate authority. This could be the case during testing, or within company intranets. In that case, use arbitrary trusted CA certificate files instead.

```c
/* Structure to load trusted root certs into. */
mbedtls_x509_crt ca_certs;
mbedtls_x509_crt_init(&ca_certs);

/* Parse the file with root certificates. */
if (mbedtls_x509_crt_parse_file(&ca_certs, "trusted_certs.pem") != 0) {
    exit(EXIT_FAILURE);
}

/* Set the certificates as trusted for this session. */
mbedtls_ssl_conf_ca_chain(&conf, &ca_certs, NULL);
```

### Relevant links

* [`mbedtls_x509_crt_init`](https://tls.mbed.org/api/group__x509__module.html#ga016dd06bc770e77b84005f305df20ed1) (Mbed TLS docs)
* [`mbedtls_x509_crt_parse_file`](https://tls.mbed.org/api/group__x509__module.html#gad4da63133d3590aa311488497d4c38ec) (Mbed TLS docs)
* [`mbedtls_ssl_conf_ca_chain`](https://tls.mbed.org/api/ssl_8h.html#a85c3bb6b682ba361d13de1c0a1eb69fb) (Mbed TLS docs)

</div></div>
<div class="section"><div class="container" markdown="1">

{:.text-success}
## Optional: Checking revocation using local CRLs

Mbed TLS natively provides only _offline_ revocation checking. That is, the revocation list must already be present locally. If the CRL is contained in `crl.pem`, we include it in the configuration as follows.

{:.text-muted}
In the most recent versions (Mbed TLS 3.7), it may be possible to implement online revocation checks manually. We will include it in the guide when this version becomes more widely adapted.

```c
/* Structure to load the CRL into. */
mbedtls_x509_crl crl;
mbedtls_x509_crl_init(&crl);

/* Load the CRL from file. */
if (mbedtls_x509_crl_parse_file(&crl, "crl.pem") != 0) {
    exit(EXIT_FAILURE);
}

/* Assign it to the config, together with the trusted CA file. */
mbedtls_ssl_conf_ca_chain(&conf, &ca_certs, &crl);
```

### Relevant links

* [`mbedtls_x509_crl_init`](https://tls.mbed.org/api/group__x509__module.html#ga8513a192e281217802837571da98e218) (Mbed TLS docs)
* [`mbedtls_x509_crl_parse_file`](https://tls.mbed.org/api/group__x509__module.html#ga8e096827f1240b8f8bc15d6a83593f22) (Mbed TLS docs)
* [`mbedtls_ssl_conf_ca_chain`](https://tls.mbed.org/api/ssl_8h.html#a85c3bb6b682ba361d13de1c0a1eb69fb) (Mbed TLS docs)

</div></div>
<div class="section"><div class="container" markdown="1">

## Initializing a TLS connection

At this point, we can initialize a TCP/IP connection and then build the TLS connection on top.

```c
/* Initialize the underlying TCP/IP connection */
if (mbedtls_net_connect(&server_fd, , opts.port, MBEDTLS_NET_PROTO_TCP) != 0) {
    exit(EXIT_FAILURE);
}

/* Link the socket wrapper to our TLS session structure.
** Also set the onput/ouput function that we will use to transfer application data. */
mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

/* Perform the TLS handshake.
** During this procedure, the peer certificate is validated. */
if (mbedtls_ssl_handshake(&ssl) != 0) {
    exit(EXIT_FAILURE);
}
```

### Relevant links

* [`mbedtls_net_connect`](https://tls.mbed.org/api/net__sockets_8h.html#ac12c400864a5aad46666828ce2a089a4) (Mbed TLS docs)
* [`mbedtls_ssl_set_bio`](https://tls.mbed.org/api/ssl_8h.html#a8b7442420aef7f1a76fa8c5336362f9e) (Mbed TLS docs)
* [`mbedtls_ssl_handshake`](https://tls.mbed.org/api/ssl_8h.html#a4a37e497cd08c896870a42b1b618186e) (Mbed TLS docs)
* [TLS handshake details](https://datatracker.ietf.org/doc/html/rfc5246#section-7.4) (RFC 5246)

</div></div>
<div class="section"><div class="container" markdown="1">

{:.text-success}
## Optional: Checking the result of peer certificate validation

If certificate validation fails, `mbedtls_ssl_handshake()` will always fail with the same error message. In that case, it is often useful to examine the specific certificate validation error as follows. You can find explanations of certificate validation messages in the official [documentation](https://tls.mbed.org/api/group__x509__module.html) or on our [page](https://x509errors.org/mbedtls#mbedtls).

```c
/* Manually retrieve the result of certificate validation. */
uint32_t res = mbedtls_ssl_get_verify_result(&ssl);

/* Print the result of certificate validation as a string into the standard error output. */
char message_buffer[2048];
mbedtls_x509_crt_verify_info(message_buffer, 2048, "", res);
fprintf(stderr, "%s", message_buffer);
```

### Relevant links

* [`mbedtls_ssl_get_verify_result`](https://tls.mbed.org/api/ssl_8h.html#a516064f1468d459159ef7cd6c496a026) (Mbed TLS docs)
* [`mbedtls_x509_crt_verify_info`](https://tls.mbed.org/api/group__x509__module.html#gae88f1d8e6696eb2beeffe0a708219e6b) (Mbed TLS docs)
* [Certificate path validation](https://datatracker.ietf.org/doc/html/rfc5280#section-6) (RFC 5280)
* [Certificate validation errors](https://tls.mbed.org/api/group__x509__module.html) (MbedTLS docs)
* [Certificate validation errors](https://x509errors.org/mbedtls#mbedtls) (x509errors.org)

</div></div>
<div class="section"><div class="container" markdown="1">

## Sending and receiving data using the TLS connection

When the connection is successfully established, we can share application data with the server. These two functions provide the basic interface.

```c
/* Prepare a message and send it to the server. */
char *message = "Hello server";
if (mbedtls_ssl_write(ssl, message, strlen(message)) != 1) {
    exit(EXIT_FAILURE);
}

/* Prepare a static buffer for the response and read the response into that buffer. */
char buffer[4096];
if (mbedtls_ssl_read(ssl, buffer, 4096) != 1) {
    exit(EXIT_FAILURE);
}
```

### Relevant links

* [`mbedtls_ssl_write`](https://tls.mbed.org/api/ssl_8h.html#a5bbda87d484de82df730758b475f32e5) (Mbed TLS docs)
* [`mbedtls_ssl_read`](https://tls.mbed.org/api/ssl_8h.html#aa2c29eeb1deaf5ad9f01a7515006ede5) (Mbed TLS docs)

</div></div>
<div class="section"><div class="container" markdown="1">

## Closing the TLS connection

The client is usually the one to indicate that the connection is finished. When we want the connection closed, the following steps are performed.

```c
/* Gracefully close the connection by sending the "close notify" message to the server. */
if (mbedtls_ssl_close_notify(&ssl) != 0) {
    exit(EXIT_FAILURE);
}

/* Clean up all used resources and structures. */
mbedtls_ssl_free(&ssl);
mbedtls_x509_crt_free(&ca_certs);
mbedtls_ssl_config_free(&conf);
mbedtls_net_free(&server_fd);
mbedtls_ctr_drbg_free(&drbg);
mbedtls_entropy_free(&entropy);
```

### Relevant links

* [`mbedtls_ssl_close_notify`](https://tls.mbed.org/api/ssl_8h.html#ac2c1b17128ead2df3082e27b603deb4c) (Mbed TLS docs)
* [`mbedtls_ssl_free`](https://tls.mbed.org/api/ssl_8h.html#a2dc104a181bcd11eafbbf7e6923978bc) (Mbed TLS docs)
* [`mbedtls_x509_crt_free`](https://tls.mbed.org/api/group__x509__module.html#gab33c1e4e20bea7ce536119f54a113c6b) (Mbed TLS docs)
* [`mbedtls_ssl_config_free`](https://tls.mbed.org/api/ssl_8h.html#a7655f025440a6c5ccd4fc13832abb1dd) (Mbed TLS docs)
* [`mbedtls_net_free`](https://tls.mbed.org/api/net__sockets_8h.html#a77c35cb3f4b9fe6035d1d3742f3b4a24) (Mbed TLS docs)
* [`mbedtls_ctr_drbg_free`](https://tls.mbed.org/api/ctr__drbg_8h.html#a1ea42b9eb6f6b33c82359f4c0a57ca43) (Mbed TLS docs)
* [`mbedtls_entropy_free`](https://tls.mbed.org/api/entropy_8h.html#a06778439f8a0e2daa2d3b444e06ad8dd) (Mbed TLS docs)

</div></div>

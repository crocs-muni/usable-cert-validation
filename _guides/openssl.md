---
layout:     default
title:      "Developer guide: OpenSSL"
slug:       openssl
---
<div class="section"><div class="container" markdown="1">

# {{ page.title }}

{:.lead}
This guide describes the implementation of a TLS client in [OpenSSL](https://www.openssl.org/).

{:.lead}
The guide covers basic aspects of initiating a secure TLS connection, including certificate validation and hostname verification. When various alternative approaches are possible, the guide presents each of them and specifies their use cases to help you choose which approach suits your needs best.

* We work with the API in C of OpenSSL, version 1.1.1.
* We assume the server to communicate with is at `x509errors.org` and accepts TLS connections on a standard port `443`.

{% include alert.html type="warning"
    content="Note: For now, the guide _does not_ cover revocation checking and advanced techniques that may follow after the connection is already established, e.g. session resumption."
%}

</div></div>
<div class="section"><div class="container" markdown="1">

## Establishing an underlying TCP/IP connection

First, we need to establish an _insecure_ TCP/IP connection with the server. For the most simple connection, a standard set of _POSIX_ functions will suffice.

```c
#include <sys/socket.h>
#include <unistd.h>

/* TCP/IP socket descriptor. */
int sockfd = -1;

/* We will send the server our connection preferences in the form of hints. */
struct addrinfo hints = {0};

/* We allow both IPv4 and IPv6. */
hints.ai_family = AF_UNSPEC;
/* We want a stream socket, not a datagram one. */
hints.ai_socktype = SOCK_STREAM;
/* We know the numeric port number beforehand. */
hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV;
/* We want to use TCP. */
hints.ai_protocol = IPPROTO_TCP;

struct addrinfo *result = NULL;

/* We query a list of addresses for the given hostname. */
if (getaddrinfo("x509errors.org", "443", &hints, &result) != 0 || result == NULL) {
    exit(EXIT_FAILURE);
}

/* Try to connect to each address from the server list until successful. */
struct addrinfo *rr;
for (rr = result; rr != NULL, rr = rr->ai_next) {
    sockfd = socket(rr->ai_family, rr->ai_socktype, rr->ai_protocol);
    if (sockfd == -1)
        continue;
    if (connect(sockfd, rr->ai_addr, rr->ai_addrlen) != -1)
        break;
    close(sockfd);
}

/* We don't need the server info anymore. */
freeaddrinfo(result);

/* We must fail if we didn't manage to connect to any server address. */
if (rr == NULL) {
    exit(EXIT_FAILURE);
}
```

If everything went well, `sockfd` is now a descriptor of a valid, connected socket. We can proceed to establishing the TLS connection on top of the TCP/IP connection.

### Relevant links

* [`getaddrinfo`](https://man7.org/linux/man-pages/man3/getaddrinfo.3.html) (linux manpages)
* [Internet Protocol](https://tools.ietf.org/html/rfc791) (RFC 791)
* [Transmission Control Protocol](https://tools.ietf.org/html/rfc793) (RFC 793)

</div></div>
<div class="section"><div class="container" markdown="1">

## Creating a TLS context

Before we connect, a TLS context structure has to be created. It will store all the necessary configuration and settings needed for our session.

```c
#include <openssl/ssl.h>

/* Create the context. We will use the version-flexible TLS method to negotiate.
** This means that we prefer the highest supported version, but agree with downgrading. */
SSL_CTX const *ctx = SSL_CTX_new(TLS_client_method());
if (ctx == NULL) {
    exit(EXIT_FAILURE);
}

/* However, we won't let the server downgrade to less than TLS v1.2, since older TLS versions are deprecated. */
if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1) {
    exit(EXIT_FAILURE);
}

/* We need to set the option to validate the peer certificate chain.
** If we skipped this step, an active attacker could impersonate the server. */
SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

/* In certificate validation, we usually want to trust the system default certificate authorities. */
if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
    exit(EXIT_FAILURE);
};
```

### Relevant links

* [`SSL_CTX_new`](https://www.openssl.org/docs/manmaster/man3/SSL_CTX_new.html) (OpenSSL docs)
* [`SSL_CTX_set_min_proto_version`](https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set_min_proto_version.html) (OpenSSL docs)
* [`SSL_CTX_set_verify`](https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set_verify.html) (OpenSSL docs)
* [`SSL_CTX_set_default_verify_paths`](https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set_default_verify_paths.html) (OpenSSL docs)

</div></div>
<div class="section"><div class="container" markdown="1">

{:.text-danger}
## Alternative: Setting an arbitrary trust anchor

In some cases, it might be useful to trust an arbitrary certificate authority. This could be the case during testing, or within company intranets. If we trust a CA located in `trusted_ca.pem` and other authorities located in `trusted_dir`, we can easily change the trust setting as follows:

```c
/* Both the file path and the directory path can be set to NULL if they are not used */
if (SSL_CTX_load_verify_locations(ctx, "trusted_ca.pem", "trusted_dir") != 1) {
    exit(EXIT_FAILURE);
}
```

### Relevant links

* [`SSL_CTX_load_verify_locations`](https://www.openssl.org/docs/manmaster/man3/SSL_CTX_load_verify_locations.html) (OpenSSL docs)

</div></div>
<div class="section"><div class="container" markdown="1">

{:.text-success}
## Optional: Custom certificate validation settings

Optionally, you may want to put additional constraints on certificate validation. OpenSSL allows for this by modifying the `verify params` structure. In this example, we enforce strict certificate validation and put requirements on the IP address contained in the _Subject Alternative Name_ extension of the server certificate. All possible settings and flags can be found in the original [documentation](https://www.openssl.org/docs/man1.1.0/man3/X509_VERIFY_PARAM_set_flags.html)

```c
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

/* Retrieve the verification parameters for modification. */
X509_VERIFY_PARAM *vpm = SSL_CTX_get0_param(ctx);
if (vpm == NULL) {
    exit(EXIT_FAILURE);
}

/* Retrieve certificate validation flags. */
unsigned long flags = X509_VERIFY_PARAM_get_flags(vpm);

/* Enable the strict certificate validation flag.
** Certificates with e.g. duplicate extensions, will now be rejected. */
flags |= X509_V_FLAG_X509_STRICT;

/* Put the modified validation flags back into the params structure. */
if (X509_VERIFY_PARAM_set_flags(vpm, flags) != 1) {
    exit(EXIT_FAILURE);
}

/* Server certificate will have to contain IP 192.168.2.1 in its Subject Alternative Name. */
if (X509_VERIFY_PARAM_set1_ip_asc(vpm, "192.168.2.1") != 1) {
    exit(EXIT_FAILURE);
}
```

### Relevant links

* [`SSL_CTX_get0_param`](https://www.openssl.org/docs/manmaster/man3/SSL_CTX_get0_param.html) (OpenSSL docs)
* [`X509_VERIFY_PARAM_set_flags`](https://www.openssl.org/docs/manmaster/man3/X509_VERIFY_PARAM_set_flags.html) (OpenSSL docs)
* [Subject Alternative Name Extension](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6) (RFC 5280)

</div></div>
<div class="section"><div class="container" markdown="1">

## Initializing a TLS connection

At this point, we can initialize a connection structure and link it with the open socket descriptor. After that, we only need to specify a couple of settings and we can connect to the server.

```c
/* Initialize a TLS connection structure. */
ssl = SSL_new(ctx);
if (ssl == NULL) {
    exit(EXIT_FAILURE);
}

/* Bind the socket descriptor to the connection structure. */
if (SSL_set_fd(ssl, sockfd) != 1) {
    exit(EXIT_FAILURE);
}

/* Set the Server Name Indication TLS extension to specify the name of the server. */
/* This is required when multiple servers are running at the same IP address (virtual hosting). */
if (SSL_set_tlsext_host_name(ssl, "x509errors.org") != 1) {
    exit(EXIT_FAILURE);
}

/* Set hostname for verification. */
/* Not setting the hostname would mean that we would accept a certificate of any trusted server. */
if (SSL_set1_host(ssl, "x509errors.org") != 1) {
    exit(EXIT_FAILURE);
}

/* Connect to the server, this performs the TLS handshake. */
/* During this procedure, the peer certificate is validated. */
if (SSL_connect(ssl) != 1) {
    exit(EXIT_FAILURE);
}
```

### Relevant links

* [`SSL_new`](https://www.openssl.org/docs/manmaster/man3/SSL_new.html) (OpenSSL docs)
* [`SSL_set_fd`](https://www.openssl.org/docs/manmaster/man3/SSL_set_fd.html) (OpenSSL docs)
* [`SSL_set_tlsext_host_name`](https://www.openssl.org/docs/manmaster/man3/SSL_set_tlsext_host_name.html) (OpenSSL docs)
* [`SSL_set1_host`](https://www.openssl.org/docs/manmaster/man3/SSL_set1_host.html) (OpenSSL docs)
* [`SSL_connect`](https://www.openssl.org/docs/manmaster/man3/SSL_connect.html) (OpenSSL docs)
* [Server Name Indication](https://datatracker.ietf.org/doc/html/rfc6066#section-3) (RFC 6066)
* [TLS handshake](https://datatracker.ietf.org/doc/html/rfc5246#section-7.4) (RFC 5246)

</div></div>
<div class="section"><div class="container" markdown="1">

{:.text-success}
## Optional: Checking the result of peer certificate validation

If certificate validation fails, `SSL_connect()` will always fail with the same error message. In that case, it is often useful to examine the specific certificate validation error as follows. You can find explanations of certificate validation messages in the official [documentation](https://www.openssl.org/docs/manmaster/man3/X509_STORE_CTX_get_error.html) or on our [page](https://x509errors.org/#openssl).

```c
/* Retrieve the error code of the error that occured during certificate validation. */
int verifyResult = SSL_get_verify_result(ssl);

/* Convert the error code to a human-readable string. */
const char *message = X509_verify_cert_error_string(verifyResult);

/* Print the string to the standard error output. */
fprintf(stderr, "%s", message);
```

### Relevant links

* [`SSL_get_verify_result`](https://www.openssl.org/docs/manmaster/man3/SSL_get_verify_result.html) (OpenSSL docs)
* [`X509_verify_cert_error_string`](https://www.openssl.org/docs/manmaster/man3/X509_verify_cert_error_string.html) (OpenSSL docs)
* [Certificate validation errors](https://www.openssl.org/docs/manmaster/man3/X509_STORE_CTX_get_error.html) (OpenSSL docs)
* [Certificate validation errors](https://x509errors.org/#openssl) (x509errors.org)
* [Certificate path validation](https://datatracker.ietf.org/doc/html/rfc5280#section-6) (RFC 5280)

</div></div>
<div class="section"><div class="container" markdown="1">

## Sending and receiving data using the TLS connection

When the connection is successfully established, we can share application data with the server. These two functions provide the basic interface.

```c
/* Prepare a message and send it to the server. */
char *message = "Hello server";
if (SSL_write(ssl, message, strlen(message)) != 1) {
    exit(EXIT_FAILURE);
}

/* Prepare a static buffer for the response and read the response into that buffer. */
char buffer[4096];
if (SSL_read(ssl, buffer, 4096) != 1) {
    exit(EXIT_FAILURE);
}
```

### Relevant links

* [`SSL_write`](https://www.openssl.org/docs/manmaster/man3/SSL_write.html) (OpenSSL docs)
* [`SSL_read`](https://www.openssl.org/docs/manmaster/man3/SSL_read.html) (OpenSSL docs)

</div></div>
<div class="section"><div class="container" markdown="1">

## Closing the TLS connection

The client is usually the one to indicate that the connection is finished. When we want the connection closed, the following steps are performed.

```c
/* To finish the connection properly, we send a "close notify" alert to the server. */
/* In most cases, we have to wait for the same message from the server, and perform the call again. */
int ret = SSL_shutdown(ssl);
if (ret < 0) {
    exit(EXIT_FAILURE);
} else if (ret == 0) {
    if (SSL_shutdown(ssl) != 1) {
        exit(EXIT_FAILURE);
    }
}

/* Free the TLS connection structure. */
if (ssl != NULL) {
    SSL_free(ssl);
}

/* Free the TLS context structure. */
if (ctx != NULL) {
    SSL_CTX_free(ctx);
}

/* Close the underlying TCP socket. */
if (sockfd >= 0) {
    close(sockfd);
}
```

### Relevant links

* [`SSL_shutdown`](https://www.openssl.org/docs/manmaster/man3/SSL_shutdown.html) (OpenSSL docs)
* [`SSL_free`](https://www.openssl.org/docs/manmaster/man3/SSL_free.html) (OpenSSL docs)
* [`SSL_CTX_free`](https://www.openssl.org/docs/manmaster/man3/SSL_CTX_free.html) (OpenSSL docs)

</div></div>

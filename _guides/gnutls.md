---
layout:     default
title:      "Developer guide: GnuTLS"
slug:       gnutls
---
<div class="section"><div class="container" markdown="1">

{:#{{ page.slug }}}
# {{ page.title }}

{:.lead}
This guide describes the implementation of a TLS client in [GnuTLS](https://www.gnutls.org/).

{:.lead}
The guide covers basic aspects of initiating a secure TLS connection, including certificate validation and hostname verification. When various alternative approaches are possible, the guide presents each of them and specifies their use cases to help you choose which approach suits your needs best.

* We work with the API in C of GnuTLS, version 3.7.1.
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

## Creating a session context structure

Before we connect, a session context structure has to be created and initialized. It will store all the necessary configuration and settings.

```c
#include <gnutls/gnutls.h>

/* Create a TLS session context. */
gnutls_session_t session = NULL;

/* Initialize the TLS session context. */
if (gnutls_init(&session, GNUTLS_CLIENT) < 0) {
    exit(EXIT_FAILURE);
}

/* Create a credentials structure. This is required to set a trusted root. */
gnutls_certificate_credentials_t creds = NULL;

/* Initialize the credentials structure. */
if (gnutls_certificate_allocate_credentials(&creds) < 0) {
    exit(EXIT_FAILURE)
}
```

### Relevant links

* [Session Initialization](https://www.gnutls.org/manual/html_node/Session-initialization.html) (GnuTLS docs)
* [`gnutls_init`](https://gnutls.org/manual/gnutls.html#gnutls_005finit) (GnuTLS docs)
* [`gnutls_certificate_allocate_credentials`](https://gnutls.org/manual/gnutls.html#gnutls_005fcertificate_005fallocate_005fcredentials) (GnuTLS docs)

</div></div>
<div class="section"><div class="container" markdown="1">

## Preparing the necessary session settings

For the connection to be functional and secure, we must set multiple options beforehand.

```c
/* Set default cipher suite priorities. These are the recommended option. */
if (gnutls_set_default_priority(session) < 0) {
    exit(EXIT_FAILURE)
}

/* Enable server certificate validation, together with a hostname check.
** Not setting the hostname would mean that we would accept a certificate of any trusted server. */
gnutls_session_set_verify_cert(session, "x509errors.org", 0);

/* In certificate validation, we usually want to trust the system default certificate authorities. */
if (gnutls_certificate_set_x509_system_trust(creds) < 0) {
    exit(EXIT_FAILURE);
}

/* Associate the credentials structure with the session structure. */
if (gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, creds) < 0) {
    exit(EXIT_FAILURE);
}

/* Set the Server Name Indication TLS extension to specify the name of the server. */
/* This is required when multiple servers are running at the same IP address (virtual hosting). */
if (r = gnutls_server_name_set(session, GNUTLS_NAME_DNS, "x509errors.org", strlen("x509errors.org")) < 0) {
    exit(EXIT_FAILURE);
}
```

### Relevant links

* [Session Initialization](https://www.gnutls.org/manual/html_node/Session-initialization.html) (GnuTLS docs)
* [`gnutls_set_default_priority`](https://gnutls.org/manual/gnutls.html#gnutls_005fset_005fdefault_005fpriority) (GnuTLS docs)
* [`gnutls_session_set_verify_cert`](https://gnutls.org/manual/gnutls.html#index-gnutls_005fsession_005fset_005fverify_005fcert-1) (GnuTLS docs)
* [`gnutls_certificate_set_x509_system_trust`](https://gnutls.org/manual/gnutls.html#index-gnutls_005fcertificate_005fset_005fx509_005fsystem_005ftrust-1) (GnuTLS docs)
* [`gnutls_credentials_set`](https://gnutls.org/manual/gnutls.html#index-gnutls_005fcredentials_005fset-1) (GnuTLS docs)
* [`gnutls_server_name_set`](https://gnutls.org/manual/gnutls.html#index-gnutls_005fserver_005fname_005fset) (GnuTLS docs)
* [Server Name Indication](https://datatracker.ietf.org/doc/html/rfc6066#section-3) (RFC 6066)

</div></div>
<div class="section"><div class="container" markdown="1">

{:.text-danger}
## Alternative: Setting a custom trust anchor

In some cases, it might be useful to trust an arbitrary certificate authority. This could be the case during testing, or within company intranets. If we trust a CA located in `trusted_ca.pem` and other authorities located in `trusted_dir`, we can easily change the trust setting as follows (any of the two procedures can be skipped). This must be done _before_ we link the credentials structure to the session context.

```c
/* Set a custom trusted CA for certificate validation from file. The certificate must be in PEM format. */
if (gnutls_certificate_set_x509_trust_file(creds, "trusted_ca.pem", GNUTLS_X509_FMT_PEM) < 0) {
    exit(EXIT_FAILURE);
}

/* Set a custom trusted CA directory. All certificates in the directory must be in the PEM format. */
if (gnutls_certificate_set_x509_trust_dir(creds, "trusted_dir", GNUTLS_X509_FMT_PEM) < 0) {
    exit(EXIT_FAILURE);
}

/* Associate the credentials structure with the session structure. */
if (gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, creds) < 0) {
    exit(EXIT_FAILURE);
}
```

### Relevant links

* [Certificate credentials](https://gnutls.org/manual/html_node/Certificate-credentials.html) (GnuTLS docs)
* [`gnutls_certificate_set_x509_trust_file`](https://gnutls.org/manual/gnutls.html#gnutls_005fcertificate_005fset_005fx509_005ftrust_005ffile) (GnuTLS docs)
* [`gnutls_certificate_set_x509_trust_dir`](https://gnutls.org/manual/gnutls.html#gnutls_005fcertificate_005fset_005fx509_005ftrust_005fdir) (GnuTLS docs)
* [`gnutls_credentials_set`](https://gnutls.org/manual/gnutls.html#index-gnutls_005fcredentials_005fset-1) (GnuTLS docs)

</div></div>
<div class="section"><div class="container" markdown="1">

{:.text-success}
## Optional: Sending an OCSP status request to the server

One of the modern methods of revocation checking is via OCSP-stapling, when the server sends revocation information "stapled" in the TLS handshake. GnuTLS checks such revocation information by default, but the server will not send it unless we explicitly tell it to do so.

{% include alert.html type="danger"
    content="Note that if the server does not support OCSP stapling, it may not send the certificate status, and this will not result in a failure. It will only fail if the server certificate contains the OCSP \"must-staple\" extension."
%}

```c
/* Send the status request extension to the server during the TLS handshake. */
if (r = gnutls_ocsp_status_request_enable_client(session, NULL, 0, NULL) < 0) {
    exit(EXIT_FAILURE);
}
```

### Relevant links

* [`gnutls_ocsp_status_request_enable_client`](https://gnutls.org/manual/gnutls.html#index-gnutls_005focsp_005fstatus_005frequest_005fenable_005fclient) (GnuTLS docs)
* [OCSP protocol](https://datatracker.ietf.org/doc/html/rfc6960) (RFC 6960)
* [OCSP stapling](https://www.gnutls.org/manual/html_node/OCSP-stapling.html) (GnuTLS docs)
* [OCSP "must-staple" extension](https://datatracker.ietf.org/doc/html/rfc7633) (RFC 7633)
* [Certificate Status Request TLS Extension](https://datatracker.ietf.org/doc/html/rfc6066#section-8) (RFC 6066)

</div></div>
<div class="section"><div class="container" markdown="1">

## Initializing a TLS connection

At this point, we can link the open socket descriptor to our session context and perform the TLS handshake.

```c
/* Bind the open socket to the TLS session. */
gnutls_transport_set_int(session, sockfd);

/* Set default timeout for the handshake. */
gnutls_handshake_set_timeout(session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

/* Try to perform handshake until successful (this is the standard way). */
do {
    r = gnutls_handshake(session);
} while (r < 0 && gnutls_error_is_fatal(r) == 0);

/* Fail if the handshake was not succesful. */
if (r < 0) {
    exit(EXIT_FAILURE);
}
```

### Relevant links

* [`gnutls_transport_set_int`](https://gnutls.org/manual/gnutls.html#index-gnutls_005ftransport_005fset_005fint) (GnuTLS docs)
* [`gnutls_handshake_set_timeout`](https://gnutls.org/manual/gnutls.html#gnutls_005fhandshake_005fset_005ftimeout) (GnuTLS docs)
* [`gnutls_handshake`](https://gnutls.org/manual/gnutls.html#gnutls_005fhandshake) (GnuTLS docs)
* [`gnutls_error_is_fatal`](https://gnutls.org/manual/gnutls.html#gnutls_005ferror_005fis_005ffatal) (GnuTLS docs)
* [TLS handshake](https://datatracker.ietf.org/doc/html/rfc5246#section-7.4) (RFC 5246)
* [Setting up the transport layer](https://www.gnutls.org/manual/html_node/Setting-up-the-transport-layer.html) (GnuTLS docs)
* [TLS handshake](https://www.gnutls.org/manual/html_node/TLS-handshake.html) (GnuTLS docs)

</div></div>
<div class="section"><div class="container" markdown="1">

{:.text-success}
## Optional: Checking the result of peer certificate validation

If certificate validation fails, `gnutls_handshake()` will always fail with the same error message. In that case, it is often useful to examine the specific certificate validation error as follows. You can find explanations of certificate validation messages in the official [documentation](https://www.gnutls.org/manual/html_node/Verifying-X_002e509-certificate-paths.html#gnutls_005fcertificate_005fstatus_005ft) or on our [page](https://x509errors.org/gnutls#gnutls).

```c
/* Retrieve the certificate validation status. */
unsigned status = gnutls_session_get_verify_cert_status(session);

/* Retrieve the certificate type. */
gnutls_certificate_type_t cert_type = gnutls_certificate_type_get2(session);

/* Prepare a buffer for the error message, fill it, and print the message to the standard error output. */
gnutls_datum_t out = {0};
gnutls_certificate_verification_status_print(status, cert_type, &out, 0);
fprintf(stderr, "%s", out.data);
gnutls_free(out.data);
```

### Relevant links

* [`gnutls_session_get_verify_cert_status`](https://gnutls.org/manual/gnutls.html#index-gnutls_005fsession_005fget_005fverify_005fcert_005fstatus) (GnuTLS docs)
* [`gnutls_certificate_type_get2`](https://gnutls.org/manual/gnutls.html#index-gnutls_005fcertificate_005ftype_005fget2) (GnuTLS docs)
* [`gnutls_certificate_verification_status_print`](https://gnutls.org/manual/gnutls.html#index-gnutls_005fcertificate_005fverification_005fstatus_005fprint) (GnuTLS docs)
* [Certificate validation errors](https://x509errors.org/gnutls#gnutls) (x509errors.org)
* [Certificate path validation](https://datatracker.ietf.org/doc/html/rfc5280#section-6) (RFC 5280)

</div></div>
<div class="section"><div class="container" markdown="1">

## Sending and receiving data using the TLS connection

When the connection is successfully established, we can share application data with the server. These two functions provide the basic interface.

```c
/* Prepare a message and send it to the server. */
char *message = "Hello server";
if (gnutls_record_send(session, message, strlen(message)) < 0) {
    exit(EXIT_FAILURE);
}

/* Prepare a static buffer for the response and read the response into that buffer. */
char buffer[4096];
if (gnutls_record_recv(session, buffer, 4096) < 0) {
    exit(EXIT_FAILURE);
}
```

### Relevant links

* [Data transfer and termination](https://www.gnutls.org/manual/html_node/Data-transfer-and-termination.html#Data-transfer-and-termination) (GnuTLS docs)
* [`gnutls_record_send`](https://gnutls.org/manual/gnutls.html#index-gnutls_005frecord_005fsend-1) (GnuTLS docs)
* [`gnutls_record_recv`](https://gnutls.org/manual/gnutls.html#index-gnutls_005frecord_005frecv-1) (GnuTLS docs)

</div></div>
<div class="section"><div class="container" markdown="1">

## Closing the connection

The client is usually the one to indicate that the connection is finished. When we want the connection closed, the following steps are performed.

```c
/* Send the "close notify" message to the server, alerting it that we are closing the connection. */
if (gnutls_bye(session, GNUTLS_SHUT_RDWR) < 0) {
    exit(EXIT_FAILURE);
}

/* Free the credentials structure. */
if (creds != NULL) {
    gnutls_certificate_free_credentials(creds);
}

/* Free the session context structure. */
if (session != NULL) {
    gnutls_deinit(session);
}

/* Close the underlying TCP socket. */
if (sockfd >= 0) {
    close(sockfd);
}
```

### Relevant links

* [Data transfer and termination](https://www.gnutls.org/manual/html_node/Data-transfer-and-termination.html#Data-transfer-and-termination) (GnuTLS docs)
* [`gnutls_bye`](https://gnutls.org/manual/gnutls.html#gnutls_005fbye) (GnuTLS docs)
* [`gnutls_certificate_free_credentials`](https://gnutls.org/manual/gnutls.html#gnutls_005fcertificate_005ffree_005fcredentials) (GnuTLS docs)
* [`gnutls_deinit`](https://gnutls.org/manual/gnutls.html#gnutls_005fdeinit) (GnuTLS docs)

</div></div>

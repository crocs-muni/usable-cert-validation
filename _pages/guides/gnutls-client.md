---
layout:     default
title:      GnuTLS client - Developer guide
slug:       gnutls-client
---
<div class="section"><div class="container" markdown="1">

## **Initiating client-side TLS connection using OpenSSL**
Assume we want to communicate with a server at _HOSTNAME:PORT_ using TLS. This guide describes precise steps to take in order to do that successfully using the [OpenSSL 1.1.1](https://www.openssl.org/) API in C. The guide covers all neccessary aspects of initiating a secure TLS connection, including certificate verification, hostname validation and certificate revocation checking. When various alternative approaches are possible, the guide presents each of them and provides a comparison to help you choose which approach suits your needs best.

(For now, the guide _does not_ cover techniques that follow after the connection is already established, such as session resumption.)

### Establishing an underlying TCP/IP connection
First, we need to establish a TCP/IP connection with the server. For the most simple connection, a standard set of _POSIX_ functions will suffice.
~~~c

    #include <sys/socket.h>
    #include <unistd.h>
    
    /* TCP/IP socket descriptor */
    int sockfd = -1;

    /* Hints that we send to server with our preferences */
    struct addrinfo hints = {0};

    /* We allow both IPv4 and IPv6 */
    hints.ai_family = AF_UNSPEC;
    /* We want a stream socket, not a datagram one */
    hints.ai_socktype = SOCK_STREAM;
    /* We know the numeric port number beforehand */
    hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV;
    /* We want to use TCP */
    hints.ai_protocol = IPPROTO_TCP;

    struct addrinfo *result = NULL;

    /* Try to get the server addrinfo list */
    if (getaddrinfo(HOSTNAME, PORT, &hints, &result) != 0 || result == NULL) {
        exit(EXIT_FAILURE);
    }

    /* Try each address from the server list until successful */
    struct addrinfo *rr;
    for (rr = result; rr != NULL, rr = rr->ai_next) {
        sockfd = socket(rr->ai_family, rr->ai_socktype, rr->ai_protocol);
        if (sockfd == -1)
            continue;
        if (connect(sockfd, rr->ai_addr, rr->ai_addrlen) != -1)
            break;
        close(sockfd);
    }

    /* We don't need the server info anymore */
    freeaddrinfo(result);
    
    /* Fail if we didn't manage to connect to any server address */
    if (rr == NULL) {
        exit(EXIT_FAILURE);
    }

~~~
**Relevant links**:
[getaddrinfo linux manpages](https://man7.org/linux/man-pages/man3/getaddrinfo.3.html), 
[RFC 791 IP](https://tools.ietf.org/html/rfc791), 
[RFC 793 TCP](https://tools.ietf.org/html/rfc793)

If everything went well, _sockfd_ is now a descriptor of a valid, connected socket. We can proceed to establishing the TLS connection.

### Creating a TLS context
Before we connect, a TLS context structure has to be created. It will store all the necessary configuration and settings needed for our session.
~~~c

    #include <openssl/ssl.h>
    
    /* Create the context. We will use the version-flexible TLS method to negotiate */
    SSL_CTX const *ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        exit(EXIT_FAILURE);
    }

    /* However, we want to use at least TLS v1.2, since older versions are deprecated */
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1) {
        exit(EXIT_FAILURE);
    }
    
    /* Very importantly, we need to set the option to verify the peer certificate */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    /* Upon verification, we usually want to trust the system default certificate authorities */
    if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
        exit(EXIT_FAILURE);
    };

~~~
**Relevant links**:
[SSL_CTX_new](https://www.openssl.org/docs/manmaster/man3/SSL_CTX_new.html),
[SSL_CTX_set_min_proto_version](https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set_min_proto_version.html),
[SSL_CTX_set_verify](https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set_verify.html),
[SSL_CTX_set_default_verify_paths](https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set_default_verify_paths.html)

### <span style = "color: #9b0000" >Alternative: Setting a custom trust anchor</span>
In some cases (such as testing or in company intranets), it might be useful to trust a custom certificate authority. Assume we trust a CA located in _TRUSTED_CA_FILE_ and other authorities located in _TRUSTED_CA_DIR_ (these are filepath strings). We can easily change the trust setting as follows:
~~~c

    /* Both the file path and the directory path can be set to NULL if they are not used */
    if (SSL_CTX_load_verify_locations(ctx, TRUSTED_CA_FILE, TRUSTED_CA_DIR) != 1) {
        exit(EXIT_FAILURE);
    }

~~~
**Relevant links**:
[SSL_CTX_load_verify_locations](https://www.openssl.org/docs/manmaster/man3/SSL_CTX_load_verify_locations.html)

### Initializing a TLS connection
~~~c

    SSL *ssl = SSL_new(ctx);
    
    SSL_set_fd(ssl, socketfd);
    //alternatively, any bio can be used

    SSL_set_tlsext_host_name(ssl, HOSTNAME);

    SSL_set1_host(ssl, HOSTNAME);

    SSL_connect(ssl);

~~~
### Checking the result of peer certificate verification
~~~c

    X509* cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL)
        X509_free(cert);

    int verifyResult = SSL_get_verify_result(ssl);

~~~
### Sending and receiving data using the TLS connection
~~~c

    SSL_write(ssl, req, strlen(req));
    SSL_read(ssl, buf, sizeof(buf));
    //alternatively, we can wrap the connection in a BIO again

~~~
### Closing the connection
~~~c

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);

~~~
</div></div>

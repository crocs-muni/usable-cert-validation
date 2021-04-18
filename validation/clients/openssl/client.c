#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include "client.h"
#include "parse_opts.h"

#define OPENSSL_FAIL() do { \
        ret = EXIT_FAILURE; \
        ERR_print_errors_fp(stderr); \
        goto cleanup; \
    } while (0)
#define OPENSSL_CHECK(x) if ((x) != 1) { \
        OPENSSL_FAIL(); \
    }
#define CUSTOM_FAIL(error) do { \
        ret = EXIT_FAILURE; \
        fprintf(stderr, "Error: %s\n", error); \
        goto cleanup; \
    } while (0)


int main(int argc, char **argv)
{
	// final return value
    int ret = EXIT_SUCCESS;

    // options to get from argv
    struct tls_options opts = 
    {
        .check_crl = false,
        .check_ocsp = false,
        .check_ocsp_staple = false,
        .check_ct = false,
        .strict = false,
        .allow_proxy = false,
        .check_policies = false,
        .explicit_policy = false,
        .inhibit_any_policy = false,
        .inhibit_mapping = false,
        .use_deltas = false,
        .purpose = {0},
        .policy = {0},
        .host = {0},
        .port = {0},
        .trust_anchor = {0},
        .max_depth = -1,
        .ip = {0},
        .email = {0},
        .trust = {0}
    };

    if (parse_opts(argc, argv, &opts) != PARSING_SUCCESS) {
        CUSTOM_FAIL("Parsing command line arguments failed.");
    }

	// tls context
	SSL_CTX *ctx = NULL;

	// tls connection
	SSL *ssl = NULL;

	// the socket descriptor to use for connection
	int sockfd = -1;

	// establish the tls context
	// will use a flexible TLS client method to negotiate the TLS version
	ctx = SSL_CTX_new(TLS_client_method());
	if (ctx == NULL) {
		OPENSSL_FAIL();
	}

	// TODO: set verification flags in openssl through SSL_CTX_set1_param (...)

	// require TLS 1.2 at least
	OPENSSL_CHECK(SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION));

	// verify server cert and use the default verify callback
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

	// Retrieve the verification parameters for modification
	X509_VERIFY_PARAM *vpm = SSL_CTX_get0_param(ctx);
	
	if (opts.max_depth != -1) {
		X509_VERIFY_PARAM_set_depth(vpm, opts.max_depth);
	}

	if (strlen(opts.purpose) != 0) {
		int purpose_id = get_purpose_id(opts.purpose);
		if (purpose_id == -1) {
			CUSTOM_FAIL("Wrong purpose in parameter.");
		}
		OPENSSL_CHECK(X509_VERIFY_PARAM_set_purpose(vpm, purpose_id));
	}

	if (strlen(opts.trust) != 0) {
		int trust_id = get_trust_id(opts.trust);
		if (trust_id == -1) {
			CUSTOM_FAIL("Wrong trust in parameter.");
		}
		OPENSSL_CHECK(X509_VERIFY_PARAM_set_trust(vpm, trust_id));
	}

	if (strlen(opts.email) != 0) {
		OPENSSL_CHECK(X509_VERIFY_PARAM_set1_email(vpm, opts.email, strlen(opts.email)));
	}

	if (strlen(opts.ip) != 0) {
		OPENSSL_CHECK(X509_VERIFY_PARAM_set1_ip_asc(vpm, opts.ip));
	}

	if (strlen(opts.policy) != 0) {
		STACK_OF(ASN1_OBJECT) *policies = sk_ASN1_OBJECT_new_null();
		if (policies == NULL) {
			CUSTOM_FAIL("Failed to create a policy stack.");
		}
		ASN1_OBJECT *policy = OBJ_txt2obj(opts.policy, 1);
		OPENSSL_CHECK(sk_ASN1_OBJECT_push(policies, policy));
		OPENSSL_CHECK(X509_VERIFY_PARAM_set1_policies(vpm, policies));
	}

	unsigned long flags = X509_VERIFY_PARAM_get_flags(vpm);

	if (opts.strict) {
		flags |= X509_V_FLAG_X509_STRICT;
	}

	if (opts.check_crl) {
		flags |= X509_V_FLAG_CRL_CHECK;
	}

	if (opts.allow_proxy) {
		flags |= X509_V_FLAG_ALLOW_PROXY_CERTS;
	}

	if (opts.check_policies) {
		flags |= X509_V_FLAG_POLICY_CHECK;
	}

	if (opts.explicit_policy) {
		flags |= X509_V_FLAG_EXPLICIT_POLICY;
	}

	if (opts.inhibit_any_policy) {
		flags |= X509_V_FLAG_INHIBIT_ANY;
	}

	if (opts.inhibit_mapping) {
		flags |= X509_V_FLAG_INHIBIT_MAP;
	}

	if (opts.use_deltas) {
		flags |= X509_V_FLAG_USE_DELTAS;
	}

	OPENSSL_CHECK(X509_VERIFY_PARAM_set_flags(vpm, flags));

	// TODO: specify security parameters here (ciphers, ...)

	// set the trust anchor for certificate validation
	OPENSSL_CHECK(SSL_CTX_load_verify_locations(ctx, opts.trust_anchor, NULL));
	// TODO: normally we would use `SSL_CTX_set_default_verify_paths`

    ssl = SSL_new(ctx);
    if (ssl == NULL) {
    	OPENSSL_FAIL();
    }

    // initialize the underlying TCP connection
	sockfd = tcp_connect((const char *) &(opts.host), (const char *) &(opts.port));
	if (sockfd == -1) {
        CUSTOM_FAIL("Could not establish TCP/IP connection to server.");
    }

    // connect the socket
    OPENSSL_CHECK(SSL_set_fd(ssl, sockfd));
    //alternatively, any bio can be used

    // tell server the hostname
    OPENSSL_CHECK(SSL_set_tlsext_host_name(ssl, opts.host));

    // set hostname for verification
    OPENSSL_CHECK(SSL_set1_host(ssl, opts.host));

    // do handshake but don't fail immediately
    //int r = 
    SSL_connect(ssl);

    // check and print the result of certificate verification
	int verifyResult = SSL_get_verify_result(ssl);
	//fprintf(stderr, "%d\n", verifyResult);
	const char *message = X509_verify_cert_error_string(verifyResult);
	fprintf(stderr, "%s", message);

	// only now fail if something was wrong before
    // TODO: run this only if r is not verify error
	// OPENSSL_CHECK(r);

	/* lastly - check that a certificate was presented by the peer (redundant?)
	 X509* cert = SSL_get_peer_certificate(ssl);
	if (cert == NULL) {
		CUSTOM_FAIL("Server did not send certificate.");
	}
    */
    // TODO: why this doesn't work?

	// TODO: do something useful here

cleanup:
    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (ctx != NULL) {
        SSL_CTX_free(ctx);
    }
    if (sockfd >= 0) {
        close(sockfd);
    }

	return ret;
}


int tcp_connect(const char *host, const char *port)
{   
    // TODO: move this function somewhere else

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
    if (getaddrinfo(host, port, &hints, &result) != 0 || result == NULL) {
        return -1;
    }

    /* Try each address from the server list until successful */
    struct addrinfo *rr;
    for (rr = result; rr != NULL; rr = rr->ai_next) {
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
        return -1;
    }

    return sockfd;
}


int get_purpose_id(const char *purpose)
{
	if (strcmp(purpose, "SSL_CLIENT")) {
		return 1;
	}
	if (strcmp(purpose, "SSL_SERVER")) {
		return 2;
	}
	if (strcmp(purpose, "ANY")) {
		return 7;
	}
	if (strcmp(purpose, "CRL_SIGN")) {
		return 6;
	}
	return -1;
}


int get_trust_id(const char *trust)
{
	if (strcmp(trust, "SSL_CLIENT")) {
		return 2;
	}
	if (strcmp(trust, "SSL_SERVER")) {
		return 3;
	}
	return -1;
}

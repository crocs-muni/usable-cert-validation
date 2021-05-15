#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "mbedtls/net.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/error.h"

#include "parse_opts.h"

#define MBEDTLS_FAIL(x) do { \
        char error_buffer[500] = ""; \
        mbedtls_strerror(x, error_buffer, 500); \
        fprintf(stderr, "mbed TLS error: %s\n", error_buffer); \
        ret = EXIT_FAILURE; \
        goto cleanup; \
    } while (0)
#define MBEDTLS_CHECK(x) if ((ret = (x)) != 0) { \
        MBEDTLS_FAIL(ret); \
    }
#define CUSTOM_FAIL(error) do { \
        ret = EXIT_FAILURE; \
        fprintf(stderr, "Error: %s\n", error); \
        goto cleanup; \
    } while (0)


// TODO: ocsp, crl, options
int main(int argc, char **argv)
{
	// final return value
    int ret = EXIT_SUCCESS;

    // options to get from argv
    struct tls_options opts = 
    {
        .crl_file = {0},
        .host = {0},
        .port = {0},
        .trust_anchor = {0},
    };

    // parse the command line options
    if (parse_opts(argc, argv, &opts) != PARSING_SUCCESS) {
        CUSTOM_FAIL("Parsing command line arguments failed.");
    }
	// socket wrapper
	mbedtls_net_context server_fd;

	// entropy context
	mbedtls_entropy_context entropy;
	
	// RBG context
	mbedtls_ctr_drbg_context drbg;

	// TLS context
	mbedtls_ssl_context ssl;

	// TLS configuration to use by the TLS context
	mbedtls_ssl_config conf;

	// trust anchor
	mbedtls_x509_crt cacert;

	// CRL
	mbedtls_x509_crl crl;

	// initialize all context/config variables
	mbedtls_net_init(&server_fd);
	mbedtls_ssl_init(&ssl);
	mbedtls_ssl_config_init(&conf);
	mbedtls_x509_crt_init(&cacert);
	mbedtls_ctr_drbg_init(&drbg);
	mbedtls_entropy_init(&entropy);

	// seed the DRBG
	MBEDTLS_CHECK(mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy, NULL, 0));

	// initiate the underlying TCP connection
	MBEDTLS_CHECK(mbedtls_net_connect(&server_fd, opts.host, opts.port, MBEDTLS_NET_PROTO_TCP));

	// set TLS config defaults
	MBEDTLS_CHECK(mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT));

	// assign the RNG to the SSL config
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &drbg);

	// accept only TLS 1.2 and higher
	mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);

	// require server certificate verification
	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);

	// load trusted CA cert, normally we would use /etc/ssl/certs
	MBEDTLS_CHECK(mbedtls_x509_crt_parse_file(&cacert, opts.trust_anchor));

	// load the CRL file if present
	if (strlen(opts.crl_file) != 0) {
		MBEDTLS_CHECK(mbedtls_x509_crl_parse_file(&crl, opts.crl_file));
    	// assign the trust anchor to the config
    	mbedtls_ssl_conf_ca_chain(&conf, &cacert, &crl);
	} else {
		mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
	}


    // assign the config to the ssl context
    MBEDTLS_CHECK(mbedtls_ssl_setup(&ssl, &conf));

    // set the SNI extension
    MBEDTLS_CHECK(mbedtls_ssl_set_hostname(&ssl, opts.host));

    // set the IO functions to use in the underlying connection
    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    // explicitly perform the handshake, don't fail yet
    int r = mbedtls_ssl_handshake(&ssl);
    if (r != 0) {
    	MBEDTLS_FAIL(r);
    }

    // check the result of certificate verification
    uint32_t res = mbedtls_ssl_get_verify_result(&ssl);
    //fprintf(stderr, "0x%x", res);

    char message_buffer[2048];
    mbedtls_x509_crt_verify_info(message_buffer, 2048, "", res);
    fprintf(stderr, "%s", message_buffer);
    // TODO: make this a bit prettier

    /* can fail now, TODO: only fail if not a verify error
    MBEDTLS_CHECK(r);
    */
	// TODO: do something useful here

cleanup:
    mbedtls_ssl_free(&ssl);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_ssl_config_free(&conf);
    mbedtls_net_free(&server_fd);
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&entropy);
    
	return ret;
}

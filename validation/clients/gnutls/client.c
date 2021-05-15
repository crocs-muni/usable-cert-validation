#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/ocsp.h>

#include <curl/curl.h>

#include "client.h"

/* Default values of all command line options */
struct tls_options opts = {
      .check_crl = false,
      .check_ocsp = false,
      .check_ocsp_staple = false,
      .host = {0},
      .port = {0},
      .trust_anchor = {0},
};

/* Credentials structure required to set a trusted root */
gnutls_certificate_credentials_t creds = NULL;

int main(int argc, char **argv) {
  /* Final return value of the program */
  int ret = EXIT_SUCCESS;

  /* TLS session context */
  gnutls_session_t session = NULL;

  /* Socket descriptor that we will use in the TCP/IP connection */
  int sockfd = -1;

  /* Parse the command line options */
  if (parse_opts(argc, argv, &opts) != PARSING_SUCCESS) {
    CUSTOM_FAIL("Parsing command line arguments failed.");
  }

  /* NOTE: Using gnutls_global_init() here may speed things up */

  /* Initialize the TLS session context */
  GNUTLS_CHECK(gnutls_init(&session, GNUTLS_CLIENT));

  /* Initialize the credentials structure */
  GNUTLS_CHECK(gnutls_certificate_allocate_credentials(&creds));


  /* Set the SNI extension to enable "virtual hosting" */
  GNUTLS_CHECK(gnutls_server_name_set(session, GNUTLS_NAME_DNS, opts.host,
                                      strlen(opts.host)));

  /* Set the trust anchor for certificate validation */
  GNUTLS_CHECK(gnutls_certificate_set_x509_trust_file(creds, opts.trust_anchor,
                                                      GNUTLS_X509_FMT_PEM)); 
  /*NOTE: Normally we would use gnutls_certificate_set_x509_system_trust() */

  /* Associate the credentials with the session */
  GNUTLS_CHECK(gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, creds));

  /* Enable server certificate verification with hostname checking */
  /* gnutls_session_set_verify_cert(session, opts.host, 0); */

  gnutls_session_set_verify_function(session, &verify_callback);

  /* Request a stapled OCSP if the corresponding option is set */
  if (opts.check_ocsp_staple) {
    GNUTLS_CHECK(
        gnutls_ocsp_status_request_enable_client(session, NULL, 0, NULL));
  }

  /* Set default cipher suite priorities */
  GNUTLS_CHECK(gnutls_set_default_priority(session));

  /* Initialize the underlying TCP connection */
  sockfd = tcp_connect((const char *)&(opts.host), (const char *)&(opts.port));
  if (sockfd == -1) {
    CUSTOM_FAIL("Could not establish TCP/IP connection to server.");
  }

  /* Bind the socket to the TLS context */
  gnutls_transport_set_int(session, sockfd);

  /* Set default timeout for the handshake */
  gnutls_handshake_set_timeout(session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

  /* Handshake return value */
  int r;

  /* Try to perform handshake until possible (this is the standard way) */
  do {
    r = gnutls_handshake(session);
  } while (r < 0 && gnutls_error_is_fatal(r) == 0);

  /* Print verification result if it failed, fail on other errors 
  unsigned status = gnutls_session_get_verify_cert_status(session);
  if (status != (unsigned int)(-1)) {
    gnutls_certificate_type_t cert_type = gnutls_certificate_type_get(session);
    gnutls_datum_t out = {0};
    gnutls_certificate_verification_status_print(status, cert_type, &out, 0);
    fprintf(stderr, "%s", out.data);
    gnutls_free(out.data);
  } else {
    GNUTLS_FAIL(r);
  }
  */

  GNUTLS_CHECK(r);

  /* Alert server that we are closing connection */
  GNUTLS_CHECK(gnutls_bye(session, GNUTLS_SHUT_RDWR));

/* Clean up all structures and close the connection*/
cleanup:
  if (sockfd >= 0) {
    close(sockfd);
  }
  if (creds != NULL) {
    gnutls_certificate_free_credentials(creds);
  }
  if (session != NULL) {
    gnutls_deinit(session);
  }
  return ret;
}

int tcp_connect(const char *host, const char *port) {
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

int parse_opts(int argc, char **argv, struct tls_options *opts) {
  int c;
  while (1) {
    static struct option long_options[] = {
        {"check_crl", no_argument, NULL, 'c'},
        {"check_ocsp", no_argument, NULL, 'o'},
        {"check_ocsp_staple", no_argument, NULL, 's'},
        {"host", required_argument, NULL, 'h'},
        {"port", required_argument, NULL, 'p'},
        {"trust_anchor", required_argument, NULL, 't'},
        {NULL, 0, NULL, 0},
    };

    c = getopt_long(argc, argv, "", long_options, NULL);
    if (c == -1) {
      break;
    }

    switch (c) {
    case 'c':
      opts->check_crl = true;
      break;
    case 'o':
      opts->check_ocsp = true;
      break;
    case 's':
      opts->check_ocsp_staple = true;
      break;
    case 'h':
      strncpy(opts->host, optarg, HOST_BUFFER_LENGTH);
      break;
    case 'p':
      strncpy(opts->port, optarg, PORT_BUFFER_LENGTH);
      break;
    case 't':
      strncpy(opts->trust_anchor, optarg, PATH_BUFFER_LENGTH);
      break;
    default:
      return PARSING_ERROR;
    }
  }

  return PARSING_SUCCESS;
}

int verify_callback(gnutls_session_t session) {
  int ret = 0;
  curl_global_init(CURL_GLOBAL_ALL);

  /* Get the server certificates */
  unsigned int data_size = 0;
  const gnutls_datum_t *cert_data = gnutls_certificate_get_peers(session, &data_size);

  /* Parse the end certificate */
  gnutls_x509_crt_t end_cert;
  ret = gnutls_x509_crt_init(&end_cert);
  if (ret < 0) {
    curl_global_cleanup();
    return ret;
  }
  ret = gnutls_x509_crt_import(end_cert, &cert_data[0], GNUTLS_X509_FMT_DER);
  if (ret < 0) {
    gnutls_x509_crt_deinit(end_cert);
    curl_global_cleanup();
    return ret;
  }

  gnutls_x509_crt_t issuer_cert;
  ret = gnutls_x509_crt_init(&issuer_cert);
  if (ret < 0) {
    gnutls_x509_crt_deinit(end_cert);
    curl_global_cleanup();
    return ret;
  }
  ret = gnutls_x509_crt_import(issuer_cert, &cert_data[1], GNUTLS_X509_FMT_DER);
  if (ret < 0) {
    gnutls_x509_crt_deinit(end_cert);
    gnutls_x509_crt_deinit(issuer_cert);
    curl_global_cleanup();
    return ret;
  }

  gnutls_certificate_credentials_t new_creds;
  gnutls_x509_trust_list_t tlist;

  if (opts.check_crl) {
    /* Get the first CRL distribution point */
    char crldp_buffer[512] = {0};
    size_t crldp_size = 512;
    unsigned int crldp_flags = 0;
    ret = gnutls_x509_crt_get_crl_dist_points(end_cert, 0, crldp_buffer, &crldp_size, &crldp_flags, NULL);
    if (ret < 0) {
      gnutls_x509_crt_deinit(end_cert);
      gnutls_x509_crt_deinit(issuer_cert);
      curl_global_cleanup();
      return ret;
    }

    /* Download the CRL using HTTP */
    int crl_port = atoi(opts.port) + 1;

    CURL *easy = curl_easy_init();
    curl_easy_setopt(easy, CURLOPT_URL, crldp_buffer);
    curl_easy_setopt(easy, CURLOPT_PORT, crl_port);
    curl_easy_setopt(easy, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, write_data);
    FILE *fd = fopen("tmp.crl", "wb");
    curl_easy_setopt(easy, CURLOPT_WRITEDATA, fd);
    curl_easy_perform(easy);
    fclose(fd);
    curl_easy_cleanup(easy);
        
    ret = gnutls_certificate_allocate_credentials(&new_creds);
    if (ret < 0) {
      gnutls_x509_crt_deinit(end_cert);
      gnutls_x509_crt_deinit(issuer_cert);
      curl_global_cleanup();
      return ret;
    }

    
    ret = gnutls_x509_trust_list_init(&tlist, 0);
    if (ret < 0) {
      gnutls_x509_crt_deinit(end_cert);
      gnutls_x509_crt_deinit(issuer_cert);
      gnutls_certificate_free_credentials(new_creds);
      curl_global_cleanup();
      return ret;
    }
    
    ret = gnutls_x509_trust_list_add_trust_file(tlist, opts.trust_anchor, "tmp.crl",  GNUTLS_X509_FMT_PEM, GNUTLS_TL_VERIFY_CRL|GNUTLS_TL_FAIL_ON_INVALID_CRL, 0);
    if (ret < 0) {
      gnutls_x509_crt_deinit(end_cert);
      gnutls_x509_crt_deinit(issuer_cert);
      gnutls_x509_trust_list_deinit(tlist, 1);
      gnutls_certificate_free_credentials(new_creds);
      curl_global_cleanup();
      return ret;
    }
    
    gnutls_certificate_set_trust_list(new_creds, tlist, 0);

    ret = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, new_creds);
    if (ret < 0) {
      gnutls_x509_crt_deinit(end_cert);
      gnutls_x509_crt_deinit(issuer_cert);
      gnutls_certificate_free_credentials(new_creds);
      curl_global_cleanup();
      return ret;
    }
  }

  if (opts.check_ocsp) {
    /* Get the first OCSP issuer URI */
    gnutls_datum_t aia_buffer;
    int i = 0;
    do {
      ret = gnutls_x509_crt_get_authority_info_access(end_cert, i++,
                  GNUTLS_IA_OCSP_URI,
                  &aia_buffer,
                  NULL);
    } while(ret == GNUTLS_E_UNKNOWN_ALGORITHM);

    if (ret < 0) {
      gnutls_x509_crt_deinit(end_cert);
      gnutls_x509_crt_deinit(issuer_cert);
      curl_global_cleanup();
      return ret;
    }
    
    gnutls_ocsp_req_t ocsp_req;
    ret = gnutls_ocsp_req_init(&ocsp_req);
    if (ret < 0) {
      gnutls_x509_crt_deinit(end_cert);
      gnutls_x509_crt_deinit(issuer_cert);
      curl_global_cleanup();
      gnutls_free((void *)aia_buffer.data);
      return ret;
    }

    ret = gnutls_ocsp_req_add_cert(ocsp_req, GNUTLS_DIG_SHA1, issuer_cert, end_cert);
    if (ret < 0) {
      gnutls_ocsp_req_deinit(ocsp_req);
      gnutls_x509_crt_deinit(end_cert);
      gnutls_x509_crt_deinit(issuer_cert);
      curl_global_cleanup();
      gnutls_free((void *)aia_buffer.data);
      return ret;
    }

    gnutls_datum_t ocsp_raw;
    ret = gnutls_ocsp_req_export(ocsp_req, &ocsp_raw);
    if (ret < 0) {
      gnutls_ocsp_req_deinit(ocsp_req);
      gnutls_x509_crt_deinit(end_cert);
      gnutls_x509_crt_deinit(issuer_cert);
      curl_global_cleanup();
      return ret;
    }
    gnutls_ocsp_req_deinit(ocsp_req);

    char ocsp_host[128] = {0};
    memcpy((void*)ocsp_host, (void*)aia_buffer.data, (size_t)aia_buffer.size);
    int ocsp_port = atoi(opts.port) + 2;

    char host_header[128] = {0};
    strcpy(host_header, "Host: ");
    strcat(host_header, ocsp_host);

    char length_header[128] = {0};
    strcpy(length_header, "Content-Length: ");
    sprintf(length_header + strlen(length_header), "%d", aia_buffer.size);

    struct curl_slist *list = NULL;
    list = curl_slist_append(list, host_header);
    list = curl_slist_append(list, "Accept: */*");
    list = curl_slist_append(list, "Content-Type: application/ocsp-request");
    list = curl_slist_append(list, length_header);
    list = curl_slist_append(list, "Connection: close");

    CURL *easy = curl_easy_init();
    curl_easy_setopt(easy, CURLOPT_URL, ocsp_host);
    curl_easy_setopt(easy, CURLOPT_PORT, ocsp_port);
    curl_easy_setopt(easy, CURLOPT_HTTPHEADER, list);
    curl_easy_setopt(easy, CURLOPT_POST, 1L);
    curl_easy_setopt(easy, CURLOPT_POSTFIELDS, (char *)ocsp_raw.data);
    curl_easy_perform(easy);

    curl_easy_cleanup(easy);
    curl_slist_free_all(list);
    gnutls_free((void *)ocsp_raw.data);
    gnutls_free((void *)aia_buffer.data);
  }

  unsigned int status = 0;
  int verify_ret = gnutls_certificate_verify_peers3(session, opts.host, &status);

  if (verify_ret == 0) {
    gnutls_certificate_type_t cert_type = gnutls_certificate_type_get(session);
    gnutls_datum_t out = {0};
    gnutls_certificate_verification_status_print(status, cert_type, &out, 0);
    fprintf(stderr, "%s", out.data);
    gnutls_free(out.data);
  }

  if (opts.check_crl) {
    gnutls_certificate_free_credentials(new_creds);
    ret = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, creds);
    if (ret < 0) {
      gnutls_x509_crt_deinit(end_cert);
      gnutls_x509_crt_deinit(issuer_cert);
      curl_global_cleanup();
      return ret;
    }
  }
  
  gnutls_x509_crt_deinit(end_cert);
  gnutls_x509_crt_deinit(issuer_cert);
  curl_global_cleanup();
  return verify_ret;
}

static size_t write_data(void *ptr, size_t size, size_t nmemb, void *stream)
{
  size_t written = fwrite(ptr, size, nmemb, (FILE *)stream);
  return written;
}
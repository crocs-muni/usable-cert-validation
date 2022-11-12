
#include "utils.h"

#include <err.h>
#include <openssl/ocsp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <stdbool.h>
#include <string.h>

STACK_OF(X509) * retrieve_server_certificate_chain(SSL *s_connection,
                                                   int *cert_chain_stack_size,
                                                   bool useVerified) {
  /* Retrieve the server's certificate chain from the OpenSSL connection. */
  /* Another option: SSL_get0_verified_chain() */
  STACK_OF(X509) *cert_chain_stack = NULL;
  if (useVerified) {
    cert_chain_stack = SSL_get0_verified_chain(s_connection);
  } else {
    cert_chain_stack = SSL_get_peer_cert_chain(s_connection);
  }

  if (cert_chain_stack == NULL) {
    fprintf(stderr, "- certificate chain is not present!\n");
    return NULL;
  }

  *cert_chain_stack_size = sk_X509_num(cert_chain_stack);
  return cert_chain_stack;
}

void print_x509_certificate_info(X509 *certificate) {
  if (certificate == NULL) {
    fprintf(stderr, "- retrieved certificate is NULL\n");
    return;
  }

  /* Print the information about the current certificate. */

  X509_NAME *subject_name = X509_get_subject_name(certificate);
  char *subject_name_oneline = X509_NAME_oneline(subject_name, NULL, 0);
  printf("- subject name: %s\n", subject_name_oneline);

  X509_NAME *issuer_name = X509_get_issuer_name(certificate);
  char *issuer_name_oneline = X509_NAME_oneline(issuer_name, NULL, 0);
  printf("- issuer name: %s\n", issuer_name_oneline);

  //    ASN1_INTEGER *serial_number_asn = X509_get_serialNumber(certificate);

  /* Deinitialize*/
  free(subject_name_oneline);
  free(issuer_name_oneline);
}

void print_x509_certificate_chain_info(SSL *s_connection) {
  /* struct x509_extension_t -> typedef X509_EXTENSION -> in stack as
   * STACK_OF(X509_EXTENSION) -> typedef X509_EXTENSIONS */

  printf("\nCertificate chain details: \n");

  /* Get the certificate chain sent by the peer */
  int cert_chain_stack_size;
  STACK_OF(X509) *cert_chain_stack = retrieve_server_certificate_chain(
      s_connection, &cert_chain_stack_size, false);
  if (cert_chain_stack == NULL) {
    return;
  }

  for (int index = 0; index < cert_chain_stack_size; index++) {
    X509 *current_certificate = sk_X509_value(cert_chain_stack, index);
    printf("\nPrinting information about certificate at index: %d\n", index);
    print_x509_certificate_info(current_certificate);
  }
}

/**
 * @brief get_data
 * Callback function supplied to curl during its configuration
 * (CURLOPT_WRITEFUNCTION). Curl calls this function whenever it receives a new
 * piece of a data to save. The data transfer does never takes place all at
 * once, but gradually in parts.
 * @param buffer - pointer pointing to the new chunk of delivered data (not null
 * terminated!)
 * @param size - a value that is equal to 1 each time this function is invoked
 * @param nmemb - the size of the new chunk of delivered data, pointing by the
 * first argument
 * @param userp - old, already processed data from previous transfers
 * @return the number of bytes that were processed successfully
 */
size_t get_data(void *buffer, size_t size, size_t nmemb, void *userp) {
  /* Already processed data from previous transfers */
  struct datum_t *ud = (struct datum_t *)userp;

  /* nmemb bytes of new data */
  size *= nmemb;

  /* Reallocate the buffer containing the previous data so that it can also
   * accommodate nmemb of new data */
  ud->data = realloc(ud->data, ud->size + size);
  if (ud->data == NULL) {
    errx(EXIT_FAILURE, "Function 'realloc' has failed");
  }

  /* Append nmemb new bytes to the previous data */
  memcpy(&ud->data[ud->size], buffer, size);
  ud->size += size;

  return size;
}

void save_OCSP_request_to_file(OCSP_REQUEST *ocsp_request, char *filename) {
  BIO *file = BIO_new_file(filename, "wb");
  i2d_OCSP_REQUEST_bio(file, ocsp_request);
  BIO_free(file);
}

void save_OCSP_response_to_file(OCSP_RESPONSE *ocsp_response, char *filename) {
  BIO *file = BIO_new_file(filename, "wb");
  i2d_OCSP_RESPONSE_bio(file, ocsp_response);
  BIO_free(file);
}


#include "crl_revoc.h"

#include <curl/curl.h>
#include <err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <string.h>

#include "utils.h"

int process_single_certificate(X509 *certificate, X509 *issuer_certificate) {
  int status = REVOC_CHECK_SUCCESS;
  int ret_error_val;

  CURL *handle = NULL;
  STACK_OF(DIST_POINT) *dist_points_stack = NULL;

  /* Prepare the custom datum_t structure, where the downloaded CRL in DER
   * format will be stored. */
  struct datum_t downloaded_crl_der = {0};

  /* Prepare the cURL for making out-of-band connection, downloading the CRLs
   * from distribution points */
  curl_global_init(CURL_GLOBAL_ALL);
  handle = curl_easy_init();
  if (handle == NULL) {
    fprintf(stderr, "Function 'curl_easy_init' has failed!\n");
    status = REVOC_CHECK_INTERNAL_ERROR;
    goto cleanup;
  }

  /* Tell curl to write each chunk of data (our CRL list during downloading)
   * with this function callback */
  curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, get_data);
  /* Tell curl to write each chunk of data to the given location, in our case,
   * to the variable in the memory. */
  curl_easy_setopt(handle, CURLOPT_WRITEDATA, &downloaded_crl_der);

  /* Get the STACK of all crl distribution point entries. */
  /* CRL_DIST_POINTS is typedef on STACK_OF(DIST_POINT). */
  dist_points_stack =
      X509_get_ext_d2i(certificate, NID_crl_distribution_points, NULL, NULL);
  if (dist_points_stack == NULL) {
    fprintf(stderr, "Function 'X509_get_ext_d2i' has failed!\n");
    status = REVOC_CHECK_INTERNAL_ERROR;
    goto cleanup;
  }

  for (int index = 0; index < sk_DIST_POINT_num(dist_points_stack); index++) {
    DIST_POINT *dist_point = sk_DIST_POINT_value(dist_points_stack, index);

    GENERAL_NAMES *general_names = dist_point->distpoint->name.fullname;

    for (int index2 = 0; index2 < sk_GENERAL_NAME_num(general_names);
         index2++) {
      int gtype;
      GENERAL_NAME *actual_general_name =
          sk_GENERAL_NAME_value(general_names, index2);
      ASN1_STRING *asn_string_uri =
          GENERAL_NAME_get0_value(actual_general_name, &gtype);

      if (gtype != GEN_URI || ASN1_STRING_length(asn_string_uri) <= 6) {
        printf("- control1 failed!\n");
      }

      const char *crl_dist_point_uri =
          (const char *)ASN1_STRING_get0_data(asn_string_uri);
      printf("- %s\n", crl_dist_point_uri);

      if (crl_dist_point_uri == NULL ||
          strncmp(crl_dist_point_uri, "http://", sizeof("http://") - 1) != 0) {
        printf("- control2 failed!\n");
      }

      /* Tell curl the URL, location where the data should be send. */
      curl_easy_setopt(handle, CURLOPT_URL, crl_dist_point_uri);

      /* Start downloading. */
      if (curl_easy_perform(handle) != 0) {
        fprintf(stderr, "Function 'curl_easy_perform' has failed!\n");
        status = REVOC_CHECK_INTERNAL_ERROR;
        goto cleanup;
      }

      /* The download has successfully finished. */

      /* Downloaded CRL should be stored in the prepared variable in DER format.
       */
      const unsigned char *downloaded_crl_der_data =
          (const unsigned char *)downloaded_crl_der.data;
      /* Downloaded CRL size */
      unsigned int downloaded_crl_der_size = downloaded_crl_der.size;

      /* Import downloaded CRL from DER format to native OpenSSL structure. */
      X509_CRL *downloaded_crl =
          d2i_X509_CRL(NULL, &downloaded_crl_der_data, downloaded_crl_der_size);
      if (downloaded_crl == NULL) {
        fprintf(stderr, "Function 'd2i_X509_CRL' has failed!\n");
        status = REVOC_CHECK_INTERNAL_ERROR;
        free(downloaded_crl_der.data);
        goto cleanup;
      }

      /* From this moment on, i can not free downloaded_crl_der.data, since the
       * d2i_X509_CRL took the pointer, it is now "" */

      /* Verify the signature of downloaded CRL. */

      /* Retrieve the public key of the issuer. */
      EVP_PKEY *issuer_public_key = X509_get0_pubkey(issuer_certificate);
      if (issuer_public_key == NULL) {
        fprintf(stderr, "Function 'X509_get0_pubkey' has failed!\n");
        status = REVOC_CHECK_INTERNAL_ERROR;
        free(downloaded_crl_der.data);
        X509_CRL_free(downloaded_crl);
        goto cleanup;
      }

      /* Verify the signature of downloaded CRL. */
      if (X509_CRL_verify(downloaded_crl, issuer_public_key) != 1) {
        fprintf(stderr, "- signature of the downloaded CRL does not match!\n");
        status = REVOC_CHECK_FAILURE;
        free(downloaded_crl_der.data);
        X509_CRL_free(downloaded_crl);
        goto cleanup;
      } else {
        printf("- signature of the downloaded CRL is OK!\n");
      }

      /* Check the revocation status of the certificate */
      X509_REVOKED *revoked_certificate = NULL;
      if (X509_CRL_get0_by_cert(downloaded_crl, &revoked_certificate,
                                certificate) == 0) {
        /* Certificate is not revoked! */
        /* Pointer revoked_certificate is NULL. */
        printf("- not revoked!\n");
      } else {
        /* Certificate is revoked! */
        /* Pointer revoked_certificate is pointing to the revoked entry in CRL
         * list. */
        printf("- revoked!\n");
        status = REVOC_CHECK_FAILURE;
        free(downloaded_crl_der.data);
        X509_CRL_free(downloaded_crl);
        goto cleanup;
      }

      /* Deinitialize actual loop. */
      free(downloaded_crl_der.data);
      X509_CRL_free(downloaded_crl);
      downloaded_crl_der.data = NULL;
      downloaded_crl_der.size = 0;
    }
  }

  /* Deinitialize. */
  curl_easy_cleanup(handle);
  sk_DIST_POINT_pop_free(dist_points_stack, DIST_POINT_free);
  return status;

cleanup:
  if (handle != NULL) {
    curl_easy_cleanup(handle);
  }
  if (dist_points_stack != NULL) {
    sk_DIST_POINT_pop_free(dist_points_stack, DIST_POINT_free);
  }
  return status;
}

int crl_check(SSL *s_connection) {
  printf("\n*** Performing Certificate Revocation List (CRL) check! ***\n");

  /* Retrieve the server's certificate chain from the OpenSSL connection. */
  int cert_chain_stack_size;
  STACK_OF(X509) *cert_chain_stack = retrieve_server_certificate_chain(
      s_connection, &cert_chain_stack_size, false);
  if (cert_chain_stack == NULL) {
    return REVOC_CHECK_INTERNAL_ERROR;
  }

  /* Check that the certificate chain contains at least 2 certificates. */
  if (cert_chain_stack_size < 2) {
    fprintf(stderr, "- certificate chain is smaller than 2\n");
    return REVOC_CHECK_INTERNAL_ERROR;
  }

  /* Check the revocation status for every certificate from the chain (except
   * the root one). */
  X509 *certificate;
  X509 *issuer_certificate;
  int status;
  for (int index = 0; index < cert_chain_stack_size - 1; index++) {
    printf("\nCertificate at index %d\n", index);
    certificate = sk_X509_value(cert_chain_stack, index);
    issuer_certificate = sk_X509_value(cert_chain_stack, index + 1);
    status = process_single_certificate(certificate, issuer_certificate);
    if (status != REVOC_CHECK_SUCCESS) {
      return status;
    }
  }

  return REVOC_CHECK_SUCCESS;
}

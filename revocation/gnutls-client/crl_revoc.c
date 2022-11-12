#include "crl_revoc.h"

#include <curl/curl.h>
#include <err.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

static int add_trusted_CAs_into_trusted_list(
    gnutls_x509_trust_list_t trusted_list) {
  int ret_err_val;
  /* Another options: 'gnutls_x509_trust_list_add_cas',
   * 'gnutls_x509_trust_list_add_trust_file'. */
  if ((ret_err_val =
           gnutls_x509_trust_list_add_system_trust(trusted_list, 0, 0)) <= 0) {
    fprintf(
        stderr,
        "Function 'gnutls_x509_trust_list_add_system_trust' has failed: %s\n",
        gnutls_strerror(ret_err_val));
    return REVOC_CHECK_FAILURE;
  }

  return REVOC_CHECK_SUCCESS;
}

static int add_trusted_CRLs_into_trusted_list(
    gnutls_x509_trust_list_t trusted_list, gnutls_x509_crt_t certificate,
    gnutls_x509_crt_t issuer_certificate) {
  int status = REVOC_CHECK_SUCCESS;

  int ret_error_val;
  CURL *handle = NULL;
  /* Prepare gnutls_datum_t structure, where the downloaded CRL in DER format
   * will be stored */
  gnutls_datum_t downloaded_crl_DER = {0};
  gnutls_x509_crl_t downloaded_crl = {0};

  /* Prepare buffer for storing the URL adress for one CRL distribution point */
  size_t buffer_crl_dist_point_size = 1024;
  char *buffer_crl_dist_point =
      (char *)calloc(buffer_crl_dist_point_size, sizeof(char));
  if (buffer_crl_dist_point == NULL) {
    fprintf(stderr, "Function 'calloc' has failed!\n");
    return REVOC_CHECK_INTERNAL_ERROR;
  }

  /* Prepare the native gnutls_x509_crl_t structure where the downloaded CRL
   * will be placed */
  if ((ret_error_val = gnutls_x509_crl_init(&downloaded_crl)) !=
      GNUTLS_E_SUCCESS) {
    fprintf(stderr, "Function 'gnutls_x509_crl_init' has failed: %s\n",
            gnutls_strerror(ret_error_val));
    status = REVOC_CHECK_INTERNAL_ERROR;
    goto cleanup;
  }

  /* Prepare and initialize the curl for making out-of-band connection and
   * downloading CRLs from distribution point */
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
   * to the variable in the memory */
  curl_easy_setopt(handle, CURLOPT_WRITEDATA, &downloaded_crl_DER);

  /* gnutls_x509_crl_reason_flags_t enum */
  unsigned int revocation_reasons;
  int dist_points_index = 0;

  /* Each certificate can have more than one CRL distribution point entry. */
  /* This cycle will iterate through every distribution point, until
   * GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE will be returned. */
  while (1) {
    /* Store the CRL distribution point at given index into the prepared buffer.
     */
    ret_error_val = gnutls_x509_crt_get_crl_dist_points(
        certificate, dist_points_index, buffer_crl_dist_point,
        &buffer_crl_dist_point_size, &revocation_reasons, NULL);

    /* If buffer for storing URL of Distribution point is not big enough,
     * reallocate it with returned required size. */
    if (ret_error_val == GNUTLS_E_SHORT_MEMORY_BUFFER) {
      buffer_crl_dist_point =
          (char *)realloc(buffer_crl_dist_point, buffer_crl_dist_point_size);
      if (buffer_crl_dist_point == NULL) {
        fprintf(stderr, "Function 'realloc' has failed\n");
        status = REVOC_CHECK_INTERNAL_ERROR;
        goto cleanup;
      }
      continue;
    }

    if (ret_error_val == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
      break;
    }

    printf("\n- distribution point: %s\n", buffer_crl_dist_point);

    /* Tell curl to download from retrieved URL. */
    curl_easy_setopt(handle, CURLOPT_URL, buffer_crl_dist_point);

    /* Start downloading. */
    ret_error_val = curl_easy_perform(handle);
    if (ret_error_val != 0) {
      fprintf(stderr, "Function curl_easy_perform has failed!\n");
      status = REVOC_CHECK_INTERNAL_ERROR;
      goto cleanup;
    }

    printf("- download successful\n");

    /* Convert the downloaded CRL from structure gnutls_datum_t to structure
     * gnutls_crl_t. */
    if ((ret_error_val = gnutls_x509_crl_import(
             downloaded_crl, &downloaded_crl_DER, GNUTLS_X509_FMT_DER)) != 0) {
      fprintf(stderr, "Function 'gnutls_x509_crl_import' has failed: %s\n",
              gnutls_strerror(ret_error_val));
      gnutls_free(downloaded_crl_DER.data);
      status = REVOC_CHECK_INTERNAL_ERROR;
      goto cleanup;
    }

    /* After downloading, check the signature of the downloaded CRL (if CRL was
     * signed by the CA which signed the certificate). */
    if (gnutls_x509_crl_check_issuer(downloaded_crl, issuer_certificate) != 1) {
      fprintf(stderr, "- signature of the downloaded CRL does not match! \n");
      gnutls_free(downloaded_crl_DER.data);
      status = REVOC_CHECK_FAILURE;
      goto cleanup;
    } else {
      printf("- signature of downloaded CRL matches!\n");
    }

    /* Add downloaded DER encoded CRL to the trusted list */
    if (gnutls_x509_trust_list_add_trust_mem(trusted_list, NULL,
                                             &downloaded_crl_DER,
                                             GNUTLS_X509_FMT_DER, 0, 0) <= 0) {
      fprintf(stderr,
              "Function 'gnutls_x509_trust_list_add_trust_mem' added nothing "
              "to the trusted list!\n");
      gnutls_free(downloaded_crl_DER.data);
      status = REVOC_CHECK_INTERNAL_ERROR;
      goto cleanup;
    }

    /* Deinitialize after each loop. */
    gnutls_free(downloaded_crl_DER.data);
    downloaded_crl_DER.data = NULL;
    downloaded_crl_DER.size = 0;

    memset(buffer_crl_dist_point, 0, buffer_crl_dist_point_size);
    dist_points_index++;
  }

  /* If server's certificate has not a single CRL distribution point, we can not
   * provide CRL revocation check. */
  if (dist_points_index == 0) {
    fprintf(stderr, "- no distribution point found\n");
  }

  free(buffer_crl_dist_point);
  gnutls_x509_crl_deinit(downloaded_crl);
  curl_easy_cleanup(handle);
  return REVOC_CHECK_SUCCESS;

cleanup:
  if (buffer_crl_dist_point != NULL) {
    free(buffer_crl_dist_point);
  }
  if (downloaded_crl != NULL) {
    gnutls_x509_crl_deinit(downloaded_crl);
  }
  if (handle != NULL) {
    curl_easy_cleanup(handle);
  }
  return status;
}

static int verify_server_chain_against_trusted_list(
    gnutls_x509_trust_list_t trusted_list, gnutls_x509_crt_t *server_chain_crt,
    size_t server_chain_size) {
  int ret_error_val;

  /* Verify the server's chain against filled trusted list. */
  /* Possible to modify behaviour with 4th argument which is enum of
   * gnutls_certicate_cerify_flags (GNUTLS_VERIFY_*). */
  /* ORed sequence of gnutls_certificate_status_t enum. */
  unsigned int verify_output;
  if ((ret_error_val = gnutls_x509_trust_list_verify_crt(
           trusted_list, server_chain_crt, server_chain_size, 0, &verify_output,
           NULL)) != 0) {
    fprintf(stderr,
            "Function 'gnutls_x509_trust_list_verify_crt' has failed: %s\n",
            gnutls_strerror(ret_error_val));
    return REVOC_CHECK_INTERNAL_ERROR;
  }

  if (verify_output & GNUTLS_CERT_INVALID) {
    printf("Result of verification: [NOK]\n");
    if (verify_output & GNUTLS_CERT_REVOKED) {
      printf("- certificate is revoked\n");
    } else if (verify_output & GNUTLS_CERT_EXPIRED) {
      printf("- cerficate expired\n");
    } else if (verify_output & GNUTLS_CERT_SIGNER_NOT_CA) {
      printf("- signer of the certificate is not CA\n");
    } else if (GNUTLS_CERT_SIGNER_NOT_FOUND) {
      printf("- signer not found\n");
    }
    /* List goes on, possible invalid macros are available at:
     * https://gnutls.org/manual/gnutls.html#gnutls_005fcertificate_005fstatus_005ft
     */
    else {
      printf("- other verification problem\n");
    }
    return REVOC_CHECK_FAILURE;
  }

  /* No verification error */
  printf("Result of verification: [OK]\n");
  return REVOC_CHECK_SUCCESS;
}

int crl_revoc_check(gnutls_session_t session) {
  int status = REVOC_CHECK_SUCCESS;

  printf(
      "\n--- Performing Certificate Revocation List (CRL) verification! ---\n");

  /* Retrieve the whole server certificate chain. */
  size_t server_chain_size;
  gnutls_x509_crt_t *server_chain_crt =
      retrieve_server_certificate_chain(session, &server_chain_size);
  if (server_chain_crt == NULL) {
    return REVOC_CHECK_INTERNAL_ERROR;
  }

  /* Prepare the trust list structure. */
  /* This structure is gonna be filled with system's default trusted CAs and
   * trusted verified CRLs which we gonna download during the following steps.
   */
  gnutls_x509_trust_list_t trusted_list = {0};
  gnutls_x509_trust_list_init(&trusted_list, 0);

  /* a) Fill the trust list with system's default trusted CAs */
  if ((status = add_trusted_CAs_into_trusted_list(trusted_list)) !=
      REVOC_CHECK_SUCCESS) {
    goto cleanup;
  }

  /* b) Download all CRLs from CRL Distribution Point extension, verify them and
   * then add to the trusted list. */
  for (int index = 0; index < server_chain_size - 1; index++) {
    printf("\nDownloading CRLs of certificate at index %d\n", index);
    if ((status = add_trusted_CRLs_into_trusted_list(
             trusted_list, server_chain_crt[index],
             server_chain_crt[index + 1])) != REVOC_CHECK_SUCCESS) {
      goto cleanup;
    }
  }

  /* Verify the whole chain with the filled trusted list. */
  if ((status = verify_server_chain_against_trusted_list(
           trusted_list, server_chain_crt, server_chain_size)) !=
      REVOC_CHECK_SUCCESS) {
    goto cleanup;
  }

  /* Deinitialize. */
  deinitialize_certificate_chain(server_chain_crt, server_chain_size);
  gnutls_x509_trust_list_deinit(trusted_list, 1);
  return status;

cleanup:
  deinitialize_certificate_chain(server_chain_crt, server_chain_size);
  if (trusted_list != NULL) {
    gnutls_x509_trust_list_deinit(trusted_list, 1);
  }
  return status;
}

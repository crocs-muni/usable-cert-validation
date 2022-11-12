#include "ocsp_revoc.h"

#include <curl/curl.h>
#include <err.h>
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <gnutls/ocsp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "utils.h"

/*
 * gnutls_ocsp_print_formats_t -- GNUTLS_OCSP_PRINT_*
 * gnutls_ocsp_resp_status_t  -- GNUTLS_OCSP_RESP_*  -- from
 * gnutls_ocsp_resp_get_status gnutls_ocsp_cert_status_t -- GNUTLS_OCSP_CERT_*
 * gnutls_x509_crl_reason_t -- GNUTLS_X509_CRLREASON_*
 * gnutls_ocsp_verify_reason_t -- GNUTLS_OCSP_VERIFY_*
 */

static char *extract_ocsp_responder_uri(gnutls_x509_crt_t certificate,
                                        int *number_of_responders) {
  /* The received OCSP Responder URL will be stored in this variable. */
  gnutls_datum_t ocsp_responder_uri_datum = {0};

  int ret_val;
  /* If there are multiple records with the same extension specified.  */
  int act_index = 0;

  while (1) {
    /* Parse the URL adress of the certificate from its extension called
     * authority info access. */
    ret_val = gnutls_x509_crt_get_authority_info_access(
        certificate, act_index, GNUTLS_IA_OCSP_URI, &ocsp_responder_uri_datum,
        NULL);

    /* Requested OID of the Authorify Info Access extension does not match, call
     * again with another index. */
    if (ret_val == GNUTLS_E_UNKNOWN_ALGORITHM) {
      act_index++;
      continue;
    }

    /* Index out of bounds. */
    if (ret_val == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
      printf("- no URL of OCSP Responder found\n");
      *number_of_responders = 0;
      return NULL;
    }
    if (ret_val < 0) {
      fprintf(stderr, "- error occured while parsing aia extension: %s\n",
              gnutls_strerror(ret_val));
      return NULL;
    }

    /* No error occured, we have succesfully parsed the URL from AIA extension.
     */
    break;
  }

  /* Convert the received URL of OCSP Responder to string (char *). */
  char *ocsp_responder_uri =
      (char *)gnutls_malloc((ocsp_responder_uri_datum.size + 1) * sizeof(char));
  if (ocsp_responder_uri == NULL) {
    gnutls_free(ocsp_responder_uri_datum.data);
    fprintf(stderr, "Function 'gnutls_malloc' has failed!\n");
    return NULL;
  }
  memcpy(ocsp_responder_uri, ocsp_responder_uri_datum.data,
         ocsp_responder_uri_datum.size);
  ocsp_responder_uri[ocsp_responder_uri_datum.size] = 0;

  /* Deinitialize. */
  gnutls_free(ocsp_responder_uri_datum.data);

  printf("- OCSP responder URL: %s\n", ocsp_responder_uri);

  return ocsp_responder_uri;
}

static gnutls_ocsp_req_t generate_ocsp_request(
    gnutls_x509_crt_t certificate, gnutls_x509_crt_t issuer_certificate,
    gnutls_datum_t *_nonce) {
  int ret_error_val;

  /* Initialize empty ocsp_req_t structure for storing the OCSP Request. */
  gnutls_ocsp_req_t ocsp_req;
  if ((ret_error_val = gnutls_ocsp_req_init(&ocsp_req)) < 0) {
    fprintf(stderr, "Function 'gnutls_ocsp_req_init' has failed: %s\n",
            gnutls_strerror(ret_error_val));
    return NULL;
  }

  /* Add the serial number of the certificate we want to check, its issuer name
   * and key. */
  /* Serial number and issuer's name and key are parsed from the supplied
   * certificates. */
  /* Fields are hashed with the supplied hashing algorithm
   * (gnutls_digest_algorithm_t enum). */
  if ((ret_error_val = gnutls_ocsp_req_add_cert(
           ocsp_req, GNUTLS_DIG_SHA1, issuer_certificate, certificate)) !=
      GNUTLS_E_SUCCESS) {
    fprintf(stderr, "Function 'gnutls_ocsp_req_add_cert' has failed: %s\n",
            gnutls_strerror(ret_error_val));
    gnutls_ocsp_req_deinit(ocsp_req);
    return NULL;
  }

  /* Add or update a nonce extension to the OCSP request with newly generated
   * random value. */
  if ((ret_error_val = gnutls_ocsp_req_randomize_nonce(ocsp_req)) !=
      GNUTLS_E_SUCCESS) {
    fprintf(stderr,
            "Function 'gnutls_ocsp_req_randomize_nonce' has failed: %s\n",
            gnutls_strerror(ret_error_val));
    gnutls_ocsp_req_deinit(ocsp_req);
    return NULL;
  }

  /* Retrieve the OCSP request nonce extension data. */
  gnutls_datum_t nonce_req = {0};
  if ((ret_error_val = gnutls_ocsp_req_get_nonce(ocsp_req, NULL, &nonce_req)) !=
      GNUTLS_E_SUCCESS) {
    fprintf(stderr, "Function 'gnutls_ocsp_req_get_nonce' has failed: %s\n",
            gnutls_strerror(ret_error_val));
    gnutls_ocsp_req_deinit(ocsp_req);
    return NULL;
  }

  memcpy(&(_nonce->data), &nonce_req.data, nonce_req.size);
  _nonce->size = nonce_req.size;

  /* Deinitialize */
  gnutls_free(nonce_req.data);

  return ocsp_req;
}

static gnutls_ocsp_resp_t send_generated_ocsp_request(
    gnutls_ocsp_req_t ocsp_req, char *ocsp_responder_uri) {
  int ret_val;
  CURL *handle = NULL;
  gnutls_datum_t ocsp_req_datum_DER = {0};
  struct curl_slist *headers = NULL;
  gnutls_ocsp_resp_t ocsp_response = NULL;
  /* Structure where the retrieved OCSP Response will be placed. */
  gnutls_datum_t ocsp_response_datum = {0};

  /* Export OCSP Request from gnutls_ocsp_req_t structure to gnutls_datum_t
   * structure. */
  if ((ret_val = gnutls_ocsp_req_export(ocsp_req, &ocsp_req_datum_DER)) != 0) {
    fprintf(stderr, "Function 'gnutls_ocsp_req_export' has failed: %s\n",
            gnutls_strerror(ret_val));
    goto cleanup;
  }

  /* Initialize the curl. */
  curl_global_init(CURL_GLOBAL_ALL);
  handle = curl_easy_init();
  if (handle == NULL) {
    fprintf(stderr, "Function 'curl_easy_init' has failed!\n");
    goto cleanup;
  }

  headers =
      curl_slist_append(headers, "Content-Type: application/ocsp-request");
  if (headers == NULL) {
    fprintf(stderr, "Function 'curl_slist_append' has failed!\n");
    goto cleanup;
  }

  /* Tell curl which data we want to send (in our case OCSP Request data). */
  curl_easy_setopt(handle, CURLOPT_POSTFIELDS, ocsp_req_datum_DER.data);
  /* Tell curl the size of the data we want to send (size of the OCSP Request).
   */
  curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE, ocsp_req_datum_DER.size);
  /* Tell curl URL where the data should be send. */
  curl_easy_setopt(handle, CURLOPT_URL, ocsp_responder_uri);
  /* Add our custom HTTP headers. */
  curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers);
  /* Tell curl to write each chunk of data (our OCSP Response) with this
   * function callback. */
  curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, get_data);
  /* Tell curl to write each chunk of data to the given location, in our case,
   * to the variable in the memory. */
  curl_easy_setopt(handle, CURLOPT_WRITEDATA, &ocsp_response_datum);

  /* Send the request. */
  ret_val = curl_easy_perform(handle);
  if (ret_val != 0) {
    fprintf(stderr, "Function 'curl_easy_perform' has failed!\n");
    goto cleanup;
  }

  /* Convert the retrieved OCSP Response from gnutls_datum_t structure to
   * gnutls_ocsp_resp_t structure. */
  if ((ret_val = gnutls_ocsp_resp_init(&ocsp_response)) != GNUTLS_E_SUCCESS) {
    fprintf(stderr, "Function 'gnutls_ocsp_resp_init' has failed: %s\n",
            gnutls_strerror(ret_val));
    goto cleanup;
  }
  if ((ret_val = gnutls_ocsp_resp_import(
           ocsp_response, &ocsp_response_datum)) != GNUTLS_E_SUCCESS) {
    fprintf(stderr, "Function 'gnutls_ocsp_resp_import' has failed: %s\n",
            gnutls_strerror(ret_val));
    goto cleanup;
  }

  /* Deinitialize cURL and other structures. */
  curl_slist_free_all(headers);
  curl_easy_cleanup(handle);
  gnutls_free(ocsp_req_datum_DER.data);
  gnutls_free(ocsp_response_datum.data);

  return ocsp_response;

cleanup:
  if (ocsp_req_datum_DER.data != NULL) {
    gnutls_free(ocsp_req_datum_DER.data);
  }
  if (ocsp_response_datum.data != NULL) {
    gnutls_free(ocsp_response_datum.data);
  }
  if (handle != NULL) {
    curl_easy_cleanup(handle);
  }
  if (headers != NULL) {
    curl_slist_free_all(headers);
  }
  if (ocsp_response != NULL) {
    gnutls_ocsp_resp_deinit(ocsp_response);
  }
  return NULL;
}

int verify_ocsp_response_signature(gnutls_ocsp_resp_t ocsp_response,
                                   gnutls_x509_crt_t certificate,
                                   gnutls_x509_crt_t issuer_certificate,
                                   gnutls_datum_t nonce_req) {
  int ret_value;

  /* Check the status of OCSP response (as gnutls_ocsp_resp_status_t enum). */
  if (gnutls_ocsp_resp_get_status(ocsp_response) !=
      GNUTLS_OCSP_RESP_SUCCESSFUL) {
    fprintf(stderr, "- ocsp response has not valid confirmations\n");
    return REVOC_CHECK_FAILURE;
  }

  /* Check whether the OCSP response is about the provided certificate. */
  if (gnutls_ocsp_resp_check_crt(ocsp_response, 0, certificate) !=
      GNUTLS_E_SUCCESS) {
    fprintf(
        stderr,
        "- ocsp response does not contain correct certificate's serial number");
    return REVOC_CHECK_FAILURE;
  }

  /* Extract the nonce extension from the OCSP response. */
  gnutls_datum_t nonce_resp = {0};

  if (gnutls_ocsp_resp_get_nonce(ocsp_response, NULL, &nonce_resp) ==
      GNUTLS_E_SUCCESS) {
    /* Check that the nonces from the OCSP Request and OCSP Response are the
     * same. */
    if (nonce_req.size != nonce_resp.size ||
        memcmp(nonce_req.data, nonce_resp.data, nonce_resp.size) != 0) {
      fprintf(stderr,
              "- nonce OCSP Req and nonce OCSP Resp are not the same\n");
    }

    gnutls_free(nonce_resp.data);
  } else {
    fprintf(stderr, "- nonce extension in OCSP Response is not present\n");
  }

  /* Verify signature of the Basic OCSP Response against the public key in the
   * issuer's certificate. */
  /* Output variable as gnutls_ocsp_verify_reason_t enum. */
  unsigned int verify_result;
  if ((ret_value = gnutls_ocsp_resp_verify_direct(
           ocsp_response, issuer_certificate, &verify_result, 0)) !=
      GNUTLS_E_SUCCESS) {
    fprintf(stderr,
            "Function 'gnutls_ocsp_resp_verify_direct' has failed: %s\n",
            gnutls_strerror(ret_value));
    return REVOC_CHECK_INTERNAL_ERROR;
  }

  printf("- verifying the signature of OCSP Basic Response ... ");

  if (verify_result & GNUTLS_OCSP_VERIFY_SIGNER_NOT_FOUND) {
    printf("[NOK] - signer certificate not found\n");
    return REVOC_CHECK_FAILURE;
  }
  if (verify_result & GNUTLS_OCSP_VERIFY_SIGNER_KEYUSAGE_ERROR) {
    printf("[NOK] - Signer certificate keyusage error\n");
    return REVOC_CHECK_INTERNAL_ERROR;
  }
  if (verify_result & GNUTLS_OCSP_VERIFY_UNTRUSTED_SIGNER) {
    printf("[NOK] - signer certificate is not trusted\n");
    return REVOC_CHECK_INTERNAL_ERROR;
  }
  if (verify_result & GNUTLS_OCSP_VERIFY_INSECURE_ALGORITHM) {
    printf("[NOK] - insecure algorithm\n");
    return REVOC_CHECK_INTERNAL_ERROR;
  }
  if (verify_result & GNUTLS_OCSP_VERIFY_SIGNATURE_FAILURE) {
    printf("[NOK] - signature failure\n");
    return REVOC_CHECK_INTERNAL_ERROR;
  }
  if (verify_result & GNUTLS_OCSP_VERIFY_CERT_NOT_ACTIVATED) {
    printf("[NOK] - Signer certificate is not activated\n");
    return REVOC_CHECK_INTERNAL_ERROR;
  }
  if (verify_result & GNUTLS_OCSP_VERIFY_CERT_EXPIRED) {
    printf("[NOK] - Signer cerificate has expired\n");
    return REVOC_CHECK_INTERNAL_ERROR;
  }

  printf("[OK] \n");
  return REVOC_CHECK_SUCCESS;
}

int ocsp_revocation_result(gnutls_ocsp_resp_t ocsp_response) {
  int ret_err_val;
  int status;

  printf("- verifying the revocation status of certificate ... ");

  /* Retrieve the revocation status of the certificate. */
  /* Specifies response number to get, 0 means the first one. */
  unsigned int index = 0;
  /* Hash algoritm used when hashing issuer's name and key. */
  gnutls_digest_algorithm_t hash_algorithm;
  /* Hash of the issuer's name will be stored here. */
  gnutls_datum_t issuer_name_hash;
  /* Hash of the issuer's key will be stored here. */
  gnutls_datum_t issuer_key_hash;
  /* Serial number of the certificate that was checked. */
  gnutls_datum_t serial_number;
  /* Certificate status as gnutls_ocsp_cert_status_t enum. */
  unsigned int cert_status;
  /* If cert_status is GNUTLS_OCSP_CERT_REVOKED, then this variable holds time
   * of revocation. */
  time_t revocation_time;
  /* If cert_status is GNUTLS_OCSP_CERT_REVOKED, then this variable hold
   * gnutls_x509_crl_reason_t enum value. */
  unsigned int revocation_reason;

  if ((ret_err_val = gnutls_ocsp_resp_get_single(
           ocsp_response, index, &hash_algorithm, &issuer_name_hash,
           &issuer_key_hash, &serial_number, &cert_status, NULL, NULL,
           &revocation_time, &revocation_reason)) != GNUTLS_E_SUCCESS) {
    fprintf(stderr, "Function 'gnutls_ocsp_resp_get_single' has failed: %s\n",
            gnutls_strerror(ret_err_val));
    return REVOC_CHECK_INTERNAL_ERROR;
  }

  /* Examine the revocation result of given certificate */

  if (cert_status == GNUTLS_OCSP_CERT_GOOD) {
    printf(" [OK] \n");
    status = REVOC_CHECK_SUCCESS;
  }

  else if (cert_status == GNUTLS_OCSP_CERT_UNKNOWN) {
    printf(" [UNKNOWN] \n");
    status = REVOC_CHECK_SUCCESS;
  }

  else if (cert_status == GNUTLS_OCSP_CERT_REVOKED) {
    printf(" [NOK] \n");
    status = REVOC_CHECK_FAILURE;
    /* Can further inspect revocation_time, revocation_reason, etc */
  }

  else {
    printf(" [SHOULD_NOT_HAPPEN] \n");
    status = REVOC_CHECK_INTERNAL_ERROR;
  }

  /* Deinitialize */
  gnutls_free(issuer_name_hash.data);
  gnutls_free(issuer_key_hash.data);
  gnutls_free(serial_number.data);
  return status;
}

static int ocsp_revoc_check_single_certificate(
    gnutls_x509_crt_t certificate, gnutls_x509_crt_t issuer_certificate) {
  int status = REVOC_CHECK_SUCCESS;

  char *ocsp_responder_uri;
  gnutls_ocsp_req_t ocsp_req = NULL;
  gnutls_ocsp_resp_t ocsp_response = NULL;

  /* Extract the URL of OCSP Responder from the certificate's extension. */
  int number_of_responders = -1;
  ocsp_responder_uri =
      extract_ocsp_responder_uri(certificate, &number_of_responders);
  if (ocsp_responder_uri == NULL && number_of_responders == 0) {
    return REVOC_CHECK_SUCCESS;
  }
  if (ocsp_responder_uri == NULL) {
    return REVOC_CHECK_INTERNAL_ERROR;
  }

  /* Generate the OCSP Request containing the certificate we want to verify. */
  gnutls_datum_t nonce_req = {0};
  ocsp_req = generate_ocsp_request(certificate, issuer_certificate, &nonce_req);
  if (ocsp_req == NULL) {
    status = REVOC_CHECK_INTERNAL_ERROR;
    goto cleanup;
  }

  /* Print the generated OCSP Request to the stdout. */
  print_ocsp_request_info(ocsp_req);

  /* Send the generated OCSP Request with libcurl to the OCSP Responder and
   * retrieve the response. */
  ocsp_response = send_generated_ocsp_request(ocsp_req, ocsp_responder_uri);
  if (ocsp_response == NULL) {
    status = REVOC_CHECK_INTERNAL_ERROR;
    goto cleanup;
  }

  /* Print the OCSP Response to the stdout. */
  print_ocsp_response_info(ocsp_response);

  /* Verify the signature of the OCSP Response. */
  if ((status = verify_ocsp_response_signature(
           ocsp_response, certificate, issuer_certificate, nonce_req)) !=
      REVOC_CHECK_SUCCESS) {
    goto cleanup;
  }

  /* Get the OCSP Revocation result for this certificate */
  if ((status = ocsp_revocation_result(ocsp_response)) != REVOC_CHECK_SUCCESS) {
    goto cleanup;
  }

  /* Deinitialize */
  gnutls_free(ocsp_responder_uri);
  gnutls_ocsp_req_deinit(ocsp_req);
  gnutls_ocsp_resp_deinit(ocsp_response);
  return status;

cleanup:
  if (ocsp_responder_uri != NULL) {
    gnutls_free(ocsp_responder_uri);
  }
  if (ocsp_req != NULL) {
    gnutls_ocsp_req_deinit(ocsp_req);
  }
  if (ocsp_response != NULL) {
    gnutls_ocsp_resp_deinit(ocsp_response);
  }
  return status;
}

int ocsp_revoc_check(gnutls_session_t session) {
  int status = REVOC_CHECK_SUCCESS;

  printf(
      "\n--- Performing Online Certificate Status Protocol (OCSP) "
      "verification! ---\n");

  /* Retrieve the whole server certificate chain */
  size_t chain_size;
  gnutls_x509_crt_t *server_chain_crt =
      retrieve_server_certificate_chain(session, &chain_size);
  if (server_chain_crt == NULL) {
    return REVOC_CHECK_INTERNAL_ERROR;
  }

  /* For each certificate in certificate chain (except the root one), perform
   * OCSP revocation check */
  /* That includes finding the URL of OCSP Responder for each certificate,
   * generating and sending OCSP Request. retrieving and processing OCSP
   * Response, verifying the signature of OCSP Response and finally checking the
   * revocation status for each certificate.
   */
  for (int index = 0; index < chain_size - 1; index++) {
    printf("\nVerifying certificate at index %d \n", index);
    if (!ocsp_revoc_check_single_certificate(server_chain_crt[index],
                                             server_chain_crt[index + 1])) {
      goto cleanup;
    }
  }

  /* Deinitialize */
  deinitialize_certificate_chain(server_chain_crt, chain_size);
  return status;

cleanup:
  deinitialize_certificate_chain(server_chain_crt, chain_size);
  return status;
}

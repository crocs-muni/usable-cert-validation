#include "ct_check.h"

#include <err.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509-ext.h>
#include <gnutls/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "utils.h"

static bool ct_check_single_timestamp(gnutls_datum_t logid,
                                      gnutls_sign_algorithm_t sigalg,
                                      gnutls_datum_t signature,
                                      time_t timestamp) {
  /* Verify the obtained information */

  /* CT check not completed for gnutls! */
  printf("[UNKNOWN] \n");
  printf("    - timestamp: %s", ctime(&timestamp));
  return true;
}

static bool ct_check_single_certificate(gnutls_x509_crt_t certificate) {
  int ret_err_val;

  /* This is the defined OID for Signed Certificate Timestamp (SCT) extension */
  char *CT_SCT_OID = "1.3.6.1.4.1.11129.2.4.2";

  /* SCT list in DER encoded raw form */
  gnutls_datum_t sct_list_DER = {0};
  /* STC list in native gnutls_x509_ct_scts_t structure */
  gnutls_x509_ct_scts_t sct_list = {0};

  /* Information about one SCT from SCT list */
  /* DER encoded ID of the public log that appended the given certificate to
   * itself */
  gnutls_datum_t logid = {0};
  /* Algorithm which was used for signing this SCT */
  gnutls_sign_algorithm_t sigalg = {0};
  /* DER encoded signature */
  gnutls_datum_t signature = {0};
  /* Timestamp, when was this SCT added to the public log */
  time_t timestamp;

  /* Retrieve the CT SCT list of the given certificate from SCT extension into
   * gnutls_datum_t structure in DER format */

  /* Index specifies the index of OID in case multiple same OIDs exist in
   * certificate extensions , we are working only with index 0 */
  int index = 0;
  /* Information whether the required extension is marked as critical or not */
  unsigned int critical;

  ret_err_val = gnutls_x509_crt_get_extension_by_oid2(
      certificate, CT_SCT_OID, index, &sct_list_DER, &critical);
  if (ret_err_val != GNUTLS_E_SUCCESS) {
    if (ret_err_val == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
      printf("- certificate does not contain specified extension!\n");
      return true;
    }

    /* Other error code means failure */
    fprintf(stderr,
            "Function 'gnutls_x509_crt_get_extension_by_oid2' has failed: %s\n",
            gnutls_strerror(ret_err_val));
    exit(EXIT_FAILURE);
  }

  /* Convert the DER encoded CT SCT list from gnutls_datum_t structure to native
   * gnutls_x509_ct_scts_t structure. */
  if ((ret_err_val = gnutls_x509_ext_ct_scts_init(&sct_list)) !=
      GNUTLS_E_SUCCESS) {
    fprintf(stderr, "Function 'gnutls_x509_ext_ct_scts_init' has failed: %s\n",
            gnutls_strerror(ret_err_val));
    goto cleanup;
  }
  if ((ret_err_val = gnutls_x509_ext_ct_import_scts(&sct_list_DER, sct_list,
                                                    0)) != GNUTLS_E_SUCCESS) {
    fprintf(stderr,
            "Function 'gnutls_x509_ext_ct_import_scts' has failed: %s\n",
            gnutls_strerror(ret_err_val));
    goto cleanup;
  }

  /* Check each SCT from SCT list */

  for (int index = 0;; index++) {
    /* Retrieve single SCT from the SCT list */
    ret_err_val = gnutls_x509_ct_sct_get(sct_list, index, &timestamp, &logid,
                                         &sigalg, &signature);

    if (ret_err_val == GNUTLS_E_SUCCESS) {
      printf("  Verifying SCT at index %d ... ", index);
      ct_check_single_timestamp(logid, sigalg, signature, timestamp);
    } else {
      if (ret_err_val == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
        break;
      } else {
        goto cleanup;
      }
    }
    /* Deinitialize after each loop */
    gnutls_free(logid.data);
    gnutls_free(signature.data);
  }

  /* Deinitialize */
  gnutls_free(sct_list_DER.data);
  gnutls_x509_ext_ct_scts_deinit(sct_list);
  return true;

cleanup:
  if (sct_list_DER.data != NULL) {
    gnutls_free(sct_list_DER.data);
  }
  if (sct_list != NULL) {
    gnutls_x509_ext_ct_scts_deinit(sct_list);
  }
  exit(EXIT_FAILURE);
}

bool ct_check(gnutls_session_t session) {
  printf("\n--- Performing Certificate Transparency (CT) verification! ---\n");

  /* Retrieve the whole server certificate chain */
  size_t chain_size;
  gnutls_x509_crt_t *server_chain_crt =
      retrieve_server_certificate_chain(session, &chain_size);
  if (server_chain_crt == NULL) {
    exit(EXIT_FAILURE);
  }

  for (int index = 0; index < chain_size; index++) {
    printf("\n");
    printf("Verifying certificate at index %d\n", index);
    if (!ct_check_single_certificate(server_chain_crt[index])) {
      printf("[NOK] \n");
      goto cleanup;
    }

    printf("[UNKNOWN] \n");
  }

  printf("\nResult of verification: [UNKNOWN]\n");

  /* Deinitialize the certificate chain */
  deinitialize_certificate_chain(server_chain_crt, chain_size);
  return true;

cleanup:
  deinitialize_certificate_chain(server_chain_crt, chain_size);
  return false;
}

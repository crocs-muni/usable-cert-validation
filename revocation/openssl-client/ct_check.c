#include "ct_check.h"

#include <err.h>
#include <openssl/ssl.h>

#include "utils.h"

CT_POLICY_EVAL_CTX *fill_CT_POLICY_structure(SSL *s_connection,
                                             CTLOG_STORE *ctlog_store) {
  /* Retrieve the server's certificate chain from the OpenSSL connection. */
  int cert_chain_stack_size;
  STACK_OF(X509) *cert_chain_stack = retrieve_server_certificate_chain(
      s_connection, &cert_chain_stack_size, false);
  if (cert_chain_stack == NULL) {
    return NULL;
  }

  if (cert_chain_stack_size < 2) {
    fprintf(stderr, "- certificate chain is smaller than 2\n");
    return NULL;
  }

  X509 *server_certificate = sk_X509_value(cert_chain_stack, 0);
  X509 *issuer_certificate = sk_X509_value(cert_chain_stack, 1);
  if (server_certificate == NULL || issuer_certificate == NULL) {
    fprintf(stderr, "- some certificate was not parsed from certificate chain");
    return NULL;
  }

  /* Initialize empty CT POLICY structure. */
  /* This structure is used during the validation wheter the SCTs fulfil a CT
   * policy. */
  CT_POLICY_EVAL_CTX *ct_policy_eval = CT_POLICY_EVAL_CTX_new();
  if (ct_policy_eval == NULL) {
    fprintf(stderr, "Function 'CT_POLICY_EVAL_CTX_new' has failed!\n");
    return NULL;
  }

  /* 1.) Populate the policy with the certificate that the SCT was issued for.
   */
  if (CT_POLICY_EVAL_CTX_set1_cert(ct_policy_eval, server_certificate) != 1) {
    fprintf(stderr, "Function 'CT_POLICY_EVAL_CTX_set1_cert' has failed!\n");
    CT_POLICY_EVAL_CTX_free(ct_policy_eval);
    return NULL;
  }

  /* 2.) Populate the policy with the issuer's certificate (needed when SCT is
   * embedded in the extension of the X.509 certificate). */
  if (CT_POLICY_EVAL_CTX_set1_issuer(ct_policy_eval, issuer_certificate) != 1) {
    fprintf(stderr, "Function 'CT_POLICY_EVAL_CTX_set1_issuer' has failed!\n");
    CT_POLICY_EVAL_CTX_free(ct_policy_eval);
    return NULL;
  }

  /* 3.) Populate the policy with all available trusted public logs from the
   * CTLOG_STORE structure. */
  CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE(ct_policy_eval, ctlog_store);

  /* 4) Populate the policy with current time + 5 min to verify the timestamp of
   * the SCT. */
  CT_POLICY_EVAL_CTX_set_time(ct_policy_eval, (time(NULL) + 300) * 1000);

  return ct_policy_eval;
}

CTLOG_STORE *fill_CTLOG_STORE_structure() {
  /* Initialize empty CTLOG_STORE structure which will be used later during
   * validation of SCTs and printing the SCTs to stdout. */
  CTLOG_STORE *ctlog_store = CTLOG_STORE_new();
  if (ctlog_store == NULL) {
    fprintf(stderr, "Function 'CTLOG_STORE_new' has failed");
    return NULL;
  }

  /* Fill CTLOG_STORE structure with information about public log servers. */
  /* For this purpose, configuration 'ct_log_list.cnf' file from OpenSSL is
   * used. */
  /* NOTE: Need to manually generate this file. */
  /* Other option: CTLOG_STORE_load_file */
  if (CTLOG_STORE_load_default_file(ctlog_store) == 1) {
    printf(
        "- all CT logs from the provided file were successfully appended to "
        "the CTLOG_STORE structure!\n");
  } else {
    fprintf(stderr,
            "- WARNING: not all CT logs from the provided file were "
            "successfully appeneded to the CTLOG_STORE structure!\n");
  }

  return ctlog_store;
}

int validate_entire_SCT_list(const STACK_OF(SCT) * sct_list_stack,
                             CT_POLICY_EVAL_CTX *ct_policy_eval) {
  /* Validate whole list, 1 is returned only if every SCT from list passed the
   * validation! */
  /* Perform validation check at entire STC list. */
  /* Result of validation is possible to examine through
   * SCT_get_validation_status call. */
  int ret_value = SCT_LIST_validate(sct_list_stack, ct_policy_eval);
  if (ret_value < 0) {
    /* Internal error occured, function has failed. */
    fprintf(stderr, "Function 'SCT_LIST_validate' has failed!\n");
    return REVOC_CHECK_INTERNAL_ERROR;
  } else if (ret_value == 0) {
    fprintf(
        stderr,
        "- WARNING: at least one SCT from the SCT list failed validation!\n");
  } else if (ret_value == 1) {
    printf("- The entire SCT list has passed the validation!\n");
  } else {
    printf("- should not happen.");
  }

  return REVOC_CHECK_SUCCESS;
}

int validate_each_SCT_from_list(const STACK_OF(SCT) * sct_list_stack,
                                CT_POLICY_EVAL_CTX *ct_policy_eval) {
  /* Alternative */
  SCT *single_sct;
  sct_validation_status_t validation_status;
  int ret_val;

  /* Iterate through the list and check every single SCT from the list. */
  /* Iterate through the whole SCT list and in each iteration validate one SCT
   * from the list. */
  int sct_list_stack_size = sk_SCT_num(sct_list_stack);
  for (int index = 0; index < sct_list_stack_size; index++) {
    printf("\nPerforming validation of SCT at index: %d ... ", index);

    /* Retrieve one SCT from the SCT list at the given index. */
    single_sct = sk_SCT_value(sct_list_stack, index);

    /* Validate the single SCT. */
    ret_val = SCT_validate(single_sct, ct_policy_eval);
    if (ret_val < 0) {
      /* Internal error occured, function has failed. */
      fprintf(stderr, "Function 'SCT_validate' has failed!\n");
      return REVOC_CHECK_INTERNAL_ERROR;
    }
    if (ret_val == 1) {
      printf("[OK]\n");
    } else if (ret_val == 0) {
      /* ret_val == 0 means failure. */
      printf("[NOK]\n");
    } else {
      printf("[ERROR]\n");
      return REVOC_CHECK_INTERNAL_ERROR;
    }

    /* Examine the validation status (in both cases, failure and success). */

    /* Retrieve the validation status of current SCT. */
    validation_status = SCT_get_validation_status(single_sct);
    if (validation_status == SCT_VALIDATION_STATUS_UNVERIFIED) {
      fprintf(stderr, "- failure to provide the certificate!\n");
    } else if (validation_status == SCT_VALIDATION_STATUS_UNKNOWN_LOG) {
      fprintf(stderr,
              "- public log that issued this SCT is not present in CTLOG_STORE "
              "structure!\n");
    } else if (validation_status == SCT_VALIDATION_STATUS_UNKNOWN_VERSION) {
      fprintf(stderr,
              "- current SCT is of an unsupported version (only v1 is "
              "currently supported)!\n");
    } else if (validation_status == SCT_VALIDATION_STATUS_INVALID) {
      fprintf(stderr,
              "- current SCT´s signature is incorrect or its timestamp is "
              "invalid or SCT is otherwise invalid!\n");
    } else if (validation_status == SCT_VALIDATION_STATUS_VALID) {
      printf("- current SCT is valid!\n");
    }

    /* It is also possible to retrieve a human-readable string of validation
     * status */
    const char *validation_message = SCT_validation_status_string(single_sct);
    printf("- message: %s\n", validation_message);
  }

  return REVOC_CHECK_SUCCESS;
}

int ct_check(SSL *s_connection) {
  printf("\n*** Performing Certificate Transparency check ***\n");

  int status = REVOC_CHECK_SUCCESS;

  BIO *out = NULL;
  CT_POLICY_EVAL_CTX *ct_policy_eval = NULL;

  /* Retrieve a list of SCTs which have been found for a given SSL instance. */
  /* TLS extensions, OCSP response and the peer's certificate are examined for
   * this purpose. */
  /* Does not mean for every certificate from the chain. */
  const STACK_OF(SCT) *sct_list_stack = SSL_get0_peer_scts(s_connection);
  if (sct_list_stack == NULL) {
    fprintf(stderr, "Function 'SSL_get0_peer_scts' has failed!\n");
    return REVOC_CHECK_INTERNAL_ERROR;
  }

  /* Prepare and fill the CTLOG_STORE structure containing information about all
   * supplied public log servers. */
  CTLOG_STORE *ctlog_store = fill_CTLOG_STORE_structure();
  if (ctlog_store == NULL) {
    return REVOC_CHECK_INTERNAL_ERROR;
  }

  // - - - - - - - - - - - - - - -
  /* OPTIONAL */
  // - - - - - - - - - - - - - - -
  /* Create new BIO stream from stdout, for printing the SCTs to the stdout. */
  out = BIO_new_fp(stdout, BIO_NOCLOSE);
  if (out == NULL) {
    fprintf(stderr, "Function 'BIO_new_fp' has failed!\n");
    status = REVOC_CHECK_INTERNAL_ERROR;
    goto cleanup;
  }

  /* Pretty print every SCT from the SCT list to the stdout. */
  /* Log ID, Log name, Timestamp, Signature and Signature algorithm are printed
   * in human-readable format. */
  printf("\n");
  SCT_LIST_print(sct_list_stack, out, 1, "\n\n", ctlog_store);
  printf("\n\n");
  // - - - - - - - - - - - - - -

  /* Prepare the CT_POLICY_EVAL_CTX structure */
  /* Fill it with Server Certificate, Issuer Certificate, Actual Time,
   * CTLOG_STORE - list of all public logs with pubkeys. */
  ct_policy_eval = fill_CT_POLICY_structure(s_connection, ctlog_store);
  if (ct_policy_eval == NULL) {
    status = REVOC_CHECK_INTERNAL_ERROR;
    goto cleanup;
  }

  validate_entire_SCT_list(sct_list_stack, ct_policy_eval);

  validate_each_SCT_from_list(sct_list_stack, ct_policy_eval);

  /* Deinitialize! */
  CTLOG_STORE_free(ctlog_store);
  CT_POLICY_EVAL_CTX_free(ct_policy_eval);
  BIO_free(out);

  return status;

cleanup:
  if (ctlog_store != NULL) {
    CTLOG_STORE_free(ctlog_store);
  }
  if (ct_policy_eval != NULL) {
    CT_POLICY_EVAL_CTX_free(ct_policy_eval);
  }
  if (out != NULL) {
    BIO_free(out);
  }
  return status;
}

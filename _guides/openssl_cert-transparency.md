---
layout:     default
title:      "Certificate Transparency"
slug:       openssl-cert-transparency
library:    openssl
---

{% assign libraryData = site.data.libraries | where: "name", page.library | first %}
<div class="section"><div class="container" markdown="1">

{:#{{ page.slug }}}

# {{ libraryData.title }}: {{ page.title }}

{:.lead}
This guide describes how to obtain a Signed Certificate Timestamp (SCT) from a certificate and its subsequent verification. The SCT serves as proof that the certificate was appended to the public log.

{% include navigation-guides.html library=libraryData %}

</div></div>
<div class="section"><div class="container" markdown="1">

## Introduction

Certificate Transparency is a project initiated by Google in 2013. The main goal of this project was to make all certificates on the Internet publicly visible and, therefore, accessible and verifiable by anyone. Publicly available log servers are used to achieve this goal. Anyone can upload their certificates to these log servers and view the certificates from there. Every certificate that wants to support Certificate Transparency must be added to one of the publicly available log servers. However, one such certificate is often added to several log servers. That is also because Google requires such a certificate to be added to multiple public log servers. After the public log is asked to add a certificate, it responds with the Signed Certificate Timestamp (SCT). This SCT serves as a promise that the certificate will be inserted into the log. If a TLS client wants to verify that the certificate has been inserted into the public log, it must verify the validity of the certificate's SCT. During the verification of the SCT, its signature and timestamp are verified. The signature is verified against the log's public key that signed the SCT. The timestamp is then verified against the current time to prevent the SCT from being issued in the future.

Certificate Transparency is defined in [RFC 6962](https://www.rfc-editor.org/info/rfc6962).
Certificate Transparency on [Wikipedia](https://en.wikipedia.org/wiki/Certificate_Transparency).

**Summary of this guide:**

1. Retrieve the Signed Certificate Timestamp (SCT) List from the session instance
2. Create and initialize a structure containing records about public log servers
3. Create and initialize a structure containg CT policy
4. Validate the entire SCT list
5. Deinitialize

The only prerequisite for this guide is that the `SSL *s_connection` variable has already been initialized. This variable represents the current TLS session or connection, which could have already been established or is currently in the TLS handshake phase. For more information, see our [guide](/guides/openssl) on how to initiate a secure TLS connection.

</div></div>
<div class="section"><div class="container" markdown="1">

## 1. Retrieve the Signed Certificate Timestamp (SCT) List from the session instance

The first step is to retrieve all available signed certificate timestamps (SCTs) that are obtained from the SSL session instance.

```c
/* Retrieve a list of SCTs which have been found for a given SSL instance. */
/* TLS extensions, OCSP response and the peer's certificate are examined for this purpose. */
const STACK_OF(SCT) *sct_list_stack = SSL_get0_peer_scts(s_connection);
if (sct_stack == NULL) {
    exit(EXIT_FAILURE);
}
```

### Relevant links

* [SSL_get0_peer_scts](https://www.openssl.org/docs/man3.0/man3/SSL_get0_peer_scts.html) (OpenSSL docs)

</div></div>
<div class="section"><div class="container" markdown="1">

## 2. Create and initialize a structure containing records about public log servers

Before validation of individual SCTs can be performed, it is first necessary to obtain cryptographic information about publicly available log servers which issued the SCTs mentioned above. Such information includes, for example, the ID of the public log or its public key. To represent and store this kind of information, OpenSSL uses the `CTLOG_STORE` structure, which must be first initialized and then filled with individual records of public log servers. To fill this structure, we will use the default configuration file, which contains a list of some publicly available log servers and was shipped together with the OpenSSL library during the installation.

NOTE: on Linux systems, this default file is located at `/etc/ssl/ct_log_list.cnf`

NOTE: This file is empty by default and needs to be filled in manually. For this purpose, we have provided a simple shell script that demonstrates the procedure in a few steps.

```c
/* Initialize empty CTLOG_STORE structure which will be used later during validation of SCTs and printing the SCTs to stdout. */
CTLOG_STORE *ctlog_store = CTLOG_STORE_new();
if (ctlog_store == NULL) {
    exit(EXIT_FAILURE);
}

/* Fill CTLOG_STORE structure with information about public log servers. */
/* For this purpose, configuration 'ct_log_list.cnf' file from OpenSSL is used. */
if (CTLOG_STORE_load_default_file(ctlog_store) == 1) {
    /* All CT logs from the provided file were successfully appended to the CTLOG_STORE structure. */
}
else {
    /* At least one CT log from the provided file was not appended to the CTLOG_STORE structure. */
}
```

### Relevant links

* [CTLOG_STORE_new](https://www.openssl.org/docs/man3.0/man3/CTLOG_STORE_new.html) (OpenSSL docs)
* [CTLOG_STORE_load_default_file](https://www.openssl.org/docs/man3.0/man3/CTLOG_STORE_load_default_file.html) (OpenSSL docs)

Shell script demonstrating the individual steps required for the manual generation of the above-mentioned file:

```sh
# Download all necessary python script files from Google CT github repository
wget -q https://github.com/google/certificate-transparency/blob/master/python/utilities/log_list/print_log_list.py
wget -q https://github.com/google/certificate-transparency/blob/master/python/utilities/log_list/cpp_generator.py
wget -q https://github.com/google/certificate-transparency/blob/master/python/utilities/log_list/java_generator.py
wget -q https://github.com/google/certificate-transparency/blob/master/python/utilities/log_list/openssl_generator.py

# Download other necessary files from Google CT Community Site github repository
# Download json containing list of all CT logs that are currently compliant with Google's CT policy
wget -q https://www.gstatic.com/ct/log_list/log_list.json
# Download the signature of the Log list json, signed by Google
wget -q https://www.gstatic.com/ct/log_list/log_list.sig
# Download the Google's public key in order to verify signature
wget -q https://www.gstatic.com/ct/log_list/log_list_pubkey.pem
# Download the list of all known and announced CT logs
wget -q https://www.gstatic.com/ct/log_list/all_logs_list.json
# Download the json schema, Log list and All log list should conform to this schema
wget -q https://www.gstatic.com/ct/log_list/log_list_schema.json

# Install required python dependencies
pip install absl-py
pip install jsonschema
pip install m2crypto

# Generate the 'ct_log_list.cnf' for the OpenSSL
# This output file should be located under /etc/ssl/ct_log_list.cnf on Linux distributions
python print_log_list.py \
 --log_list_schema log_list_schema.json \
 --log_list log_list.json \
 --signer_key log_list_pubkey.pem \
 --signature log_list.sig \
 --openssl_output ct_log_list.cnf

# Clean
rm all_logs_list.json log_list.json log_list.sig log_list_pubkey.pem log_list_schema.json
rm *.py
```

The script shown above serves only as a demonstration example. The official list of public logs from Google can be found [here](https://github.com/google/certificate-transparency-community-site/blob/master/docs/google/known-logs.md) and the python program that converts the log list to OpenSSL format can be found [here](https://github.com/google/certificate-transparency/blob/master/python/utilities/log_list/print_log_list.py).

### Relevant links

* [Google's list of public logs](https://www.certificate-transparency.org/known-logs)
* [Python program to convert the log list to OpenSSL's format](https://github.com/google/certificate-transparency/blob/master/python/utilities/log_list/print_log_list.py)

</div></div>
<div class="section"><div class="container" markdown="1">

{:.text-success}

## Optional: Pretty the entire SCT list to stdout

The retrieved SCT list can also be printed to standard output in a human-readable form. In case when individual SCT was issued by a public log that is stored in the CTLOG_STORE structure, then the name of this public log is also printed together with its ID.

```c
/* Create new BIO wrapping the stdout stream, for printing the SCTs to the stdout. */
BIO *out = BIO_new_fp(stdout, BIO_NOCLOSE);
if (out == NULL) {
    exit(EXIT_FAILURE);
}

/* Pretty print every SCT from the SCT list to the stdout. */
/* Log ID, Log name, Timestamp, Signature and Signature algorithm are printed in human-readable format. */
SCT_LIST_print(sct_stack, out, 1, "\n\n", ctlog_store);

/* Deinitialize. */
BIO_free(out);
```

### Relevant links

* [SCT_LIST_print](https://www.openssl.org/docs/man3.0/man3/SCT_LIST_print.html) (OpenSSL docs)

</div></div>
<div class="section"><div class="container" markdown="1">

## 3. Create and initialize a structure containg CT policy

The last step before SCTs can be validated is the creation of a policy evaluation context structure called `CT_POLICY_EVAL_CTX`. OpenSSL uses this structure to evaluate whether individual SCT fulfils a Certificate Transparency (CT) policy.

```c
/* Initialize empty CT POLICY structure. */
CT_POLICY_EVAL_CTX *ct_policy_eval = CT_POLICY_EVAL_CTX_new();
if (ct_policy_eval == NULL) {
    exit(EXIT_FAILURE);
}

/* 1.) Populate the policy with the certificate that the SCT was issued for. */
if (CT_POLICY_EVAL_CTX_set1_cert(ct_policy_eval, certificate) != 1) {
    exit(EXIT_FAILURE);
}

/* 2.) Populate the policy with the issuer's certificate (needed when SCT is embedded in the extension of the X.509 certificate). */
if (CT_POLICY_EVAL_CTX_set1_issuer(ct_policy_eval, issuer_certificate) != 1) {
    exit(EXIT_FAILURE);
}

/* 3.) Populate the policy with all available trusted public logs from the CTLOG_STORE structure. */
CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE(ct_policy_eval, ctlog_store);

/* 4) Populate the policy with current time + 5 min to verify the timestamp of the SCT. */
CT_POLICY_EVAL_CTX_set_time(ct_policy_eval, (time(NULL) + 300) * 1000);
```

### Relevant links

* [CT_POLICY_EVAL_CTX_new](https://www.openssl.org/docs/man3.0/man3/CT_POLICY_EVAL_CTX_new.html) (OpenSSL docs)
* [CT_POLICY_EVAL_CTX_set1_cert](https://www.openssl.org/docs/man3.0/man3/CT_POLICY_EVAL_CTX_set1_cert.html) (OpenSSL docs)
* [CT_POLICY_EVAL_CTX_set1_issuer](https://www.openssl.org/docs/man3.0/man3/CT_POLICY_EVAL_CTX_set1_issuer.html) (OpenSSL docs)
* [CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE](https://www.openssl.org/docs/man3.0/man3/CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE.html) (OpenSSL docs)
* [CT_POLICY_EVAL_CTX_set_time](https://www.openssl.org/docs/man3.0/man3/CT_POLICY_EVAL_CTX_set_time.html) (OpenSSL docs)

</div></div>
<div class="section"><div class="container" markdown="1">

## 4. Validate the entire SCT list

After filling all the necessary structures, it is possible to validate the entire SCT list.

```c
/* Perform validation check at entire STC list. */
/* Result of validation is possible to examine through SCT_get_validation_status call. */
int ret_value = SCT_LIST_validate(sct_stack, ct_policy_eval);
if (ret_value < 0) {
    /* Internal error occured, function has failed! */
}
else if (ret_value == 0) {
    /* At least one SCT from SCT list has failed validation! */
}
else if (ret_value == 1) {
    /* The entire SCT list has passed the validation! */
}
```

### Relevant links

* [SCT_LIST_validate](https://www.openssl.org/docs/man3.0/man3/SCT_LIST_validate.html) (OpenSSL docs) (OpenSSL docs)

</div></div>
<div class="section"><div class="container" markdown="1">

{:.text-danger}

## Alternative: Validate each SCT item from SCT list separately

An alternative to validating the entire SCT list at once is to validate each SCT from the SCT list separately and one at a time. In case of validation failure, it is possible to examine the exact reason why the validation failed.

```c
SCT *single_sct;
sct_validation_status_t validation_status;
int ret_val;

/* Iterate through the whole SCT list and, in each iteration, validate one SCT from the list. */
int sct_list_stack_size = sk_SCT_num(sct_stack);
for (int index = 0; index < sct_list_stack_size; index++) {
    /* Retrieve one SCT from the SCT list at the given index. */
    single_sct = sk_SCT_value(sct_stack, index);

    /* Validate the single SCT. */
    int ret_val = SCT_validate(single_sct, ct_policy_eval);
    if (ret_val < 0) {
        /* Internal error occured, function has failed. */
        exit(EXIT_FAILURE);
    }
    if (ret_val == 1) {
        /* Validation of this SCT passed. */
        /* Validation status should be equal to SCT_VALIDATION_STATUS_VALID. */
    }
    if (ret_val == 0) {
        /* Validation of this SCT failed. */
        /* Retrieve and examine the validation status and the reason of the failure. */
        validation_status = SCT_get_validation_status(single_sct);
        if (validation_status == SCT_VALIDATION_STATUS_UNVERIFIED) {
            /* Failure to provide the certificate. */
        }
        else if (validation_status == SCT_VALIDATION_STATUS_UNKNOWN_LOG) {
            /* Public log that issued the SCT is not present in the CTLOG_STORE structure. */
        }
        else if (validation_status == SCT_VALIDATION_STATUS_UNKNOWN_VERSION) {
            /* Current SCT is of an unsupported version. */
        }
        else if (validation_status == SCT_VALIDATION_STATUS_INVALID) {
            /* Current SCT's signature is incorrect, its timestamp is invalid or SCT is otherwise invalid. */
        }
    }

    /* It is also possible to retrieve a human-readable string of validation status */
    const char *validation_message = SCT_validation_status_string(single_sct);
    printf("%s\n", validation_message);
}
```

### Relevant links

* [SCT_validate](https://www.openssl.org/docs/man3.0/man3/SCT_validate.html) (OpenSSL docs)
* [SCT_get_validation_status](https://www.openssl.org/docs/man3.0/man3/SCT_get_validation_status.html) (OpenSSL docs)
* [SCT_validation_status_string](https://www.openssl.org/docs/man3.0/man3/SCT_validation_status_string.html) (OpenSSL docs)

</div></div>
<div class="section"><div class="container" markdown="1">

## 5. Deinitialize

Free the previously allocated structures, which are no longer required.

```c
CTLOG_STORE_free(ctlog_store);
CT_POLICY_EVAL_CTX_free(ct_policy_eval);
```

### Relevant links

* [CTLOG_STORE_free](https://www.openssl.org/docs/man3.0/man3/CTLOG_STORE_free.html) (OpenSSL docs)
* [CT_POLICY_EVAL_CTX_free](https://www.openssl.org/docs/man3.0/man3/CT_POLICY_EVAL_CTX_free.html) (OpenSSL docs)

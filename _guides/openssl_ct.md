
This guide describes how to obtain a Signed Certificate Timestamp (SCT) from a certificate and then verify it. The SCT serves as proof that the certificate has been appended into a public log. In our guide, we will validate the TLS server's certificate.


**Short description:**
Certificate Transparency is a project initiated by Google in 2013. The main goal of this project was to make all certificates on the Internet publicly visible and therefore accessible and verifiable by anyone. Publicly available log servers are used to achieve this goal. Anyone can upload their certificates to these log servers and view their certificates from there. Every certificate that wants to support Certificate Transparency must be added to one of the publicly available logs. However, one such certificate is often added to several log servers. That is also because Google requires such a certificate to be added to multiple public logs. After the public log is asked to add a certificate, it responds with the Signed Certificate Timestamp (SCT). This SCT serves as a promise that the certificate will be inserted into the log. If a TLS client wants to verify that the TLS server’s certificate, with which the TLS client communicates, has been inserted to the public log, it must verify the validity of its SCT. During the verification of the SCT, its signature and timestamp are verified. The signature is verified against the log’s public key that signed the SCT. The timestamp is then verified against the current time to prevent the SCT from being issued in the future.

Certificate Transparency is defined in [RFC 6962](https://www.rfc-editor.org/info/rfc6962).  
Certificate Transparency on [Wikipedia](https://en.wikipedia.org/wiki/Certificate_Transparency).

**Summary of this guide:**
1. Retrieve the Signed Certificate Timestamp (SCT) List from the secured connection
2. Prepare and fill the structure containing all public logs
3. Prepare and fill the structure containing SCT Policy
4. Validate the whole SCT list
5. Deinitialize

---

We assume that the TLS client-server connection has already been established, that is, the client has access to the TLS server's certificate. In other words, we assume that the variable `SSL *s_connection` represents an already established connection. TLS client-server initialization guide can be found [here](https://x509errors.org/guides/openssl).



## 1.) Retrieve the Signed Certificate Timestamp (SCT) List from the secured connection

First, we will first receive all the SCTs that could be found from our established TLS client-server connection. All SCTs will be stored in a collection of STACK_OF(SCT) structure.

```c
/* Get the SCT list, every SCT which could be found in the SSL connection */
const STACK_OF(SCT) *sct_stack = SSL_get0_peer_scts(s_connection);
if (sct_stack == NULL)
{
    exit(EXIT_FAILURE);
}
```

### Relevant links

* [SSL_get0_peer_scts](https://www.openssl.org/docs/man3.0/man3/SSL_get0_peer_scts.html) (OpenSSL docs)


## 2.) Prepare and fill the structure containing all public logs

After receiving all the SCTs from the secured connection, we need to initialize and fill the structure with information about all public logs. This information includes the ID of public logs and its public key, which will be later used to verify the signature that the public log signed the corresponding SCT. The `CTLOG_STORE` structure is used for this purpose and we will fill this structure using the default file which was shipped together with the openSSL installation.  

NOTE: on Linux systems, this default file is located at `/etc/ssl/ct_log_list.cnf`

NOTE: This file is often empty and must be filled in manually. A sample shell script that fills the file is shown below.

```c
/* Create empty CTLOG_STORE (used in validation and pretty printing later!) */
CTLOG_STORE *ctlog_store = CTLOG_STORE_new();
if (ctlog_store == NULL)
{
    exit(EXIT_FAILURE);
}

/* Fill CTLOG_STORE with openssl "ct_log_list.cnf' file */
if (CTLOG_STORE_load_default_file(ctlog_store) == 1)
{   
    /* All CT logs from the file were succesfully added */
}
else
{
    /* Some CT logs, at least one, was not succesfully parsed from file and thus not added to the structure */
}
```

### Relevant links

* [CTLOG_STORE_new](https://www.openssl.org/docs/man3.0/man3/CTLOG_STORE_new.html) (OpenSSL docs)
* [CTLOG_STORE_load_default_file](https://www.openssl.org/docs/man3.0/man3/CTLOG_STORE_load_default_file.html) (OpenSSL docs)


Sample shell script:

```sh
# Download all necessary python files from google ct tools
wget -q https://raw.githubusercontent.com/google/certificate-transparency/master/python/utilities/log_list/print_log_list.py
wget -q https://raw.githubusercontent.com/google/certificate-transparency/master/python/utilities/log_list/cpp_generator.py
wget -q https://raw.githubusercontent.com/google/certificate-transparency/master/python/utilities/log_list/java_generator.py
wget -q https://raw.githubusercontent.com/google/certificate-transparency/master/python/utilities/log_list/openssl_generator.py

# Download all necessary ct log & signature files from google
wget -q https://www.gstatic.com/ct/log_list/log_list.json
wget -q https://www.gstatic.com/ct/log_list/log_list.sig
wget -q https://www.gstatic.com/ct/log_list/log_list_pubkey.pem
wget -q https://www.gstatic.com/ct/log_list/all_logs_list.json
wget -q https://www.gstatic.com/ct/log_list/log_list_schema.json

# Install python dependencies
pip install absl-py
pip install jsonschema
pip install m2crypto

# Create the .cnf file!
# This output file should be located under /etc/ssl/ct_log_list.cnf on Linux distributions
python print_log_list.py \
	--log_list_schema log_list_schema.json \
	--log_list log_list.json \
	--signer_key log_list_pubkey.pem \
	--signature log_list.sig \
	--openssl_output ct_log_list.cnf

# Clean 
rm -rf __pycache__
rm all_logs_list.json log_list.json log_list.sig log_list_pubkey.pem log_list_schema.json
rm *.py
```

### Relevant links

* [Google's list of logs](www.certificate-transparency.org/known-logs)
* [Python program to convert the log list to OpenSSL's format](https://github.com/google/certificate-transparency/blob/master/python/utilities/log_list/print_log_list.py)


## Optional: Pretty print the SCT list with the public log information

After filling the structure with the data about public logs, we can print every SCT from collection to stdout with the information about the public log which issued corresponding SCT.

```c
/* Create the BIO from stdout */
BIO *out = BIO_new_fp(stdout, BIO_NOCLOSE);
if (out == NULL)
{
    exit(EXIT_FAILURE);
}

/* Pretty print every SCT from list! */
/* LOG ID, Log Name, Timestamp and Signature of the SCT can be visible in human-readable format */
SCT_LIST_print(sct_stack, out, 1, "\n\n", ctlog_store);

/* Deinitialize the BIO, no longer needed */
BIO_free(out);
```

### Relevant links

* [SCT_LIST_print](https://www.openssl.org/docs/man3.0/man3/SCT_LIST_print.html) (OpenSSL docs)


## 3.) Prepare and fill the structure containing SCT Policy

Finally, we need to fulfill the structure used by the validation function to be able to decide whether a given SCT complies with the Certificate Transparency policy. For this purpose, `CT_POLICY_EVAL_CTX` structure is used.

```c
/* Initialize empty CT POLICY structure! */
CT_POLICY_EVAL_CTX *ct_policy_eval = CT_POLICY_EVAL_CTX_new();
if (ct_policy_eval == NULL)
{
    exit(EXIT_FAILURE);
}

/* 1) Populate the policy with the certificate that the SCT was issued for */
if (CT_POLICY_EVAL_CTX_set1_cert(ct_policy_eval, server_certificate) != 1)
{
    exit(EXIT_FAILURE);
}

/* 2) Populate the policy with the issuer's certificate (needed when X509 Extensions used) */
if (CT_POLICY_EVAL_CTX_set1_issuer(ct_policy_eval, issuer_certificate) != 1)
{
    exit(EXIT_FAILURE);
}

/* 3) Populate the policy with the public key the log that issued the SCT */
/* It will be automatically found from all the logs in store */
CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE(ct_policy_eval, ctlog_store);

/* 4) Populate the policy with Current time + 5 min to check wheter the SCT was not issued in the future */
CT_POLICY_EVAL_CTX_set_time(ct_policy_eval, (time(NULL) + 300) * 1000);
```

### Relevant links

* [CT_POLICY_EVAL_CTX_new](https://www.openssl.org/docs/man3.0/man3/CT_POLICY_EVAL_CTX_new.html) (OpenSSL docs)
* [CT_POLICY_EVAL_CTX_set1_cert](https://www.openssl.org/docs/man3.0/man3/CT_POLICY_EVAL_CTX_set1_cert.html) (OpenSSL docs)
* [CT_POLICY_EVAL_CTX_set1_issuer](https://www.openssl.org/docs/man3.0/man3/CT_POLICY_EVAL_CTX_set1_issuer.html) (OpenSSL docs)
* [CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE](https://www.openssl.org/docs/man3.0/man3/CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE.html) (OpenSSL docs)
* [CT_POLICY_EVAL_CTX_set_time](https://www.openssl.org/docs/man3.0/man3/CT_POLICY_EVAL_CTX_set_time.html) (OpenSSL docs)


## 4.) Validate the whole SCT list

After we have filled in and received all necessary structures, we can validate all SCTs at once.

```c
int ret_value = SCT_LIST_validate(sct_stack, ct_policy_eval);
if (ret_value < 0)
{
    /* Internal error occured, function has failed */
}
else if (ret_value == 0)
{   
    /* At least one SCT from SCT list has failed validation */
}
else if (ret_value == 1)
{   
    /* Every single SCT from SCT list has passed the validation */
}
```

### Relevant links

* [SCT_LIST_validate](https://www.openssl.org/docs/man3.0/man3/SCT_LIST_validate.html) (OpenSSL docs) (OpenSSL docs)


## Alternative: Validate SCT items one by one in more detail

After we have filled in and obtained all the necessary structures, we can go through the collection of SCTs and validate each SCT separately. In case of failure, we can examine the validation failure reason.

```c
/* Iterate through the list and check every single SCT from this list! */
int counter_of_scts = sk_SCT_num(sct_stack);
for (int index = 0; index < counter_of_scts; index++)
{
    /* Retrieve one SCT from the whole list at given index */
    SCT *actual_sct = sk_SCT_value(sct_stack, index);

    /* Validate this single SCT */
    if (SCT_validate(actual_sct, ct_policy_eval) != 1)
    {
        /* SCT fails validation */
        /* Can further inspect the reason of failure */    

        /* Retrieve the validation status */
        sct_validation_status_t status = SCT_get_validation_status(actual_sct);
        if (status == SCT_VALIDATION_STATUS_UNVERIFIED)
        {   
            /* Failure to provide TLS server's certificate (or issuer's) */
        }
        else if (status == SCT_VALIDATION_STATUS_UNKNOWN_LOG)
        {   
            /* Log that issued this SCT is not in CTLOG_STORE */
        }
        else if (status == SCT_VALIDATION_STATUS_UNKNOWN_VERSION)
        {   
            /* SCT is of an unsupported version, only v1 is currently supported */
        }
        else if (status == SCT_VALIDATION_STATUS_INVALID)
        {   
            /* SCT's signature is incorrect or its timestamp is in the future or the SCT is otherwise invalid */
        }

        /* It is also possible to retrieve a human-readable string of validation status */
        const char *validation_message = SCT_validation_status_string(actual_sct);
        printf("%s\n", validation_message);
    }

    /* This SCT item has succesfully passed the validation */
    /* Status, if retrieved, should be SCT_VALIDATION_STATUS_VALID */
}
```

### Relevant links

* [SCT_validate](https://www.openssl.org/docs/man3.0/man3/SCT_validate.html) (OpenSSL docs)
* [SCT_get_validation_status](https://www.openssl.org/docs/man3.0/man3/SCT_get_validation_status.html) (OpenSSL docs)
* [SCT_validation_status_string](https://www.openssl.org/docs/man3.0/man3/SCT_validation_status_string.html) (OpenSSL docs)


## 5.) Deinitialize

Free the previously allocated structures, which are no longer required.

```c
CTLOG_STORE_free(ctlog_store);
CT_POLICY_EVAL_CTX_free(ct_policy_eval);
```

### Relevant links

* [CTLOG_STORE_free](https://www.openssl.org/docs/man3.0/man3/CTLOG_STORE_free.html) (OpenSSL docs)
* [CT_POLICY_EVAL_CTX_free](https://www.openssl.org/docs/man3.0/man3/CT_POLICY_EVAL_CTX_free.html) (OpenSSL docs)


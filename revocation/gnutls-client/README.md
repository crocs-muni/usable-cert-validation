# GnuTLS Revocation Client

TLS client program that securely connects to the specified server using the TLS version 1.3 protocol. During the TLS handshake, this client validates the certificate chain it received from the connection with the specified server. If an error occurs during the certificate chain validation, the server to which this client connects is considered untrustworthy, and the whole connection is immediately terminated. If no error occurred during the certificate chain validation, the certificate chain is considered valid. In this case, the client subsequently checks the revocation statuses of all X.509 certificates from the certificate chain. Supported revocation schemes are CRL, OCSP and OCSP-stapling. In addition to these schemes, the client also supports checking Signed Certificate Timestamps (SCTs), which are stored in the X.509 certificate extension and are part of the Certificate Transparency Policy.

## More detailed description

The functionality of this TLS client program could be described by the following steps:

1. The program processes the supplied options from the command line, which can be used to modify the program's behavior.

2. Using the standard C sockets that are part of the standard C library, the client tries to connect to the specified server using the TCP protocol. The server is specified by its hostname, which is supplied as a program's required argument. By default, port 443 is used, but it can be customized too.

3. After successfully establishing the TCP connection, the client tries to establish a secure TLS connection. In order for the TLS connection to be successfully established, validation of the certification chain and subsequent revocation check of each X.509 certificate from the certificate chain must be performed. Both of these checks are performed during the TLS handshake, where the revocation check is triggered only if the previous validation of the certificate chain was successful. In case when the validation of the certificate chain or any certificate from the certificate chain is revoked, the TLS connection will not be established, and the entire connection will be terminated.

4. After the successful establishment of the TLS connection, both the TLS and the underlying TCP connection will be closed immediately, as the client's main task is to check the revocation statuses of X.509 certificates from the certification chain.

## Supported command line options

The following switches that modify the behavior of the program are supported:

1. `-p, --port=PORT`
    - Allows to explicitly change the default 443 https port and set any custom port.
2. `-i, --print-cert-chain-info`
    - Prints detail information about each certificate from the certificate chain.
3. `--crl-check`
    - The CRL revocation scheme is performed during the revocation checks.
    - An implementation guide can be found at [x509errors.org](https://x509errors.org/guides/gnutls-crl).
4. `--ocsp-check`
    - The OCSP revocation scheme is performed during the revocation checks.
    - An implementation guide can be found at [x509errors.org](https://x509errors.org/guides/ocsp-crl).
5. `--ocsp-stapling-check`
    - The OCSP-stapling revocation scheme is performed during the revocation checks.
    - An implementation guide can be found at [x509errors.org](https://x509errors.org/guides/gnutls-ocsp-stapling).
6. `--certificate-transparency-check`
    - In addition to to the revocation checks, the SCTs validation is also performed.
    - An implementation guide can be found at [x509errors.org](https://x509errors.org/guides/gnutls-cert-transparency).
7. `-h, --help`
    - Display help utility and exit program.

**NOTE:** Multiple revocation schemes can be selected and in this case, each X.509 certificate from the certificate chain will be checked using multiple schemes.

**NOTE:** If no revocation scheme is explicitly selected, all are used by default.

## File structure

The entire program is divided into the following files:

- `main.c`
  - program's entry point, contains TCP connection logic, TLS configuration and TLS connection logic
- `options.c`
  - declaration in `options.h`, contains logic for processing options from the command line
- `utils.c`
  - declaration in `utils.h`, contains auxiliary functions usable through the entire program
- `crl_revoc.c`
  - declaration in `crl_revoc.h`, contains the logic necessary to successfully perform CRL revocation check
- `ocsp_revoc.c`
  - declaration in `ocsp_revoc.h`, contains the logic necessary to successfully perform OCSP revocation check
- `ocsp_stapling_revoc.c`
  - declaration in `ocsp_stapling_revoc.h`, contains the logic necessary to successfully perform OCSP-stapling revocation check
- `ct_check.c`
  - declaration in `ct_check.h`, contains the logic necessary to validate SCTs according to the Certificate Transparency policy

## Build

To build the GnuTLS revocation client, the following libraries as dependencies are required:

- GnuTLS (version 3.7.8 used)
- cURL (version 7.85.0 used)

The folder with the client also contains a simple `makefile`. For compiling the source code to the resulting binary, run the command `make`. To clean the client binary and auto-generated files (.DER files), run `make clean`. To format source code files, run the command `make format`. If no explicit `.clang-format` configuration file is provided, the fallback Google style is used by default.

## Examples

`$ ./gnutls_client --print-cert-chain-info -p 443 x509errors.org`

- To securely connect to the x509errors.org web server, which is listening at port 443. In addition, print detailed information about each certificate from the certificate chain. Explicitly, no revocation scheme is selected; thus, each certificate from the certificate chain is checked using all currently supported revocation schemes.

`$ ./gnutls_client --crl-check google.com`

- To securely connect to the google.com web server, which is listening at default port 443. Check the revocation status of the certificates from the certificate chain using only the CRL revocation scheme.

## Authors

This TLS revocation client is part of the "Usable X.509 errors" project. For more information, see the project's main website at [x509errors.org](https://x509errors.org). The official GitHub repository is located [here](https://github.com/crocs-muni/usable-cert-validation). The project is led by [Martin Ukrop](https://crocs.fi.muni.cz/people/mukrop) at the [Centre for Research on Cryptography and Security](https://www.fi.muni.cz/research/crocs/) of [Masaryk University](http://www.muni.cz/) in Brno, Czech Republic.

This TLS revocation client, readme and related revocation developer guides located on the main page were created by [Marián Svitek](https://github.com/Werxis) on 5.12.2022 under the MIT license.

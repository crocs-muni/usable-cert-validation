# Usable certificate validation

[![Build Status](https://travis-ci.org/crocs-muni/usable-cert-validation.svg?branch=master)](https://travis-ci.org/crocs-muni/usable-cert-validation)

A research initiative to make TLS certificate validation usable.

## What problems do we want to solve?

The system of working with (validating) TLS certificates:

* It is complicated, even a bit chaotic.
* There are multiple different tools to do the same thing.
* The tools are not unified (they work and behave differently).
* Yet certificate validation is important and frequent (e.g. TLS on the Internet).

## So in short, what do we want to do?

Our goal is to simplify the ecosystem by consolidating the errors and their documentation and by explaining better what the validation errors mean. A similar (although much larger) effort was done [by Mozilla for browser documentation](https://blog.mozilla.org/blog/2017/10/18/mozilla-brings-microsoft-google-w3c-samsung-together-create-cross-browser-documentation-mdn/) in 2017.

In the ideal case, we aim for a unified, accessible, widely-used and academically interesting taxonomy of certificate validation errors and accompanying usable documentation. For every error, we aim to provide an example certificate, documentation from OpenSSL and other TLS libraries.

In the future, we plan the possibility of reorganization based on the other libraries (currently, the web is organized by OpenSSL), adding the error frequencies based on IP-wide scans and elaborating on the consequences of individual errors.
  
## Local build

To build TLS clients, the development versions of the following libraries are required:

* [OpenSSL](https://www.openssl.org/)
* [GnuTLS](https://www.gnutls.org/) (also requires [libcurl](https://curl.se/libcurl/))
* [Botan](https://botan.randombit.net/), preferentially version 2
* [mBedTLS](https://tls.mbed.org/)
* [OpenJDK](https://openjdk.java.net/)

On Ubuntu 20.04 LTS or Fedora 33 you can install them using the appropriate of the following commands:

```bash
# Ubuntu 20.04
apt install libssl-dev libgnutls28-dev botan libbotan-2-dev libmbedtls-dev openjdk-16-jdk libcurl4-openssl-dev
# Fedora 33
dnf install openssl-devel gnutls-devel botan2-devel mbedtls-devel java-latest-openjdk-devel libcurl-devel
```

The necessary Python packages are locally installed by running `make install`. Building the certificate chains requires the following Python packages: [setuptools](https://pypi.org/project/setuptools/), [asn1tools](https://github.com/eerimoq/asn1tools) and [pycryptodomex](https://pypi.org/project/pycryptodomex/). Running certificate validation further requires [shyaml](https://github.com/0k/shyaml), [yq](https://kislyuk.github.io/yq/), [jq](https://stedolan.github.io/jq/) and [pyYAML](https://github.com/yaml/pyyaml) for parsing and manipulating YAML files.

The website is build using [Jekyll](https://jekyllrb.com/). To develop locally, install Jekyll (e.g. according to [this guide](https://help.github.com/en/articles/setting-up-your-github-pages-site-locally-with-jekyll). Then run `make local` and see the website served at `localhost:4000`.

## Authors

The project is developed at the [Centre for Research on Cryptography and Security](https://www.fi.muni.cz/research/crocs/) of [Masaryk University](http://www.muni.cz/) in Brno, Czech Republic. The main contributors are listed in [CONTRIBUTORS.md](CONTRIBUTORS.md).

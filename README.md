# Usable certificate validation

[![Build Status](https://travis-ci.org/crocs-muni/usable-cert-validation.svg?branch=master)](https://travis-ci.org/crocs-muni/usable-cert-validation)

A research initiative to make TLS certificate validation usable.

## What problems do we want to solve?

The system of working with TLS certificates (our focus: especially validating them):

* It is complicated, even a bit chaotic.
* There are multiple different tools to do the same thing.
* The tools are not unified (they work and behave differently).
* Yet certificate validation is important and frequent (e.g. TLS on the Internet).

## So in short, what do we want to do?

Our goal is to simplify the ecosystem by consolidating the errors and their documentation and by explaining better what the validation errors mean. A similar (although much larger) effort was done [by Mozilla for browser documentation](https://blog.mozilla.org/blog/2017/10/18/mozilla-brings-microsoft-google-w3c-samsung-together-create-cross-browser-documentation-mdn/) in 2017.

In the ideal case, we aim for a unified, accessible, widely-used and academically interesting taxonomy of certificate validation errors and accompanying usable documentation. For every error, we aim to provide an example certificate, documentation from OpenSSL and other TLS libraries.

In the future, we plan the possibility of reorganization based on the other libraries (currently, the web is organized by OpenSSL), adding the error frequencies based on IP-wide scans and elaborating on the consequences of individual errors.
  
## Local build

The website is build using [Jekyll](https://jekyllrb.com/). To develop locally, install Jekyll (e.g. according to [this guide](https://help.github.com/en/articles/setting-up-your-github-pages-site-locally-with-jekyll). Then run `make web-local` and see the website served at `localhost:4000`.

Running certificate tests requires [shyaml](https://github.com/0k/shyaml) for parsing YAML files.

## Authors

The project is developed at the [Centre for Research on Cryptography and Security](https://www.fi.muni.cz/research/crocs/) of [Masaryk University](http://www.muni.cz/) in Brno, Czech Republic. The main contributors are:

* **Martin Ukrop**(https://crocs.fi.muni.cz/people/mukrop), 2019–today, project lead, graphic design
* **Pavol Žáčik**, 2019–today, example certificates, error mapping
* **Matěj Grabovský**, 2019–today, feedback, TLS clients, bugfixs
* **Michaela balážová**, 2019–today, improved error messages
* **Eric Valčík**, 2020–today, bug fixes and pull requests to other libraries

The authors are grateful for the financial support by and [Red Hat Czech](https://research.redhat.com/) and [Kiwi.com](https://www.kiwi.com/).

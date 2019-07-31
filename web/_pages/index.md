---
layout: default
title: Usable certificate validation
---

Research initiative to make TLS certificate validation usable.

* [DevConf 2018 experiment site](/devconf-2018-experiment)

## Errors

Bellow are all OpenSSL errors with documentation, some with example certificate causing them.

{% for error in site.errors %}
### {{ error.title }}

{{ error.content }}

Verification in OpenSSL:
```
{{ error.verify-openssl }}
```
{% endfor %}

## Authors

The project is developed at the [Centre for Research on Cryptography and Security](https://www.fi.muni.cz/research/crocs/), [Masaryk University](http://www.muni.cz/), Brno, Czech Republic.
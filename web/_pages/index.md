---
layout: default
title: Usable certificate validation
---

Research initiative to make TLS certificate validation usable.

* [DevConf 2018 experiment site](/devconf-2018-experiment)

## Errors

Below are all OpenSSL errors with documentation, some with example certificate causing them.

{% assign sorted_errors = site.errors | sort: 'weight' %}
{% for error in sorted_errors %}
{% include error_box.html page=error %}
{% endfor %}

## Authors

The project is developed at the [Centre for Research on Cryptography and Security](https://www.fi.muni.cz/research/crocs/), [Masaryk University](http://www.muni.cz/), Brno, Czech Republic.



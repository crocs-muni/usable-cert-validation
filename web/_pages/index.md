---
layout: default
title: Usable certificate validation
---

Research initiative to make TLS certificate validation usable.

* [DevConf 2018 experiment site](/devconf-2018-experiment)

{% assign sorted_errors = site.errors | sort: 'weight' %}
{% assign errors_chaining = sorted_errors | where:"tags","chaining" %}
{% assign errors_validity = sorted_errors | where:"tags","validity" %}
{% assign errors_crl = sorted_errors | where:"tags","crl" %}

## Errors related to invalid certificate chaining

{% for error in errors_chaining %}
{% include error_box.html page=error %}
{% endfor %}

## Certificate validity errors

{% for error in errors_validity %}
{% include error_box.html page=error %}
{% endfor %}

## CRL-related errors

{% for error in errors_crl %}
{% include error_box.html page=error %}
{% endfor %}

More categories will come soon...

---

## All errors

{% assign sorted_errors = site.errors | sort: 'weight' %}
{% for error in sorted_errors %}
{% include error_box.html page=error %}
{% endfor %}

## Authors

The project is developed at the [Centre for Research on Cryptography and Security](https://www.fi.muni.cz/research/crocs/), [Masaryk University](http://www.muni.cz/), Brno, Czech Republic.



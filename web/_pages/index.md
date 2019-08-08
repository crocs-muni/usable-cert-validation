---
layout: default
title: Usable X.509 errors
---

<div class="section"><div class="container">
    <h1>{{ page.title }}</h1>
    <div class="tagline">Research initiative to make X.509 certificate validation usable</div>

    <div class="row">
    <div class="col-sm-4">
        <div class="card">
        <div class="card-body">
            <h5 class="card-title">Special title treatment</h5>
            <p class="card-text">With supporting text below as a natural lead-in to additional content.</p>
            <a href="#" class="btn btn-primary">Go somewhere</a>
        </div>
        </div>
    </div>
    <div class="col-sm-4">
        <div class="card">
        <div class="card-body">
            <h5 class="card-title">Special title treatment</h5>
            <p class="card-text">With supporting text below as a natural lead-in to additional content.</p>
            <a href="#" class="btn btn-primary">Go somewhere</a>
        </div>
        </div>
    </div>
    <div class="col-sm-4">
        <div class="card">
        <div class="card-body">
            <h5 class="card-title">Special title treatment</h5>
            <p class="card-text">With supporting text below as a natural lead-in to additional content.</p>
            <a href="#" class="btn btn-primary">Go somewhere</a>
        </div>
        </div>
    </div>
    </div>
</div></div>

{% assign sorted_errors = site.errors | sort: 'weight' %}

<div class="section"><div class="container" markdown="1">
## Errors related to invalid certificate chaining

{% assign errors_chaining = sorted_errors | where:"tags","chaining" %}
{% for error in errors_chaining %}
{% include error_box.html page=error %}
{% endfor %}
</div></div>

<div class="section"><div class="container" markdown="1">
## Certificate validity errors

{% assign errors_validity = sorted_errors | where:"tags","validity" %}
{% for error in errors_validity %}
{% include error_box.html page=error %}
{% endfor %}
</div></div>

<div class="section"><div class="container" markdown="1">
## CRL-related errors

{% assign errors_crl = sorted_errors | where:"tags","crl" %}
{% for error in errors_crl %}
{% include error_box.html page=error %}
{% endfor %}
</div></div>

<div class="section"><div class="container" markdown="1">
More categories will come soon...
</div></div>

<div class="section"><div class="container" markdown="1">
## All errors

{% assign sorted_errors = site.errors | sort: 'weight' %}
{% for error in sorted_errors %}
{% include error_box.html page=error %}
{% endfor %}
</div></div>

<div class="section"><div class="container" markdown="1">
## Authors

The project is developed at the [Centre for Research on Cryptography and Security](https://www.fi.muni.cz/research/crocs/), [Masaryk University](http://www.muni.cz/), Brno, Czech Republic.

* Add author names (Martin, Pavol)
* Add link to old [DevConf 2018 experiment site](/devconf-2018-experiment)
</div></div>
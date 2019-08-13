---
layout: default
title: Usable X.509 errors
---

<div class="section"><div class="container">
    <h1>{{ page.title }}</h1>
    <div class="tagline">Research initiative to make X.509 certificate validation usable</div>

    <p>Intro text about what we do and why (very shortly).</p>

    <div class="row intro">
    <div class="col-sm-4">
        <div class="card">
        <div class="card-body">
            <h5 class="card-title">Special title treatment</h5>
            <p class="card-text">With supporting text below as a natural lead-in to additional content.</p>
            <a href="#" class="btn btn-primary">{% include icon.html icon="button-methodology" %} Detailed methodology</a>
        </div>
        </div>
    </div>
    <div class="col-sm-4">
        <div class="card">
        <div class="card-body">
            <h5 class="card-title">Special title treatment</h5>
            <p class="card-text">With supporting text below as a natural lead-in to additional content.</p>
            <a href="https://docs.google.com/spreadsheets/d/1AYX02k49lBhrZ7fLoh5UsEaXU-OND27zX4LexnzVR-k/edit?usp=sharing" target="_blank" class="btn btn-primary">{% include icon.html icon="button-table" %} Error mapping</a>
        </div>
        </div>
    </div>
    <div class="col-sm-4">
        <div class="card">
        <div class="card-body">
            <h5 class="card-title">Special title treatment</h5>
            <p class="card-text">With supporting text below as a natural lead-in to additional content.</p>
            <a href="{{ site.repo-url }}" target="_blank" class="btn btn-primary">{% include icon.html icon="button-github" %} Project repository</a>
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
## Errors yet uncategorizes

{% assign errors_uncategorized = sorted_errors | where:"tags","uncategorized" %}
{% for error in errors_uncategorized %}
{% include error_box.html page=error %}
{% endfor %}
</div></div>

<div class="section"><div class="container" markdown="1">
## Unused, deprecated or never occurring errors

{% assign errors_unused = sorted_errors | where:"tags","unused" %}
{% for error in errors_unused %}
{% include error_box.html page=error %}
{% endfor %}
</div></div>

<div class="section"><div class="container" markdown="1">
## Authors

The project is developed at the [Centre for Research on Cryptography and Security](https://www.fi.muni.cz/research/crocs/), [Masaryk University](http://www.muni.cz/), Brno, Czech Republic.

* Add author names (Martin, Pavol)
* Thanks to [Kiwi.com](https://www.kiwi.com) and [Red Hat Czech](https://research.redhat.com/) for supporting the project.
* Add link to old [DevConf 2018 experiment site](/devconf-2018-experiment)
</div></div>
---
layout: default
title: Usable X.509 errors
---

<div class="section"><div class="container">
    <h1>Making X.509 errors usable.</h1>
    <div class="lead">
    <p>Validating X.509 certificates correctly turns out to be pretty complicated (e.g. <a href="http://www.cs.utexas.edu/~shmat/shmat_ccs12.pdf" target="_blank">Georgiev2012</a>). Yet certificate validation is absolutely crucial for secure communication on the Internet (think <a href="https://en.wikipedia.org/wiki/Transport_Layer_Security" target="_blank">TLS</a>).</p>
    <p>Our goal is to simplify the ecosystem by consolidating the errors and their documentation (similarly to <a href="https://blog.mozilla.org/blog/2017/10/18/mozilla-brings-microsoft-google-w3c-samsung-together-create-cross-browser-documentation-mdn/" target="_blank">web documentation</a>) and by explaining better what the validation errors mean.</p>
    </div>
    <div class="row intro">
    <div class="col-sm-4">
        <div class="card card-body">
            <h4>Samples and documentation</h4>
            <p>For every error, we aim to provide an example certificate ({% include icon.html icon="certificate" %}), documentation from OpenSSL ({% include icon.html icon="openssl-docs" %}) and other libraries ({% include icon.html icon="gnutls-docs" %}).</p>
            <p>We plan to include the error frequency based on IP-wide scans and detailed explanation of the consequences.</p>
        </div>
    </div>
    <div class="col-sm-4">
        <div class="card card-body">
            <h4>Multiple libraries</h4>
            <p>Our consolidated taxonomy aims for eight most used TLS-enabled libraries. The main structure is based on <a href="https://www.openssl.org/" target="_blank">OpenSSL</a> as it is by far the most used library in the domain of TLS.</p>
            <a href="https://docs.google.com/spreadsheets/d/1AYX02k49lBhrZ7fLoh5UsEaXU-OND27zX4LexnzVR-k/edit?usp=sharing" target="_blank" class="btn btn-primary">{% include icon.html icon="button-table" %} Error mapping</a>
        </div>
    </div>
    <div class="col-sm-4">
        <div class="card card-body">
            <h4>Methodology</h4>
            <p>We extend the existing research on security, TLS and documentation design. Details are described on a separate page.</p>
            <a href="#" class="btn btn-secondary" data-container="body" data-toggle="popover" data-placement="bottom" data-content="Page coming soon!">{% include icon.html icon="button-methodology" %} Detailed methodology</a>
        </div>
    </div>
    </div>
</div></div>

{% for category in site.data.errors %}

<div class="section"><div class="container" markdown="1">
## {{ category.title }}

{% assign errors = site.errors | where:"tags",category.tag | sort: 'weight' %}
{% for error in errors %}
{% include error_box.html page=error %}
{% endfor %}
</div></div>

{% endfor %}

<div class="section"><div class="container" markdown="1">
# Authors

The project is developed at the [Centre for Research on Cryptography and Security](https://www.fi.muni.cz/research/crocs/), [Masaryk University](http://www.muni.cz/), Brno, Czech Republic.

* Add author names (Martin, Pavol)
* Thanks to [Kiwi.com](https://www.kiwi.com) and [Red Hat Czech](https://research.redhat.com/) for supporting the project.
* Add link to old [DevConf 2018 experiment site](/devconf-2018-experiment)

</div></div>

---
layout: default
title: Usable certificate validation
---

Research initiative to make TLS certificate validation usable.

* [DevConf 2018 experiment site](/devconf-2018-experiment)

## Errors

Bellow are all OpenSSL errors with documentation, some with example certificate causing them.

{% for error in site.errors %}
<div class="card-header collapsed" data-toggle="collapse" href="#{{ error.slug }}" role="button" aria-expanded="false" aria-controls="collapseExample">
    <h3><i class="fa fa-fw fa-chevron-down"></i> <i class="fa fa-fw fa-chevron-right"></i> {{ error.title }}</h3>
</div>
<div class="collapse" id="{{ error.slug }}">
    <div class="card card-body">
        {{ error.content }}   
        <button class="btn btn-secondary" target="_blank" href="{{ site.repo-url }}/tree/master/errors/{{ error.title }}">Generating script here</button>
        <button class="btn btn-secondary" target="_blank" href="{{ site.url }}/assets/certs/{{ error.title }}.zip">Ready certs here</button>
        <br>
        Verification in OpenSSL: {{ error.verify-openssl }}
  </div>
</div>
{% endfor %}

## Authors

The project is developed at the [Centre for Research on Cryptography and Security](https://www.fi.muni.cz/research/crocs/), [Masaryk University](http://www.muni.cz/), Brno, Czech Republic.
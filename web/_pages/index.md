---
layout: default
title: Usable X.509 errors
---

<div class="section"><div class="container">
    <h1>{{ page.title }}</h1>
    <div class="tagline">{{ site.description }}</div>

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
## Authors

The project is developed at the [Centre for Research on Cryptography and Security](https://www.fi.muni.cz/research/crocs/), [Masaryk University](http://www.muni.cz/), Brno, Czech Republic.

* Add author names (Martin, Pavol)
* Thanks to [Kiwi.com](https://www.kiwi.com) and [Red Hat Czech](https://research.redhat.com/) for supporting the project.
* Add link to old [DevConf 2018 experiment site](/devconf-2018-experiment)

</div></div>

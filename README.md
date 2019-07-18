# Usable certificate validation

A research initiative to make TLS certificate validation usable.

## What problems do we want to solve?

The system of working with TLS certificates (our focus: especially validating them)
  * It is complicated, even a bit chaotic.
  * There are multiple different tools to do the same thing.
  * The tools are not unified (they work and behave differently).
  * Yet certificate validation is important and frequent (e.g. on the Internet).

## So in short, what do we want to do?

Simplify and unify the ecosystem of certificate validation by standardizing the validation errors. A similar (although much larger) effort was done [by Mozilla for browser documentation](https://blog.mozilla.org/blog/2017/10/18/mozilla-brings-microsoft-google-w3c-samsung-together-create-cross-browser-documentation-mdn/) in 2017.

In the ideal case, we aim for a unified, accessible, widely-used and academically interesting taxonomy of certificate validation errors and accompanying usable documentation. That means, for example:
  * There is a web page with the taxonomy of errors and the documentation to them.
  * Major certificate manipulation libraries are using our system and linking our documentation (e.g. OpenSSL, GnuTLS, NSS, ...)
  * If a developer is trying to understand an error, they end up finding our resources -- and our resources help them understand and solve the problem.
  * We have published a USENIX paper about it and made multiple talks for developers.
  
## Authors

The project is developed at the [Centre for Research on Cryptography and Security (formerly Laboratory of Security and Applied Cryptography)](https://www.fi.muni.cz/research/crocs/), [Masaryk University](http://www.muni.cz/), Brno, Czech Republic.

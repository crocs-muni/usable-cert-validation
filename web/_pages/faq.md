---
layout: default
title:  Frequently asked questions
slug:   faq
---
<div class="section"><div class="container" markdown="1">
<h1 id="faq">{{ page.title }}</h1>

### **FAQ page coming soon.**

Our apologies. This section is not yet finished. A very crude list of notes follows.

* The common libraries to analyze were chosen based on the paper [Measuring Popularity of Cryptographic Libraries in Internet-Wide Scans](https://crocs.fi.muni.cz/public/papers/acsac2017)
* Standardization parallel in the web world: [Mozilla blog post](https://blog.mozilla.org/blog/2017/10/18/mozilla-brings-microsoft-google-w3c-samsung-together-create-cross-browser-documentation-mdn/)
* Relevant related work: [The Most Dangerous Code in the World: Validating SSL Certificates in Non-Browser Software](http://www.cs.utexas.edu/~shmat/shmat_ccs12.pdf)

</div></div>

<div class="section"><div class="container" markdown="1">
# Our related work

Below we list our current and past related work on the usability of X.509 certificate ecosystem.

## Ongoing improvements for x509errors.org

* Adding reproducible certificate examples for more cases.
* Adding more libraries to the mapping and documentation (see above).
* Developing a public repository of code examples performing the secure TLS connection.
* Conducting experiments regarding the developers' preferences on documentation content. This will allow us to design a version that fits the developers' needs.
* Investigating the occurrence of individual errors in the wild by analyzing the existing certificate databases (think [crt.sh](https://crt.sh/), [Censys](https://censys.io/) or [Rapid7 datasets](https://opendata.rapid7.com/)).

## Trust perceptions in flawed TLS certificates

Our paper [Will You Trust This TLS Certificate? Perceptions of People Working in IT](https://crocs.fi.muni.cz/public/papers/acsac2019) was published at the Annual Computer Security Applications Conference (ACSAC) 2019.

> **Abstract:** Flawed TLS certificates are not uncommon on the Internet. While they signal a potential issue, in most cases they have benign causes (e.g., misconfiguration or even deliberate deployment). This adds fuzziness to the decision on whether to trust a connection or not. Little is known about perceptions of flawed certificates by IT professionals, even though their decisions impact high numbers of end users. Moreover, it is unclear how much does the content of error messages and documentation influence these perceptions.
>
> To shed light on these issues, we observed 75 attendees of an industrial IT conference investigating, different certificate validation errors. Furthermore, we focused on the influence of re-worded error messages and redesigned documentation. We find that people working in IT have very nuanced opinions regarding the tested certificate flaws with trust decisions being far from binary. The self-signed and the name constrained certificates seem to be over-trusted (the latter also being poorly understood). We show that even small changes in existing error messages and documentation can positively influence resource use, comprehension, and trust assessment. Our conclusions can be directly used in practice by adopting the re-worded error messages and documentation.

## The usability of certificate-manipulation tools

Our paper [Why Johnny the Developer Can't Work with Public Key Certificates](https://crocs.fi.muni.cz/public/papers/rsa2018) was published at RSA Cryptographers' Track 2018.

> **Abstract:** There have been many studies exposing poor usability of security software for the common end user. However, only a few inspect the usability challenges faced by more knowledgeable users. We conducted an experiment to empirically assess usability of the command line interface of OpenSSL, a well known and widely used cryptographic library. Based on the results, we try to propose specific improvements that would encourage more secure behavior. We observed 87 developers/administrators at two certificate-related tasks in a controlled environment. Furthermore, we collected participant opinions on both the tool interface and available documentation. Based on the overall results, we deem the OpenSSL usability insufficient according to both user opinions and standardized measures. Moreover, the perceived usability seems to be correlated with previous experience and used resources. There was a great disproportion between the participant views of a successful task accomplishment and the reality. A general dissatisfaction with both OpenSSL interface and its manual page was shared among the majority of the participants. As hinted by a participant, OpenSSL gradually “turned into a complicated set of sharp kitchen knives” – it can perform various jobs very well, but laymen risk stabbing themselves in the process. This highlights the necessity of a usable design even for tools targeted at experienced users.

## The evolution of TLS warnings in browsers

Our paper in collaboration with our colleague [Lydia Kraus](https://crocs.fi.muni.cz/people/lkraus) entitled [Evolution of SSL/TLS Indicators and Warnings in Web Browsers](https://crocs.fi.muni.cz/public/papers/spw2019) was published at the Security Protocols Workshop (SPW) of 2019.

> **Abstract:** The creation of the World Wide Web (WWW) in the early 1990’s finally made the Internet accessible to a wider part of the population. With this increase in users, security became more important. To address confidentiality and integrity requirements on the web, Netscape—by then a major web browser vendor—presented the Secure Socket Layer (SSL), later versions of which were renamed to Transport Layer Security (TLS). In turn, this necessitated the introduction of both security indicators in browsers to inform users about the TLS connection state and also of warnings to inform users about potential errors in the TLS connection to a website. Looking at the evolution of indicators and warnings, we find that the qualitative data on security indicators and warnings, i.e., screen shots of different browsers over time is inconsistent. Hence, in this paper we outline our methodology for collecting a comprehensive data set of web browser security indicators and warnings, which will enable researchers to better understand how security indicators and TLS warnings in web browsers evolved over time.

Based on the ideas presented in this paper, we started developing a tool for automatic collection of SSL/TLS warnings and errors in different browser. The tool **TLS warning collector** can be found on [GitHub](https://github.com/crocs-muni/tls-warning-collector).

</div></div>

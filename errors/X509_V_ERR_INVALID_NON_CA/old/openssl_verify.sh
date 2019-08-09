#!/bin/bash
openssl verify -allow_proxy_certs -CAfile files/ca.crt files/proxy.crt


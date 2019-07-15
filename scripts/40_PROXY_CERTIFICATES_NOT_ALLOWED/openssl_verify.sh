#!/bin/bash
openssl verify -CAfile files/ca.crt -untrusted files/subca.crt files/proxy.crt


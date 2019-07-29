#!/bin/bash
mkdir -p files

certtool --generate-privkey --outfile files/ca.key
certtool --generate-self-signed --load-privkey files/ca.key --outfile files/ca.crt --template ca.cfg

certtool --generate-privkey --outfile files/user.key
certtool --generate-request --load-privkey files/user.key --outfile files/user.csr --template user.cfg
certtool --generate-certificate --load-request files/user.csr --outfile files/user.crt --load-ca-certificate files/ca.crt --load-ca-privkey files/ca.key --template user.cfg

certtool --generate-crl --load-ca-certificate files/ca.crt --load-ca-privkey files/ca.key --outfile files/ca.crl --template crl.cfg

# change something in the last part of the crl






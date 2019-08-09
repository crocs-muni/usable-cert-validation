#!/bin/bash
mkdir -p files

certtool --generate-privkey --outfile files/ca.key
certtool --generate-self-signed --load-privkey files/ca.key --outfile files/ca.crt --template ca.cfg

certtool --generate-privkey --outfile files/proxy.key
#certtool --generate-request --load-privkey files/user.key --outfile files/user.csr --template user.cfg
certtool --generate-proxy --outfile files/proxy.crt --load-certificate files/ca.crt --load-ca-privkey files/ca.key --load-privkey files/proxy.key --template user.cfg







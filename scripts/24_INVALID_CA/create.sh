#!/bin/bash
certtool --generate-privkey --outfile files/ca.key
certtool --generate-self-signed --load-privkey files/ca.key --outfile files/ca.crt --template ca.cfg

certtool --generate-privkey --outfile files/subca.key
certtool --generate-request --load-privkey files/subca.key --outfile files/subca.csr --template subca.cfg
certtool --generate-certificate --load-request files/subca.csr --outfile files/subca.crt --load-ca-certificate files/ca.crt --load-ca-privkey  files/ca.key --template subca.cfg

certtool --generate-privkey --outfile files/user.key
certtool --generate-request --load-privkey files/user.key --outfile files/user.csr --template user.cfg
certtool --generate-certificate --load-request files/user.csr --outfile files/user.crt --load-ca-certificate files/subca.crt --load-ca-privkey files/subca.key --template user.cfg




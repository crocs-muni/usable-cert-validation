#!/bin/bash
certtool --generate-privkey --outfile files/ca.key --ecdsa
certtool --generate-self-signed --load-privkey files/ca.key --outfile files/ca.crt --template ca.cfg --ecdsa

certtool --generate-privkey --outfile files/user.key --ecdsa
certtool --generate-request --load-privkey files/user.key --outfile files/user.csr --template user.cfg 
certtool --generate-certificate --load-request files/user.csr --outfile files/user.crt --load-ca-certificate files/ca.crt --load-ca-privkey files/ca.key --template user.cfg --ecdsa






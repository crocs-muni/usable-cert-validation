oi#!/bin/bash
certtool --generate-privkey --outfile files/subca0.key
certtool --generate-self-signed --load-privkey files/subca0.key --outfile files/subca0.crt --template ca.cfg

for $i in 1..100
do
certtool --generate-privkey --outfile files/subca$i.key
certtool --generate-request --load-privkey files/subca$i.key --outfile files/subca$i.csr --template subca.cfg
certtool --generate-certificate --load-request files/subca$i.csr --outfile files/subca$i.crt --load-ca-certificate files/subca[$i - 1].crt --load-ca-privkey files/subca[$i - 1].key --template subca.cfg
done

certtool --generate-privkey --outfile files/user.key
certtool --generate-request --load-privkey files/user.key --outfile files/user.csr --template user.cfg
certtool --generate-certificate --load-request files/user.csr --outfile files/user.crt --load-ca-certificate files/subca$i.crt --load-ca-privkey files/subca$i.key --template user.cfg






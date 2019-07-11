#!/bin/bash
openssl genrsa -out ca.key
openssl req -new -x509 -key ca.key -out ca.crt

openssl genrsa -out subca.key
openssl req -new -key subca.key -out subca.csr
touch v3_ca.ext
echo "basicConstraints = critical,CA:true" > v3_ca.ext
openssl x509 -req -in subca.csr -CA ca.crt -CAkey ca.key -extfile v3_ca.ext -CAcreateserial -out subca.crt

openssl genrsa -out user.key
openssl req -new -key user.key -out user.csr
openssl x509 -req -in user.csr -CA subca.crt -CAkey subca.key -CAcreateserial -out user.crt


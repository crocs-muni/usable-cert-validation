#!/bin/bash
cat files/ca.crl >> files/ca.crt
certtool --verify --load-ca-certificate files/ca.crt --load-certificate files/user.crt

#!/bin/bash
cat files/user.crt files/subca.crt files/subsubca.crt > files/chain.crt
certtool --verify --load-ca-certificate files/ca.crt --infile files/chain.crt 

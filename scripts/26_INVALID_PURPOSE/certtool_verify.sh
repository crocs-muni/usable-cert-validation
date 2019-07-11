#!/bin/bash
certtool --verify --load-ca-certificate files/ca.crt --infile files/user.crt --verify-purpose 1.3.6.1.5.5.7.3.1 


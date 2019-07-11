#!/bin/bash
certtool --verify --load-ca-certificate files/ca.crt --infile files/user.crt

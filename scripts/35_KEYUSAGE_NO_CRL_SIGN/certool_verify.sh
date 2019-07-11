#!/bin/bash
certtool --verify-crl --load-ca-certificate files/ca.crt < files/ca.crl


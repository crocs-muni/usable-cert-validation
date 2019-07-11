#!/bin/bash
certtool --load-ca-certificate files/ca.crt < files/ca.crl --verify-crl


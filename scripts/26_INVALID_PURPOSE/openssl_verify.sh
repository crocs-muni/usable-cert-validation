#!/bin/bash
openssl verify -CAfile files/ca.crt -purpose sslserver files/user.crt verify-purpose 1.3.6.1.5.5.7.3.4


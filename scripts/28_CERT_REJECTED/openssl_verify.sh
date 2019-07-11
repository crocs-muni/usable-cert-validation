#!/bin/bash
openssl verify -CAfile files/serverca.crt -purpose sslserver files/user.crt 


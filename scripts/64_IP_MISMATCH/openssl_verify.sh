#!/bin/bash
openssl verify -CAfile files/ca.crt -verify_ip 1.1.1.1 files/user.crt 


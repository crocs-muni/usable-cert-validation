#!/bin/bash
openssl verify -CAfile files/ca.crt -verify_hostname hello.com files/user.crt 


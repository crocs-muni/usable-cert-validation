#!/bin/bash
openssl verify -CAfile files/ca.crt -verify_email hello@hello.com files/user.crt 


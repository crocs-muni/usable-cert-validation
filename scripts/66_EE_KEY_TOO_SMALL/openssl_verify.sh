#!/bin/bash
openssl verify -CAfile files/ca.crt -auth_level 1 files/user.crt 


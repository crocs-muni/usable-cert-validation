#!/bin/bash
openssl verify -CAfile files/ca.crt -auth_level 2 files/user.crt 


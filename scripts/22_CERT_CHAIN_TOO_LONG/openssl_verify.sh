#!/bin/bash
openssl verify -CAfile files/subca.crt -untrusted files/subca.crt -verify_depth 0 files/user.crt

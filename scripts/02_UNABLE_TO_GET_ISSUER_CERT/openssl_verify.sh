#!/bin/bash
openssl verify -CAfile files/subca.crt -untrusted files/subca.crt files/user.crt

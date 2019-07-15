#!/bin/bash
openssl verify -CAfile files/ca.crt -untrusted files/subca.crt -untrusted files/subsubca.crt files/user.crt

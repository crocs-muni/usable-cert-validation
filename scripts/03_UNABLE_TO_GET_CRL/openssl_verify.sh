#!/bin/bash
openssl verify -CAfile files/ca.crt -crl_check files/user.crt


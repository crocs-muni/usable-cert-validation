#!/bin/bash
openssl verify -CAfile files/ca.crt -CRLfile files/ca.crl -crl_check files/user.crt


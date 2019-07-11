#!/bin/bash
openssl verify -CAfile files/ca.crt -crl_check -CRLfile files/ca.crl files/user.crt


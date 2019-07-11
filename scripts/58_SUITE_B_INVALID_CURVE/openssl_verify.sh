#!/bin/bash
openssl verify -CAfile files/ca.crt -suiteB_128_only files/user.crt


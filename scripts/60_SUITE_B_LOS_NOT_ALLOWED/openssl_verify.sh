#!/bin/bash
openssl verify -CAfile files/ca.crt -suiteB_192 files/user.crt


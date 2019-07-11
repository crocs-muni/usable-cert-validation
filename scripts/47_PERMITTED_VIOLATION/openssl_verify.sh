#!/bin/bash
openssl verify -CAfile files/ca.crt files/user.crt

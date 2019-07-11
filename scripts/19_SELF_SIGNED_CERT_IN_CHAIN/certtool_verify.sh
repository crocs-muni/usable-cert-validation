#!/bin/bash
cat files/user.crt files/ca.crt > files/chain.crt
certtool --verify --infile files/chain.crt

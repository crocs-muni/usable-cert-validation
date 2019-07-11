#!/bin/bash
certtool --generate-privkey --outfile files/ca.key
certtool --generate-self-signed --load-privkey files/ca.key --outfile files/ca.crt --template ca.cfg








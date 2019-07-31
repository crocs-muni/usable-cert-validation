#!/bin/bash

if [ $# -eq 0 ]
then
    echo "usage: "$0" <error scripts folder>"
    exit -1
fi

if [ ! $# -eq 1 ]
then
    echo "Error: Incorrect number of parameters (exactly 1 parameter required)."
    exit -1
fi

CERTS_SCRIPTS_FOLDER=$1
if [ ! -d $CERTS_SCRIPTS_FOLDER ]
then
    echo "Error: Cannot open folder '"$CERTS_SCRIPTS_FOLDER"'."
    exit -2
fi

echo "---"
echo -n "title: "
make --silent --directory=$CERTS_SCRIPTS_FOLDER error-code
echo -n "slug: "
make --silent --directory=$CERTS_SCRIPTS_FOLDER error-code | sed 's/[A-Z]/\L&/g' | sed 's/_/-/g'
echo "verify-openssl: |"
make --silent --directory=$CERTS_SCRIPTS_FOLDER --just-print --always-make verify-openssl | sed 's/^/    /' | sed 's|_certs/||g'
echo "---"
echo "Extra text or documentation here."
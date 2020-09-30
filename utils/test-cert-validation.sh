#!/bin/bash

if [ $# -eq 0 ]
then
    echo "usage: "$0" <path/certs-build-folder> <path/error-code.yml>"
    exit -1
fi

if [ ! $# -eq 2 ]
then
    echo "Error: Incorrect number of parameters (exactly 2 parameters required)."
    exit -1
fi

CERTS_BUILD_FOLDER=$1
ERROR_FILE=$2
ERROR=`basename $ERROR_FILE | sed s/.yml//`
VERIFY_CERT=`cat $ERROR_FILE | shyaml get-value verify-cert`
VERIFY_COMMAND=`cat $ERROR_FILE | shyaml get-value verify-command`
VERIFY_EXPECTED=`cat $ERROR_FILE | shyaml get-value verify-expected`
VERIFY_OUTPUT_FILE=openssl-verify.txt

cd $CERTS_BUILD_FOLDER/$VERIFY_CERT
eval $VERIFY_COMMAND >$VERIFY_OUTPUT_FILE 2>&1
GREP_RESULT=`grep -F "$VERIFY_EXPECTED" $VERIFY_OUTPUT_FILE | wc -l`

if [ ! $GREP_RESULT -eq 1 ]
then
    echo "### Validation with unexpected results for $ERROR! ###"
    echo "====== Expected ======"
    echo $VERIFY_EXPECTED
    echo "====== Observed ======"
    cat $VERIFY_OUTPUT_FILE
    echo "====== (end) ======"
    exit -2
fi

rm -f $VERIFY_OUTPUT_FILE

#!/bin/bash

if [ $# -eq 0 ]
then
    echo "usage: "$0" <path/error-code> <path/cert-build-dir>"
    exit -1
fi

if [ ! $# -eq 2 ]
then
    echo "Error: Incorrect number of parameters (exactly 2 parameters required)."
    exit -1
fi

ERROR_PATH=$1
ERROR=`basename $ERROR_PATH`
BUILD_DIR=$2
VERIFY_OUTPUT_FILE=$BUILD_DIR/$ERROR.openssl-verify

make --silent --directory=$ERROR_PATH BUILD_DIR=$BUILD_DIR verify-openssl >$VERIFY_OUTPUT_FILE 2>&1
GREP_RESULT=`grep -f $ERROR_PATH/expected.txt $VERIFY_OUTPUT_FILE | wc -l`

if [ ! $GREP_RESULT -eq 1 ]
then
    echo "### Validation with unexpected results for $ERROR! ###"
    exit -2
fi
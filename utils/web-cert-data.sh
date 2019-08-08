#!/bin/bash

if [ $# -eq 0 ]
then
    echo "usage: "$0" <scripts-path/error-code> <docs/error-code.yml> <code-weight>"
    exit -1
fi

if [ ! $# -eq 3 ]
then
    echo \#: $#
    echo 1:$1
    echo 2:$2
    echo 3:$3
    echo 4:$4
    echo "Error: Incorrect number of parameters (exactly 3 parameters required)."
    exit -1
fi

CERTS_SCRIPTS_FOLDER=$1
CERTS_DOCS_FILE=$2
CODE_WEIGHT=$3
ERROR_CODE=`basename $CERTS_SCRIPTS_FOLDER`

echo "---"
echo "title: "`echo $ERROR_CODE | sed 's/_/_\&shy;/g'`
echo -n "slug: "
echo $ERROR_CODE | sed 's/[A-Z]/\L&/g' | sed 's/_/-/g'
echo "weight: "$CODE_WEIGHT

if [ -f $CERTS_DOCS_FILE ]
then
    cat $CERTS_DOCS_FILE
fi
echo

if [ -f $CERTS_SCRIPTS_FOLDER/Makefile ]
then
    echo "verify-openssl: |"
    make --silent --directory=$CERTS_SCRIPTS_FOLDER --just-print --always-make verify-openssl | sed 's/^/    /' | sed 's|_certs/||g'
fi

echo "---"
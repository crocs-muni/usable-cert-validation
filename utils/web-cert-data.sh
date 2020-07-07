#!/bin/bash

if [ $# -eq 0 ]
then
    echo "usage: "$0" <path/error-code>"
    exit -1
fi

if [ ! $# -eq 1 ]
then
    echo "Error: Incorrect number of parameters (exactly 1 parameter required)."
    exit -1
fi

ERROR_FOLDER=$1
ERROR_CODE=`basename $ERROR_FOLDER`
ERROR_DATA_FILE=$ERROR_FOLDER/data.yml

echo "error-code: "$ERROR_CODE
echo -n "slug: "
echo $ERROR_CODE | sed 's/[A-Z]/\L&/g' | sed 's/_/-/g'

if [ -f $ERROR_DATA_FILE ]
then
    cat $ERROR_DATA_FILE
fi

if [ -f $ERROR_FOLDER/Makefile ]
then
    make --directory=$ERROR_FOLDER --question verify-openssl 2>/dev/null
    RET=$?
    if [ $RET -eq 1 ]
    then
        echo "verify-openssl: |"
        make --silent --directory=$ERROR_FOLDER --just-print --always-make verify-openssl | sed 's/^/    /' | sed 's|_certs/||g' | sed 's/</\&lt;/g' | sed 's/>/\&gt;/g'
    fi
    make --directory=$ERROR_FOLDER --question verify-gnutls 2>/dev/null
    RET=$?
    if [ $RET -eq 1 ]
    then
        echo "verify-gnutls: |"
        make --silent --directory=$ERROR_FOLDER --just-print --always-make verify-gnutls | sed 's/^/    /' | sed 's|_certs/||g' | sed 's/</\&lt;/g' | sed 's/>/\&gt;/g'
    fi
    make --directory=$ERROR_FOLDER --question verify-botan 2>/dev/null
    RET=$?
    if [ $RET -eq 1 ]
    then
        echo "verify-botan: |"
        make --silent --directory=$ERROR_FOLDER --just-print --always-make verify-botan | sed 's/^/    /' | sed 's|_certs/||g' | sed 's/</\&lt;/g' | sed 's/>/\&gt;/g'
    fi
    make --directory=$ERROR_FOLDER --question verify-mbedtls 2>/dev/null
    RET=$?
    if [ $RET -eq 1 ]
    then
        echo "verify-mbedtls: |"
        make --silent --directory=$ERROR_FOLDER --just-print --always-make verify-mbedtls | sed 's/^/    /' | sed 's|_certs/||g' | sed 's/</\&lt;/g' | sed 's/>/\&gt;/g'
    fi
fi

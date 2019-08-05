#!/bin/bash
OPENSSL_DOC=openssl.txt
GNUTLS_DOC=gnutls.txt

if [ $# -eq 0 ]
then
    echo "usage: "$0" <scripts-path/error-code> <docs-path/error-code>"
    exit -1
fi

if [ ! $# -eq 2 ]
then
    echo "Error: Incorrect number of parameters (exactly 2 parameters required)."
    exit -1
fi

CERTS_SCRIPTS_FOLDER=$1
CERTS_DOCS_FOLDER=$2
ERROR_CODE=`basename $CERTS_SCRIPTS_FOLDER`

echo "---"
echo "title: "$ERROR_CODE
echo -n "slug: "
echo $ERROR_CODE | sed 's/[A-Z]/\L&/g' | sed 's/_/-/g'

if [ -f $CERTS_SCRIPTS_FOLDER/Makefile ]
then
    echo "verify-openssl: |"
    make --silent --directory=$CERTS_SCRIPTS_FOLDER --just-print --always-make verify-openssl | sed 's/^/    /' | sed 's|_certs/||g'
fi

echo "---"
echo "## OpenSSL documentation"
if [ -f $CERTS_DOCS_FOLDER/$OPENSSL_DOC ]
then
    cat $CERTS_DOCS_FOLDER/$OPENSSL_DOC
else
    echo "OpenSSL documentation not yet imported."
fi
echo -e "\n"
echo "## GnuTLS documentation"
if [ -f $CERTS_DOCS_FOLDER/$GNUTLS_DOC ]
then
    cat $CERTS_DOCS_FOLDER/$GNUTLS_DOC
else
    echo "GnuTLS documentation not yet imported."
fi
echo
# YAML-TO-ASN1 CERTIFICATE GENERATOR

This simple application can generate a certificate using a YAML template which describes the ASN.1 certificate structure.

The YAML template uses tags equal to ASN.1 tags (with some additions). 
To view an example of such a template, see *template.yml*.

## Pre-Build

To be able to build this application correctly, install the GO language and the following GO libraries:

__$ go get gopkg.in/yaml.v3__

__$ cd $GOPATH/src/golang.org/x && git clone https://github.com/zacikpa/crypto.git__

## Build

To build this application, use:

__$ go build -o generate *.go__

## Usage

To run, use:

__$ ./generate -signingKey key_file --templateFile template --outFile out.pem --privateKey priv.pem --issuerFile ca.pem__

*signingKey* is a filename of an RSA key to be used to sign the final certificate

*templateFile* is a filename of the YAML template to use

*outFile* is a filename, where the resulting certificate will be written in PEM form

*privateKey* is a filename of an RSA key whose public counterpart is signed in the certificate

*issuerFile* is a filename of the issuing CA certificate

### Supported template types and equivalent ASN.1 tags


- SET is equivalent to ASN.1 SET, a structured type. \
It must be represented as a YAML mapping. \
Duplicate mapping keys are allowed in this context.

- SEQUENCE is equivalent to ASN.1 SEQUENCE, a structured type. \
It must be represented as an ordered YAML mapping. \
Duplicate mapping keys are allowed in this context. 

- INTEGER is equivalent to ASN.1 INTEGER. \
It must be represented as an integer that can be parsed as golang's **int**.

- BOOLEAN is equivalent to ASN.1 BOOLEAN. \
Possible values are **true** or **false**.

- IA5STRING is equivalent to ASN.1 IA5String. \
Possible values are strings containing only ISO 646 (IA5) characters.

- UTF8STRING is equivalent to ASN.1 UTF8String. \
Possible values are strings containing UTF8 characters.

- PRTINTABLESTRING is equivalent to ASN.1 PrintableString. \
Possible values are strings containing only printable ASCII characters.

- DATE is a type which generates ASN.1 GeneralizedTime. \
Valid date must be in the form **YYYY/MM/DD**.

- YEAROFFSET is a type which generates ASN.1 GeneralizedTime \
Any **int** is a valid value. The generated time is the current time + number of years given by the integer.

- OID is equivalent to ASN.1 OBJECT IDENTIFIER. \
Possible values are arbitrary number of digits separated by commas arbitrarily.

- NULL_TAG is equivalent to ASN.1 NULL. \
The only meaningful value is NULL, as it is ignored.

- OCTETSTRING is equivalent to ASN.1 OCTETSTRING.

- OCTETCAPSULE generates an ASN.1 OCTETSTRING. \
It must be represented as a mapping and it creates a DER capsule around the types underneath. 

- PRIVATEKEY is a special type used to create RFC5280 PublicKeyInfo certificate value. \
Valid value is a filename of a PEM encoded private key complementary to the public one. 

 
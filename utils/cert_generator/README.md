# YAML-ASN1 CERTIFICATE GENERATOR

This application can generate a certificate using a YAML template which describes the ASN.1 certificate structure.

The YAML template uses tags/types similar to ASN.1 tags. \
To view an example of such a template, see *template.yml*.

## Pre-Build

Install the GO language at:
    
    golang.org/doc/install

Install the yaml v3:

    go get gopkg.in/yaml.v3

Install the modified fork of golang.org/x/crypto:

    git clone https://github.com/zacikpa/crypto.git $GOPATH/src/golang.org/x/crypto

## Build

To build, run:

    go build -o generate *.go

## Usage

Run the application by using the command:

    ./generate -signingKey key.pem --templateFile template --outFile out.pem [--privateKey priv.pem] [--issuerFile ca.pem]

*signingKey* is a filename of an RSA key to be used to sign the final certificate.

*templateFile* is a filename of the YAML template to use.

*outFile* is a filename, where the resulting certificate will be written in PEM form.

*privateKey* (optional) is a filename of an RSA key whose public counterpart is signed in the certificate.

*issuerFile* (optional) is a filename of the issuing CA certificate.

## Supported template types and equivalent ASN.1 tags

**SET** is equivalent to **ASN.1 SET**, a structured type. \
It must be represented as a YAML mapping. \
Duplicate mapping keys are allowed in this context.
    
    SET:
        INTEGER: 2
        BOOLEAN: false

**SEQUENCE** is equivalent to **ASN.1 SEQUENCE**, a structured type. \
It must be represented as an ordered YAML mapping. \
Duplicate mapping keys are allowed in this context. 

        SEQUENCE:
            INTEGER: 2
            BOOLEAN: true
            INTEGER: 1
            
**INTEGER** is equivalent to **ASN.1 INTEGER**. \
It must be represented as an integer that can be parsed as golang's int.

    INTEGER: -12
    
**BOOLEAN** is equivalent to **ASN.1 BOOLEAN**. \
Possible values are true or false.

    BOOLEAN: false

**IA5STRING** is equivalent to **ASN.1 IA5String**. \
Possible values are strings containing only ISO 646 (IA5) characters (TO DO)

    IA5STRING: Roy
    
**UTF8STRING** is equivalent to **ASN.1 UTF8String**. \
Possible values are strings containing UTF8 characters (TO DO)

    UTF8STRING: "Some name"
    
**PRTINTABLESTRING** is equivalent to **ASN.1 PrintableString**. \
Possible values are strings containing only printable ASCII characters.

    PRINTABLESTRING: Other name

**DATE** is a type which generates **ASN.1 GeneralizedTime**. \
Valid date must be in the form YYYY/MM/DD.

    DATE: 2020/09/16

**YEAROFFSET** is a type which generates **ASN.1 GeneralizedTime** \
Any int is a valid value. The generated time is the current time + number of years given by the integer.

    YEAROFFSET: 10
    
**OID** is equivalent to **ASN.1 OBJECT IDENTIFIER**. \
Possible values are arbitrary number of digits separated by commas arbitrarily.

    OID: 1.2.840.113549.1.1.11 
    
**NULLTAG** is equivalent to **ASN.1 NULL**. \
The only meaningful value is NULL, as it is ignored.

    NULLTAG: NULL
    
**OCTETCAPSULE** generates an **ASN.1 OCTETSTRING**. \
It must be represented as a mapping and it creates a DER capsule around the types underneath. 

    OCTETCAPSULE:
        SEQUENCE:
            INTEGER: 2
            DATE: 2025/05/03
            
**PRIVATEKEY** is a special type used to create RFC5280 **publicKeyInfo** certificate value. \
Valid value is a filename of a PEM encoded private key complementary to the public one.

    PRIVATEKEY: priv.pem
    
**ISSUERFILE** is a special type used to fill the **issuer** field of the generated certificate. \
Valid value is a filename of a PEM encoded certificate.

    ISSUERFILE: ca.pem
    
## Implicit, explicit and override tags

Additionally, tags can be appended with keywords **EXPLICIT**, **IMPLICIT** and **OVERRIDE** plus tag number to manipulate the final ASN.1 structure.

**EXPLICIT** keyword is the equivalent of **ASN.1 explicit** keyword.
It creates an outer layer over the value with the tag number given

    INTEGER EXPLICIT 0: 1
    
**IMPLICIT** keyword is the equivalent of **ASN.1 implicit** keyword.
It is used to distinguish between values of the same type inside structured types.

    UTF8STRING IMPLICIT 3: subject name  
    
**OVERRIDE** keyword has no direct equivalent in ASN.1. Use it when you want the ASN.1 tag to be different than the actual type used.

    BOOLEAN OVERRIDE 24: false
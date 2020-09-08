# YAML-TO-ASN1 CERTIFICATE GENERATOR

This simple application can generate a certificate using a YAML template which describes the ASN.1 certificate structure.

The YAML template uses tags equal to ASN.1 tags (with some additions). 
To view an example of such a template, see *template.yml*.

## Build

To build this application, use:

__go build -o cert_generator *.go__

## Usage

To run, use:

__$ ./cert_generator -signingKey key_file --templateFile template --outFile out.pem__

*signingKey* is a filename of an RSA key to be used to sign the final certificate

*templateFile* is a filename of the YAML template to use

*outFile* is a filename, where the resulting certificate will be written in PEM form

 
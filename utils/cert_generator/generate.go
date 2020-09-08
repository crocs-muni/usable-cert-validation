package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/crypto/cryptobyte"
	"io/ioutil"
)

// to-be-signed certificate field, but each subfield accepts an "arbitrary" value
type tbsCertificate struct {
	Version            		asn1.RawValue	`asn1:"optional"`
	SerialNumber       		asn1.RawValue
	Signature	 			asn1.RawValue
	Issuer             		asn1.RawValue
	Validity           		asn1.RawValue
	Subject            		asn1.RawValue
	SubjectPublicKeyInfo	asn1.RawValue
	IssuerUniqueId      	asn1.RawValue	`asn1:"optional"`
	SubjectUniqueId    		asn1.RawValue	`asn1:"optional"`
	Extensions         		asn1.RawValue	`asn1:"optional"`
}

// Standard x.509 certificate, but each field can be of arbitrary value
type certificate struct {
	TBSCertificate 		tbsCertificate
	SignatureAlgorithm 	asn1.RawValue
	SignatureValue 		asn1.RawValue
}

// Determines which field of the cert shall be used according to the parsed string
func getFieldPtr(str string, cert *certificate) (*[]byte, error) {
	switch str {
	case "version":
		return &cert.TBSCertificate.Version.FullBytes, nil
	case "serialNumber":
		return &cert.TBSCertificate.SerialNumber.FullBytes, nil
	case "signature":
		return &cert.TBSCertificate.Signature.FullBytes, nil
	case "issuer":
		return &cert.TBSCertificate.Issuer.FullBytes, nil
	case "validity":
		return &cert.TBSCertificate.Validity.FullBytes, nil
	case "subject":
		return &cert.TBSCertificate.Subject.FullBytes, nil
	case "subjectPublicKeyInfo":
		return &cert.TBSCertificate.SubjectPublicKeyInfo.FullBytes, nil
	case "issuerUniqueID":
		return &cert.TBSCertificate.IssuerUniqueId.FullBytes, nil
	case "subjectUniqueID":
		return &cert.TBSCertificate.SubjectUniqueId.FullBytes, nil
	case "extensions":
		return &cert.TBSCertificate.Extensions.FullBytes, nil
	case "signatureAlgorithm":
		return &cert.SignatureAlgorithm.FullBytes, nil
	case "signatureValue":
		return &cert.SignatureValue.FullBytes, nil
	default:
		return nil, errors.New("unknown certificate field name")
	}
}

// Loads all certificate data from an Object to a certificate
func loadData(obj *Object, cert *certificate) error {
	for _, ch := range obj.Children {
		ptr, err := getFieldPtr(ch.Name, cert)
		if err != nil {
			return err
		}
		var b cryptobyte.Builder
		for _, grandchild := range ch.Children {
			err = BuildASN1(&grandchild, &b)
			if err != nil {
				return err
			}
		}
		*ptr, err = b.Bytes()
		if err != nil {
			return err
		}
	}
	return nil
}

// Signs the certificate using a given RSA key (that is, fill its signatureValue field)
func sign(cert *certificate, key *rsa.PrivateKey) error {
	tbsCertContents, err := asn1.Marshal(cert.TBSCertificate)
	if err != nil {
		return err
	}

	hashFunc := crypto.SHA256

	var signed []byte
	h := crypto.SHA256.New()
	h.Write(tbsCertContents)
	signed = h.Sum(nil)

	var signerOpts crypto.SignerOpts = hashFunc

	random := rand.Reader
	bytes, err := key.Sign(random, signed, signerOpts)
	if err != nil {
		return err
	}

	signature := asn1.BitString{Bytes: bytes, BitLength: len(bytes) * 8}
	cert.SignatureValue.FullBytes, err = asn1.Marshal(signature)
	if err != nil {
		return err
	}

	return nil
}

// Generates a certificate given a template and signs it using a given key
func main() {
	var signingKeyFile = flag.String("signingKey", "", "The private key file of the signer")
	var templateFile = flag.String("templateFile", "", "The template yml file")
	var outFile = flag.String("outFile", "", "The output filename")

	flag.Parse()

	bytes, err := ioutil.ReadFile(*templateFile)
	if err != nil {
		fmt.Println(err)
		return
	}

	obj, err := ParseYAMLDocument(bytes)
	if err != nil {
		fmt.Println(err)
		return
	}

	var cert certificate
	err = loadData(&obj, &cert)
	if err != nil {
		fmt.Println(err)
	}

	if len(cert.SignatureValue.FullBytes) == 0 {
		key, err := LoadPrivateKey(*signingKeyFile)
		if err != nil {
			fmt.Println(err)
			return
		}
		err = sign(&cert, key)
		if err != nil {
			fmt.Println(err)
			return
		}
	}

	out, err := asn1.Marshal(cert)
	if err != nil {
		fmt.Println(err)
		return
	}

	err = WritePEM(out, *outFile, "CERTIFICATE")
	if err != nil {
		fmt.Println(err)
		return
	}
}

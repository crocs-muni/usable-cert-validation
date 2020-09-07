package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
)

// Loads an RSA private key from a file into an rsa.PrivateKey object
func LoadPrivateKey(filename string) (*rsa.PrivateKey, error) {
	privateKeyBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	derBytes, rest := pem.Decode(privateKeyBytes)
	if len(rest) != 0 {
		return nil, errors.New("unknown data follows private key")
	}

	key, err := x509.ParsePKCS1PrivateKey(derBytes.Bytes)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// Converts bytes in DER form into PEM with a given type and writes it into a file
func WritePEM(bytes []byte, filename string, blockType string) error {
	block := &pem.Block{
		Type: blockType,
		Headers: map[string]string{
		},
		Bytes: bytes,
	}

	f, err := os.Create(filename)
	if err != nil {
		return err
	}

	err = pem.Encode(f, block)
	if err != nil {
		return err
	}

	return nil
}

package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
)

func LoadPEM(filename string) ([]byte, error) {
	pemBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	derBytes, rest := pem.Decode(pemBytes)
	if len(rest) != 0 {
		return nil, errors.New("unknown data follows private key")
	}

	return derBytes.Bytes, nil
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

// Loads an RSA private key from a file into an rsa.PrivateKey object
func LoadPrivateKey(filename string) (*rsa.PrivateKey, error) {
	bytes, err := LoadPEM(filename)
	if err != nil {
		return nil, err
	}

	key, err := x509.ParsePKCS1PrivateKey(bytes)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func LoadCertificate(filename string) (*x509.Certificate, error) {
	bytes, err := LoadPEM(filename)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

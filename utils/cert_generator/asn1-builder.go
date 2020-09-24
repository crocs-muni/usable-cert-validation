package main

import (
	"errors"
	"golang.org/x/crypto/cryptobyte"
	cryptobyteasn1 "golang.org/x/crypto/cryptobyte/asn1"
	"strconv"
	"strings"
	"time"
)

func parseName(name string) (string, string, int, error) {
	data := strings.Split(name, " ")

	if len(data) == 1 {
		return data[0], "", 0, nil
	}

	number, err := strconv.Atoi(data[2])
	if err != nil {
		return "", "", 0, err
	}

	return data[0], data[1], number, nil
}

func parseOID(data string) ([]int, error) {
	numbers := strings.Split(data, ".")
	var oid []int
	for _, c := range numbers {
		next, err := strconv.Atoi(c)
		if err != nil {
			return nil, err
		}
		oid = append(oid, next)
	}
	return oid, nil
}

func buildCapsule(obj *Object) ([]byte, error) {
	var b cryptobyte.Builder
	for _, ch := range obj.Children {
		err := BuildASN1(&ch, &b)
		if err != nil {
			return nil, err
		}
	}
	bytes, _ := b.Bytes()
	return bytes, nil
}

func buildPublicKeyInfo(filename string) ([]byte, error) {
	key, err := LoadPrivateKey(filename)
	if err != nil {
		return nil, err
	}
	var subB cryptobyte.Builder
	subB.AddASN1(cryptobyteasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(key.N, nil)
		b.AddASN1Int64(int64(key.E), nil)
	})
	bytes, _ := subB.Bytes()
	return bytes, nil
}

// Builds ASN.1 DER data from a given Object
func BuildASN1(obj *Object,  builder *cryptobyte.Builder) error {

	buildChildren := func(b *cryptobyte.Builder) {
		for _, ch := range obj.Children {
			err := BuildASN1(&ch, b)
			if err != nil {
				panic(err)
			}
		}
	}

	typename, tag, number, err := parseName(obj.Name)
	if err != nil {
		return err
	}

	if tag == "EXPLICIT" {
		builder.AddASN1(cryptobyteasn1.Tag(number).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				obj.Name = typename
				err := BuildASN1(obj, b)
				if err != nil {
					panic(err)
				}
		})
		return nil
	}

	var implicit *cryptobyteasn1.Tag
	implicit = nil

	if tag == "IMPLICIT" {
		t := cryptobyteasn1.Tag(number).ContextSpecific()
		implicit = &t
	}

	switch typename {
	case "SEQUENCE":
		builder.AddASN1(cryptobyteasn1.SEQUENCE, buildChildren)
	case "SET":
		builder.AddASN1(cryptobyteasn1.SET, buildChildren)
	case "BOOLEAN":
		boolValue, err := strconv.ParseBool(obj.Content)
		if err != nil {
			return err
		}
		builder.AddASN1Boolean(boolValue, implicit)
	case "INTEGER":
		intValue, err := strconv.Atoi(obj.Content)
		if err != nil {
			return err
		}
		builder.AddASN1Int64(int64(intValue), implicit)
	case "IA5STRING":
		builder.AddASN1IA5String(obj.Content, implicit)
	case "UTF8STRING":
		builder.AddASN1UTF8String(obj.Content, implicit)
	case "PRINTABLESTRING":
		builder.AddASN1PrintableString(obj.Content, implicit)
	case "OID":
		oid, err := parseOID(obj.Content)
		if err != nil {
			return err
		}
		builder.AddASN1ObjectIdentifier(oid, implicit)
	case "NULLTAG":
		builder.AddASN1NULL()
	case "DATE":
		t, err := time.Parse("2006/01/02", obj.Content)
		if err != nil {
			return err
		}
		builder.AddASN1GeneralizedTime(t, implicit)
	case "YEAROFFSET":
		years, err := strconv.Atoi(obj.Content)
		if err != nil {
			return err
		}
		t := time.Now().AddDate(years, 0, 0)
		builder.AddASN1GeneralizedTime(t, implicit)
	case "OCTETCAPSULE":
		bytes, err := buildCapsule(obj)
		if err != nil {
			return err
		}
		builder.AddASN1OctetString(bytes, implicit)
	case "OCTETSTRING":
		builder.AddASN1OctetString([]byte(obj.Content), implicit)
	case "PRIVATEKEY":
		bytes, err := buildPublicKeyInfo(obj.Content)
		if err != nil {
			return err
		}
		builder.AddASN1BitString(bytes, implicit)
	case "ISSUERCERT":
		cert, err := LoadCertificate(obj.Content)
		if err != nil {
			return err
		}
		builder.AddBytes(cert.RawSubject)
	default:
		return errors.New("unknown type " + obj.Name)
	}
	return nil
}
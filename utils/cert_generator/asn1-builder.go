package main

import (
	"errors"
	"golang.org/x/crypto/cryptobyte"
	cryptobyteasn1 "golang.org/x/crypto/cryptobyte/asn1"
	"strconv"
	"strings"
	"time"
)

// Builds ASN.1 DER data from a given Object
func BuildASN1(obj *Object,  builder *cryptobyte.Builder) error {
	name := splitType(obj.Name)
	switch name[0] {
	case "SEQUENCE":
		builder.AddASN1(cryptobyteasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			for _, ch := range obj.Children {
				err := BuildASN1(&ch, b)
				if err != nil {
					panic(err)
				}
			}
		})
	case "SET":
		builder.AddASN1(cryptobyteasn1.SET, func(b *cryptobyte.Builder) {
			for _, ch := range obj.Children {
				err := BuildASN1(&ch, b)
				if err != nil {
					panic(err)
				}
			}
		})
	case "BOOLEAN":
		boolValue, _ := strconv.ParseBool(obj.Content)
		builder.AddASN1Boolean(boolValue)
	case "INTEGER":
		intValue, _ := strconv.Atoi(obj.Content)
		builder.AddASN1Int64(int64(intValue))
	case "IA5String":
		builder.AddASN1(cryptobyteasn1.Tag(22), func(b *cryptobyte.Builder) {
			b.AddBytes([]byte(obj.Content))
		})
	case "UTF8String":
		builder.AddASN1(cryptobyteasn1.Tag(12), func(b *cryptobyte.Builder) {
			b.AddBytes([]byte(obj.Content))
		})
	case "PrintableString":
		builder.AddASN1(cryptobyteasn1.Tag(19), func(b *cryptobyte.Builder) {
			b.AddBytes([]byte(obj.Content))
		})
	case "OID":
		numbers := strings.Split(obj.Content, ".")
		var bytes []int
		for _, c := range numbers {
			next, _ := strconv.Atoi(c)
			bytes = append(bytes, next)
		}
		builder.AddASN1ObjectIdentifier(bytes)
	case "NULL_TAG":
		builder.AddASN1NULL()
	case "TIME":
		t, _ := time.Parse("2006/01/02", obj.Content)
		builder.AddASN1GeneralizedTime(t)
	case "BITSTRING":
		builder.AddASN1BitString([]byte(obj.Content))
	case "OCTETSTRING":
		var subB cryptobyte.Builder
		for _, ch := range obj.Children {
			err := BuildASN1(&ch, &subB)
			if err != nil {
				return err
			}
		}
		bytes, _ := subB.Bytes()
		builder.AddASN1OctetString(bytes)
	case "PRIVATE_KEY_FILE":
		key, err := LoadPrivateKey(obj.Content)
		if err != nil {
			return err
		}
		var subB cryptobyte.Builder
		subB.AddASN1(cryptobyteasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1BigInt(key.N)
			b.AddASN1Int64(int64(key.E))
		})
		res, _ := subB.Bytes()
		builder.AddASN1BitString(res)
	case "EXPLICIT":
		tag, _ := strconv.Atoi(name[1])
		builder.AddASN1(cryptobyteasn1.Tag(tag).ContextSpecific().Constructed(),func(b *cryptobyte.Builder) {
			for _, ch := range obj.Children {
				err := BuildASN1(&ch, b)
				if err != nil {
					panic(err)
				}
			}
		})
	case "IMPLICIT":
		tag, _ := strconv.Atoi(name[1])
		builder.AddASN1(cryptobyteasn1.Tag(tag).ContextSpecific(), func(b *cryptobyte.Builder) {
			b.AddBytes([]byte(obj.Content))
		})
	default:
		return errors.New("unknown type")
	}
	return nil
}

// Splits a string by a delimiter "-", used in type names
func splitType(name string) []string {
	return strings.Split(name, "-")
}
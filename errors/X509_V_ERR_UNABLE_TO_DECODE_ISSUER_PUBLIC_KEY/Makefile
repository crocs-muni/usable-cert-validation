# Environment varibales (may be overriden crom CLI)

# How to replicate this error:
# Create a simple chain consisting of a self-signed CA and non-ca endpoint
# Convert the CA from the DER form into ASN.1 structure using a suitable tool (e.g `unber`)
# Manually change the OID of the public key signature algorithm to some nonsense value
# Convert the altered CA back to DER and PEM

BUILD_DIR=_certs
VERBOSITY=

all: error-code generate-cert verify-openssl verify-gnutls verify-botan verify-mbedtls

error-code:
	@basename $$PWD

generate-cert: $(BUILD_DIR)/endpoint.crt

STATIC_CERTS=$(wildcard *.crt)
$(BUILD_DIR)/endpoint.crt: $(STATIC_CERTS)
	cp *.crt $(BUILD_DIR)

verify-openssl:
	-openssl verify -CAfile $(BUILD_DIR)/ca.crt $(BUILD_DIR)/endpoint.crt

verify-gnutls:
	-certtool --verify --load-ca-certificate $(BUILD_DIR)/ca.crt --infile $(BUILD_DIR)/endpoint.crt

verify-botan:
	-botan cert_verify $(BUILD_DIR)/endpoint.crt $(BUILD_DIR)/ca.crt

verify-mbedtls:
	-mbedtls/programs/x509/cert_app mode=file filename=endpoint.crt ca_file=ca.crt

.PHONY: all error-code generate-cert verify-openssl verify-gnutls verify-botan verify-mbedtls

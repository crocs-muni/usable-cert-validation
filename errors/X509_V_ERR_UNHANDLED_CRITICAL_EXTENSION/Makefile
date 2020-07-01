# Environment varibales (may be overriden crom CLI)

# How to replicate this error:
# Various tools (golang's x509 module included) provide and option to include a user-defined extension with arbitrary data.
# Use such tool to generate a valid certificate chain with one root CA and an endpoint with some nonsense extention. 

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

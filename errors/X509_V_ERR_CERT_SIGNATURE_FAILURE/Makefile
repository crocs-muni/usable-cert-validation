# Environment varibales (may be overriden crom CLI)
BUILD_DIR=_certs
VERBOSITY=

# How to replicate this error:
# Create a simple chain consisting of a self-signed CA and non-ca endpoint.
# In some of the last bytes of the endpoint certificate, change a few characters manually
# The last part of the certificate is signature, this should invalidate it.

all: error-code generate-cert verify-openssl verify-gnutls verify-botan verify-mbedtls

error-code:
	@basename $$PWD

generate-cert: $(BUILD_DIR)/endpoint.crt

$(BUILD_DIR)/endpoint.crt:
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

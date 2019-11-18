# Environment varibales (may be overriden crom CLI)
BUILD_DIR=_certs
VERBOSITY=

all: error-code generate-cert verify-openssl verify-gnutls verify-botan

error-code:
	@basename $$PWD

generate-cert: $(BUILD_DIR)/endpoint.crt

CERT_CONFIGS=$(wildcard *.cfg)
$(BUILD_DIR)/endpoint.crt: $(CERT_CONFIGS)
	mkdir -p $(BUILD_DIR)
	certtool --generate-privkey --outfile $(BUILD_DIR)/ca.key $(VERBOSITY)
	certtool --generate-self-signed --load-privkey $(BUILD_DIR)/ca.key --outfile $(BUILD_DIR)/ca.crt --template ca.cfg $(VERBOSITY)
	certtool --generate-privkey --outfile $(BUILD_DIR)/endpoint.key $(VERBOSITY)
	certtool --generate-request --load-privkey $(BUILD_DIR)/endpoint.key --outfile $(BUILD_DIR)/endpoint.csr --template endpoint.cfg $(VERBOSITY)
	certtool --generate-certificate --load-request $(BUILD_DIR)/endpoint.csr --outfile $(BUILD_DIR)/endpoint.crt --load-ca-certificate $(BUILD_DIR)/ca.crt \
			 --load-ca-privkey $(BUILD_DIR)/ca.key --template endpoint.cfg $(VERBOSITY)
	# needs improvement
	sed -i 's/......=/QQQQQQ=/g' $(BUILD_DIR)/endpoint.crt

verify-openssl:
	-openssl verify -CAfile $(BUILD_DIR)/ca.crt $(BUILD_DIR)/endpoint.crt

verify-gnutls:
	-certtool --verify --load-ca-certificate $(BUILD_DIR)/ca.crt --infile $(BUILD_DIR)/endpoint.crt

verify-botan:
	-botan cert_verify $(BUILD_DIR)/endpoint.crt $(BUILD_DIR)/ca.crt

.PHONY: all error-code generate-cert verify-openssl verify-gnutls

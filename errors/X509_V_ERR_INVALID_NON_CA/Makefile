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
	certtool --generate-proxy --outfile $(BUILD_DIR)/endpoint.crt --load-certificate $(BUILD_DIR)/ca.crt --load-ca-privkey $(BUILD_DIR)/ca.key --load-privkey $(BUILD_DIR)/endpoint.key --template endpoint.cfg $(VERBOSITY)

verify-openssl:
	-openssl verify -allow_proxy_certs -CAfile $(BUILD_DIR)/ca.crt $(BUILD_DIR)/endpoint.crt

verify-gnutls:


verify-botan:

.PHONY: all error-code generate-cert verify-openssl verify-gnutls verify-botan

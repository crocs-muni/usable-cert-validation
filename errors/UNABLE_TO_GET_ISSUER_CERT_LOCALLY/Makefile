# Error code name
ERROR_CODE="CERT_HAS_EXPIRED"

# Environment varibales (may be overriden crom CLI)
BUILD_DIR=_certs
VERBOSITY=

all: error-code generate-cert verify-openssl verify-gnutls

error-code:
	@echo $(ERROR_CODE)

generate-cert: $(BUILD_DIR)/endpoint.crt

CERT_CONFIGS=$(wildcard *.cfg)
$(BUILD_DIR)/endpoint.crt: $(CERT_CONFIGS)
	mkdir -p $(BUILD_DIR)
	certtool --generate-privkey --outfile $(BUILD_DIR)/ca.key $(VERBOSITY)
	certtool --generate-self-signed --load-privkey $(BUILD_DIR)/ca.key --outfile $(BUILD_DIR)/ca.crt --template ca.cfg $(VERBOSITY)
	certtool --generate-privkey --outfile $(BUILD_DIR)/user.key $(VERBOSITY)
	certtool --generate-request --load-privkey $(BUILD_DIR)/user.key --outfile $(BUILD_DIR)/user.csr --template endpoint.cfg $(VERBOSITY)
	certtool --generate-certificate --load-request $(BUILD_DIR)/user.csr --outfile $(BUILD_DIR)/user.crt --load-ca-certificate $(BUILD_DIR)/ca.crt \
			 --load-ca-privkey $(BUILD_DIR)/ca.key --template endpoint.cfg $(VERBOSITY)

verify-openssl:
	-openssl verify $(BUILD_DIR)/user.crt

verify-gnutls:
	-certtool --verify --infile $(BUILD_DIR)/user.crt

.PHONY: all error-code generate-cert verify-openssl verify-gnutls

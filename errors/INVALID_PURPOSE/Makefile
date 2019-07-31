# Error code name
ERROR_CODE="INVALID_PURPOSE"

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
	certtool --generate-privkey --outfile $(BUILD_DIR)/endpoint.key $(VERBOSITY)
	certtool --generate-request --load-privkey $(BUILD_DIR)/endpoint.key --outfile $(BUILD_DIR)/endpoint.csr --template endpoint.cfg $(VERBOSITY)
	certtool --generate-certificate --load-request $(BUILD_DIR)/endpoint.csr --outfile $(BUILD_DIR)/endpoint.crt --load-ca-certificate $(BUILD_DIR)/ca.crt \
	         --load-ca-privkey $(BUILD_DIR)/ca.key --template endpoint.cfg $(VERBOSITY)

verify-openssl:
	@echo "### OpenSSL verify on "$(ERROR_CODE):
	-openssl verify -CAfile $(BUILD_DIR)/ca.crt -purpose sslserver $(BUILD_DIR)/endpoint.crt verify-purpose 1.3.6.1.5.5.7.3.4

verify-gnutls:
	@echo "### GnuTLS verify on "$(ERROR_CODE):
	certtool --verify --load-ca-certificate $(BUILD_DIR)/ca.crt --infile $(BUILD_DIR)/endpoint.crt --verify-purpose 1.3.6.1.5.5.7.3.1 

.PHONY: all error-code generate-cert verify-openssl verify-gnutls

# Environment varibales (may be overriden crom CLI)
BUILD_DIR=_certs
VERBOSITY=

all: generate-cert

generate-cert: $(BUILD_DIR)/endpoint.crt

CERT_CONFIGS=$(wildcard *.cfg)
$(BUILD_DIR)/endpoint.crt: $(CERT_CONFIGS)
	mkdir -p $(BUILD_DIR)

	certtool --generate-privkey --outfile $(BUILD_DIR)/ca.key $(VERBOSITY)
	certtool --generate-self-signed --load-privkey $(BUILD_DIR)/ca.key --outfile $(BUILD_DIR)/ca.crt --template ca.cfg $(VERBOSITY)

	certtool --generate-privkey --outfile $(BUILD_DIR)/subca.key $(VERBOSITY)
	certtool --generate-request --load-privkey $(BUILD_DIR)/subca.key --outfile $(BUILD_DIR)/subca.csr --template subca.cfg $(VERBOSITY)
	certtool --generate-certificate --load-request $(BUILD_DIR)/subca.csr --outfile $(BUILD_DIR)/subca.crt --load-ca-certificate $(BUILD_DIR)/ca.crt --load-ca-privkey  $(BUILD_DIR)/ca.key --template subca.cfg $(VERBOSITY)

	certtool --generate-privkey --outfile $(BUILD_DIR)/endpoint.key $(VERBOSITY)
	certtool --generate-request --load-privkey $(BUILD_DIR)/endpoint.key --outfile $(BUILD_DIR)/endpoint.csr --template endpoint.cfg $(VERBOSITY)
	certtool --generate-certificate --load-request $(BUILD_DIR)/endpoint.csr --outfile $(BUILD_DIR)/endpoint.crt --load-ca-certificate $(BUILD_DIR)/subca.crt --load-ca-privkey $(BUILD_DIR)/subca.key --template endpoint.cfg $(VERBOSITY)
	cat $(BUILD_DIR)/endpoint.crt $(BUILD_DIR)/subca.crt > $(BUILD_DIR)/chain.crt

.PHONY: all generate-cert


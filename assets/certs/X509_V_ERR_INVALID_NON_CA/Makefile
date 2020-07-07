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
	certtool --generate-privkey --outfile $(BUILD_DIR)/endpoint.key $(VERBOSITY)
	certtool --generate-proxy --outfile $(BUILD_DIR)/endpoint.crt --load-certificate $(BUILD_DIR)/ca.crt --load-ca-privkey $(BUILD_DIR)/ca.key --load-privkey $(BUILD_DIR)/endpoint.key --template endpoint.cfg $(VERBOSITY)

.PHONY: all generate-cert


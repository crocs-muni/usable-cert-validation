# Environment varibales (may be overriden crom CLI)
BUILD_DIR=_certs
VERBOSITY=

all: generate-cert

generate-cert: $(BUILD_DIR)/endpoint.crt

CERT_CONFIGS=$(wildcard *.cfg)
$(BUILD_DIR)/endpoint.crt: $(CERT_CONFIGS)
	mkdir -p $(BUILD_DIR)
	certtool --generate-privkey --outfile $(BUILD_DIR)/endpoint.key $(VERBOSITY)
	certtool --generate-self-signed --load-privkey $(BUILD_DIR)/endpoint.key --outfile $(BUILD_DIR)/endpoint.crt --template endpoint.cfg $(VERBOSITY)

.PHONY: all generate-cert


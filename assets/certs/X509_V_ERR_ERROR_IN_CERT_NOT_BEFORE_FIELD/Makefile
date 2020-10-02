# Environment varibales (may be overriden crom CLI)
BUILD_DIR=_certs
VERBOSITY=
CERT_GENERATOR=../../../utils/cert_generator/generate

all: generate-cert

generate-cert: $(BUILD_DIR)/endpoint.crt

CERT_CONFIGS=$(wildcard *.cfg)
$(BUILD_DIR)/endpoint.crt: $(CERT_CONFIGS)
	mkdir -p $(BUILD_DIR)
	certtool --generate-privkey --outfile $(BUILD_DIR)/ca.key $(VERBOSITY)
	certtool --generate-self-signed --load-privkey $(BUILD_DIR)/ca.key --outfile $(BUILD_DIR)/ca.crt --template ca.cfg $(VERBOSITY)
	certtool --generate-privkey --outfile $(BUILD_DIR)/endpoint.key $(VERBOSITY)
	./$(CERT_GENERATOR) -signingKey $(BUILD_DIR)/ca.key -outFile $(BUILD_DIR)/endpoint.crt -templateFile endpoint.yml -issuerFile $(BUILD_DIR)/ca.crt -privateKey $(BUILD_DIR)/endpoint.key

.PHONY: all generate-cert


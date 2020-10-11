# Environment varibales (may be overriden crom CLI)
BUILD_DIR=_certs
VERBOSITY=
YML2CERT=../../../utils/yml2cert/yml2cert

all: generate-cert

generate-cert: $(BUILD_DIR)/endpoint.crt

CERT_CONFIGS=$(wildcard *.cfg)
$(BUILD_DIR)/endpoint.crt: $(CERT_CONFIGS)
	mkdir -p $(BUILD_DIR)
	certtool --generate-privkey --outfile $(BUILD_DIR)/ca.key $(VERBOSITY)
	$(YML2CERT) -signingKey $(BUILD_DIR)/ca.key -outFile $(BUILD_DIR)/ca.crt -templateFile ca.yml -privateKey $(BUILD_DIR)/ca.key
	certtool --generate-privkey --outfile $(BUILD_DIR)/endpoint.key $(VERBOSITY)
	$(YML2CERT) -signingKey $(BUILD_DIR)/ca.key -outFile $(BUILD_DIR)/endpoint.crt -templateFile endpoint.yml -issuerFile $(BUILD_DIR)/ca.crt -privateKey $(BUILD_DIR)/endpoint.key

.PHONY: all generate-cert


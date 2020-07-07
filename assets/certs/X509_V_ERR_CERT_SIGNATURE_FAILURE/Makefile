# Environment varibales (may be overriden crom CLI)

BUILD_DIR=_certs
VERBOSITY=

# How to replicate this error:
# Create a simple chain consisting of a self-signed CA and non-ca endpoint.
# In some of the last bytes of the endpoint certificate, change a few characters manually
# The last part of the certificate is signature, this should invalidate it.

all: generate-cert

generate-cert: $(BUILD_DIR)/endpoint.crt

STATIC_CERTS=$(wildcard *.crt)
$(BUILD_DIR)/endpoint.crt: $(STATIC_CERTS)
	cp *.crt $(BUILD_DIR)

.PHONY: all generate-cert


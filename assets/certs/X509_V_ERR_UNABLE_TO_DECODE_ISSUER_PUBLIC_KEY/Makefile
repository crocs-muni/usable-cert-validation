# Environment varibales (may be overriden crom CLI)

# How to replicate this error:
# Create a simple chain consisting of a self-signed CA and non-ca endpoint
# Convert the CA from the DER form into ASN.1 structure using a suitable tool (e.g `unber`)
# Manually change the OID of the public key signature algorithm to some nonsense value
# Convert the altered CA back to DER and PEM

BUILD_DIR=_certs
VERBOSITY=

all: generate-cert

generate-cert: $(BUILD_DIR)/endpoint.crt

STATIC_CERTS=$(wildcard *.crt)
$(BUILD_DIR)/endpoint.crt: $(STATIC_CERTS)
	cp *.crt $(BUILD_DIR)

.PHONY: all generate-cert


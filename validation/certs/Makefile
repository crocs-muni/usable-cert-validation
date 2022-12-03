# Directory with clients
CLIENTS_DIR=../clients
# Directory with servers
SERVERS_DIR=../servers

# Directory with all generating scripts
SCRIPTS_DIR=scripts
# Directory to build chains into
BUILD_DIR=build
# Directory with all asn1 specifications
ASN_DIR=asn
# Python utils directory
UTILS_DIR=utils
# Directory with all things needed for validation
VDIR=results
# Zip archive directory
ARCHIVE_DIR=../../assets/archives
# Intended chain name for each cert chain
CHAIN_FILENAME=chain.pem
# Intended root name
ROOT=root
# chains filename
CHAINS=chains
# Filename of all generating scripts
GENERATE=generate
# Variable to specify wheter to print debug info
DEBUG=""

# Directory with scripts for all chains
CHAINS_DIR=$(SCRIPTS_DIR)/$(CHAINS)
# Directory to build the root into
ROOT_BUILD_DIR=$(BUILD_DIR)/$(ROOT)
# Intended root private key filepath
ROOT_KEY_FILE=$(ROOT_BUILD_DIR)/$(ROOT)_key.pem
# Intended root certificate filepath
ROOT_CERT_FILE=$(ROOT_BUILD_DIR)/$(ROOT).pem

# Validation script
VSCRIPT=$(VDIR)/validate.sh
# result dir
VRESULTS_DIR=$(VDIR)/vresults
# file to cat all results into
VRESULTS_FILE=$(VDIR)/vresults.yml
# port counter
PORT_CTR_FILE=$(VDIR)/.port
# Python TLS server
PYTHON_SERVER=$(SERVERS_DIR)/server.py

# All individual chain script directories
CHAINS_ALL=$(notdir $(wildcard $(CHAINS_DIR)/*))
# All individual chain build folders
CHAINS_BUILD_ALL=$(addsuffix /$(CHAIN_FILENAME), $(addprefix $(BUILD_DIR)/,$(CHAINS_ALL)))
# All individual validation result files
VRESULTS_FILES_ALL=$(addprefix $(VRESULTS_DIR)/, $(addsuffix .yml, $(CHAINS_ALL)))
# All zip archives
ARCHIVES_ALL=$(addprefix $(ARCHIVE_DIR)/, $(addsuffix .zip, $(CHAINS_ALL)))


# Build everyhing, validate and concat all results into a single YAML file
all: $(ROOT_KEY_FILE) $(CHAINS_BUILD_ALL) $(VRESULTS_FILES_ALL) $(ARCHIVES_ALL)
	@cat $(VRESULTS_DIR)/*.yml > $(VRESULTS_FILE)

# First we build the root key target, this creates the root cert as well
$(ROOT_KEY_FILE): $(SCRIPTS_DIR)/$(ROOT).py $(wildcard $(ASN_DIR)/*.asn) $(wildcard $(UTILS_DIR)/*.py)
	@printf "Generating certificate: %-44s" $(ROOT)
	@python3 -m $(SCRIPTS_DIR).$(ROOT) \
	            --root_cert_file=$(CURDIR)/$(ROOT_CERT_FILE) \
	            --root_key_file=$(CURDIR)/$(ROOT_KEY_FILE) \
	            --asn_dir=$(CURDIR)/$(ASN_DIR)/
	@printf "[ OK ]\n"

# Then we build all the individual certificate chains
$(BUILD_DIR)/%/$(CHAIN_FILENAME): $(ROOT_KEY_FILE) $(CHAINS_DIR)/%/$(GENERATE).py
	@printf "Generating chain: %-50s" $(notdir $(@D))
	@python3 -m $(SCRIPTS_DIR).$(CHAINS).$(notdir $(@D)).$(GENERATE) \
	            --build_dir=$(CURDIR)/$(@D)/ \
	            --asn_dir=$(CURDIR)/$(ASN_DIR)/ \
	            --root_key_file=$(CURDIR)/$(ROOT_KEY_FILE)
	@printf "[ OK ]\n"

# After building the chain, we run the validation script on it
$(VRESULTS_DIR)/%.yml: $(BUILD_DIR)/%/$(CHAIN_FILENAME) $(PYTHON_SERVER)
	@mkdir -p $(VRESULTS_DIR)
	@printf "Validating chain: %-50s" $(basename $(@F))
	@$(VSCRIPT) --certs_dir $(CURDIR) \
				--clients_dir $(CURDIR)/$(CLIENTS_DIR) \
				--servers_dir $(CURDIR)/$(SERVERS_DIR) \
				--chain_name $(basename $(@F)) \
				--out_dir $(CURDIR)/$(VRESULTS_DIR) \
				--port_ctr_file $(CURDIR)/$(PORT_CTR_FILE) $(DEBUG)
	@printf "[ OK ]\n"

# Build also the certificate zip archives
$(ARCHIVE_DIR)/%.zip: $(BUILD_DIR)/%/$(CHAIN_FILENAME)
	@mkdir -p $(ARCHIVE_DIR)
	@printf "Creating a zip archive: %-50s" $(basename $(@F))
	@cd $(BUILD_DIR) && zip --filesync --quiet ../$@ $(*F)/*.{der,pem} $(ROOT)/$(ROOT).pem
	@printf "[ OK ]\n"

clean:
	rm -rf $(BUILD_DIR)
	rm -rf $(VRESULTS_DIR)
	rm -rf $(ARCHIVE_DIR)

.PHONY: all clean

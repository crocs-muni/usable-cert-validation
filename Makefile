# Environment settiongs
CERTS_FOLDER=assets/certs
CERTS_BUILD_FOLDER=assets/certs-build
CERTS_BUILD_DEBUG_FOLDER=assets/certs-build/_debug
CERTS_ARCHIVES_FOLDER=assets/certs-archives
VERBOSITY=">/dev/null 2>&1"
ERRORS_FOLDER=_data

# Computed variables
CERTS_IDS_ALL=$(notdir $(wildcard $(CERTS_FOLDER)/*))
CERTS_BUILD_ALL=$(addprefix $(CERTS_BUILD_FOLDER)/,$(CERTS_IDS_ALL))
CERTS_ARCHIVES_ALL=$(addsuffix .zip, $(addprefix $(CERTS_ARCHIVES_FOLDER)/, $(CERTS_IDS_ALL)) )
ERRORS_ALL=$(wildcard $(ERRORS_FOLDER)/*/*.yml)

all: $(CERTS_BUILD_ALL) $(CERTS_ARCHIVES_ALL)

# Generate certificates
$(CERTS_BUILD_FOLDER)/%: $(CERTS_FOLDER)/%/Makefile $(wildcard ($(CERTS_FOLDER)/%/*.cfg))
	@printf "Generating certs for %-60s" $(*F)
	@mkdir -p $@
	@$(MAKE) --silent --directory=$(CERTS_FOLDER)/$(@F) BUILD_DIR=$(CURDIR)/$@ VERBOSITY=$(VERBOSITY) generate-cert
	@printf "[ OK ]\n"
#	@printf "Testing OpenSSL validation for %-50s" $(*F)
#	@utils/test-cert-validation.sh $(CERTS_FOLDER)/$(@F) $(CURDIR)/$@ && [ $$? -eq 0 ] || \
	( rm -rf $(CERTS_BUILD_DEBUG_FOLDER) && mv $@ $(CERTS_BUILD_DEBUG_FOLDER)/ && printf "## See the failing certificate chain in $(CERTS_BUILD_DEBUG_FOLDER).\n" && exit 1 )
#	@printf "[ OK ]\n"

# Generate certificate archives
.SECONDEXPANSION:
$(CERTS_ARCHIVES_FOLDER)/%.zip: $(CERTS_BUILD_FOLDER)/% $$(wildcard $(CERTS_BUILD_FOLDER)/%/*)
	@printf "Generating zip for %-62s" $(*F)
	@mkdir -p $(CERTS_ARCHIVES_FOLDER)
	@cd $(CERTS_BUILD_FOLDER) && zip --filesync --quiet ../../$@ $(*F)/*.crt $(*F)/*.crl
	@printf "[ OK ]\n"
	
# Test web consistency
test: all $(ERRORS_ALL)
	@echo "Building the website using Jekyll ..."
	@bundle exec jekyll build
	@echo "Running tests on the generated sites using html-proofer ..."
	-@bundle exec ruby utils/web-test.rb

# Test generated certificates for assigned errors
$(ERRORS_FOLDER)/*/*.yml:
	@printf "Testing certificates for %-70s" $(@D)/$(@F)
	@if RES=`grep verify-cert $@ | wc -l` && [ $$RES -eq 0 ]; then printf "[ -- ]\n"; \
		else utils/test-cert-validation.sh $(CERTS_BUILD_FOLDER) $@ && printf "[ OK ]\n"; fi

# Web targets
local: all
	bundle exec jekyll serve

# Utility targets
clean:
	rm -rf $(CERTS_FOLDER)/*/_certs
	rm -rf $(CERTS_BUILD_FOLDER)
	rm -rf $(CERTS_BUILD_DEBUG_FOLDER)
	rm -rf $(CERTS_ARCHIVES_FOLDER)
	rm -rf _site

.PHONY: all clean test local $(ERRORS_ALL)

# Environment settiongs
CERTS_FOLDER=assets/certs
CERTS_BUILD_FOLDER=assets/certs-build
CERTS_BUILD_DEBUG_FOLDER=assets/certs-build/_debug
CERTS_ARCHIVES_FOLDER=assets/certs-archives
VERBOSITY=">/dev/null 2>&1"
ERROR_CODES_ALL=$(notdir $(wildcard $(CERTS_FOLDER)/*) )
ERROR_CODES_DATA=$(notdir $(subst /data.yml,,$(wildcard $(CERTS_FOLDER)/*/data.yml)) )
ERROR_CODES_SCRIPTS=$(notdir $(subst /Makefile,,$(wildcard $(CERTS_FOLDER)/*/Makefile)) )

all: certs web

# Generating certificates

certs: $(addprefix $(CERTS_BUILD_FOLDER)/,$(ERROR_CODES_SCRIPTS))

$(CERTS_BUILD_FOLDER)/%: $(CERTS_FOLDER)/%/Makefile $(wildcard ($(CERTS_FOLDER)/%/*.cfg))
	@printf "Generating certs for %-60s" $(*F)
	@mkdir -p $@
	@$(MAKE) --silent --directory=$(CERTS_FOLDER)/$(@F) BUILD_DIR=$(CURDIR)/$@ VERBOSITY=$(VERBOSITY) generate-cert
	@printf "[ OK ]\n"
#	@printf "Testing OpenSSL validation for %-50s" $(*F)
#	@utils/test-cert-validation.sh $(CERTS_FOLDER)/$(@F) $(CURDIR)/$@ && [ $$? -eq 0 ] || \
	( rm -rf $(CERTS_BUILD_DEBUG_FOLDER) && mv $@ $(CERTS_BUILD_DEBUG_FOLDER)/ && printf "## See the failing certificate chain in $(CERTS_BUILD_DEBUG_FOLDER).\n" && exit 1 )
#	@printf "[ OK ]\n"
	
# Web building targets

WEB_CERTS=$(addsuffix .zip, $(addprefix $(CERTS_ARCHIVES_FOLDER)/, $(ERROR_CODES_SCRIPTS)) )

web: $(WEB_CERTS)

.SECONDEXPANSION:
$(CERTS_ARCHIVES_FOLDER)/%.zip: $(CERTS_BUILD_FOLDER)/% $$(wildcard $(CERTS_BUILD_FOLDER)/%/*)
	@printf "Generating zip for %-62s" $(*F)
	@mkdir -p $(CERTS_ARCHIVES_FOLDER)
	@cd $(CERTS_BUILD_FOLDER) && zip --filesync --quiet ../../$@ $(*F)/*.crt $(*F)/*.crl
	@printf "[ OK ]\n"

local: web
	bundle exec jekyll serve

test: web
	@echo "Building the website using Jekyll ..."
	@bundle exec jekyll build
	@echo "Running tests on the generated sites using html-proofer ..."
	-@bundle exec ruby utils/web-test.rb

clean:
	rm -rf $(CERTS_FOLDER)/*/_certs
	rm -rf $(CERTS_BUILD_FOLDER)
	rm -rf $(CERTS_BUILD_DEBUG_FOLDER)
	rm -rf $(CERTS_ARCHIVES_FOLDER)
	rm -rf _site

.PHONY: all clean test web local certs

# Environment settiongs
ERRORS_PREFIX=errors
BUILD_CERTS_PREFIX=_certs
BUILD_ERRORINFO_PREFIX=web/_errors
BUILD_CERTZIP_PREFIX=web/assets/certs
VERBOSITY=">/dev/null 2>&1"
ERROR_CODES_ALL=$(notdir $(wildcard $(ERRORS_PREFIX)/*) )
ERROR_CODES_DATA=$(notdir $(subst /data.yml,,$(wildcard $(ERRORS_PREFIX)/*/data.yml)) )
ERROR_CODES_SCRIPTS=$(notdir $(subst /Makefile,,$(wildcard $(ERRORS_PREFIX)/*/Makefile)) )

all: certs web

clean: certs-clean web-clean

# Generating certificates

certs: $(addprefix $(BUILD_CERTS_PREFIX)/,$(ERROR_CODES_SCRIPTS))

$(BUILD_CERTS_PREFIX)/%: $(ERRORS_PREFIX)/%/Makefile $(ERRORS_PREFIX)/%/*.cfg
	@printf "Generating certs for %-60s" $(*F)
	@mkdir -p $@
	@$(MAKE) --silent --directory=$(ERRORS_PREFIX)/$(@F) BUILD_DIR=$(CURDIR)/$@ VERBOSITY=$(VERBOSITY) generate-cert
	@printf "[ OK ]\n"
	@printf "Testing OpenSSL validation for %-50s" $(*F)
	@utils/test-cert-validation.sh $(ERRORS_PREFIX)/$(@F) $(CURDIR)/$@
	@printf "[ OK ]\n"

certs-clean:
	rm -rf errors/*/_certs
	rm -rf $(BUILD_CERTS_PREFIX)

# Web building targets

WEB_ERRORINFO=$(addsuffix .md, $(addprefix $(BUILD_ERRORINFO_PREFIX)/,$(ERROR_CODES_DATA)) )
WEB_CERTS=$(addsuffix .zip, $(addprefix $(BUILD_CERTZIP_PREFIX)/, $(ERROR_CODES_SCRIPTS)) )

web: $(WEB_ERRORINFO) $(WEB_CERTS)

.SECONDEXPANSION:
$(BUILD_ERRORINFO_PREFIX)/%.md: utils/web-cert-data.sh $$(wildcard $(ERRORS_PREFIX)/%/data.yml)
	@printf "Generating info for %-51s" $(*F)
	@mkdir -p $(BUILD_ERRORINFO_PREFIX)
	@utils/web-cert-data.sh $(ERRORS_PREFIX)/$(*F) >$@
	@printf "[ OK ]\n"

$(BUILD_CERTZIP_PREFIX)/%.zip: $(BUILD_CERTS_PREFIX)/% $$(wildcard $(BUILD_CERTS_PREFIX)/%/*)
	@printf "Generating zip for %-62s" $(*F)
	@mkdir -p $(BUILD_CERTZIP_PREFIX)
	@zip --quiet $@ $(BUILD_CERTS_PREFIX)/$(*F)/*
	@printf "[ OK ]\n"

web-local: web
	cd web && bundle exec jekyll serve

web-clean:
	rm -rf $(BUILD_ERRORINFO_PREFIX)
	rm -rf $(BUILD_CERTZIP_PREFIX)
	rm -rf web/_site

check: web
	@echo "Building the website using Jekyll ..."
	@cd web && bundle exec jekyll build
	@echo "Running tests on the generated sites using html-proofer ..."
	@cd web && bundle exec ruby ../utils/web-test.rb

.PHONY: all clean check web web-clean web-local certs certs-clean

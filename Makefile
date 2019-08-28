# Environment settiongs
REPO_URL=https://github.com/crocs-muni/usable-cert-validation
WEB_VERSION_FILE=web/_includes/version.html
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
	@printf "Generating certs for %-50s" $(*F)
	@mkdir -p $@
	@$(MAKE) --silent --directory=$(ERRORS_PREFIX)/$(@F) BUILD_DIR=$(CURDIR)/$@ VERBOSITY=$(VERBOSITY) generate-cert
	@printf "[ OK ]\n"

certs-clean:
	rm -rf errors/*/_certs
	rm -rf $(BUILD_CERTS_PREFIX)

# Web building targets

WEB_ERRORINFO=$(addsuffix .md, $(addprefix $(BUILD_ERRORINFO_PREFIX)/,$(ERROR_CODES_DATA)) )
WEB_CERTS=$(addsuffix .zip, $(addprefix $(BUILD_CERTZIP_PREFIX)/, $(ERROR_CODES_SCRIPTS)) )

web: $(WEB_ERRORINFO) $(WEB_CERTS) web-version

.SECONDEXPANSION:
$(BUILD_ERRORINFO_PREFIX)/%.md: utils/web-cert-data.sh $$(wildcard $(ERRORS_PREFIX)/%/data.yml)
	@printf "Generating info for %-51s" $(*F)
	@mkdir -p $(BUILD_ERRORINFO_PREFIX)
	@utils/web-cert-data.sh $(ERRORS_PREFIX)/$(*F) >$@
	@printf "[ OK ]\n"

$(BUILD_CERTZIP_PREFIX)/%.zip: $(BUILD_CERTS_PREFIX)/% $$(wildcard $(BUILD_CERTS_PREFIX)/%/*)
	@printf "Generating zip for %-52s" $(*F)
	@mkdir -p $(BUILD_CERTZIP_PREFIX)
	@zip --quiet $@ $(BUILD_CERTS_PREFIX)/$(*F)/*
	@printf "[ OK ]\n"

web-version:
	utils/web-version.sh $(REPO_URL) >$(WEB_VERSION_FILE)

web-local: web
	cd web && bundle exec jekyll serve

web-clean:
	rm -rf $(BUILD_ERRORINFO_PREFIX)
	rm -rf $(BUILD_CERTZIP_PREFIX)
	rm -rf web/_site

check: web
	cd web && bundle exec jekyll build
	cd web && bundle exec htmlproofer --assume-extension --check_favicon --check_html --check_img_http --url_ignore "/$(REPO_URL)/" ./_site

.PHONY: all clean web web-clean web-local web-version certs certs-clean

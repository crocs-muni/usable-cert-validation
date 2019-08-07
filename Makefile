# Environment settiongs
REPO_URL=https://github.com/crocs-muni/usable-cert-validation
WEB_VERSION_FILE=web/_includes/version.html
ERROR_LIST_FILE=error-list.txt
CERTS_SCRIPTS_PREFIX=errors
CERTS_DOCS_PREFIX=docs
CERTS_BUILD_PREFIX=_certs
WEB_ERRORINFO_PREFIX=web/_errors
WEB_CERTS_PREFIX=web/assets/certs
VERBOSITY=">/dev/null 2>&1"
ERROR_CODES=$(shell cat $(ERROR_LIST_FILE) | grep --invert-match // )
ERROR_CODES_SCRIPTS=$(notdir $(wildcard $(CERTS_SCRIPTS_PREFIX)/*) )

all: certs web

clean: certs-clean certs-new-clean web-clean

# Generating certificates

certs: $(addprefix $(CERTS_BUILD_PREFIX)/,$(ERROR_CODES_SCRIPTS))

$(CERTS_BUILD_PREFIX)/%: $(CERTS_SCRIPTS_PREFIX)/%/*
	@echo -n "Generating certs for "$(*F)" ..."
	@mkdir -p $@
	@$(MAKE) --silent --directory=$(CERTS_SCRIPTS_PREFIX)/$(@F) BUILD_DIR=$(CURDIR)/$@ VERBOSITY=$(VERBOSITY) generate-cert
	@echo -e "\t\t[ OK ]"

certs-new-clean:
	rm -rf errors/*/_certs
	rm -rf $(CERTS_BUILD_PREFIX)

# Web building targets

WEB_ERRORINFO=$(addsuffix .md, $(addprefix $(WEB_ERRORINFO_PREFIX)/,$(ERROR_CODES)) )
WEB_CERTS=$(addsuffix .zip, $(addprefix $(WEB_CERTS_PREFIX)/, $(ERROR_CODES_SCRIPTS)) )

web: $(WEB_ERRORINFO) $(WEB_CERTS) web-version

.SECONDEXPANSION:
$(WEB_ERRORINFO_PREFIX)/%.md: utils/web-cert-data.sh $$(wildcard $(CERTS_DOCS_PREFIX)/%.yml*) # wildcard handles non-existent cases
	@echo -n "Generating error info for "$(*F)" ..."
	@mkdir -p $(WEB_ERRORINFO_PREFIX)
	@utils/web-cert-data.sh $(CERTS_SCRIPTS_PREFIX)/$(*F) \
	                        $(CERTS_DOCS_PREFIX)/$(*F).yml \
							`cat $(ERROR_LIST_FILE) | grep -n ^$(*F)$$ | cut --delimiter=: --fields=1` \
							>$@
	@echo -e "\t\t[ OK ]"

$(WEB_CERTS_PREFIX)/%.zip: $(CERTS_BUILD_PREFIX)/% $$(wildcard $(CERTS_BUILD_PREFIX)/%/*)
	@echo -n "Generating certs zip for "$(*F)" ..."
	@mkdir -p $(WEB_CERTS_PREFIX)
	@zip --quiet $@ $(CERTS_BUILD_PREFIX)/$(*F)/*
	@echo -e "\t\t[ OK ]"

web-version:
	utils/web-version.sh $(REPO_URL) >$(WEB_VERSION_FILE)

web-local: web
	cd web && bundle exec jekyll serve

web-clean:
	rm -rf $(WEB_ERRORINFO_PREFIX)
	rm -rf $(WEB_CERTS_PREFIX)
	rm -rf web/_site

.PHONY: all clean web web-clean web-local web-version certs certs-clean certs-new-clean

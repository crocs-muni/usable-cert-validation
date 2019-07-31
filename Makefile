# Environment settiongs
CERTS_SCRIPTS_PREFIX=errors
CERTS_BUILD_PREFIX=_certs
WEB_ERRORINFO_PREFIX=web/_errors
WEB_CERTS_PREFIX=web/assets/certs
VERBOSITY=">/dev/null 2>&1"
ERROR_CODES=$(notdir $(wildcard $(CERTS_SCRIPTS_PREFIX)/*) )

CERTS=$(addprefix $(CERTS_BUILD_PREFIX)/,$(ERROR_CODES))
all: certs $(CERTS) web

clean: certs-clean certs-new-clean web-clean

$(CERTS_BUILD_PREFIX)/%: $(CERTS_SCRIPTS_PREFIX)/%/*
	@echo -n "Geceerating certs for "$(*F)" ..."
	@mkdir -p $@
	@$(MAKE) --silent --directory=$(CERTS_SCRIPTS_PREFIX)/$(@F) BUILD_DIR=$(CURDIR)/$@ VERBOSITY=$(VERBOSITY) generate-cert
	@echo -e "\t\t[ OK ]"

certs-new-clean:
	rm -rf errors/*/_certs
	rm -rf $(CERTS_BUILD_PREFIX)

# Old certificates structure

SCRIPTS=$(notdir $(wildcard scripts/[0-9][0-9]_*) )

certs:
	for FOLDER in $(SCRIPTS); do cd $(CURDIR)/scripts/$$FOLDER && ./create.sh; done

certs-clean:
	rm -rf scripts/*/files

# Web building targets

test:
	@echo CERTS: $(CERTS)
	@echo WEB_ERRORINFO: $(WEB_ERRORINFO)
	@echo WEB_CERTS: $(WEB_CERTS)

WEB_ERRORINFO=$(addsuffix .md, $(addprefix $(WEB_ERRORINFO_PREFIX)/,$(ERROR_CODES)) )
WEB_CERTS=$(addsuffix .zip, $(addprefix $(WEB_CERTS_PREFIX)/,$(ERROR_CODES)) )

web: $(WEB_ERRORINFO) $(WEB_CERTS) web-version

$(WEB_ERRORINFO_PREFIX)/%.md: $(CERTS_SCRIPTS_PREFIX)/%/Makefile
	@echo -n "Geceerating error info for "$(*F)" ..."
	@mkdir -p $(WEB_ERRORINFO_PREFIX)
	@utils/web-cert-data.sh $(CERTS_SCRIPTS_PREFIX)/$(*F) >$@
	@echo -e "\t\t[ OK ]"

$(WEB_CERTS_PREFIX)/%.zip: $(CERTS_BUILD_PREFIX)/%
	@echo -n "Geceerating certs zip for "$(*F)" ..."
	@mkdir -p $(WEB_CERTS_PREFIX)
	@zip --quiet $@ $(CERTS_BUILD_PREFIX)/$(*F)/*
	@echo -e "\t\t[ OK ]"

REPO_URL=https://github.com/crocs-muni/usable-cert-validation
WEB_VERSION_FILE=web/_includes/version.html
web-version:
	echo -n 'Poslední změna: <a target="_blank" ' >$(WEB_VERSION_FILE)
	echo -n 'href="$(REPO_URL)/commit/'`git rev-parse HEAD`'" ' >>$(WEB_VERSION_FILE)
	echo -n 'title="commit '`git rev-parse --short HEAD`'">' >>$(WEB_VERSION_FILE)
	echo -n `git log -1 --date=short --format=%cd` >>$(WEB_VERSION_FILE)
	echo '</a>' >>$(WEB_VERSION_FILE)

web-local: web
	cd web && jekyll serve

web-clean:
	rm -rf $(WEB_ERRORINFO_PREFIX)
	rm -rf $(WEB_CERTS_PREFIX)
	rm -rf web/_site

.PHONY: all clean web web-clean web-local web-version certs certs-clean certs-new-clean

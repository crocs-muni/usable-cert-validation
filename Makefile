ERRORS=$(notdir $(wildcard scripts/[0-9][0-9]_*) )

all: certs web

certs:
	for ERROR in $(ERRORS); do cd scripts/$$ERROR && ./create.sh; cd ../..; done

certs-clean:
	rm -rf scripts/*/files

web: web-version

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
	rm -rf web/_site

.PHONY: all web web-clean web-local web-version certs certs-clean

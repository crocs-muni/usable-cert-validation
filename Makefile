all: web

web:
	mkdir -p web-build
	cp -rv web/* web-build/

.PHONY: all web

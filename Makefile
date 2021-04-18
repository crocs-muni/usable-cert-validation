# Environment settings
MAPPING_FOLDER=_data/mapping
ERRORS_FOLDER=_data/errors
VALIDATION_FOLDER=validation

VERBOSITY=">/dev/null 2>&1"

all: validation

# Generate all certs and do the mapping
validation:
	@make --directory=$(VALIDATION_FOLDER) \
		  MAPPING_DIR=$(CURDIR)/$(MAPPING_FOLDER) \
		  ERRORS_DIR=$(CURDIR)/$(ERRORS_FOLDER)

# Test web consistency
test: all
	@echo "Building the website using Jekyll ..."
	@bundle exec jekyll build
	@echo "Running tests on the generated sites using html-proofer ..."
	-@bundle exec ruby utils/web-test.rb

# Test generated certificates for assigned errors
#$(ERRORS_FOLDER)/*/*.yml:
#	@printf "Testing certificates for %-70s" $(@D)/$(@F)
#	@if RES=`grep verify-expected $@ | wc -l` && [ $$RES -eq 0 ]; then printf "[ -- ]\n"; \
#		else utils/test-cert-validation.sh $(CERTS_BUILD_FOLDER) $@ && printf "[ OK ]\n"; fi

# Web targets
local: all
	bundle exec jekyll serve

# Utility targets
clean:
	rm -rf _site
	rm -rf $(MAPPING_FOLDER)
	make --directory=$(VALIDATION_FOLDER) clean

.PHONY: all clean test local validation

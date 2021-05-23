# Environment settings
MAPPING_FOLDER=_data/mapping
ERRORS_FOLDER=_data/errors
VALIDATION_FOLDER=validation

VERBOSITY=">/dev/null 2>&1"

all: validation

install:
	pip3 install --user -r requirements.txt
	bundle install

# Generate all certs and do the mapping
validation:
	@make --directory=$(VALIDATION_FOLDER) \
		  MAPPING_DIR=$(CURDIR)/$(MAPPING_FOLDER) \
		  ERRORS_DIR=$(CURDIR)/$(ERRORS_FOLDER)

# Run the validation with debug on
debug:
	@make --directory=$(VALIDATION_FOLDER) \
		  MAPPING_DIR=$(CURDIR)/$(MAPPING_FOLDER) \
		  ERRORS_DIR=$(CURDIR)/$(ERRORS_FOLDER) \
		  DEBUG="--debug"

# Test web consistency
test: all
	@echo "Building the website using Jekyll ..."
	@bundle exec jekyll build
	@echo "Running tests on the generated sites using html-proofer ..."
	-@bundle exec ruby utils/web-test.rb

# Web targets
local: all
	bundle exec jekyll serve

# Utility targets
clean:
	rm -rf _site
	rm -rf $(MAPPING_FOLDER)
	make --directory=$(VALIDATION_FOLDER) clean

.PHONY: all install clean test local validation

# Environment settings
MAPPING_FOLDER=_data/mapping
ERRORS_FOLDER=_data/errors
VALIDATION_FOLDER=validation

VERBOSITY=">/dev/null 2>&1"

# Set branch name (from Travis or locally)
BRANCH:=$(or $(TRAVIS_BRANCH),`git branch --show-current`)

all: build

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

# Test generated certificates for assigned errors
#$(ERRORS_FOLDER)/*/*.yml:
#	@printf "Testing certificates for %-70s" $(@D)/$(@F)
#	@if RES=`grep verify-expected $@ | wc -l` && [ $$RES -eq 0 ]; then printf "[ -- ]\n"; \
#		else utils/test-cert-validation.sh $(CERTS_BUILD_FOLDER) $@ && printf "[ OK ]\n"; fi

# === Targets for generating files  ===

generated-files: humans.txt

humans.txt: CONTRIBUTORS.md
	@echo "Creating humans.txt file ..."
	cp CONTRIBUTORS.md humans.txt

# === Web build, test and deploy targets  ===

build: validation generated-files
	@echo "Building the website using Jekyll ..."
	@if [ "$(BRANCH)" = "master" ]; then echo "=== Production build ($(BRANCH)) ==="; else echo "=== Development build ($(BRANCH)) ==="; fi
	@if [ "$(BRANCH)" = "master" ]; then JEKYLL_ENV=production bundle exec jekyll build; else bundle exec jekyll build; fi

local: validation generated-files
	bundle exec jekyll serve

test: build
	@echo "Running internal tests on the generated site using html-proofer ..."
	bundle exec ruby utils/web-test.rb
	@echo "Running tests on the external content using html-proofer ..."
	-bundle exec ruby utils/web-test.rb external

deploy-preview: build
	./firebase hosting:channel:deploy $(BRANCH) --only preview

deploy-production: build
	./firebase deploy --only hosting:production

# === Cleaning targets  ===

clean:
	rm -rf _site
	mr -rf humans.txt
	rm -rf $(MAPPING_FOLDER)
	make --directory=$(VALIDATION_FOLDER) clean

# === Target flags  ===

.PHONY: all install validation debug generated-files build local test deploy-preview deploy-production clean

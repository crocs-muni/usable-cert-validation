# Zip archive directory
ARCHIVE_DIR=../assets/clients
# Licence file
LICENSE_FILE=../LICENSE.md

# All individual client directories
CLIENTS_ALL=$(notdir $(wildcard $(CURDIR)/*-client))
ARCHIVES_ALL=$(addprefix $(ARCHIVE_DIR)/, $(addsuffix .zip, $(CLIENTS_ALL)))

# Generate revocation client archives
all: $(ARCHIVES_ALL)

# Create zip archive of a revocation client
$(ARCHIVE_DIR)/%.zip: %/* $(LICENSE_FILE)
	@mkdir -p $(ARCHIVE_DIR)
	@printf "Creating a client zip archive: %-50s" $(basename $(@F))
	@cp $(LICENSE_FILE) $(<D)
	@cd $(<D) && zip --filesync --quiet ../$@ *
	@printf "[ OK ]\n"

# === Cleaning targets  ===

clean:
	rm -rf */$(notdir $(LICENSE_FILE))
	rm -rf */*.der
	rm -rf openssl-client/openssl-client
	rm -rf gnutls-client/gnutls-client
	rm -rf $(ARCHIVE_DIR)

# === Target flags  ===

.PHONY: all clean
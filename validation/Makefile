CERTS_DIR=certs
CLIENTS_DIR=clients
SERVERS_DIR=servers
MAPPING_DIR=../_data/mapping
ERRORS_DIR=../_data/errors
VRESULTS_FILE=$(CERTS_DIR)/results/vresults.yml
MAPPING_SCRIPT=mapper.py

all: $(CLIENTS_DIR) $(CERTS_DIR) mapping

# build the TLS clients
$(CLIENTS_DIR):
	@make --no-print-directory \
		  --directory=$@ \
		  CERTS_DIR=$(CURDIR)/$(CERTS_DIR) \
		  SERVERS_DIR=$(CURDIR)/$(SERVERS_DIR)

# build all cert chains
$(CERTS_DIR): $(CLIENTS_DIR)
	@make --no-print-directory --directory=$@

# process results and do the mapping
mapping: $(CERTS_DIR) $(CLIENTS_DIR)
	@echo "Comparing the errors..."
	@python3 $(MAPPING_SCRIPT) \
	         --results_file=$(VRESULTS_FILE) \
	         --errors_dir=$(ERRORS_DIR) \
	         --mapping_dir=$(MAPPING_DIR)

clean: 
	make --directory=$(CERTS_DIR) clean
	make --directory=$(CLIENTS_DIR) clean
	rm -f $(VRESULTS_FILE)

.PHONY: all $(CERTS_DIR) $(CLIENTS_DIR) mapping clean
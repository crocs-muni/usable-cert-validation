ALL_CLIENT_DIRS=$(wildcard */)

all: $(ALL_CLIENT_DIRS)

*/:
	@make --no-print-directory --directory=$@

clean:
	$(foreach CLIENT_DIR, \
			  $(ALL_CLIENT_DIRS), \
			  make --directory=$(CLIENT_DIR) clean;)

.PHONY: all $(ALL_CLIENT_DIRS) clean
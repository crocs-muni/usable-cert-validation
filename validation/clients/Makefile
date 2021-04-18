ALL_CLIENT_MAKES=$(wildcard */Makefile)

all: $(ALL_CLIENT_MAKES)

*/Makefile:
	make --no-print-directory --directory=$(@D)

clean:
	$(foreach CLIENT_MAKE, \
			  $(ALL_CLIENT_MAKES), \
			  make --directory=$(dir $(CLIENT_MAKE)) clean;)

.PHONY: all $(ALL_CLIENT_MAKES) clean
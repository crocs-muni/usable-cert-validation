all: gnutls_client

# Format all .c files according to the .clang-format config file
# If .clang-format file is not present, format according to the default Google style
format:
	clang-format --style=file --fallback-style=Google -i *.c *.h

gnutls_client: main.c crl_revoc.c ocsp_revoc.c ocsp_stapling_revoc.c ct_check.c utils.c options.c
	gcc -o gnutls_client main.c crl_revoc.c ocsp_revoc.c ocsp_stapling_revoc.c ct_check.c utils.c options.c -lgnutls -lcurl

clean:
	$(RM) gnutls_client

.PHONY: all format clean

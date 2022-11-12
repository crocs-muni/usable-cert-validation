all: openssl_client

# Format all .c files according to the .clang-format config file
# If .clang-format file is not present, format according to the default Google style
format:
	clang-format --style=file --fallback-style=Google -i *.c *.h

openssl_client: main.c crl_revoc.c ocsp_revoc.c ocsp_stapling_revoc.c ct_check.c utils.c
	gcc -o openssl_client main.c crl_revoc.c ocsp_revoc.c ocsp_stapling_revoc.c ct_check.c utils.c -lssl -lcrypto -lcurl

clean:
	$(RM) openssl_client

.PHONY: all format clean
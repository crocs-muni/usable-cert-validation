all: openssl_client

# Format all .c files according to the .clang-format config file
# If .clang-format file is not present, format according to the default Google style
format:
	clang-format --style=file --fallback-style=Google -i *.c *.h

openssl_client: main.c crl_revoc.c ocsp_revoc.c ocsp_stapling_revoc.c ct_check.c utils.c options.c
	gcc -o openssl_client main.c crl_revoc.c ocsp_revoc.c ocsp_stapling_revoc.c ct_check.c utils.c options.c -lssl -lcrypto -lcurl

clean:
	$(RM) openssl_client ocsp_req.der ocsp_resp.der ocsp_resp_stapled.der

.PHONY: all format clean
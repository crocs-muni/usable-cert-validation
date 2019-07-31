//to compile succesfully, install libcrypto and libssl
//then compile with -lcrypto option

#include <stdlib.h>
#include <stdio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

int main() {
	
	//load cert into X509 struct
	FILE *certfile = fopen("files/user.crt", "r");
	X509 *cert = X509_new();
	PEM_read_X509(certfile, &cert, 0, NULL);
	
	//create and load X509_STORE_CTX_STRUCT
	X509_STORE_CTX* ctx = X509_STORE_CTX_new();
	X509_STORE_CTX_init(ctx, NULL, cert, NULL);

	//verify, get error and print error number
	X509_verify_cert(ctx);
	int ret = X509_STORE_CTX_get_error(ctx);
	printf("%d\n", ret);

	//cleanup
	X509_STORE_CTX_free(ctx);
	X509_free(cert);
	return 0;
}
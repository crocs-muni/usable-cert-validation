CC=gcc
CFLAGS=-Wall -Wextra -std=gnu11 -g
LDLIBS=-lmbedcrypto -lmbedx509 -lmbedtls

all: build/client

build/client: client.c
	mkdir -p build
	$(CC) $(CFLAGS) -o build/client client.c $(LDLIBS)

clean:
	rm -rf build

.PHONY: all clean
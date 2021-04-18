CC=gcc
CFLAGS=-Wall -Wextra -std=gnu11 -g
LDLIBS=-lmbedcrypto -lmbedx509 -lmbedtls

all: build/client

build/client: client.c parse_opts.c
	mkdir -p build
	$(CC) $(CFLAGS) $(LDLIBS) -o build/client client.c parse_opts.c

clean:
	rm -rf build

.PHONY: all clean
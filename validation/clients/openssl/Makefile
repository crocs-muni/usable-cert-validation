CC=gcc
CFLAGS=-Wall -Wextra -std=gnu11 -g
LDLIBS=-lssl -lcrypto

all: build/client

build/client: client.c parse_opts.c
	mkdir -p build
	$(CC) $(CFLAGS) -o build/client client.c parse_opts.c $(LDLIBS)

clean:
	rm -rf build

.PHONY: all clean

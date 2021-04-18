CXX=g++
CFLAGS=-Wall -Wextra -g -std=gnu++17
LDLIBS=-lbotan-2 -lboost_program_options

all: build/client

build/client: client.cpp
	mkdir -p build
	$(CXX) $(CFLAGS) $(LDLIBS) -o build/client client.cpp

clean:
	rm -rf build

.PHONY: all clean

CXX=g++
CXXFLAGS=-Wall -Wextra -g -std=gnu++17 -I /usr/include/botan-2
LDLIBS=-lbotan-2

all: build/client

build/client: client.cpp client.hpp
	mkdir -p build
	$(CXX) $(CXXFLAGS) -o build/client client.cpp $(LDLIBS)

clean:
	rm -rf build

.PHONY: all clean

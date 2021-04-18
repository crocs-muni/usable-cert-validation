all: build/Client.class

build/Client.class: Client.java CommandLine.java
	javac -d build Client.java CommandLine.java

clean:
	rm -rf build

.PHONY: all clean
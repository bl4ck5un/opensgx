LDFLAGS=-L/usr/local/opt/openssl/lib
CPPFLAGS=-I/usr/local/opt/openssl/include
LIBS=-lssl -lcrypto

SRC=ssl.c
BIN=ssl

all: 
	gcc -g $(LDFLAGS) $(CPPFLAGS) $(LIBS) -o $(BIN) $(SRC)

.PHONY: all

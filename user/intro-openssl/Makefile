LDFLAGS=-L/usr/local/opt/openssl/lib
CPPFLAGS=-I/usr/local/opt/openssl/include

main=withssl.c
min=min.c

# all: min
#	gcc -g $(LDFLAGS) $(CPPFLAGS) -lssl -lcrypto -o ssl $(main)

min: 
	gcc -g $(LDFLAGS) $(CPPFLAGS) -lssl -lcrypto -o min $(min)

.PHONY: min

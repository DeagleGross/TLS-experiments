CC = gcc
CFLAGS = -Wall -O3 -march=native
LDFLAGS = -lssl -lcrypto -lpthread

TARGETS = src-c/tls_handshake_server

all: $(TARGETS)

src-c/tls_handshake_server: src-c/tls_handshake_server.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS)

.PHONY: all clean

CC = gcc
CFLAGS = -Wall -O3 -march=native
LDFLAGS = -lssl -lcrypto -lpthread

TARGETS = src/tls_handshake_server src/tls_handshake_server_sync src/tls_handshake_server_async_mt

all: $(TARGETS)

src/tls_handshake_server: src/tls_handshake_server.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

src/tls_handshake_server_sync: src/tls_handshake_server_sync.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

src/tls_handshake_server_async_mt: src/tls_handshake_server_async_mt.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS)

.PHONY: all clean

CC = gcc
CFLAGS = -Wall -O3 -march=native
LDFLAGS = -lssl -lcrypto -lpthread

BIN_DIR = bin
TARGETS = $(BIN_DIR)/tls_handshake_server $(BIN_DIR)/tls_handshake_server_sync $(BIN_DIR)/tls_handshake_server_async_mt $(BIN_DIR)/tls_handshake_server_sync_pool

all: $(BIN_DIR) $(TARGETS)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(BIN_DIR)/tls_handshake_server: src/tls_handshake_server.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BIN_DIR)/tls_handshake_server_sync: src/tls_handshake_server_sync.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BIN_DIR)/tls_handshake_server_async_mt: src/tls_handshake_server_async_mt.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BIN_DIR)/tls_handshake_server_sync_pool: src/tls_handshake_server_sync_pool.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -rf $(BIN_DIR)

.PHONY: all clean

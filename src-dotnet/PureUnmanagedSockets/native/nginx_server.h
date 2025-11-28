#ifndef NGINX_SERVER_H
#define NGINX_SERVER_H

#include <openssl/ssl.h>

// Initialize OpenSSL library
void openssl_init();

// Create SSL context
SSL_CTX* openssl_create_context();

// Load certificates
int openssl_load_certificates(SSL_CTX* ctx, const char* cert_file, const char* key_file);

// Get eventfd for C# to wait on for new requests
int get_request_notify_fd();

// Dequeue request (called from C#)
// Returns 1 if request dequeued, 0 if empty
// Caller must free 'data' after use
int dequeue_request(int* conn_id, char** data, int* length);

// Enqueue response (called from C#)
// Returns 0 on success, -1 if queue full
int enqueue_response(int conn_id, const char* data, int length);

// Start nginx-style server with epoll workers
// C handles TLS, C# handles HTTP processing
// This blocks until Ctrl+C
int start_nginx_server(int port, const char* cert_file, const char* key_file, int worker_count);

// Get server statistics
void get_server_stats(unsigned long* total_handshakes, unsigned long* total_connections);

#endif // NGINX_SERVER_H



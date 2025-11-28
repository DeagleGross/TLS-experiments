#ifndef OPENSSL_NATIVE_H
#define OPENSSL_NATIVE_H

#include <openssl/ssl.h>

// Result codes
#define HANDSHAKE_COMPLETE 1
#define HANDSHAKE_WANT_READ 2
#define HANDSHAKE_WANT_WRITE 3
#define HANDSHAKE_ERROR -1

// Initialize OpenSSL
void openssl_init();

// SSL Context management
SSL_CTX* openssl_create_context();
int openssl_load_certificates(SSL_CTX* ctx, const char* cert_file, const char* key_file);
void openssl_free_context(SSL_CTX* ctx);

// SSL session management
SSL* openssl_create_ssl(SSL_CTX* ctx);
int openssl_set_fd(SSL* ssl, int fd);
int openssl_do_handshake(SSL* ssl);
int openssl_read(SSL* ssl, void* buffer, int size);
int openssl_write(SSL* ssl, const void* buffer, int size);
void openssl_shutdown(SSL* ssl);
void openssl_free_ssl(SSL* ssl);

// Error handling
const char* openssl_get_error_string();

#endif // OPENSSL_NATIVE_H

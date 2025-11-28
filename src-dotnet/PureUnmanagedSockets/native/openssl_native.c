#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

// Result codes for handshake
#define HANDSHAKE_COMPLETE 1
#define HANDSHAKE_WANT_READ 2
#define HANDSHAKE_WANT_WRITE 3
#define HANDSHAKE_ERROR -1

// Initialize OpenSSL library
void openssl_init() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

// Create SSL context
SSL_CTX* openssl_create_context() {
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    
    return ctx;
}

// Load certificate and key into context
int openssl_load_certificates(SSL_CTX* ctx, const char* cert_file, const char* key_file) {
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match certificate\n");
        return 0;
    }
    
    return 1;
}

// Free SSL context
void openssl_free_context(SSL_CTX* ctx) {
    if (ctx) {
        SSL_CTX_free(ctx);
    }
}

// Create new SSL session
SSL* openssl_create_ssl(SSL_CTX* ctx) {
    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    return ssl;
}

// Set socket file descriptor for SSL
int openssl_set_fd(SSL* ssl, int fd) {
    // Set socket to non-blocking mode
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl F_GETFL");
        return 0;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("fcntl F_SETFL");
        return 0;
    }
    
    // Attach socket to SSL
    if (SSL_set_fd(ssl, fd) != 1) {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    
    // Set server mode
    SSL_set_accept_state(ssl);
    
    return 1;
}

// Perform SSL handshake (non-blocking)
// Returns: HANDSHAKE_COMPLETE, HANDSHAKE_WANT_READ, HANDSHAKE_WANT_WRITE, or HANDSHAKE_ERROR
int openssl_do_handshake(SSL* ssl) {
    int ret = SSL_do_handshake(ssl);
    
    if (ret == 1) {
        // Handshake complete
        return HANDSHAKE_COMPLETE;
    }
    
    int err = SSL_get_error(ssl, ret);
    
    switch (err) {
        case SSL_ERROR_WANT_READ:
            return HANDSHAKE_WANT_READ;
            
        case SSL_ERROR_WANT_WRITE:
            return HANDSHAKE_WANT_WRITE;
            
        case SSL_ERROR_SYSCALL:
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Non-blocking socket would block
                return HANDSHAKE_WANT_READ;
            }
            // Fall through to error
            
        case SSL_ERROR_SSL:
        default:
            ERR_print_errors_fp(stderr);
            return HANDSHAKE_ERROR;
    }
}

// Read decrypted data from SSL connection
int openssl_read(SSL* ssl, void* buffer, int size) {
    int ret = SSL_read(ssl, buffer, size);
    
    if (ret > 0) {
        return ret;
    }
    
    int err = SSL_get_error(ssl, ret);
    
    switch (err) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            // Would block - return 0 to indicate no data
            return 0;
            
        case SSL_ERROR_ZERO_RETURN:
            // Connection closed
            return -1;
            
        default:
            ERR_print_errors_fp(stderr);
            return -1;
    }
}

// Write encrypted data to SSL connection
int openssl_write(SSL* ssl, const void* buffer, int size) {
    int ret = SSL_write(ssl, buffer, size);
    
    if (ret > 0) {
        return ret;
    }
    
    int err = SSL_get_error(ssl, ret);
    
    switch (err) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            // Would block - return 0
            return 0;
            
        default:
            ERR_print_errors_fp(stderr);
            return -1;
    }
}

// Shutdown SSL connection
void openssl_shutdown(SSL* ssl) {
    if (ssl) {
        SSL_shutdown(ssl);
    }
}

// Free SSL session
void openssl_free_ssl(SSL* ssl) {
    if (ssl) {
        SSL_free(ssl);
    }
}

// Get last error string
const char* openssl_get_error_string() {
    unsigned long err = ERR_get_error();
    if (err == 0) {
        return "No error";
    }
    return ERR_error_string(err, NULL);
}

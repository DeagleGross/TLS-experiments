#ifndef DEMO_NATIVE_H
#define DEMO_NATIVE_H

#include <openssl/ssl.h>

// Log socket and SSL_CTX information
void log_socket_and_ssl_context(int socket_fd, SSL_CTX* ssl_ctx);

#endif // DEMO_NATIVE_H

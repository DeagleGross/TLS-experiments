#ifndef URING_NATIVE_H
#define URING_NATIVE_H

#include <openssl/ssl.h>

/* Handshake status codes */
#define HANDSHAKE_COMPLETE       0
#define HANDSHAKE_WANT_READ      1
#define HANDSHAKE_WANT_WRITE     2
#define HANDSHAKE_ERROR         -1

/* CQE type identifiers */
#define CQE_TYPE_ACCEPT  1
#define CQE_TYPE_POLL    2

/* Opaque context (defined in .c) */
typedef struct uring_context_t uring_context_t;

/* Ring lifecycle */
uring_context_t *uring_create(int queue_depth);
void             uring_destroy(uring_context_t *ctx);

/* Accept / Poll / Wait */
int uring_set_listen_fd(uring_context_t *ctx, int listen_fd);
int uring_prep_poll(uring_context_t *ctx, int fd, int want_write);
int uring_wait_batch(uring_context_t *ctx,
                     int *types, int *fds, int *results,
                     int max_cqes, int timeout_ms);

/* Socket helpers */
int set_socket_nonblocking(int fd);
int set_tcp_nodelay(int fd);
int accept_nonblocking(int listen_fd);

/* SSL connection management */
SSL *ssl_connection_create(SSL_CTX *ssl_ctx, int client_fd);
void ssl_connection_destroy(SSL *ssl);
int  ssl_try_handshake(SSL *ssl);
int  ssl_read_data(SSL *ssl, char *buffer, int buffer_size);
int  ssl_write_data(SSL *ssl, const char *data, int length);
int  ssl_get_fd(SSL *ssl);

#endif /* URING_NATIVE_H */

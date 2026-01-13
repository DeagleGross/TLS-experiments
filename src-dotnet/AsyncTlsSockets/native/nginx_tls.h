#ifndef NGINX_TLS_H
#define NGINX_TLS_H

#include <stdint.h>

// Return codes matching nginx patterns
#define NGX_OK          0
#define NGX_ERROR      -1
#define NGX_AGAIN      -2
#define NGX_DONE       -3

// Opaque handle types (implementation hidden)
typedef struct ngx_ssl_ctx_s ngx_ssl_ctx_t;
typedef struct ngx_connection_s ngx_connection_t;
typedef struct ngx_epoll_ctx_s ngx_epoll_ctx_t;

// Event types
#define NGX_READ_EVENT  0
#define NGX_WRITE_EVENT 1

// SSL/TLS initialization
ngx_ssl_ctx_t* ngx_ssl_create_context(
    const char* cert_file,
    const char* key_file,
    const char* ca_file
);

void ngx_ssl_free_context(ngx_ssl_ctx_t* ctx);

// Epoll context (per worker thread)
ngx_epoll_ctx_t* ngx_epoll_create(int max_events);
void ngx_epoll_destroy(ngx_epoll_ctx_t* ctx);

// Socket operations
int ngx_create_listening_socket(const char* host, int port, int backlog);
int ngx_accept4_nonblock(int listen_fd, char* client_addr, int addr_len);

// Connection management
ngx_connection_t* ngx_connection_create(
    ngx_epoll_ctx_t* epoll_ctx,
    ngx_ssl_ctx_t* ssl_ctx,
    int fd
);

void ngx_connection_free(ngx_connection_t* conn);

// Add/remove connection from epoll (edge-triggered)
int ngx_epoll_add_connection(
    ngx_epoll_ctx_t* epoll_ctx,
    ngx_connection_t* conn
);

int ngx_epoll_del_connection(
    ngx_epoll_ctx_t* epoll_ctx,
    ngx_connection_t* conn
);

// Event processing
int ngx_epoll_wait(
    ngx_epoll_ctx_t* epoll_ctx,
    ngx_connection_t** ready_conns,
    int* ready_events,  // NGX_READ_EVENT or NGX_WRITE_EVENT
    int max_events,
    int timeout_ms
);

// SSL operations (nginx-style non-blocking)
int ngx_ssl_handshake(ngx_connection_t* conn);

int ngx_ssl_read(
    ngx_connection_t* conn,
    uint8_t* buffer,
    int size
);

int ngx_ssl_write(
    ngx_connection_t* conn,
    const uint8_t* buffer,
    int size
);

// Query connection state
int ngx_connection_is_handshake_done(ngx_connection_t* conn);
int ngx_connection_get_fd(ngx_connection_t* conn);
int ngx_connection_get_ssl_error(ngx_connection_t* conn);

// Get error description
const char* ngx_ssl_get_error_string(int error_code);

#endif // NGINX_TLS_H

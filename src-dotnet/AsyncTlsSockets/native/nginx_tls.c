// Define _GNU_SOURCE first for accept4 and other GNU extensions
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "nginx_tls.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

// Feature detection for Linux-specific functions
#ifdef __linux__
#define HAVE_ACCEPT4 1
#endif

// Internal structures (nginx-inspired)
struct ngx_ssl_ctx_s {
    SSL_CTX* ctx;
};

struct ngx_connection_s {
    int fd;
    SSL* ssl;
    ngx_ssl_ctx_t* ssl_ctx;
    int handshaked;
    int ssl_error;
    uint64_t instance;  // For stale event detection

    // Nginx-style saved handler state for bidirectional SSL events
    int saved_read_needed_write;
    int saved_write_needed_read;
};

struct ngx_epoll_ctx_s {
    int epoll_fd;
    int max_events;
    struct epoll_event* events;
};

// SSL context management
ngx_ssl_ctx_t* ngx_ssl_create_context(
    const char* cert_file,
    const char* key_file,
    const char* ca_file
) {
    // Initialize OpenSSL (idempotent in OpenSSL 1.1.0+)
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    ngx_ssl_ctx_t* ctx = (ngx_ssl_ctx_t*)malloc(sizeof(ngx_ssl_ctx_t));
    if (!ctx) return NULL;

    // Use TLS 1.2 and 1.3
    ctx->ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx->ctx) {
        free(ctx);
        return NULL;
    }

    // Disable older protocols
    SSL_CTX_set_min_proto_version(ctx->ctx, TLS1_2_VERSION);

    // Load certificate and key
    if (SSL_CTX_use_certificate_file(ctx->ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        SSL_CTX_free(ctx->ctx);
        free(ctx);
        return NULL;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx->ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        SSL_CTX_free(ctx->ctx);
        free(ctx);
        return NULL;
    }

    if (!SSL_CTX_check_private_key(ctx->ctx)) {
        SSL_CTX_free(ctx->ctx);
        free(ctx);
        return NULL;
    }

    // Optional: Load CA for client verification
    if (ca_file) {
        if (!SSL_CTX_load_verify_locations(ctx->ctx, ca_file, NULL)) {
            SSL_CTX_free(ctx->ctx);
            free(ctx);
            return NULL;
        }
    }

    // Set options for performance (nginx-style)
    SSL_CTX_set_mode(ctx->ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
    SSL_CTX_set_mode(ctx->ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_CTX_set_mode(ctx->ctx, SSL_MODE_RELEASE_BUFFERS);

    return ctx;
}

void ngx_ssl_free_context(ngx_ssl_ctx_t* ctx) {
    if (ctx) {
        if (ctx->ctx) {
            SSL_CTX_free(ctx->ctx);
        }
        free(ctx);
    }
}

// Epoll context
ngx_epoll_ctx_t* ngx_epoll_create(int max_events) {
    ngx_epoll_ctx_t* ctx = (ngx_epoll_ctx_t*)malloc(sizeof(ngx_epoll_ctx_t));
    if (!ctx) return NULL;

    ctx->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (ctx->epoll_fd == -1) {
        free(ctx);
        return NULL;
    }

    ctx->max_events = max_events;
    ctx->events = (struct epoll_event*)malloc(sizeof(struct epoll_event) * max_events);
    if (!ctx->events) {
        close(ctx->epoll_fd);
        free(ctx);
        return NULL;
    }

    return ctx;
}

void ngx_epoll_destroy(ngx_epoll_ctx_t* ctx) {
    if (ctx) {
        if (ctx->epoll_fd >= 0) {
            close(ctx->epoll_fd);
        }
        if (ctx->events) {
            free(ctx->events);
        }
        free(ctx);
    }
}

// Socket operations
int ngx_create_listening_socket(const char* host, int port, int backlog) {
#if defined(SOCK_NONBLOCK) && defined(SOCK_CLOEXEC)
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
#else
    int fd = socket(AF_INET, SOCK_STREAM, 0);
#endif
    if (fd == -1) {
        return -1;
    }

#if !defined(SOCK_NONBLOCK) || !defined(SOCK_CLOEXEC)
    // Set non-blocking mode manually if flags not available
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags != -1) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
    // Set close-on-exec manually
    flags = fcntl(fd, F_GETFD, 0);
    if (flags != -1) {ks
        fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
    }
#endif

    // Set SO_REUSEADDR (nginx does this)
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Optional: SO_REUSEPORT for multi-worker kernel-level distribution
    // Only available on Linux 3.9+ and some BSDs
#ifdef SO_REUSEPORT
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (host) {
        inet_pton(AF_INET, host, &addr.sin_addr);
    } else {
        addr.sin_addr.s_addr = INADDR_ANY;
    }

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        close(fd);
        return -1;
    }

    if (listen(fd, backlog) == -1) {
        close(fd);
        return -1;
    }

    return fd;
}

int ngx_accept4_nonblock(int listen_fd, char* client_addr, int addr_len) {
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);

    int fd;

    // Use accept4 with SOCK_NONBLOCK if available (nginx does this)
#ifdef HAVE_ACCEPT4
    fd = accept4(listen_fd, (struct sockaddr*)&addr, &len, SOCK_NONBLOCK | SOCK_CLOEXEC);
#else
    // Fallback to regular accept + manual fcntl
    fd = accept(listen_fd, (struct sockaddr*)&addr, &len);
    if (fd >= 0) {
        // Set non-blocking
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags != -1) {
            fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        }
        // Set close-on-exec
        flags = fcntl(fd, F_GETFD, 0);
        if (flags != -1) {
            fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
        }
    }
#endif

    if (fd >= 0 && client_addr && addr_len > 0) {
        inet_ntop(AF_INET, &addr.sin_addr, client_addr, addr_len);
    }

    // Set TCP_NODELAY (nginx does this for low latency)
    if (fd >= 0) {
        int opt = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
    }

    return fd;
}

// Connection management
ngx_connection_t* ngx_connection_create(
    ngx_epoll_ctx_t* epoll_ctx __attribute__((unused)),
    ngx_ssl_ctx_t* ssl_ctx,
    int fd
) {
    ngx_connection_t* conn = (ngx_connection_t*)calloc(1, sizeof(ngx_connection_t));
    if (!conn) return NULL;

    conn->fd = fd;
    conn->ssl_ctx = ssl_ctx;
    conn->handshaked = 0;
    conn->ssl_error = 0;
    conn->instance = 0;
    conn->saved_read_needed_write = 0;
    conn->saved_write_needed_read = 0;

    // Create SSL connection
    conn->ssl = SSL_new(ssl_ctx->ctx);
    if (!conn->ssl) {
        free(conn);
        return NULL;
    }

    // Set to non-blocking mode (nginx does this)
    SSL_set_mode(conn->ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
    SSL_set_mode(conn->ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_set_mode(conn->ssl, SSL_MODE_RELEASE_BUFFERS);

    // Bind SSL to socket
    if (!SSL_set_fd(conn->ssl, fd)) {
        SSL_free(conn->ssl);
        free(conn);
        return NULL;
    }

    // Set to accept mode (server)
    SSL_set_accept_state(conn->ssl);

    return conn;
}

void ngx_connection_free(ngx_connection_t* conn) {
    if (conn) {
        if (conn->ssl) {
            SSL_shutdown(conn->ssl);
            SSL_free(conn->ssl);
        }
        if (conn->fd >= 0) {
            close(conn->fd);
        }
        free(conn);
    }
}

// Epoll operations (edge-triggered like nginx)
int ngx_epoll_add_connection(
    ngx_epoll_ctx_t* epoll_ctx,
    ngx_connection_t* conn
) {
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));

    // Edge-triggered + both read and write (nginx does EPOLLIN|EPOLLOUT|EPOLLET|EPOLLRDHUP)
    ev.events = EPOLLIN | EPOLLOUT | EPOLLET | EPOLLRDHUP;
    ev.data.ptr = conn;

    if (epoll_ctl(epoll_ctx->epoll_fd, EPOLL_CTL_ADD, conn->fd, &ev) == -1) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

int ngx_epoll_del_connection(
    ngx_epoll_ctx_t* epoll_ctx,
    ngx_connection_t* conn
) {
    if (epoll_ctl(epoll_ctx->epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL) == -1) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

// Event processing
int ngx_epoll_wait(
    ngx_epoll_ctx_t* epoll_ctx,
    ngx_connection_t** ready_conns,
    int* ready_events,
    int max_events,
    int timeout_ms
) {
    int n = epoll_wait(epoll_ctx->epoll_fd, epoll_ctx->events,
                       epoll_ctx->max_events < max_events ? epoll_ctx->max_events : max_events,
                       timeout_ms);

    if (n <= 0) {
        return n;
    }

    // Process events (nginx-style)
    for (int i = 0; i < n; i++) {
        ngx_connection_t* conn = (ngx_connection_t*)epoll_ctx->events[i].data.ptr;
        uint32_t revents = epoll_ctx->events[i].events;

        ready_conns[i] = conn;

        // Determine event type (prioritize errors, then read, then write)
        if (revents & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
            ready_events[i] = NGX_ERROR;
        } else if (revents & EPOLLIN) {
            ready_events[i] = NGX_READ_EVENT;
        } else if (revents & EPOLLOUT) {
            ready_events[i] = NGX_WRITE_EVENT;
        } else {
            ready_events[i] = NGX_ERROR;
        }
    }

    return n;
}

// SSL operations (nginx-style non-blocking)
int ngx_ssl_handshake(ngx_connection_t* conn) {
    if (conn->handshaked) {
        return NGX_OK;
    }

    // Clear any stale OpenSSL errors (nginx does this)
    ERR_clear_error();

    int n = SSL_do_handshake(conn->ssl);

    if (n == 1) {
        // Success
        conn->handshaked = 1;
        conn->ssl_error = 0;
        return NGX_OK;
    }

    int sslerr = SSL_get_error(conn->ssl, n);

    if (sslerr == SSL_ERROR_WANT_READ) {
        conn->ssl_error = SSL_ERROR_WANT_READ;
        return NGX_AGAIN;
    }

    if (sslerr == SSL_ERROR_WANT_WRITE) {
        conn->ssl_error = SSL_ERROR_WANT_WRITE;
        return NGX_AGAIN;
    }

    if (sslerr == SSL_ERROR_ZERO_RETURN) {
        conn->ssl_error = SSL_ERROR_ZERO_RETURN;
        return NGX_DONE;
    }

    // Error
    conn->ssl_error = sslerr;
    return NGX_ERROR;
}

int ngx_ssl_read(
    ngx_connection_t* conn,
    uint8_t* buffer,
    int size
) {
    if (!conn->handshaked) {
        return NGX_ERROR;
    }

    ERR_clear_error();

    int n = SSL_read(conn->ssl, buffer, size);

    if (n > 0) {
        conn->ssl_error = 0;
        // Note: In nginx, this continues reading in a loop until WANT_READ
        // For simplicity, we return the bytes read and let caller loop
        return n;
    }

    int sslerr = SSL_get_error(conn->ssl, n);

    if (sslerr == SSL_ERROR_WANT_READ) {
        conn->ssl_error = SSL_ERROR_WANT_READ;
        return NGX_AGAIN;
    }

    if (sslerr == SSL_ERROR_WANT_WRITE) {
        // SSL read needs write (renegotiation) - nginx handles this
        conn->ssl_error = SSL_ERROR_WANT_WRITE;
        conn->saved_read_needed_write = 1;
        return NGX_AGAIN;
    }

    if (sslerr == SSL_ERROR_ZERO_RETURN) {
        conn->ssl_error = SSL_ERROR_ZERO_RETURN;
        return NGX_DONE;
    }

    conn->ssl_error = sslerr;
    return NGX_ERROR;
}

int ngx_ssl_write(
    ngx_connection_t* conn,
    const uint8_t* buffer,
    int size
) {
    if (!conn->handshaked) {
        return NGX_ERROR;
    }

    ERR_clear_error();

    int n = SSL_write(conn->ssl, buffer, size);

    if (n > 0) {
        conn->ssl_error = 0;

        // Clear saved state if write was needed for read
        if (conn->saved_read_needed_write) {
            conn->saved_read_needed_write = 0;
        }

        return n;
    }

    int sslerr = SSL_get_error(conn->ssl, n);

    if (sslerr == SSL_ERROR_WANT_WRITE) {
        conn->ssl_error = SSL_ERROR_WANT_WRITE;
        return NGX_AGAIN;
    }

    if (sslerr == SSL_ERROR_WANT_READ) {
        // SSL write needs read (renegotiation) - nginx handles this
        conn->ssl_error = SSL_ERROR_WANT_READ;
        conn->saved_write_needed_read = 1;
        return NGX_AGAIN;
    }

    if (sslerr == SSL_ERROR_ZERO_RETURN) {
        conn->ssl_error = SSL_ERROR_ZERO_RETURN;
        return NGX_DONE;
    }

    conn->ssl_error = sslerr;
    return NGX_ERROR;
}

// Query connection state
int ngx_connection_is_handshake_done(ngx_connection_t* conn) {
    return conn->handshaked;
}

int ngx_connection_get_fd(ngx_connection_t* conn) {
    return conn->fd;
}

int ngx_connection_get_ssl_error(ngx_connection_t* conn) {
    return conn->ssl_error;
}

const char* ngx_ssl_get_error_string(int error_code) {
    switch (error_code) {
        case SSL_ERROR_WANT_READ:
            return "SSL_ERROR_WANT_READ";
        case SSL_ERROR_WANT_WRITE:
            return "SSL_ERROR_WANT_WRITE";
        case SSL_ERROR_ZERO_RETURN:
            return "SSL_ERROR_ZERO_RETURN";
        case SSL_ERROR_SYSCALL:
            return "SSL_ERROR_SYSCALL";
        case SSL_ERROR_SSL:
            return "SSL_ERROR_SSL";
        default:
            return "UNKNOWN_SSL_ERROR";
    }
}

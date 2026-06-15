/*
 * io_uring-based Async TLS Native Layer
 *
 * Replaces epoll with io_uring for higher throughput and lower syscall overhead.
 *
 * Key advantages over the epoll version (demo_native.c):
 *   - Batched submissions: pending SQEs flushed in a single io_uring_submit() syscall
 *   - No fd management dance: no epoll_ctl ADD/MOD/DEL per connection
 *   - poll_add SQEs for readiness notification (replaces epoll events)
 *   - Kernel-side batching of completions for better cache locality
 *   - Single-shot accept via io_uring (auto-resubmitted after each accept)
 *
 * Architecture (identical I/O model to epoll version, just different multiplexer):
 *   1. Worker creates io_uring ring, submits accept SQE on listen_fd
 *   2. ACCEPT CQE fires with accepted client_fd; next accept auto-submitted
 *   3. Worker creates SSL object, calls ssl_try_handshake()
 *   4. If WANT_READ/WRITE: submit poll_add SQE for that fd
 *   5. POLL CQE fires -> retry handshake
 *   6. On handshake complete: SSL_write response, close
 *
 * Requires: Linux kernel >= 5.5, liburing >= 2.0
 */

#define _GNU_SOURCE

#include <liburing.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>

/* ── Handshake status codes ────────────────────────────────────────── */

#define HANDSHAKE_COMPLETE       0
#define HANDSHAKE_WANT_READ      1
#define HANDSHAKE_WANT_WRITE     2
#define HANDSHAKE_ERROR         -1

/* ── CQE type identifiers (encoded in upper 32 bits of user_data) ── */

#define CQE_TYPE_ACCEPT  1
#define CQE_TYPE_POLL    2

/* ── io_uring context ──────────────────────────────────────────────── */

typedef struct {
    struct io_uring ring;
    int listen_fd;
} uring_context_t;

/* ── user_data packing helpers ─────────────────────────────────────── */

static inline __u64 pack_user_data(int type, int fd) {
    return ((__u64)(unsigned int)type << 32) | (__u64)(unsigned int)fd;
}

static inline int unpack_type(__u64 ud) { return (int)(ud >> 32); }
static inline int unpack_fd  (__u64 ud) { return (int)(ud & 0xFFFFFFFF); }

/* ── Internal: submit single-shot accept (SOCK_NONBLOCK) ──────────── */

static int submit_accept(uring_context_t *ctx) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (!sqe) {
        fprintf(stderr, "[uring] No SQE available for accept\n");
        return -1;
    }

    io_uring_prep_accept(sqe, ctx->listen_fd, NULL, NULL, SOCK_NONBLOCK);
    io_uring_sqe_set_data64(sqe, pack_user_data(CQE_TYPE_ACCEPT, ctx->listen_fd));
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 *  PUBLIC API — Ring lifecycle
 * ══════════════════════════════════════════════════════════════════════ */

uring_context_t *uring_create(int queue_depth) {
    uring_context_t *ctx = calloc(1, sizeof(uring_context_t));
    if (!ctx) return NULL;

    int ret = io_uring_queue_init(queue_depth, &ctx->ring, 0);
    if (ret < 0) {
        fprintf(stderr, "[uring] io_uring_queue_init(%d) failed: %s\n",
                queue_depth, strerror(-ret));
        free(ctx);
        return NULL;
    }

    ctx->listen_fd = -1;
    return ctx;
}

void uring_destroy(uring_context_t *ctx) {
    if (ctx) {
        io_uring_queue_exit(&ctx->ring);
        free(ctx);
    }
}

/* ══════════════════════════════════════════════════════════════════════
 *  PUBLIC API — Accept / Poll / Wait
 * ══════════════════════════════════════════════════════════════════════ */

/*
 * Attach the shared listen socket and submit the first accept SQE.
 * Returns 0 on success, <0 on error.
 */
int uring_set_listen_fd(uring_context_t *ctx, int listen_fd) {
    ctx->listen_fd = listen_fd;

    if (submit_accept(ctx) < 0)
        return -1;

    int ret = io_uring_submit(&ctx->ring);
    if (ret < 0) {
        fprintf(stderr, "[uring] submit failed for accept: %s\n", strerror(-ret));
        return -1;
    }
    return 0;
}

/*
 * Prepare a one-shot poll_add SQE for fd readiness.
 * Does NOT call io_uring_submit — pending SQEs are flushed by the
 * next uring_wait_batch() call, which allows batching.
 *
 * want_write == 0  →  POLLIN   (waiting for data to read)
 * want_write != 0  →  POLLOUT  (waiting for writability)
 */
int uring_prep_poll(uring_context_t *ctx, int fd, int want_write) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (!sqe) return -1;

    unsigned mask = want_write ? POLLOUT : POLLIN;
    io_uring_prep_poll_add(sqe, fd, mask);
    io_uring_sqe_set_data64(sqe, pack_user_data(CQE_TYPE_POLL, fd));
    return 0;
}

/*
 * Flush pending SQEs, wait for completions, and return them.
 *
 * For each completion i (0 .. return_value-1):
 *   types[i]   = CQE_TYPE_ACCEPT or CQE_TYPE_POLL
 *   fds[i]     = listen_fd (for ACCEPT) or client_fd (for POLL)
 *   results[i] = accepted client_fd (ACCEPT) or poll revents (POLL)
 *
 * timeout_ms:  >0 = wait up to N ms, 0 = non-blocking peek
 *
 * Returns: number of completions filled, or <0 on error.
 */
int uring_wait_batch(uring_context_t *ctx,
                     int *types, int *fds, int *results,
                     int max_cqes, int timeout_ms)
{
    /* 1. Flush any pending SQEs (poll_add, resubmitted accept, etc.) */
    io_uring_submit(&ctx->ring);

    /* 2. Wait for at least one CQE (with timeout) */
    struct io_uring_cqe *cqe;
    struct __kernel_timespec ts;
    ts.tv_sec  = timeout_ms / 1000;
    ts.tv_nsec = (long long)(timeout_ms % 1000) * 1000000LL;

    int ret = io_uring_wait_cqe_timeout(&ctx->ring, &cqe, &ts);
    if (ret < 0) {
        if (ret == -EINTR || ret == -ETIME)
            return 0;   /* timeout or signal — nothing ready */
        return ret;
    }

    /* 3. Drain all available CQEs */
    int count = 0;
    unsigned head;

    io_uring_for_each_cqe(&ctx->ring, head, cqe) {
        if (count >= max_cqes) break;

        __u64 ud    = io_uring_cqe_get_data64(cqe);
        types[count]   = unpack_type(ud);
        fds[count]     = unpack_fd(ud);
        results[count] = cqe->res;

        /* Single-shot accept: always resubmit for the next connection */
        if (types[count] == CQE_TYPE_ACCEPT) {
            submit_accept(ctx);
        }

        count++;
    }

    io_uring_cq_advance(&ctx->ring, count);

    return count;
}

/* ══════════════════════════════════════════════════════════════════════
 *  PUBLIC API — Socket helpers
 * ══════════════════════════════════════════════════════════════════════ */

int set_socket_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int set_tcp_nodelay(int fd) {
    int flag = 1;
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
}

int accept_nonblocking(int listen_fd) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    int client_fd = accept4(listen_fd, (struct sockaddr *)&client_addr,
                            &client_len, SOCK_NONBLOCK);
    if (client_fd < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return -1;
        return -2;
    }

    set_tcp_nodelay(client_fd);
    return client_fd;
}

/* ══════════════════════════════════════════════════════════════════════
 *  PUBLIC API — SSL connection management
 * ══════════════════════════════════════════════════════════════════════ */

/*
 * Create an SSL object for an already-accepted client fd.
 * Sets socket non-blocking, TCP_NODELAY, and puts SSL into accept state.
 * Does NOT register with any multiplexer.
 */
SSL *ssl_connection_create(SSL_CTX *ssl_ctx, int client_fd) {
    if (!ssl_ctx) {
        fprintf(stderr, "[uring] ssl_connection_create: ssl_ctx is NULL\n");
        return NULL;
    }

    set_socket_nonblocking(client_fd);
    set_tcp_nodelay(client_fd);

    SSL *ssl = SSL_new(ssl_ctx);
    if (!ssl) {
        fprintf(stderr, "[uring] SSL_new failed\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    if (SSL_set_fd(ssl, client_fd) != 1) {
        fprintf(stderr, "[uring] SSL_set_fd failed\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return NULL;
    }

    SSL_set_accept_state(ssl);
    return ssl;
}

void ssl_connection_destroy(SSL *ssl) {
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
}

/*
 * Attempt to advance the TLS handshake.
 * Returns HANDSHAKE_COMPLETE / WANT_READ / WANT_WRITE / ERROR.
 * Caller is responsible for submitting poll SQE on WANT_*.
 */
int ssl_try_handshake(SSL *ssl) {
    int ret = SSL_do_handshake(ssl);

    if (ret == 1)
        return HANDSHAKE_COMPLETE;

    int err = SSL_get_error(ssl, ret);

    if (err == SSL_ERROR_WANT_READ)
        return HANDSHAKE_WANT_READ;
    if (err == SSL_ERROR_WANT_WRITE)
        return HANDSHAKE_WANT_WRITE;

    if (err == SSL_ERROR_SYSCALL) {
        if (errno != 0)
            perror("[uring] SSL_do_handshake syscall error");
    } else if (err == SSL_ERROR_SSL) {
        /* Silently ignore — these are usually client-side disconnects */
    }

    return HANDSHAKE_ERROR;
}

int ssl_read_data(SSL *ssl, char *buffer, int buffer_size) {
    int ret = SSL_read(ssl, buffer, buffer_size);
    if (ret > 0) return ret;

    int err = SSL_get_error(ssl, ret);
    if (err == SSL_ERROR_WANT_READ)   return -1;
    if (err == SSL_ERROR_ZERO_RETURN) return 0;
    return -2;
}

int ssl_write_data(SSL *ssl, const char *data, int length) {
    int ret = SSL_write(ssl, data, length);
    if (ret > 0) return ret;

    int err = SSL_get_error(ssl, ret);
    if (err == SSL_ERROR_WANT_WRITE) return -1;
    return -2;
}

int ssl_get_fd(SSL *ssl) {
    return SSL_get_fd(ssl);
}

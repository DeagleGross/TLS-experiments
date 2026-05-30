/*
 * BIO-driven TLS Native Layer
 *
 * This is an experiment-05 sibling of `demo_native.c` (experiment 04).
 *
 * The PUBLIC API is identical — same function names, signatures, status codes.
 * The C# worker (`Ssl/SslWorker.cs`) is byte-for-byte the same as in
 * experiment 04. The only thing that differs is HOW the SSL state machine
 * exchanges encrypted bytes with the socket:
 *
 *   Experiment 04 (libdemo_native.so):
 *     SSL_set_fd(ssl, client_fd)  → OpenSSL calls read()/write() on the fd directly.
 *
 *   Experiment 05 (libbio_native.so, THIS FILE):
 *     SSL_set_bio(ssl, rbio, wbio) where rbio/wbio are mem BIOs.
 *     This module read()s from the fd, BIO_write()s into rbio, runs the
 *     handshake, then BIO_read()s from wbio and write()s back to the fd.
 *     There is ONE extra memcpy per direction compared to SSL_set_fd.
 *
 * The 04↔05 pair-difference therefore measures exactly the cost of the
 * "give OpenSSL the fd" optimization vs the "drive the BIO from managed
 * code" alternative — everything else (threading, accept path, epoll,
 * EPOLLEXCLUSIVE, TCP_NODELAY, SSL_CTX config) is held constant.
 *
 * The handle returned by ssl_connection_create() is opaque from C#'s
 * point of view; internally we return a `bio_conn_t*` cast to SSL*.
 */

#define _GNU_SOURCE  // accept4, SOCK_NONBLOCK

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

// ============================================================================
// Return codes for ssl_try_handshake() — MUST match demo_native.c exactly
// so the C# enum constants are reusable.
// ============================================================================
#define HANDSHAKE_COMPLETE      0
#define HANDSHAKE_WANT_READ     1
#define HANDSHAKE_WANT_WRITE    2
#define HANDSHAKE_ERROR        -1

// ============================================================================
// Per-connection state. The BIOs are needed because SSL_set_bio gives them
// to SSL; SSL_free will free them. We just keep raw pointers for the drain
// loop in ssl_try_handshake().
//
// pending_out is for the case where draining wbio to the socket gets
// EAGAIN — we stash the rest and re-arm EPOLLOUT.
// ============================================================================
typedef struct bio_conn {
    SSL* ssl;
    int  client_fd;
    BIO* rbio;                 // bytes from socket flow INTO this BIO
    BIO* wbio;                 // bytes destined for socket come OUT of this BIO
    unsigned char* pending_out;
    int  pending_out_len;
    int  pending_out_sent;
} bio_conn_t;

// I/O buffer sizes
#define IO_CHUNK     16384      // size of socket read()/write() buffers
#define MAX_DRAIN    (64 * 1024)

// ============================================================================
// Epoll & socket utility primitives — identical to demo_native.c so the
// C# side cannot tell the difference.
// ============================================================================

int create_epoll(void)
{
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        perror("[bio_native] epoll_create1 failed");
    }
    return epoll_fd;
}

void close_epoll(int epoll_fd)
{
    if (epoll_fd >= 0) {
        close(epoll_fd);
    }
}

int set_socket_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        perror("[bio_native] fcntl F_GETFL failed");
        return -1;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("[bio_native] fcntl F_SETFL O_NONBLOCK failed");
        return -1;
    }
    return 0;
}

int set_tcp_nodelay(int fd)
{
    int flag = 1;
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
}

// ============================================================================
// Internal helpers — drain encrypted output from wbio to the socket.
// Stores the leftover (if any) in conn->pending_out and switches the
// epoll registration to EPOLLOUT.
// Returns: 0 if fully drained, 1 if blocked (WANT_WRITE), -1 on error
// ============================================================================

static int drain_wbio_to_socket(bio_conn_t* conn, int epoll_fd)
{
    unsigned char chunk[IO_CHUNK];

    // First, finish any leftover from a prior partial write.
    if (conn->pending_out != NULL) {
        while (conn->pending_out_sent < conn->pending_out_len) {
            ssize_t n = write(conn->client_fd,
                              conn->pending_out + conn->pending_out_sent,
                              conn->pending_out_len - conn->pending_out_sent);
            if (n > 0) {
                conn->pending_out_sent += (int)n;
                continue;
            }
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                // Still blocked. Stay in EPOLLOUT.
                struct epoll_event ev;
                ev.events = EPOLLOUT | EPOLLET;
                ev.data.fd = conn->client_fd;
                epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->client_fd, &ev);
                return 1;
            }
            // Real error
            return -1;
        }
        free(conn->pending_out);
        conn->pending_out = NULL;
        conn->pending_out_len = 0;
        conn->pending_out_sent = 0;
    }

    // Now drain whatever the SSL state machine just produced into wbio.
    for (;;) {
        int n = BIO_read(conn->wbio, chunk, sizeof(chunk));
        if (n <= 0) {
            // No more data in wbio (BIO_read returns ≤ 0 on empty mem-BIO).
            return 0;
        }

        // Try to push the chunk to the socket.
        int sent = 0;
        while (sent < n) {
            ssize_t w = write(conn->client_fd, chunk + sent, n - sent);
            if (w > 0) {
                sent += (int)w;
                continue;
            }
            if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                // Stash the unwritten remainder and switch to EPOLLOUT.
                int leftover = n - sent;
                conn->pending_out = (unsigned char*)malloc(leftover);
                if (conn->pending_out == NULL) {
                    return -1;
                }
                memcpy(conn->pending_out, chunk + sent, leftover);
                conn->pending_out_len = leftover;
                conn->pending_out_sent = 0;

                struct epoll_event ev;
                ev.events = EPOLLOUT | EPOLLET;
                ev.data.fd = conn->client_fd;
                epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->client_fd, &ev);
                return 1;
            }
            return -1;
        }
    }
}

// Read encrypted bytes from the socket into rbio. Loops until EAGAIN.
// Returns: 0 on success, -1 on error, -2 on EOF (peer closed).
static int feed_rbio_from_socket(bio_conn_t* conn)
{
    unsigned char chunk[IO_CHUNK];

    for (;;) {
        ssize_t n = read(conn->client_fd, chunk, sizeof(chunk));
        if (n > 0) {
            int written = BIO_write(conn->rbio, chunk, (int)n);
            if (written != (int)n) {
                fprintf(stderr, "[bio_native] BIO_write short: %d/%zd\n", written, n);
                return -1;
            }
            continue;
        }
        if (n == 0) {
            return -2;   // EOF
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        if (errno == EINTR) {
            continue;
        }
        // Real error
        return -1;
    }
}

// ============================================================================
// Public API — same names/sigs as demo_native.c
// ============================================================================

/**
 * Create a BIO-driven SSL connection AND register the fd with epoll.
 * Mirrors ssl_connection_create() in demo_native.c, but uses mem BIOs.
 *
 * Returns: opaque connection pointer (cast to SSL*) or NULL on error.
 */
SSL* ssl_connection_create(SSL_CTX* ssl_ctx, int client_fd, int epoll_fd)
{
    if (ssl_ctx == NULL) {
        fprintf(stderr, "[bio_native] ssl_connection_create: ssl_ctx is NULL\n");
        return NULL;
    }

    if (set_socket_nonblocking(client_fd) < 0) {
        return NULL;
    }
    set_tcp_nodelay(client_fd);

    SSL* ssl = SSL_new(ssl_ctx);
    if (ssl == NULL) {
        fprintf(stderr, "[bio_native] SSL_new failed\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    BIO* rbio = BIO_new(BIO_s_mem());
    BIO* wbio = BIO_new(BIO_s_mem());
    if (rbio == NULL || wbio == NULL) {
        fprintf(stderr, "[bio_native] BIO_new failed\n");
        if (rbio) BIO_free(rbio);
        if (wbio) BIO_free(wbio);
        SSL_free(ssl);
        return NULL;
    }

    // SSL takes ownership of both BIOs — they'll be freed by SSL_free.
    SSL_set_bio(ssl, rbio, wbio);
    SSL_set_accept_state(ssl);

    bio_conn_t* conn = (bio_conn_t*)calloc(1, sizeof(bio_conn_t));
    if (conn == NULL) {
        SSL_free(ssl);
        return NULL;
    }
    conn->ssl = ssl;
    conn->client_fd = client_fd;
    conn->rbio = rbio;
    conn->wbio = wbio;

    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = client_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev) < 0) {
        perror("[bio_native] epoll_ctl ADD failed");
        SSL_free(ssl);   // also frees the BIOs
        free(conn);
        return NULL;
    }

    return (SSL*)conn;
}

/**
 * Destroy the connection. SSL_free will free the BIOs since SSL_set_bio
 * transferred ownership.
 */
void ssl_connection_destroy(SSL* opaque)
{
    bio_conn_t* conn = (bio_conn_t*)opaque;
    if (conn == NULL) return;

    if (conn->ssl != NULL) {
        SSL_shutdown(conn->ssl);
        SSL_free(conn->ssl);
    }
    if (conn->pending_out != NULL) {
        free(conn->pending_out);
    }
    free(conn);
}

/**
 * Drive the handshake: feed rbio from the socket, advance SSL state,
 * drain wbio to the socket, set epoll for whichever side wants the next
 * event, and report the resulting status to C#.
 */
int ssl_try_handshake(SSL* opaque, int client_fd, int epoll_fd)
{
    bio_conn_t* conn = (bio_conn_t*)opaque;
    if (conn == NULL) return HANDSHAKE_ERROR;

    // If we still owe the socket bytes from a prior partial write, finish them
    // before we touch the SSL state machine.
    if (conn->pending_out != NULL) {
        int rc = drain_wbio_to_socket(conn, epoll_fd);
        if (rc < 0) return HANDSHAKE_ERROR;
        if (rc == 1) return HANDSHAKE_WANT_WRITE;
    }

    // Pull all available encrypted bytes from the socket into rbio.
    int fed = feed_rbio_from_socket(conn);
    if (fed == -1) {
        return HANDSHAKE_ERROR;
    }
    // EOF is OK if the handshake is already complete (peer closing); otherwise it's an error.
    // We let SSL_do_handshake decide.

    int ret = SSL_do_handshake(conn->ssl);

    if (ret == 1) {
        // Handshake succeeded — make sure any final flight is drained.
        int rc = drain_wbio_to_socket(conn, epoll_fd);
        if (rc < 0) return HANDSHAKE_ERROR;
        if (rc == 1) {
            // Still partial — caller should treat as WANT_WRITE.
            // We DON'T return COMPLETE because the C# worker would then
            // immediately call ssl_write & destroy, racing the unsent flight.
            return HANDSHAKE_WANT_WRITE;
        }
        // Fully drained — remove from epoll (matches demo_native semantics).
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_fd, NULL);
        return HANDSHAKE_COMPLETE;
    }

    int err = SSL_get_error(conn->ssl, ret);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        // Whatever SSL produced during this call needs to go out first.
        int rc = drain_wbio_to_socket(conn, epoll_fd);
        if (rc < 0) return HANDSHAKE_ERROR;
        if (rc == 1) {
            // We just set EPOLLOUT for the partial write.
            return HANDSHAKE_WANT_WRITE;
        }

        // After draining, we need MORE input from the peer → arm EPOLLIN.
        // (SSL_ERROR_WANT_WRITE with a mem-BIO actually means "I tried to
        //  write into wbio and ran out of headroom" — but BIO_s_mem grows
        //  on demand, so we treat both WANT_READ and WANT_WRITE the same
        //  here: we wait for the next round of socket I/O.)
        struct epoll_event ev;
        ev.events = EPOLLIN | EPOLLET;
        ev.data.fd = client_fd;
        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, client_fd, &ev);
        return (err == SSL_ERROR_WANT_READ) ? HANDSHAKE_WANT_READ : HANDSHAKE_WANT_WRITE;
    }

    // Real error.
    if (err == SSL_ERROR_SYSCALL) {
        if (errno != 0) perror("[bio_native] SSL_do_handshake syscall");
    } else if (err == SSL_ERROR_SSL) {
        fprintf(stderr, "[bio_native] SSL_do_handshake SSL error\n");
        ERR_print_errors_fp(stderr);
    } else if (err == SSL_ERROR_ZERO_RETURN) {
        fprintf(stderr, "[bio_native] SSL_do_handshake ZERO_RETURN (peer closed)\n");
    } else {
        fprintf(stderr, "[bio_native] SSL_do_handshake unknown err=%d\n", err);
    }
    return HANDSHAKE_ERROR;
}

/**
 * Wait for a single epoll event (kept for API parity; the workers use the
 * batch variant below).
 */
int epoll_wait_one(int epoll_fd, int timeout_ms)
{
    struct epoll_event event;
    int nfds = epoll_wait(epoll_fd, &event, 1, timeout_ms);
    if (nfds < 0) {
        if (errno == EINTR) return 0;
        perror("[bio_native] epoll_wait failed");
        return -1;
    }
    if (nfds == 0) return 0;
    return event.data.fd;
}

/**
 * Write plaintext through SSL, then drain the encrypted bytes from wbio
 * to the socket. This is called by the C# worker once the handshake
 * completes, to send the HTTP response.
 *
 * The C# worker doesn't track pending writes after the handshake stage,
 * so we loop on EAGAIN with a short retry. For a 50-byte HTTP response
 * over a fresh socket this is effectively a single non-blocking write,
 * but the retry guards against rare scheduler pauses.
 *
 * Returns: bytes written into SSL (always == length on success),
 *          -1 if blocked indefinitely, -2 on error.
 */
/**
 * Encrypt and send. Same one-shot semantics as exp 04's ssl_write:
 * SSL_write into wbio, then a single drain attempt. On EAGAIN we surrender
 * (return -1) instead of looping — matches what exp 04 does on
 * SSL_ERROR_WANT_WRITE.
 *
 * Returns: bytes written into SSL (== length on success),
 *          -1 if would block (WANT_WRITE / EAGAIN), -2 on error.
 */
int ssl_write(SSL* opaque, const char* data, int length)
{
    bio_conn_t* conn = (bio_conn_t*)opaque;
    if (conn == NULL) return -2;

    int written = SSL_write(conn->ssl, data, length);
    if (written <= 0) {
        int err = SSL_get_error(conn->ssl, written);
        if (err == SSL_ERROR_WANT_WRITE) return -1;
        return -2;
    }

    // Drain wbio → socket — single best-effort attempt, no retries.
    unsigned char chunk[IO_CHUNK];
    for (;;) {
        int n = BIO_read(conn->wbio, chunk, sizeof(chunk));
        if (n <= 0) {
            return written;
        }
        int sent = 0;
        while (sent < n) {
            ssize_t w = write(conn->client_fd, chunk + sent, n - sent);
            if (w > 0) {
                sent += (int)w;
                continue;
            }
            if (w < 0 && errno == EINTR) continue;
            if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return -1;
            return -2;
        }
    }
}

/**
 * SSL_read for application data after handshake. Not used in the bench
 * (the server replies without consuming any request body) but kept for
 * API parity.
 */
int ssl_read(SSL* opaque, char* buffer, int buffer_size)
{
    bio_conn_t* conn = (bio_conn_t*)opaque;
    if (conn == NULL) return -2;

    // Try to top up rbio first; ignore EAGAIN.
    (void)feed_rbio_from_socket(conn);

    int ret = SSL_read(conn->ssl, buffer, buffer_size);
    if (ret > 0) return ret;

    int err = SSL_get_error(conn->ssl, ret);
    if (err == SSL_ERROR_WANT_READ)   return -1;
    if (err == SSL_ERROR_ZERO_RETURN) return 0;
    return -2;
}

/**
 * Return the fd — the C# worker stores it itself so this is rarely called,
 * but kept for API parity.
 */
int ssl_get_fd(SSL* opaque)
{
    bio_conn_t* conn = (bio_conn_t*)opaque;
    return conn != NULL ? conn->client_fd : -1;
}

// ============================================================================
// Batch epoll wait and listen-fd helpers — identical to demo_native.c
// ============================================================================

#define MAX_BATCH_EVENTS 64

int epoll_wait_batch(int epoll_fd, int timeout_ms, int* fds_out, int max_events)
{
    struct epoll_event events[MAX_BATCH_EVENTS];

    if (max_events > MAX_BATCH_EVENTS) {
        max_events = MAX_BATCH_EVENTS;
    }

    int nfds = epoll_wait(epoll_fd, events, max_events, timeout_ms);
    if (nfds < 0) {
        if (errno == EINTR) return 0;
        perror("[bio_native] epoll_wait_batch failed");
        return -1;
    }

    for (int i = 0; i < nfds; i++) {
        fds_out[i] = events[i].data.fd;
    }
    return nfds;
}

int epoll_add_listen_fd(int epoll_fd, int listen_fd)
{
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLEXCLUSIVE;
    ev.data.fd = listen_fd;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &ev) < 0) {
        perror("[bio_native] epoll_ctl ADD listen_fd failed");
        return -1;
    }
    return 0;
}

int accept_nonblocking(int listen_fd)
{
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    int client_fd = accept4(listen_fd, (struct sockaddr*)&client_addr, &client_len, SOCK_NONBLOCK);
    if (client_fd < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return -1;
        perror("[bio_native] accept4 failed");
        return -2;
    }
    set_tcp_nodelay(client_fd);
    return client_fd;
}

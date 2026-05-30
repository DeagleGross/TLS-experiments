/*
 * TLS Handshake Performance Test - MULTI-THREADED ASYNC Server (TUNED)
 *
 * This is the *actual ceiling* C server. It applies three optimizations
 * the original tls_handshake_server_async_mt.c was missing, so the
 * comparison vs the C# fd-binding worker is apples-to-apples:
 *
 *   1. accept4(SOCK_NONBLOCK) instead of accept() + fcntl(O_NONBLOCK)
 *      -> saves one syscall per accept (1 vs 2)
 *
 *   2. EPOLLEXCLUSIVE on the listen socket instead of EPOLLET
 *      -> only one worker is woken per accept event (no thundering herd
 *         where all 4 workers wake and 3 get EAGAIN).
 *      -> also removes SO_REUSEPORT (irrelevant when only one listen fd
 *         is shared across multiple epoll instances).
 *
 *   3. Skip SSL_shutdown() before SSL_free()
 *      -> avoids sending a TLS close_notify alert record. Our HTTP response
 *         already includes "Connection: close", so the client knows we're
 *         tearing down. SSL_shutdown adds a full encrypt+write+flush per
 *         request -- significant overhead at this scale.
 *
 * Everything else is identical to tls_handshake_server_async_mt.c so the
 * delta between the two C servers cleanly attributes to these three changes.
 */

#define _GNU_SOURCE  // accept4, EPOLLEXCLUSIVE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAX_EVENTS 1024
#define BACKLOG 511
#define NUM_WORKERS 4

typedef struct {
    int fd;
    SSL *ssl;
    int handshake_complete;
    int ssl_do_handshake_calls;
    int epoll_ctl_calls;
} client_context_t;

typedef struct {
    int worker_id;
    int epoll_fd;
    SSL_CTX *ssl_ctx;
    unsigned long handshakes_completed;
    unsigned long handshakes_failed;
    unsigned long total_ssl_do_handshake_calls;
    unsigned long total_epoll_ctl_calls;
    unsigned long total_accepts;
} worker_context_t;

static volatile int running = 1;
static int listen_fd;
static struct timespec start_time;

void signal_handler(int sig) {
    running = 0;
}

int set_tcp_nodelay(int fd) {
    int flag = 1;
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
}

SSL_CTX* create_ssl_context() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256");
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

    return ctx;
}

int handle_tls_handshake(client_context_t *client, worker_context_t *worker) {
    int ret = SSL_do_handshake(client->ssl);
    client->ssl_do_handshake_calls++;
    worker->total_ssl_do_handshake_calls++;

    if (ret == 1) {
        client->handshake_complete = 1;
        worker->handshakes_completed++;

        const char *response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        SSL_write(client->ssl, response, strlen(response));

        return 1;
    }

    int err = SSL_get_error(client->ssl, ret);

    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        struct epoll_event ev;
        ev.data.ptr = client;
        ev.events = (err == SSL_ERROR_WANT_READ) ? EPOLLIN : EPOLLOUT;
        ev.events |= EPOLLET;

        epoll_ctl(worker->epoll_fd, EPOLL_CTL_MOD, client->fd, &ev);
        client->epoll_ctl_calls++;
        worker->total_epoll_ctl_calls++;
        return 0;
    }

    if (err != SSL_ERROR_SYSCALL && err != SSL_ERROR_ZERO_RETURN) {
        worker->handshakes_failed++;
    } else {
        worker->handshakes_failed++;
    }
    return -1;
}

void* worker_thread(void *arg) {
    worker_context_t *worker = (worker_context_t*)arg;
    struct epoll_event events[MAX_EVENTS];

    printf("[Worker %d] Started on epoll_fd=%d\n", worker->worker_id, worker->epoll_fd);

    while (running) {
        int nfds = epoll_wait(worker->epoll_fd, events, MAX_EVENTS, 100);

        if (nfds < 0) {
            if (errno == EINTR) continue;
            perror("epoll_wait");
            break;
        }

        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == listen_fd) {
                // Accept new connections in a loop until EAGAIN
                while (1) {
                    struct sockaddr_in client_addr;
                    socklen_t client_len = sizeof(client_addr);

                    // TUNED CHANGE #1: accept4 with SOCK_NONBLOCK in a single syscall
                    int client_fd = accept4(listen_fd,
                                            (struct sockaddr*)&client_addr,
                                            &client_len,
                                            SOCK_NONBLOCK);

                    if (client_fd < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        continue;
                    }

                    set_tcp_nodelay(client_fd);

                    SSL *ssl = SSL_new(worker->ssl_ctx);
                    if (!ssl) {
                        close(client_fd);
                        continue;
                    }

                    SSL_set_fd(ssl, client_fd);
                    SSL_set_accept_state(ssl);

                    client_context_t *ctx = malloc(sizeof(client_context_t));
                    ctx->fd = client_fd;
                    ctx->ssl = ssl;
                    ctx->handshake_complete = 0;
                    ctx->ssl_do_handshake_calls = 0;
                    ctx->epoll_ctl_calls = 0;

                    worker->total_accepts++;

                    struct epoll_event client_ev;
                    client_ev.events = EPOLLIN | EPOLLET;
                    client_ev.data.ptr = ctx;
                    epoll_ctl(worker->epoll_fd, EPOLL_CTL_ADD, client_fd, &client_ev);
                    ctx->epoll_ctl_calls++;
                    worker->total_epoll_ctl_calls++;
                }
            } else {
                client_context_t *ctx = (client_context_t*)events[i].data.ptr;

                int result = handle_tls_handshake(ctx, worker);
                if (result != 0) {
                    epoll_ctl(worker->epoll_fd, EPOLL_CTL_DEL, ctx->fd, NULL);
                    ctx->epoll_ctl_calls++;
                    worker->total_epoll_ctl_calls++;
                    if (ctx->ssl) {
                        // TUNED CHANGE #3: skip SSL_shutdown() to avoid the
                        // TLS close_notify alert. The client knows we're
                        // closing because the response has Connection: close.
                        SSL_free(ctx->ssl);
                    }
                    if (ctx->fd >= 0) {
                        close(ctx->fd);
                    }
                    free(ctx);
                }
            }
        }
    }

    printf("[Worker %d] Shutting down. Completed: %lu, Failed: %lu\n",
           worker->worker_id, worker->handshakes_completed, worker->handshakes_failed);

    return NULL;
}

void resolve_curve_paths(const char *curve, const char **cert_file, const char **key_file) {
    static char cert_path[256];
    static char key_path[256];

    if (strcmp(curve, "p256") == 0) {
        snprintf(cert_path, sizeof(cert_path), "certs/server-p256.crt");
        snprintf(key_path, sizeof(key_path), "certs/server-p256.key");
    } else if (strcmp(curve, "p384") == 0) {
        snprintf(cert_path, sizeof(cert_path), "certs/server-p384.crt");
        snprintf(key_path, sizeof(key_path), "certs/server-p384.key");
    } else {
        fprintf(stderr, "Unknown curve: %s. Supported: p256, p384\n", curve);
        exit(1);
    }

    *cert_file = cert_path;
    *key_file = key_path;
}

int main(int argc, char *argv[]) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    int port = 6002;
    const char *cert_file = "certs/server-p384.crt";
    const char *key_file = "certs/server-p384.key";
    const char *curve = NULL;

    if (argc >= 2) {
        port = atoi(argv[1]);
    }

    if (argc >= 3) {
        if (strcmp(argv[2], "p256") == 0 || strcmp(argv[2], "p384") == 0) {
            curve = argv[2];
            resolve_curve_paths(curve, &cert_file, &key_file);
        } else {
            cert_file = argv[2];
            if (argc >= 4) key_file = argv[3];
        }
    }

    printf("MULTI-THREADED ASYNC TLS Handshake Server (TUNED CEILING)\n");
    printf("Port: %d\n", port);
    printf("Workers: %d\n", NUM_WORKERS);
    if (curve) printf("Curve: %s\n", curve);
    printf("Cert: %s\n", cert_file);
    printf("Key: %s\n", key_file);
    printf("Tunings: accept4(SOCK_NONBLOCK) | EPOLLEXCLUSIVE on listen | no SSL_shutdown\n\n");

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    SSL_CTX *ssl_ctx = create_ssl_context();
    if (!ssl_ctx) {
        fprintf(stderr, "Failed to create SSL context\n");
        return 1;
    }

    if (SSL_CTX_use_certificate_file(ssl_ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Failed to load certificate: %s\n", cert_file);
        ERR_print_errors_fp(stderr);
        return 1;
    }

    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Failed to load private key: %s\n", key_file);
        ERR_print_errors_fp(stderr);
        return 1;
    }

    // Create listening socket (non-blocking from the start via accept4 later)
    listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (listen_fd < 0) {
        perror("socket");
        return 1;
    }

    int reuse = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    // NOTE: no SO_REUSEPORT -- with a single listen fd shared across worker
    // epolls via EPOLLEXCLUSIVE, SO_REUSEPORT would be a no-op anyway.

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }

    if (listen(listen_fd, BACKLOG) < 0) {
        perror("listen");
        return 1;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    clock_gettime(CLOCK_MONOTONIC, &start_time);

    pthread_t workers[NUM_WORKERS];
    worker_context_t worker_contexts[NUM_WORKERS];

    for (int i = 0; i < NUM_WORKERS; i++) {
        worker_contexts[i].worker_id = i;
        worker_contexts[i].ssl_ctx = ssl_ctx;
        worker_contexts[i].handshakes_completed = 0;
        worker_contexts[i].handshakes_failed = 0;
        worker_contexts[i].total_ssl_do_handshake_calls = 0;
        worker_contexts[i].total_epoll_ctl_calls = 0;
        worker_contexts[i].total_accepts = 0;

        worker_contexts[i].epoll_fd = epoll_create1(0);
        if (worker_contexts[i].epoll_fd < 0) {
            perror("epoll_create1");
            return 1;
        }

        // TUNED CHANGE #2: EPOLLEXCLUSIVE on the listen fd
        // Only ONE worker is woken per incoming connection (no thundering herd).
        struct epoll_event ev;
        ev.events = EPOLLIN | EPOLLEXCLUSIVE;
        ev.data.fd = listen_fd;
        if (epoll_ctl(worker_contexts[i].epoll_fd, EPOLL_CTL_ADD, listen_fd, &ev) < 0) {
            perror("epoll_ctl");
            return 1;
        }

        if (pthread_create(&workers[i], NULL, worker_thread, &worker_contexts[i]) != 0) {
            perror("pthread_create");
            return 1;
        }
    }

    printf("\nServer listening on port %d with %d workers...\n", port, NUM_WORKERS);
    printf("Press Ctrl+C to stop and show stats\n\n");

    while (running) {
        sleep(5);
        if (!running) break;

        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        double elapsed = (now.tv_sec - start_time.tv_sec) +
                       (now.tv_nsec - start_time.tv_nsec) / 1e9;

        unsigned long total_completed = 0;
        unsigned long total_failed = 0;
        unsigned long total_accepts = 0;

        for (int i = 0; i < NUM_WORKERS; i++) {
            total_completed += worker_contexts[i].handshakes_completed;
            total_failed += worker_contexts[i].handshakes_failed;
            total_accepts += worker_contexts[i].total_accepts;
        }

        printf("[%ld] Handshakes: %lu ok, %lu fail (%.2f/sec) | accepts=%lu\n",
               time(NULL), total_completed, total_failed, total_completed / elapsed,
               total_accepts);
    }

    for (int i = 0; i < NUM_WORKERS; i++) {
        pthread_join(workers[i], NULL);
        close(worker_contexts[i].epoll_fd);
    }

    struct timespec end_time;
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    double elapsed = (end_time.tv_sec - start_time.tv_sec) +
                     (end_time.tv_nsec - start_time.tv_nsec) / 1e9;

    unsigned long total_completed = 0;
    unsigned long total_failed = 0;
    unsigned long total_accepts = 0;
    // Per-worker stats for distribution check (EPOLLEXCLUSIVE should distribute evenly)
    for (int i = 0; i < NUM_WORKERS; i++) {
        total_completed += worker_contexts[i].handshakes_completed;
        total_failed += worker_contexts[i].handshakes_failed;
        total_accepts += worker_contexts[i].total_accepts;
    }

    printf("\n=== TUNED CEILING Performance Stats ===\n");
    printf("Runtime: %.2f seconds\n", elapsed);
    printf("Workers: %d\n", NUM_WORKERS);
    printf("Completed: %lu  Failed: %lu  Total accepts: %lu\n", total_completed, total_failed, total_accepts);
    printf("Handshakes/sec: %.2f\n", total_completed / elapsed);
    printf("\n--- Per-worker accept distribution (EPOLLEXCLUSIVE evenness check) ---\n");
    for (int i = 0; i < NUM_WORKERS; i++) {
        printf("  Worker %d: accepts=%lu  completed=%lu\n",
               i, worker_contexts[i].total_accepts, worker_contexts[i].handshakes_completed);
    }
    printf("=========================================\n");

    close(listen_fd);
    SSL_CTX_free(ssl_ctx);

    return 0;
}

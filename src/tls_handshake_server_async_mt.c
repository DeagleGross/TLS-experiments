/*
 * TLS Handshake Performance Test - MULTI-THREADED ASYNC Server
 * Similar to nginx's multi-worker architecture
 * Each worker thread runs its own epoll loop, handling connections asynchronously
 */

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
#define NUM_WORKERS 4  // Number of worker threads (like nginx workers)

typedef struct {
    int fd;
    SSL *ssl;
    int handshake_complete;
    int ssl_do_handshake_calls;  // Track SSL_do_handshake calls per request
    int epoll_ctl_calls;         // Track epoll_ctl calls per request
} client_context_t;

typedef struct {
    int worker_id;
    int epoll_fd;
    SSL_CTX *ssl_ctx;
    unsigned long handshakes_completed;
    unsigned long handshakes_failed;
    unsigned long total_ssl_do_handshake_calls;  // Total SSL_do_handshake calls
    unsigned long total_epoll_ctl_calls;         // Total epoll_ctl calls (excluding listen fd)
    unsigned long total_accepts;                 // Total accepted connections
} worker_context_t;

static volatile int running = 1;
static int listen_fd;
static struct timespec start_time;

void signal_handler(int sig) {
    running = 0;
}

int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
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

    // Force TLS 1.3 only
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    
    // TLS 1.3 ciphersuites
    SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256");
    
    // Disable session resumption - force full handshake every time
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    
    return ctx;
}

int handle_tls_handshake(client_context_t *client, worker_context_t *worker) {
    int ret = SSL_do_handshake(client->ssl);
    client->ssl_do_handshake_calls++;
    worker->total_ssl_do_handshake_calls++;
    
    if (ret == 1) {
        // Handshake complete
        client->handshake_complete = 1;
        worker->handshakes_completed++;
        
        // Send response and close
        const char *response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        SSL_write(client->ssl, response, strlen(response));
        
        return 1; // Signal to close connection
    }
    
    int err = SSL_get_error(client->ssl, ret);
    
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        // Need to wait for I/O
        struct epoll_event ev;
        ev.data.ptr = client;
        ev.events = (err == SSL_ERROR_WANT_READ) ? EPOLLIN : EPOLLOUT;
        ev.events |= EPOLLET;
        
        epoll_ctl(worker->epoll_fd, EPOLL_CTL_MOD, client->fd, &ev);
        client->epoll_ctl_calls++;
        worker->total_epoll_ctl_calls++;
        return 0; // Continue
    }
    
    // Error
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
                // Accept new connections
                while (1) {
                    struct sockaddr_in client_addr;
                    socklen_t client_len = sizeof(client_addr);
                    int client_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &client_len);
                    
                    if (client_fd < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        continue;
                    }
                    
                    set_nonblocking(client_fd);
                    set_tcp_nodelay(client_fd);
                    
                    // Create SSL connection
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
                    
                    // Add to this worker's epoll
                    struct epoll_event client_ev;
                    client_ev.events = EPOLLIN | EPOLLET;
                    client_ev.data.ptr = ctx;
                    epoll_ctl(worker->epoll_fd, EPOLL_CTL_ADD, client_fd, &client_ev);
                    ctx->epoll_ctl_calls++;
                    worker->total_epoll_ctl_calls++;
                }
            } else {
                // Handle client I/O
                client_context_t *ctx = (client_context_t*)events[i].data.ptr;
                
                int result = handle_tls_handshake(ctx, worker);
                if (result != 0) {
                    epoll_ctl(worker->epoll_fd, EPOLL_CTL_DEL, ctx->fd, NULL);
                    ctx->epoll_ctl_calls++;
                    worker->total_epoll_ctl_calls++;
                    if (ctx->ssl) {
                        SSL_shutdown(ctx->ssl);
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

int main(int argc, char *argv[]) {
    // Disable stdout buffering for Docker compatibility
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    
    int port = 6001;
    const char *cert_file = "certs/server-p384.crt";
    const char *key_file = "certs/server-p384.key";
    
    if (argc >= 2) port = atoi(argv[1]);
    if (argc >= 3) cert_file = argv[2];
    if (argc >= 4) key_file = argv[3];
    
    printf("MULTI-THREADED ASYNC TLS Handshake Server\n");
    printf("Port: %d\n", port);
    printf("Workers: %d\n", NUM_WORKERS);
    printf("Cert: %s\n", cert_file);
    printf("Key: %s\n", key_file);
    printf("Mode: ASYNC (epoll per worker, like nginx)\n\n");
    
    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    // Create SSL context (shared by all workers)
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
    
    // Create listening socket
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return 1;
    }
    
    int reuse = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
    
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
    
    set_nonblocking(listen_fd);
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    
    // Create worker threads
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
        
        // Each worker gets its own epoll instance
        worker_contexts[i].epoll_fd = epoll_create1(0);
        if (worker_contexts[i].epoll_fd < 0) {
            perror("epoll_create1");
            return 1;
        }
        
        // Add listen socket to each worker's epoll
        // SO_REUSEPORT allows multiple workers to accept from same socket
        struct epoll_event ev;
        ev.events = EPOLLIN | EPOLLET;
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
    
    // Print periodic stats
    while (running) {
        sleep(5);
        if (!running) break;
        
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        double elapsed = (now.tv_sec - start_time.tv_sec) + 
                       (now.tv_nsec - start_time.tv_nsec) / 1e9;
        
        unsigned long total_completed = 0;
        unsigned long total_failed = 0;
        unsigned long total_ssl_do_handshake = 0;
        unsigned long total_epoll_ctl = 0;
        unsigned long total_accepts = 0;
        
        for (int i = 0; i < NUM_WORKERS; i++) {
            total_completed += worker_contexts[i].handshakes_completed;
            total_failed += worker_contexts[i].handshakes_failed;
            total_ssl_do_handshake += worker_contexts[i].total_ssl_do_handshake_calls;
            total_epoll_ctl += worker_contexts[i].total_epoll_ctl_calls;
            total_accepts += worker_contexts[i].total_accepts;
        }
        
        printf("[%ld] Handshakes: %lu ok, %lu fail (%.2f/sec) | SSL_do_handshake: %lu (%.2f/req) | epoll_ctl: %lu (%.2f/req)\n",
               time(NULL), total_completed, total_failed, total_completed / elapsed,
               total_ssl_do_handshake, total_accepts > 0 ? (double)total_ssl_do_handshake / total_accepts : 0,
               total_epoll_ctl, total_accepts > 0 ? (double)total_epoll_ctl / total_accepts : 0);
    }
    
    // Wait for workers to finish
    for (int i = 0; i < NUM_WORKERS; i++) {
        pthread_join(workers[i], NULL);
        close(worker_contexts[i].epoll_fd);
    }
    
    // Final stats
    struct timespec end_time;
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    double elapsed = (end_time.tv_sec - start_time.tv_sec) + 
                     (end_time.tv_nsec - start_time.tv_nsec) / 1e9;
    
    unsigned long total_completed = 0;
    unsigned long total_failed = 0;
    unsigned long total_ssl_do_handshake_calls = 0;
    unsigned long total_epoll_ctl_calls = 0;
    unsigned long total_accepts = 0;
    
    for (int i = 0; i < NUM_WORKERS; i++) {
        total_completed += worker_contexts[i].handshakes_completed;
        total_failed += worker_contexts[i].handshakes_failed;
        total_ssl_do_handshake_calls += worker_contexts[i].total_ssl_do_handshake_calls;
        total_epoll_ctl_calls += worker_contexts[i].total_epoll_ctl_calls;
        total_accepts += worker_contexts[i].total_accepts;
    }
    
    printf("\n=== MULTI-THREADED ASYNC TLS Performance Stats ===\n");
    printf("Runtime: %.2f seconds\n", elapsed);
    printf("Workers: %d\n", NUM_WORKERS);
    printf("Completed handshakes: %lu\n", total_completed);
    printf("Failed handshakes: %lu\n", total_failed);
    printf("Handshakes/sec: %.2f\n", total_completed / elapsed);
    printf("\n--- Per-Request Statistics ---\n");
    printf("Total accepts: %lu\n", total_accepts);
    printf("Total SSL_do_handshake calls: %lu\n", total_ssl_do_handshake_calls);
    printf("Total epoll_ctl calls: %lu\n", total_epoll_ctl_calls);
    if (total_accepts > 0) {
        printf("Avg SSL_do_handshake per request: %.2f\n", (double)total_ssl_do_handshake_calls / total_accepts);
        printf("Avg epoll_ctl per request: %.2f\n", (double)total_epoll_ctl_calls / total_accepts);
    }
    printf("\n--- Per-Worker Statistics ---\n");
    for (int i = 0; i < NUM_WORKERS; i++) {
        printf("Worker %d: accepts=%lu, SSL_do_handshake=%lu (avg=%.2f), epoll_ctl=%lu (avg=%.2f)\n",
               i,
               worker_contexts[i].total_accepts,
               worker_contexts[i].total_ssl_do_handshake_calls,
               worker_contexts[i].total_accepts > 0 ? (double)worker_contexts[i].total_ssl_do_handshake_calls / worker_contexts[i].total_accepts : 0,
               worker_contexts[i].total_epoll_ctl_calls,
               worker_contexts[i].total_accepts > 0 ? (double)worker_contexts[i].total_epoll_ctl_calls / worker_contexts[i].total_accepts : 0);
    }
    printf("===================================================\n");
    
    close(listen_fd);
    SSL_CTX_free(ssl_ctx);
    
    return 0;
}

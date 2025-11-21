/*
 * TLS Handshake Performance Test - Server
 * Measures pure TLS handshake throughput using OpenSSL
 * Similar to nginx's async TLS handling
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
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
#define BUFFER_SIZE 4096

typedef struct {
    int fd;
    SSL *ssl;
    int handshake_complete;
    struct timespec start_time;
} client_context_t;

static volatile int running = 1;
static unsigned long handshakes_completed = 0;
static unsigned long handshakes_failed = 0;
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

    // Use modern, efficient cipher suites (avoid RSA key exchange)
    SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256");
    
    // Disable session resumption - force full handshake every time
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    
    return ctx;
}

void print_stats() {
    struct timespec end_time;
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    
    double elapsed = (end_time.tv_sec - start_time.tv_sec) + 
                     (end_time.tv_nsec - start_time.tv_nsec) / 1e9;
    
    printf("\n=== TLS Handshake Performance Stats ===\n");
    printf("Runtime: %.2f seconds\n", elapsed);
    printf("Completed handshakes: %lu\n", handshakes_completed);
    printf("Failed handshakes: %lu\n", handshakes_failed);
    printf("Handshakes/sec: %.2f\n", handshakes_completed / elapsed);
    printf("=======================================\n");
}

int handle_tls_handshake(client_context_t *client, int epoll_fd) {
    int ret = SSL_do_handshake(client->ssl);
    
    if (ret == 1) {
        // Handshake complete
        client->handshake_complete = 1;
        handshakes_completed++;
        
        // Send a simple response and close
        const char *response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        SSL_write(client->ssl, response, strlen(response));
        
        return 1; // Signal to close connection
    }
    
    int err = SSL_get_error(client->ssl, ret);
    
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        // Need to wait for I/O, modify epoll event
        struct epoll_event ev;
        ev.data.ptr = client;
        ev.events = (err == SSL_ERROR_WANT_READ) ? EPOLLIN : EPOLLOUT;
        ev.events |= EPOLLET; // Edge-triggered
        
        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, client->fd, &ev);
        return 0; // Continue
    }
    
    // Error occurred
    handshakes_failed++;
    return -1;
}

int main(int argc, char *argv[]) {
    int port = 8443;
    const char *cert_file = "certs/server.crt";
    const char *key_file = "certs/server.key";
    
    if (argc >= 2) port = atoi(argv[1]);
    if (argc >= 3) cert_file = argv[2];
    if (argc >= 4) key_file = argv[3];
    
    printf("TLS Handshake Server\n");
    printf("Port: %d\n", port);
    printf("Cert: %s\n", cert_file);
    printf("Key: %s\n", key_file);
    
    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    // Create SSL context
    SSL_CTX *ssl_ctx = create_ssl_context();
    if (!ssl_ctx) {
        fprintf(stderr, "Failed to create SSL context\n");
        return 1;
    }
    
    // Load certificate and key
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
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
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
    
    // Create epoll instance
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        perror("epoll_create1");
        return 1;
    }
    
    // Add listen socket to epoll
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = listen_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &ev) < 0) {
        perror("epoll_ctl");
        return 1;
    }
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    printf("\nServer listening on port %d...\n", port);
    printf("Press Ctrl+C to stop and show stats\n\n");
    
    struct epoll_event events[MAX_EVENTS];
    
    while (running) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, 1000);
        
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
                        perror("accept");
                        continue;
                    }
                    
                    set_nonblocking(client_fd);
                    set_tcp_nodelay(client_fd);
                    
                    // Create SSL connection
                    SSL *ssl = SSL_new(ssl_ctx);
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
                    clock_gettime(CLOCK_MONOTONIC, &ctx->start_time);
                    
                    // Add to epoll
                    struct epoll_event client_ev;
                    client_ev.events = EPOLLIN | EPOLLET;
                    client_ev.data.ptr = ctx;
                    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &client_ev);
                    
                    // Try handshake immediately
                    int result = handle_tls_handshake(ctx, epoll_fd);
                    if (result != 0) {
                        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_fd, NULL);
                        SSL_free(ctx->ssl);
                        close(ctx->fd);
                        free(ctx);
                    }
                }
            } else {
                // Handle client I/O
                client_context_t *ctx = (client_context_t*)events[i].data.ptr;
                
                int result = handle_tls_handshake(ctx, epoll_fd);
                if (result != 0) {
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, ctx->fd, NULL);
                    SSL_free(ctx->ssl);
                    close(ctx->fd);
                    free(ctx);
                }
            }
        }
    }
    
    print_stats();
    
    close(epoll_fd);
    close(listen_fd);
    SSL_CTX_free(ssl_ctx);
    
    return 0;
}

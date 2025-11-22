/*
 * TLS Handshake Performance Test - SYNCHRONOUS Server
 * Demonstrates blocking/synchronous TLS handling (similar to Kestrel's approach)
 * Each connection handled by a separate thread - blocks during SSL_do_handshake()
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BACKLOG 511
#define MAX_THREADS 1000

typedef struct {
    int fd;
    SSL_CTX *ssl_ctx;
    struct timespec start_time;
} thread_args_t;

static volatile int running = 1;
static unsigned long handshakes_completed = 0;
static unsigned long handshakes_failed = 0;
static unsigned long threads_active = 0;
static pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;
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

    // Force TLS 1.3 only
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    
    // TLS 1.3 ciphersuites (note: different API than TLS 1.2)
    SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256");
    
    // Disable session resumption - force full handshake every time
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    
    return ctx;
}

void print_stats() {
    struct timespec end_time;
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    
    double elapsed = (end_time.tv_sec - start_time.tv_sec) + 
                     (end_time.tv_nsec - start_time.tv_nsec) / 1e9;
    
    printf("\n=== SYNC TLS Handshake Performance Stats ===\n");
    printf("Runtime: %.2f seconds\n", elapsed);
    printf("Completed handshakes: %lu\n", handshakes_completed);
    printf("Failed handshakes: %lu\n", handshakes_failed);
    printf("Active threads: %lu\n", threads_active);
    printf("Handshakes/sec: %.2f\n", handshakes_completed / elapsed);
    printf("============================================\n");
}

void* handle_client(void *arg) {
    thread_args_t *args = (thread_args_t*)arg;
    SSL *ssl = NULL;
    int ret;
    
    pthread_mutex_lock(&stats_mutex);
    threads_active++;
    pthread_mutex_unlock(&stats_mutex);
    
    // Enable TCP_NODELAY
    set_tcp_nodelay(args->fd);
    
    // Set socket timeout to avoid hanging on broken connections
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    setsockopt(args->fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(args->fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    // Create SSL connection
    ssl = SSL_new(args->ssl_ctx);
    if (!ssl) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    
    SSL_set_fd(ssl, args->fd);
    SSL_set_accept_state(ssl);
    
    // BLOCKING HANDSHAKE - This is the key difference!
    // Thread is stuck here until handshake completes
    // Just like Kestrel's SSL_do_handshake() behavior
    ret = SSL_do_handshake(ssl);
    
    if (ret == 1) {
        // Handshake succeeded
        pthread_mutex_lock(&stats_mutex);
        handshakes_completed++;
        pthread_mutex_unlock(&stats_mutex);
        
        // Send a simple response and close immediately
        // This forces new TLS handshake on next request
        const char *response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        SSL_write(ssl, response, strlen(response));
    } else {
        // Handshake failed
        int err = SSL_get_error(ssl, ret);
        
        pthread_mutex_lock(&stats_mutex);
        handshakes_failed++;
        pthread_mutex_unlock(&stats_mutex);
        
        // Only log real errors, not client disconnects
        if (err != SSL_ERROR_SYSCALL && err != SSL_ERROR_ZERO_RETURN) {
            // Uncomment to debug: fprintf(stderr, "SSL handshake failed: error=%d\n", err);
            // Uncomment to debug: ERR_print_errors_fp(stderr);
        }
    }
    
cleanup:
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    close(args->fd);
    free(args);
    
    pthread_mutex_lock(&stats_mutex);
    threads_active--;
    pthread_mutex_unlock(&stats_mutex);
    
    return NULL;
}

int main(int argc, char *argv[]) {
    int port = 8443;
    const char *cert_file = "certs/server-p384.crt";
    const char *key_file = "certs/server-p384.key";
    
    if (argc >= 2) port = atoi(argv[1]);
    if (argc >= 3) cert_file = argv[2];
    if (argc >= 4) key_file = argv[3];
    
    printf("SYNCHRONOUS TLS Handshake Server\n");
    printf("Port: %d\n", port);
    printf("Cert: %s\n", cert_file);
    printf("Key: %s\n", key_file);
    printf("Mode: BLOCKING (one thread per connection)\n");
    
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
    
    // Create listening socket (BLOCKING MODE - no O_NONBLOCK!)
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
    
    // NOTE: listen_fd is BLOCKING (synchronous mode)
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    printf("\nServer listening on port %d...\n", port);
    printf("Press Ctrl+C to stop and show stats\n");
    printf("WARNING: This will create one thread per connection!\n\n");
    
    // Accept loop - spawns thread for each connection
    unsigned long connection_count = 0;
    time_t last_stats_time = time(NULL);
    
    while (running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        // Print periodic stats
        time_t current_time = time(NULL);
        if (current_time - last_stats_time >= 5) {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            double elapsed = (now.tv_sec - start_time.tv_sec) + 
                           (now.tv_nsec - start_time.tv_nsec) / 1e9;
            printf("[%ld] Handshakes: %lu completed, %lu failed, Active threads: %lu, Rate: %.2f/sec\n",
                   current_time, handshakes_completed, handshakes_failed, 
                   threads_active, handshakes_completed / elapsed);
            last_stats_time = current_time;
        }
        
        // BLOCKING accept() - waits for connection
        int client_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &client_len);
        
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }
        
        // Check thread limit
        pthread_mutex_lock(&stats_mutex);
        unsigned long current_threads = threads_active;
        pthread_mutex_unlock(&stats_mutex);
        
        if (current_threads >= MAX_THREADS) {
            fprintf(stderr, "Max threads reached (%d), rejecting connection\n", MAX_THREADS);
            close(client_fd);
            continue;
        }
        
        // Allocate args for thread
        thread_args_t *args = malloc(sizeof(thread_args_t));
        if (!args) {
            perror("malloc");
            close(client_fd);
            continue;
        }
        
        args->fd = client_fd;
        args->ssl_ctx = ssl_ctx;
        clock_gettime(CLOCK_MONOTONIC, &args->start_time);
        
        // Spawn thread to handle connection
        pthread_t thread;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        
        if (pthread_create(&thread, &attr, handle_client, args) != 0) {
            perror("pthread_create");
            close(client_fd);
            free(args);
            pthread_attr_destroy(&attr);
            continue;
        }
        
        pthread_attr_destroy(&attr);
    }
    
    print_stats();
    
    // Wait a bit for threads to finish
    printf("\nWaiting for threads to complete...\n");
    sleep(2);
    
    printf("Final active threads: %lu\n", threads_active);
    
    close(listen_fd);
    SSL_CTX_free(ssl_ctx);
    
    return 0;
}

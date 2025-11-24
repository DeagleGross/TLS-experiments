/*
 * TLS Handshake Performance Test - THREAD POOL SYNC Server
 * Similar to .NET thread pool: pre-created worker threads that block on SSL_do_handshake()
 * Each worker picks up connections from a shared queue
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BACKLOG 511
#define NUM_WORKERS 4  // Thread pool size (like .NET thread pool)
#define QUEUE_SIZE 1000

typedef struct {
    int fd;
    struct sockaddr_in addr;
} connection_t;

typedef struct {
    connection_t queue[QUEUE_SIZE];
    int head;
    int tail;
    int count;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} connection_queue_t;

typedef struct {
    int worker_id;
    SSL_CTX *ssl_ctx;
    unsigned long handshakes_completed;
    unsigned long handshakes_failed;
} worker_context_t;

static volatile int running = 1;
static connection_queue_t conn_queue;
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
    
    // TLS 1.3 ciphersuites
    SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256");
    
    // Disable session resumption
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    
    return ctx;
}

void queue_init(connection_queue_t *q) {
    q->head = 0;
    q->tail = 0;
    q->count = 0;
    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->not_empty, NULL);
    pthread_cond_init(&q->not_full, NULL);
}

int queue_push(connection_queue_t *q, int fd, struct sockaddr_in addr) {
    pthread_mutex_lock(&q->mutex);
    
    while (q->count >= QUEUE_SIZE && running) {
        pthread_cond_wait(&q->not_full, &q->mutex);
    }
    
    if (!running) {
        pthread_mutex_unlock(&q->mutex);
        return -1;
    }
    
    q->queue[q->tail].fd = fd;
    q->queue[q->tail].addr = addr;
    q->tail = (q->tail + 1) % QUEUE_SIZE;
    q->count++;
    
    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->mutex);
    
    return 0;
}

int queue_pop(connection_queue_t *q, connection_t *conn) {
    pthread_mutex_lock(&q->mutex);
    
    while (q->count == 0 && running) {
        pthread_cond_wait(&q->not_empty, &q->mutex);
    }
    
    if (!running && q->count == 0) {
        pthread_mutex_unlock(&q->mutex);
        return -1;
    }
    
    *conn = q->queue[q->head];
    q->head = (q->head + 1) % QUEUE_SIZE;
    q->count--;
    
    pthread_cond_signal(&q->not_full);
    pthread_mutex_unlock(&q->mutex);
    
    return 0;
}

void* worker_thread(void *arg) {
    worker_context_t *worker = (worker_context_t*)arg;
    connection_t conn;
    SSL *ssl;
    
    printf("[Worker %d] Started\n", worker->worker_id);
    
    while (running || conn_queue.count > 0) {
        if (queue_pop(&conn_queue, &conn) < 0) {
            break;
        }
        
        set_tcp_nodelay(conn.fd);
        
        // Set socket timeout
        struct timeval timeout;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        setsockopt(conn.fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(conn.fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        
        // Create SSL connection
        ssl = SSL_new(worker->ssl_ctx);
        if (!ssl) {
            close(conn.fd);
            worker->handshakes_failed++;
            continue;
        }
        
        SSL_set_fd(ssl, conn.fd);
        SSL_set_accept_state(ssl);
        
        // BLOCKING HANDSHAKE - thread blocks here (like .NET thread pool)
        int ret = SSL_do_handshake(ssl);
        
        if (ret == 1) {
            // Handshake succeeded
            worker->handshakes_completed++;
            
            // Send response
            const char *response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            SSL_write(ssl, response, strlen(response));
        } else {
            worker->handshakes_failed++;
        }
        
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(conn.fd);
    }
    
    printf("[Worker %d] Shutting down. Completed: %lu, Failed: %lu\n",
           worker->worker_id, worker->handshakes_completed, worker->handshakes_failed);
    
    return NULL;
}

int main(int argc, char *argv[]) {
    int port = 8443;
    const char *cert_file = "certs/server-p384.crt";
    const char *key_file = "certs/server-p384.key";
    
    if (argc >= 2) port = atoi(argv[1]);
    if (argc >= 3) cert_file = argv[2];
    if (argc >= 4) key_file = argv[3];
    
    printf("THREAD POOL SYNC TLS Handshake Server\n");
    printf("Port: %d\n", port);
    printf("Workers: %d\n", NUM_WORKERS);
    printf("Cert: %s\n", cert_file);
    printf("Key: %s\n", key_file);
    printf("Mode: THREAD POOL with blocking SSL (like .NET thread pool)\n\n");
    
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
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    
    // Initialize connection queue
    queue_init(&conn_queue);
    
    // Create worker threads
    pthread_t workers[NUM_WORKERS];
    worker_context_t worker_contexts[NUM_WORKERS];
    
    for (int i = 0; i < NUM_WORKERS; i++) {
        worker_contexts[i].worker_id = i;
        worker_contexts[i].ssl_ctx = ssl_ctx;
        worker_contexts[i].handshakes_completed = 0;
        worker_contexts[i].handshakes_failed = 0;
        
        if (pthread_create(&workers[i], NULL, worker_thread, &worker_contexts[i]) != 0) {
            perror("pthread_create");
            return 1;
        }
    }
    
    printf("\nServer listening on port %d with %d worker threads...\n", port, NUM_WORKERS);
    printf("Press Ctrl+C to stop and show stats\n\n");
    
    // Main thread: accept connections and queue them
    time_t last_stats_time = 0;
    
    while (running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &client_len);
        
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }
        
        // Queue connection for workers to pick up
        if (queue_push(&conn_queue, client_fd, client_addr) < 0) {
            close(client_fd);
        }
        
        // Print periodic stats
        time_t current_time = time(NULL);
        if (current_time - last_stats_time >= 5) {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            double elapsed = (now.tv_sec - start_time.tv_sec) + 
                           (now.tv_nsec - start_time.tv_nsec) / 1e9;
            
            unsigned long total_completed = 0;
            unsigned long total_failed = 0;
            
            for (int i = 0; i < NUM_WORKERS; i++) {
                total_completed += worker_contexts[i].handshakes_completed;
                total_failed += worker_contexts[i].handshakes_failed;
            }
            
            printf("[%ld] Queue: %d, Handshakes: %lu completed, %lu failed, Rate: %.2f/sec\n",
                   current_time, conn_queue.count, total_completed, total_failed, 
                   total_completed / elapsed);
            last_stats_time = current_time;
        }
    }
    
    // Signal workers to stop
    pthread_cond_broadcast(&conn_queue.not_empty);
    
    // Wait for workers to finish
    for (int i = 0; i < NUM_WORKERS; i++) {
        pthread_join(workers[i], NULL);
    }
    
    // Final stats
    struct timespec end_time;
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    double elapsed = (end_time.tv_sec - start_time.tv_sec) + 
                     (end_time.tv_nsec - start_time.tv_nsec) / 1e9;
    
    unsigned long total_completed = 0;
    unsigned long total_failed = 0;
    
    for (int i = 0; i < NUM_WORKERS; i++) {
        total_completed += worker_contexts[i].handshakes_completed;
        total_failed += worker_contexts[i].handshakes_failed;
    }
    
    printf("\n=== THREAD POOL SYNC TLS Performance Stats ===\n");
    printf("Runtime: %.2f seconds\n", elapsed);
    printf("Workers: %d\n", NUM_WORKERS);
    printf("Completed handshakes: %lu\n", total_completed);
    printf("Failed handshakes: %lu\n", total_failed);
    printf("Handshakes/sec: %.2f\n", total_completed / elapsed);
    printf("===============================================\n");
    
    close(listen_fd);
    SSL_CTX_free(ssl_ctx);
    
    return 0;
}

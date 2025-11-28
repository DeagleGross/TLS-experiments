#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <stdatomic.h>

#define MAX_EVENTS 64
#define MAX_CONNECTIONS 10000
#define QUEUE_SIZE 4096

// Request item (C ? C#)
typedef struct {
    int connection_id;
    char* data;
    int length;
    _Atomic int ready; // 0 = empty, 1 = ready
} request_item_t;

// Response item (C# ? C)
typedef struct {
    int connection_id;
    char* data;
    int length;
    _Atomic int ready; // 0 = empty, 1 = ready
} response_item_t;

// Lock-free queue for requests
typedef struct {
    request_item_t* items;
    int capacity;
    _Atomic int write_idx;
    _Atomic int read_idx;
} request_queue_t;

// Lock-free queue for responses
typedef struct {
    response_item_t* items;
    int capacity;
    _Atomic int write_idx;
    _Atomic int read_idx;
} response_queue_t;

// Connection state
typedef struct {
    int id;                    // Unique connection ID
    int fd;
    SSL* ssl;
    int handshake_complete;
    int response_pending;      // Waiting for C# response
    struct timespec start_time;
} connection_state_t;

// Worker thread context
typedef struct {
    int worker_id;
    int epoll_fd;
    int listen_fd;
    SSL_CTX* ssl_ctx;
    pthread_t thread;
    
    // Statistics
    unsigned long handshakes_completed;
    unsigned long handshakes_failed;
    unsigned long connections_accepted;
    unsigned long requests_processed;
} worker_context_t;

// Global state
static volatile int running = 1;
static worker_context_t* workers = NULL;
static int num_workers = 0;

// Request/response queues
static request_queue_t* g_request_queue = NULL;
static response_queue_t* g_response_queue = NULL;

// Event FDs for notification
static int g_request_notify_fd = -1;  // C notifies C#
static int g_response_notify_fd = -1; // C# notifies C

// Connection tracking
static connection_state_t** g_connections = NULL;
static _Atomic int g_next_conn_id = 0;
static pthread_mutex_t g_connections_lock = PTHREAD_MUTEX_INITIALIZER;

// Initialize queues
static int init_queues() {
    // Request queue
    g_request_queue = malloc(sizeof(request_queue_t));
    g_request_queue->capacity = QUEUE_SIZE;
    g_request_queue->items = calloc(QUEUE_SIZE, sizeof(request_item_t));
    atomic_init(&g_request_queue->write_idx, 0);
    atomic_init(&g_request_queue->read_idx, 0);
    
    // Response queue
    g_response_queue = malloc(sizeof(response_queue_t));
    g_response_queue->capacity = QUEUE_SIZE;
    g_response_queue->items = calloc(QUEUE_SIZE, sizeof(response_item_t));
    atomic_init(&g_response_queue->write_idx, 0);
    atomic_init(&g_response_queue->read_idx, 0);
    
    // Create eventfds
    g_request_notify_fd = eventfd(0, EFD_NONBLOCK | EFD_SEMAPHORE);
    g_response_notify_fd = eventfd(0, EFD_NONBLOCK | EFD_SEMAPHORE);
    
    if (g_request_notify_fd < 0 || g_response_notify_fd < 0) {
        perror("eventfd");
        return -1;
    }
    
    // Connection tracking
    g_connections = calloc(MAX_CONNECTIONS, sizeof(connection_state_t*));
    
    return 0;
}

// Enqueue request (C ? C#) - NON-BLOCKING!
static int enqueue_request(int conn_id, const char* data, int length) {
    int write_idx = atomic_load(&g_request_queue->write_idx);
    int next_write = (write_idx + 1) % g_request_queue->capacity;
    int read_idx = atomic_load(&g_request_queue->read_idx);
    
    if (next_write == read_idx) {
        // Queue full
        return -1;
    }
    
    request_item_t* item = &g_request_queue->items[write_idx];
    
    // Allocate and copy data
    item->data = malloc(length);
    memcpy(item->data, data, length);
    item->length = length;
    item->connection_id = conn_id;
    
    // Mark ready
    atomic_store(&item->ready, 1);
    
    // Update write index
    atomic_store(&g_request_queue->write_idx, next_write);
    
    // Notify C# thread
    uint64_t val = 1;
    write(g_request_notify_fd, &val, sizeof(val));
    
    return 0;
}

// Enqueue response (C# ? C) - called from C#
int enqueue_response(int conn_id, const char* data, int length) {
    int write_idx = atomic_load(&g_response_queue->write_idx);
    int next_write = (write_idx + 1) % g_response_queue->capacity;
    int read_idx = atomic_load(&g_response_queue->read_idx);
    
    if (next_write == read_idx) {
        return -1;
    }
    
    response_item_t* item = &g_response_queue->items[write_idx];
    
    // Allocate and copy data
    item->data = malloc(length);
    memcpy(item->data, data, length);
    item->length = length;
    item->connection_id = conn_id;
    
    // Mark ready
    atomic_store(&item->ready, 1);
    
    // Update write index
    atomic_store(&g_response_queue->write_idx, next_write);
    
    // Notify C workers
    uint64_t val = 1;
    write(g_response_notify_fd, &val, sizeof(val));
    
    return 0;
}

// Dequeue request (called from C#)
int dequeue_request(int* conn_id, char** data, int* length) {
    int read_idx = atomic_load(&g_request_queue->read_idx);
    int write_idx = atomic_load(&g_request_queue->write_idx);
    
    if (read_idx == write_idx) {
        return 0; // Empty
    }
    
    request_item_t* item = &g_request_queue->items[read_idx];
    
    // Check if ready
    if (atomic_load(&item->ready) != 1) {
        return 0;
    }
    
    *conn_id = item->connection_id;
    *data = item->data;
    *length = item->length;
    
    // Mark as consumed
    atomic_store(&item->ready, 0);
    
    // Move read index
    int next_read = (read_idx + 1) % g_request_queue->capacity;
    atomic_store(&g_request_queue->read_idx, next_read);
    
    return 1; // Success
}

// Dequeue response (called from C worker)
static int dequeue_response(int* conn_id, char** data, int* length) {
    int read_idx = atomic_load(&g_response_queue->read_idx);
    int write_idx = atomic_load(&g_response_queue->write_idx);
    
    if (read_idx == write_idx) {
        return 0;
    }
    
    response_item_t* item = &g_response_queue->items[read_idx];
    
    if (atomic_load(&item->ready) != 1) {
        return 0;
    }
    
    *conn_id = item->connection_id;
    *data = item->data;
    *length = item->length;
    
    atomic_store(&item->ready, 0);
    
    int next_read = (read_idx + 1) % g_response_queue->capacity;
    atomic_store(&g_response_queue->read_idx, next_read);
    
    return 1;
}

// Get eventfd for C# to wait on
int get_request_notify_fd() {
    return g_request_notify_fd;
}

// Set socket to non-blocking
static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// Set TCP_NODELAY
static int set_tcp_nodelay(int fd) {
    int flag = 1;
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
}

// Handle SSL handshake
static int handle_ssl_handshake(connection_state_t* conn) {
    int ret = SSL_do_handshake(conn->ssl);
    
    if (ret == 1) {
        conn->handshake_complete = 1;
        return 1;
    }
    
    int err = SSL_get_error(conn->ssl, ret);
    
    switch (err) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            return 0;
        default:
            ERR_print_errors_fp(stderr);
            return -1;
    }
}

// Read request and enqueue for C# processing
static void handle_ssl_read(connection_state_t* conn, worker_context_t* worker) {
    char buffer[16384];
    
    int bytes = SSL_read(conn->ssl, buffer, sizeof(buffer));
    
    if (bytes > 0) {
        // Enqueue for C# processing - NON-BLOCKING!
        if (enqueue_request(conn->id, buffer, bytes) == 0) {
            conn->response_pending = 1;
            worker->requests_processed++;
        }
    } else {
        int err = SSL_get_error(conn->ssl, bytes);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            // Error or EOF
            conn->response_pending = -1; // Mark for cleanup
        }
    }
}

// Worker thread
static void* worker_thread(void* arg) {
    worker_context_t* worker = (worker_context_t*)arg;
    struct epoll_event events[MAX_EVENTS];
    
    // Add response notify fd to epoll
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = g_response_notify_fd;
    epoll_ctl(worker->epoll_fd, EPOLL_CTL_ADD, g_response_notify_fd, &ev);
    
    printf("[Worker %d] Started\n", worker->worker_id);
    
    while (running) {
        int nfds = epoll_wait(worker->epoll_fd, events, MAX_EVENTS, 100);
        
        if (nfds < 0) {
            if (errno == EINTR) continue;
            break;
        }
        
        for (int i = 0; i < nfds; i++) {
            int fd = events[i].data.fd;
            
            // Check if it's response notification
            if (fd == g_response_notify_fd) {
                // Drain eventfd
                uint64_t val;
                read(g_response_notify_fd, &val, sizeof(val));
                
                // Process all pending responses
                int conn_id;
                char* data;
                int length;
                
                while (dequeue_response(&conn_id, &data, &length)) {
                    pthread_mutex_lock(&g_connections_lock);
                    connection_state_t* conn = g_connections[conn_id];
                    pthread_mutex_unlock(&g_connections_lock);
                    
                    if (conn && conn->ssl) {
                        SSL_write(conn->ssl, data, length);
                        
                        // Cleanup connection
                        epoll_ctl(worker->epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
                        SSL_shutdown(conn->ssl);
                        SSL_free(conn->ssl);
                        close(conn->fd);
                        
                        pthread_mutex_lock(&g_connections_lock);
                        g_connections[conn_id] = NULL;
                        pthread_mutex_unlock(&g_connections_lock);
                        
                        free(conn);
                    }
                    
                    free(data);
                }
                continue;
            }
            
            // Listen socket - accept
            if (fd == worker->listen_fd) {
                struct sockaddr_in addr;
                socklen_t len = sizeof(addr);
                
                int client_fd = accept(worker->listen_fd, (struct sockaddr*)&addr, &len);
                if (client_fd < 0) continue;
                
                worker->connections_accepted++;
                
                set_nonblocking(client_fd);
                set_tcp_nodelay(client_fd);
                
                SSL* ssl = SSL_new(worker->ssl_ctx);
                if (!ssl) {
                    close(client_fd);
                    continue;
                }
                
                SSL_set_fd(ssl, client_fd);
                SSL_set_accept_state(ssl);
                
                connection_state_t* conn = malloc(sizeof(connection_state_t));
                conn->id = atomic_fetch_add(&g_next_conn_id, 1) % MAX_CONNECTIONS;
                conn->fd = client_fd;
                conn->ssl = ssl;
                conn->handshake_complete = 0;
                conn->response_pending = 0;
                
                pthread_mutex_lock(&g_connections_lock);
                g_connections[conn->id] = conn;
                pthread_mutex_unlock(&g_connections_lock);
                
                ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
                ev.data.ptr = conn;
                epoll_ctl(worker->epoll_fd, EPOLL_CTL_ADD, client_fd, &ev);
                
                handle_ssl_handshake(conn);
            }
            else {
                // Client connection
                connection_state_t* conn = (connection_state_t*)events[i].data.ptr;
                
                if (!conn->handshake_complete) {
                    int result = handle_ssl_handshake(conn);
                    
                    if (result == 1) {
                        worker->handshakes_completed++;
                    } else if (result < 0) {
                        worker->handshakes_failed++;
                        
                        pthread_mutex_lock(&g_connections_lock);
                        g_connections[conn->id] = NULL;
                        pthread_mutex_unlock(&g_connections_lock);
                        
                        epoll_ctl(worker->epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
                        SSL_free(conn->ssl);
                        close(conn->fd);
                        free(conn);
                    }
                } else if (!conn->response_pending) {
                    // Read request and enqueue for C#
                    handle_ssl_read(conn, worker);
                }
            }
        }
    }
    
    printf("[Worker %d] Shutting down\n", worker->worker_id);
    return NULL;
}

// Initialize OpenSSL
void openssl_init() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

// Create SSL context
SSL_CTX* openssl_create_context() {
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    return ctx;
}

// Load certificates
int openssl_load_certificates(SSL_CTX* ctx, const char* cert_file, const char* key_file) {
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) return 0;
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) return 0;
    if (!SSL_CTX_check_private_key(ctx)) return 0;
    return 1;
}

// Start server
int start_nginx_server(int port, const char* cert_file, const char* key_file, int worker_count) {
    printf("=== Native C SSL Server (nginx-style with C# processing) ===\n");
    printf("Port: %d, Workers: %d\n", port, worker_count);
    printf("C handles TLS, C# handles HTTP\n\n");
    
    if (init_queues() < 0) return -1;
    
    openssl_init();
    
    SSL_CTX* ssl_ctx = openssl_create_context();
    if (!ssl_ctx || !openssl_load_certificates(ssl_ctx, cert_file, key_file)) {
        return -1;
    }
    
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) return -1;
    
    int reuse = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
    
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0 ||
        listen(listen_fd, 1024) < 0) {
        return -1;
    }
    
    set_nonblocking(listen_fd);
    
    num_workers = worker_count;
    workers = calloc(num_workers, sizeof(worker_context_t));
    
    for (int i = 0; i < num_workers; i++) {
        workers[i].worker_id = i;
        workers[i].listen_fd = listen_fd;
        workers[i].ssl_ctx = ssl_ctx;
        workers[i].epoll_fd = epoll_create1(0);
        
        struct epoll_event ev;
        ev.events = EPOLLIN | EPOLLET;
        ev.data.fd = listen_fd;
        epoll_ctl(workers[i].epoll_fd, EPOLL_CTL_ADD, listen_fd, &ev);
        
        pthread_create(&workers[i].thread, NULL, worker_thread, &workers[i]);
    }
    
    printf("Started %d workers. C# can now process requests!\n\n", num_workers);
    
    for (int i = 0; i < num_workers; i++) {
        pthread_join(workers[i].thread, NULL);
    }
    
    close(listen_fd);
    SSL_CTX_free(ssl_ctx);
    free(workers);
    
    return 0;
}

void get_server_stats(unsigned long* total_handshakes, unsigned long* total_connections) {
    *total_handshakes = 0;
    *total_connections = 0;
    
    for (int i = 0; i < num_workers; i++) {
        *total_handshakes += workers[i].handshakes_completed;
        *total_connections += workers[i].connections_accepted;
    }
}


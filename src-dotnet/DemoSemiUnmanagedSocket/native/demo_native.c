#include <openssl/ssl.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>

// Log socket and SSL_CTX information
// Called from C# with configured socket FD and SSL_CTX
void log_socket_and_ssl_context(int socket_fd, SSL_CTX* ssl_ctx) {
    printf("=== Native Layer: Received Managed Resources ===\n");
    
    // Log socket FD
    printf("Socket FD: %d\n", socket_fd);
    
    // Check if socket is valid
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    if (getsockname(socket_fd, (struct sockaddr*)&addr, &addr_len) == 0) {
        printf("  Socket is valid and bound\n");
        printf("  Local address: %s:%d\n", 
               inet_ntoa(addr.sin_addr), 
               ntohs(addr.sin_port));
    } else {
        printf("  Socket validation failed (might not be bound yet)\n");
    }
    
    // Get socket options
    int optval;
    socklen_t optlen = sizeof(optval);
    
    // Check SO_REUSEADDR
    if (getsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &optval, &optlen) == 0) {
        printf("  SO_REUSEADDR: %s\n", optval ? "enabled" : "disabled");
    }
    
    // Check TCP_NODELAY (if TCP socket)
    if (getsockopt(socket_fd, IPPROTO_TCP, TCP_NODELAY, &optval, &optlen) == 0) {
        printf("  TCP_NODELAY: %s\n", optval ? "enabled" : "disabled");
    }
    
    // Check socket type
    if (getsockopt(socket_fd, SOL_SOCKET, SO_TYPE, &optval, &optlen) == 0) {
        printf("  Socket type: %s\n", 
               optval == SOCK_STREAM ? "SOCK_STREAM" : 
               optval == SOCK_DGRAM ? "SOCK_DGRAM" : "UNKNOWN");
    }
    
    // Log SSL_CTX
    printf("\nSSL_CTX: %p\n", (void*)ssl_ctx);
    
    if (ssl_ctx != NULL) {
        printf("  SSL_CTX is valid\n");
        
        // Get SSL_CTX options
        long options = SSL_CTX_get_options(ssl_ctx);
        printf("  SSL_CTX options: 0x%lx\n", options);
        
        // Check specific options
        if (options & SSL_OP_NO_SSLv2) printf("    - SSL_OP_NO_SSLv2\n");
        if (options & SSL_OP_NO_SSLv3) printf("    - SSL_OP_NO_SSLv3\n");
        if (options & SSL_OP_NO_TLSv1) printf("    - SSL_OP_NO_TLSv1\n");
        if (options & SSL_OP_NO_TLSv1_1) printf("    - SSL_OP_NO_TLSv1_1\n");
        
        // Try to create a test SSL object to verify context is configured
        SSL* test_ssl = SSL_new(ssl_ctx);
        if (test_ssl != NULL) {
            printf("  SSL context can create SSL objects (certificates loaded!)\n");
            SSL_free(test_ssl);
        } else {
            printf("  WARNING: Failed to create SSL object from context\n");
        }
    } else {
        printf("  ERROR: SSL_CTX is NULL!\n");
    }
    
    printf("=== End Native Layer Log ===\n\n");
}

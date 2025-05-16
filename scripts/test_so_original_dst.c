#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netfilter_ipv4.h>

// Define SO_ORIGINAL_DST if not defined
#ifndef SO_ORIGINAL_DST
#define SO_ORIGINAL_DST 80
#endif

int main(int argc, char *argv[]) {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    int port = 9900;
    
    // Parse command line arguments
    if (argc > 1) {
        port = atoi(argv[1]);
    }
    
    printf("=== SO_ORIGINAL_DST Test Server ===\n");
    printf("Listening on port: %d\n\n", port);
    
    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    
    // Set socket options
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }
    
    // Bind to the port
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);
    
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    
    // Listen for connections
    if (listen(server_fd, 3) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }
    
    printf("Waiting for connections...\n");
    
    while(1) {
        // Accept a connection
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept failed");
            exit(EXIT_FAILURE);
        }
        
        // Get client IP and port
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(address.sin_addr), client_ip, INET_ADDRSTRLEN);
        int client_port = ntohs(address.sin_port);
        
        printf("\nNew connection from %s:%d\n", client_ip, client_port);
        
        // Try to get original destination
        struct sockaddr_in orig_dst;
        socklen_t orig_dst_len = sizeof(orig_dst);
        
        if (getsockopt(new_socket, SOL_IP, SO_ORIGINAL_DST, &orig_dst, &orig_dst_len) == 0) {
            char orig_dst_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(orig_dst.sin_addr), orig_dst_ip, INET_ADDRSTRLEN);
            int orig_dst_port = ntohs(orig_dst.sin_port);
            
            printf("Original destination: %s:%d\n", orig_dst_ip, orig_dst_port);
            
            // Send the original destination back to the client
            char response[256];
            snprintf(response, sizeof(response), 
                     "HTTP/1.1 200 OK\r\n"
                     "Content-Type: text/plain\r\n"
                     "Connection: close\r\n"
                     "\r\n"
                     "Original destination: %s:%d\r\n", 
                     orig_dst_ip, orig_dst_port);
            
            send(new_socket, response, strlen(response), 0);
        } else {
            perror("getsockopt SO_ORIGINAL_DST failed");
            
            // Send error response to the client
            char response[] = "HTTP/1.1 500 Internal Server Error\r\n"
                             "Content-Type: text/plain\r\n"
                             "Connection: close\r\n"
                             "\r\n"
                             "Failed to get original destination\r\n";
            
            send(new_socket, response, strlen(response), 0);
        }
        
        // Close the socket
        close(new_socket);
    }
    
    return 0;
}

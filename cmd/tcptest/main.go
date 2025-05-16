package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"syscall"
)

const SO_ORIGINAL_DST = 80

func main() {
	// Parse command line flags
	port := flag.Int("port", 9900, "Port to listen on")
	flag.Parse()

	// Create a TCP listener
	addr := fmt.Sprintf(":%d", *port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Printf("Error creating listener: %v\n", err)
		os.Exit(1)
	}
	defer listener.Close()

	fmt.Printf("TCP test server listening on %s\n", addr)
	fmt.Printf("This server will log all incoming connections and attempt to get the original destination\n")
	fmt.Printf("Press Ctrl+C to exit\n\n")

	// Accept connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("Error accepting connection: %v\n", err)
			continue
		}

		// Handle the connection in a goroutine
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	// Log the connection
	fmt.Printf("\n[CONNECTION] New connection from %s to %s\n", conn.RemoteAddr(), conn.LocalAddr())

	// Try to get the original destination
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		fmt.Printf("[ORIGINAL_DST] Attempting to get original destination for connection from %s\n", conn.RemoteAddr())

		// Get the file descriptor
		file, err := tcpConn.File()
		if err != nil {
			fmt.Printf("[ORIGINAL_DST] Failed to get file descriptor: %v\n", err)
		} else {
			defer file.Close()

			fd := int(file.Fd())
			fmt.Printf("[ORIGINAL_DST] Got file descriptor %d\n", fd)

			// Get original destination using SO_ORIGINAL_DST socket option
			addr, err := syscall.GetsockoptIPv6Mreq(fd, syscall.IPPROTO_IP, SO_ORIGINAL_DST)
			if err != nil {
				fmt.Printf("[ORIGINAL_DST] Failed to get original destination: %v\n", err)
			} else {
				// Extract IP and port from the sockaddr structure
				ip := net.IPv4(
					addr.Multiaddr[4],
					addr.Multiaddr[5],
					addr.Multiaddr[6],
					addr.Multiaddr[7],
				)

				// Convert port from network byte order (big endian)
				port := int(addr.Multiaddr[2])<<8 | int(addr.Multiaddr[3])

				fmt.Printf("[ORIGINAL_DST] Original destination: %s:%d\n", ip.String(), port)

				// Send a response to the client
				response := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nOriginal destination: %s:%d\r\n", ip.String(), port)
				conn.Write([]byte(response))
			}
		}
	} else {
		fmt.Printf("[ORIGINAL_DST] Connection is not a TCP connection, cannot get original destination\n")
	}

	// Read some data from the connection
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		fmt.Printf("[READ] Error reading from connection: %v\n", err)
	} else if n > 0 {
		fmt.Printf("[READ] Read %d bytes: %s\n", n, string(buffer[:n]))
	}

	// Close the connection
	conn.Close()
	fmt.Printf("[CONNECTION] Connection from %s closed\n", conn.RemoteAddr())
}

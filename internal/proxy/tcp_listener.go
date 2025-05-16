package proxy

import (
	"fmt"
	"net"
	"syscall"
	"time"
)

// DebugListener is a wrapper around net.Listener that logs connections as soon as they're accepted
type DebugListener struct {
	net.Listener
}

// NewDebugListener creates a new DebugListener
func NewDebugListener(addr string) (*DebugListener, error) {
	// Create a TCP listener
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	return &DebugListener{
		Listener: listener,
	}, nil
}

// Accept accepts a connection and logs it immediately
func (l *DebugListener) Accept() (net.Conn, error) {
	// Accept the connection
	conn, err := l.Listener.Accept()
	if err != nil {
		fmt.Printf("[DEBUG-TCP-ACCEPT] Error accepting connection: %v\n", err)
		return nil, err
	}

	// Log the connection immediately
	fmt.Printf("[DEBUG-TCP-ACCEPT] New TCP connection accepted from %s to %s\n", 
		conn.RemoteAddr(), conn.LocalAddr())

	// Try to get the original destination using SO_ORIGINAL_DST
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		fmt.Printf("[DEBUG-TCP-ACCEPT] Attempting to get original destination for connection from %s\n", 
			conn.RemoteAddr())

		// Get the file descriptor
		file, err := tcpConn.File()
		if err != nil {
			fmt.Printf("[DEBUG-TCP-ACCEPT] Failed to get file descriptor: %v\n", err)
		} else {
			defer file.Close()

			fd := int(file.Fd())
			fmt.Printf("[DEBUG-TCP-ACCEPT] Got file descriptor %d for connection from %s\n", 
				fd, conn.RemoteAddr())

			// Get original destination using SO_ORIGINAL_DST socket option
			// This works for connections redirected by iptables REDIRECT or TPROXY
			const SO_ORIGINAL_DST = 80
			addr, err := syscall.GetsockoptIPv6Mreq(fd, syscall.IPPROTO_IP, SO_ORIGINAL_DST)
			if err != nil {
				fmt.Printf("[DEBUG-TCP-ACCEPT] Failed to get original destination: %v\n", err)
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

				fmt.Printf("[DEBUG-TCP-ACCEPT] Original destination: %s:%d for connection from %s\n", 
					ip.String(), port, conn.RemoteAddr())
			}
		}
	} else {
		fmt.Printf("[DEBUG-TCP-ACCEPT] Connection is not a TCP connection, cannot get original destination\n")
	}

	// Wrap the connection to add more debugging
	return &DebugConnection{
		Conn: conn,
	}, nil
}

// DebugConnection is a wrapper around net.Conn that logs read/write operations
type DebugConnection struct {
	net.Conn
}

// Read reads data from the connection and logs it
func (c *DebugConnection) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if err != nil && err != net.ErrClosed {
		fmt.Printf("[DEBUG-TCP-READ] Error reading from %s: %v\n", c.Conn.RemoteAddr(), err)
	} else if n > 0 {
		fmt.Printf("[DEBUG-TCP-READ] Read %d bytes from %s\n", n, c.Conn.RemoteAddr())
	}
	return
}

// Write writes data to the connection and logs it
func (c *DebugConnection) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	if err != nil {
		fmt.Printf("[DEBUG-TCP-WRITE] Error writing to %s: %v\n", c.Conn.RemoteAddr(), err)
	} else if n > 0 {
		fmt.Printf("[DEBUG-TCP-WRITE] Wrote %d bytes to %s\n", n, c.Conn.RemoteAddr())
	}
	return
}

// Close closes the connection and logs it
func (c *DebugConnection) Close() error {
	fmt.Printf("[DEBUG-TCP-CLOSE] Closing connection to %s\n", c.Conn.RemoteAddr())
	return c.Conn.Close()
}

// SetDeadline sets the read and write deadlines
func (c *DebugConnection) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline
func (c *DebugConnection) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline
func (c *DebugConnection) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}

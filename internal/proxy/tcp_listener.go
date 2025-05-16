package proxy

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// DebugListener is a wrapper around net.Listener that logs connections as soon as they're accepted
type DebugListener struct {
	net.Listener
	server *Server // Reference to the server instance
}

// NewDebugListener creates a new DebugListener
func NewDebugListener(addr string, server *Server) (*DebugListener, error) {
	// Create a TCP listener
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	return &DebugListener{
		Listener: listener,
		server:   server,
	}, nil
}

// NewDebugConnection creates a new DebugConnection
func NewDebugConnection(conn net.Conn, server *Server, domain, clientIP, reqID string) *DebugConnection {
	return &DebugConnection{
		Conn:     conn,
		server:   server,
		domain:   domain,
		clientIP: clientIP,
		reqID:    reqID,
	}
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

	// Extract client IP for logging
	clientIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

	// Try to get the original destination using SO_ORIGINAL_DST
	var origDestIP string
	var origDestPort int

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

				origDestIP = ip.String()
				origDestPort = port

				fmt.Printf("[DEBUG-TCP-ACCEPT] Original destination: %s:%d for connection from %s\n",
					origDestIP, origDestPort, conn.RemoteAddr())

				// Check if this IP is already marked for direct tunnel mode
				if l.server != nil {
					l.server.directTunnelMu.Lock()
					directTunnel := l.server.directTunnelDomains[origDestIP]
					fmt.Printf("[DEBUG-TCP-ACCEPT-DIRECT] Checking if IP %s is marked for direct tunnel: %v\n",
						origDestIP, directTunnel)

					// Also check if we have any domains in the directTunnelDomains map
					fmt.Printf("[DEBUG-TCP-ACCEPT-DIRECT] Current directTunnelDomains map contents:\n")
					for domain := range l.server.directTunnelDomains {
						fmt.Printf("[DEBUG-TCP-ACCEPT-DIRECT]   %s\n", domain)
					}
					l.server.directTunnelMu.Unlock()

					if directTunnel {
						fmt.Printf("[DEBUG-TCP-ACCEPT] Original destination IP %s is marked for direct tunnel mode\n", origDestIP)
						fmt.Printf("[DEBUG-TCP-ACCEPT] Using direct TCP tunnel for connection from %s to %s:%d\n",
							clientIP, origDestIP, origDestPort)

						// IMPORTANT: For direct tunnel mode, we handle the connection directly here
						// and do not return it to the HTTP server

						// Create a destination string for logging and dialing
						destAddr := net.JoinHostPort(origDestIP, strconv.Itoa(origDestPort))

						// Get a request ID for this connection
						reqID := l.server.logger.GetRequestID(clientIP, origDestIP)

						// Log that we're starting a direct TCP tunnel
						l.server.logger.InfoWithRequestIDf(reqID, "[TUNNEL-TCP-DIRECT] Starting direct TCP tunnel from %s to %s", clientIP, destAddr)
						fmt.Printf("[DEBUG-DIRECT-TUNNEL-TCP-DIRECT] Starting direct TCP tunnel from %s to %s\n", clientIP, destAddr)

						// Connect directly to the target server
						fmt.Printf("[DEBUG-DIRECT-TUNNEL-TCP-DIRECT] Connecting to %s\n", destAddr)
						targetConn, err := net.DialTimeout("tcp", destAddr, 30*time.Second)
						if err != nil {
							l.server.logger.ErrorWithRequestIDf(reqID, "[ERROR] Failed to connect to target %s: %v", destAddr, err)
							fmt.Printf("[DEBUG-DIRECT-TUNNEL-TCP-DIRECT] Connection failed to %s: %v\n", destAddr, err)
							conn.Close()

							// Instead of returning an error, return a dummy connection that will be ignored by the HTTP server
							// This prevents the HTTP server from exiting with an error
							dummyConn := &DummyConnection{
								clientAddr: conn.RemoteAddr(),
								localAddr:  conn.LocalAddr(),
							}
							return dummyConn, nil
						}

						fmt.Printf("[DEBUG-DIRECT-TUNNEL-TCP-DIRECT] Successfully connected to %s (local: %s, remote: %s)\n",
							destAddr, targetConn.LocalAddr(), targetConn.RemoteAddr())

						// Log that we're starting a pure TCP passthrough tunnel
						l.server.logger.InfoWithRequestIDf(reqID, "[TUNNEL-TCP-DIRECT] Starting pure TCP passthrough tunnel between client %s and target %s",
							clientIP, destAddr)

						// IMPORTANT: In direct tunnel mode, we do not inspect or modify any data
						l.server.logger.InfoWithRequestIDf(reqID, "[TUNNEL-TCP-DIRECT] Pure passthrough mode - no data inspection or modification")

						// Use io.Copy for simple, efficient bidirectional copying
						go func() {
							defer conn.Close()
							defer targetConn.Close()

							// Create a WaitGroup to wait for both copy operations to complete
							var wg sync.WaitGroup
							wg.Add(2)

							// Copy from client to target
							go func() {
								defer wg.Done()
								io.Copy(targetConn, conn)
							}()

							// Copy from target to client
							go func() {
								defer wg.Done()
								io.Copy(conn, targetConn)
							}()

							// Wait for both copy operations to complete
							wg.Wait()

							l.server.logger.InfoWithRequestIDf(reqID, "[TUNNEL-TCP-DIRECT] Direct TCP tunnel closed between %s and %s", clientIP, destAddr)
							fmt.Printf("[DEBUG-DIRECT-TUNNEL-TCP-DIRECT] Direct TCP tunnel closed between %s and %s\n", clientIP, destAddr)
						}()

						// Instead of returning an error, return a dummy connection that will be ignored by the HTTP server
						// This prevents the HTTP server from exiting with an error
						dummyConn := &DummyConnection{
							clientAddr: conn.RemoteAddr(),
							localAddr:  conn.LocalAddr(),
						}
						return dummyConn, nil
					}
				}
			}
		}
	} else {
		fmt.Printf("[DEBUG-TCP-ACCEPT] Connection is not a TCP connection, cannot get original destination\n")
	}

	// Create the debug connection with default values
	debugConn := &DebugConnection{
		Conn:     conn,
		server:   l.server,
		clientIP: clientIP,
	}

	// Set the original destination on the debug connection if we have it
	if origDestIP != "" {
		debugConn.SetOriginalDestination(origDestIP, origDestPort)
	}

	return debugConn, nil
}

// DebugConnection is a wrapper around net.Conn that logs read/write operations
type DebugConnection struct {
	net.Conn
	server       *Server // Reference to the server instance
	domain       string  // Domain being accessed
	clientIP     string  // Client IP address
	reqID        string  // Request ID for logging
	directTunnel bool    // Flag indicating if this connection should use direct tunnel mode
	origDestIP   string  // Original destination IP address
	origDestPort int     // Original destination port
}

// Read reads data from the connection and logs it
func (c *DebugConnection) Read(b []byte) (n int, err error) {
	// If this connection is marked for direct tunnel mode, we should not log or process the data
	// This is to prevent any interference with the direct tunnel
	if c.directTunnel {
		// Just pass through the read without any logging or processing
		return c.Conn.Read(b)
	}

	n, err = c.Conn.Read(b)
	if err != nil && err != net.ErrClosed {
		fmt.Printf("[DEBUG-TCP-READ] Error reading from %s: %v\n", c.Conn.RemoteAddr(), err)

		// Check for connection reset by peer or broken pipe
		if strings.Contains(err.Error(), "connection reset by peer") ||
			strings.Contains(err.Error(), "broken pipe") {
			// Log the connection reset
			fmt.Printf("[DEBUG-TCP-READ] Connection reset detected for %s - this should be treated as a test failure\n",
				c.Conn.RemoteAddr())

			// If we have a server reference and domain, call HandleConnectionReset
			if c.server != nil && c.domain != "" {
				fmt.Printf("[DEBUG-TCP-READ] Calling HandleConnectionReset for domain %s from client %s\n",
					c.domain, c.clientIP)
				c.server.HandleConnectionReset(c.clientIP, c.domain)
			} else {
				fmt.Printf("[DEBUG-TCP-READ] Cannot call HandleConnectionReset: server=%v, domain=%s\n",
					c.server != nil, c.domain)
			}
		}
	} else if n > 0 {
		fmt.Printf("[DEBUG-TCP-READ] Read %d bytes from %s\n", n, c.Conn.RemoteAddr())
	}
	return
}

// Write writes data to the connection and logs it
func (c *DebugConnection) Write(b []byte) (n int, err error) {
	// If this connection is marked for direct tunnel mode, we should not log or process the data
	// This is to prevent any interference with the direct tunnel
	if c.directTunnel {
		// Just pass through the write without any logging or processing
		return c.Conn.Write(b)
	}

	// Log the data being written for debugging
	if len(b) <= 20 {
		// For small writes, log the actual bytes
		fmt.Printf("[DEBUG-TCP-WRITE-DATA] Writing %d bytes to %s: %v\n", len(b), c.Conn.RemoteAddr(), b)

		// Also try to interpret as ASCII
		asciiStr := ""
		for _, byt := range b {
			if byt >= 32 && byt <= 126 {
				asciiStr += string(byt)
			} else {
				asciiStr += "."
			}
		}
		fmt.Printf("[DEBUG-TCP-WRITE-ASCII] ASCII interpretation: %s\n", asciiStr)
	}

	n, err = c.Conn.Write(b)
	if err != nil {
		fmt.Printf("[DEBUG-TCP-WRITE] Error writing to %s: %v\n", c.Conn.RemoteAddr(), err)

		// Check for connection reset by peer or broken pipe
		if strings.Contains(err.Error(), "connection reset by peer") ||
			strings.Contains(err.Error(), "broken pipe") ||
			strings.Contains(err.Error(), "write: broken pipe") {
			// Log the connection reset
			fmt.Printf("[DEBUG-TCP-WRITE] Connection reset detected for %s - this should be treated as a test failure\n",
				c.Conn.RemoteAddr())

			// If we have a server reference and domain, call HandleConnectionReset
			if c.server != nil && c.domain != "" {
				fmt.Printf("[DEBUG-TCP-WRITE] Calling HandleConnectionReset for domain %s from client %s\n",
					c.domain, c.clientIP)
				c.server.HandleConnectionReset(c.clientIP, c.domain)
			} else {
				fmt.Printf("[DEBUG-TCP-WRITE] Cannot call HandleConnectionReset: server=%v, domain=%s\n",
					c.server != nil, c.domain)
			}
		}
	} else if n > 0 {
		fmt.Printf("[DEBUG-TCP-WRITE] Wrote %d bytes to %s\n", n, c.Conn.RemoteAddr())
	}
	return
}

// Close closes the connection and logs it
func (c *DebugConnection) Close() error {
	// If this connection is marked for direct tunnel mode, we should not log
	// This is to prevent any interference with the direct tunnel
	if c.directTunnel {
		// Just pass through the close without any logging
		return c.Conn.Close()
	}

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

// SetDomain sets the domain for this connection
func (c *DebugConnection) SetDomain(domain string) {
	if domain != "" && c.domain != domain {
		fmt.Printf("[DEBUG-TCP-DOMAIN] Setting domain for connection %s to %s\n", c.Conn.RemoteAddr(), domain)
		c.domain = domain
	}
}

// SetClientIP sets the client IP for this connection
func (c *DebugConnection) SetClientIP(clientIP string) {
	if clientIP != "" && c.clientIP != clientIP {
		fmt.Printf("[DEBUG-TCP-CLIENT] Setting client IP for connection %s to %s\n", c.Conn.RemoteAddr(), clientIP)
		c.clientIP = clientIP
	}
}

// SetRequestID sets the request ID for this connection
func (c *DebugConnection) SetRequestID(reqID string) {
	if reqID != "" && c.reqID != reqID {
		fmt.Printf("[DEBUG-TCP-REQID] Setting request ID for connection %s to %s\n", c.Conn.RemoteAddr(), reqID)
		c.reqID = reqID
	}
}

// SetDirectTunnel marks this connection for direct tunnel mode
func (c *DebugConnection) SetDirectTunnel(directTunnel bool) {
	if c.directTunnel != directTunnel {
		fmt.Printf("[DEBUG-TCP-TUNNEL] Setting direct tunnel mode for connection %s to %v\n", c.Conn.RemoteAddr(), directTunnel)
		c.directTunnel = directTunnel
	}
}

// IsDirectTunnel returns whether this connection should use direct tunnel mode
func (c *DebugConnection) IsDirectTunnel() bool {
	return c.directTunnel
}

// SetOriginalDestination sets the original destination IP and port for this connection
func (c *DebugConnection) SetOriginalDestination(ip string, port int) {
	c.origDestIP = ip
	c.origDestPort = port
	fmt.Printf("[DEBUG-TCP-ORIGDST] Setting original destination for connection %s to %s:%d\n",
		c.Conn.RemoteAddr(), ip, port)
}

// GetOriginalDestination returns the original destination IP and port for this connection
func (c *DebugConnection) GetOriginalDestination() (string, int) {
	return c.origDestIP, c.origDestPort
}

// DirectTunnelListener is a wrapper around net.Listener that handles direct tunnel connections
// It checks if the original destination IP is marked for direct tunnel mode and handles it directly
type DirectTunnelListener struct {
	net.Listener
	server *Server // Reference to the server instance
}

// Accept accepts a connection and checks if it should be handled as a direct tunnel
func (l *DirectTunnelListener) Accept() (net.Conn, error) {
	// Accept the connection from the underlying listener
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	fmt.Printf("[DEBUG-DIRECT-TUNNEL-LISTENER-ACCEPT] Accepted connection from %s to %s\n",
		conn.RemoteAddr(), conn.LocalAddr())

	// Check if this is a DebugConnection
	debugConn, ok := conn.(*DebugConnection)
	if !ok {
		// If it's not a DebugConnection, just return it as-is
		fmt.Printf("[DEBUG-DIRECT-TUNNEL-LISTENER-ACCEPT] Connection is not a DebugConnection, returning as-is\n")
		return conn, nil
	}

	fmt.Printf("[DEBUG-DIRECT-TUNNEL-LISTENER-ACCEPT] Connection is a DebugConnection\n")

	// Get the original destination IP and port
	origDestIP, origDestPort := debugConn.GetOriginalDestination()
	fmt.Printf("[DEBUG-DIRECT-TUNNEL-LISTENER-ACCEPT] Original destination: %s:%d\n",
		origDestIP, origDestPort)

	if origDestIP == "" {
		// If we don't have an original destination, just return the connection as-is
		fmt.Printf("[DEBUG-DIRECT-TUNNEL-LISTENER-ACCEPT] No original destination, returning connection as-is\n")
		return conn, nil
	}

	// Check if this IP is already marked for direct tunnel mode
	l.server.directTunnelMu.Lock()
	directTunnel := l.server.directTunnelDomains[origDestIP]

	// Log the direct tunnel domains map for debugging
	fmt.Printf("[DEBUG-DIRECT-TUNNEL-LISTENER] Checking if IP %s is marked for direct tunnel: %v\n",
		origDestIP, directTunnel)
	fmt.Printf("[DEBUG-DIRECT-TUNNEL-LISTENER] Current directTunnelDomains map contents:\n")
	for domain := range l.server.directTunnelDomains {
		fmt.Printf("[DEBUG-DIRECT-TUNNEL-LISTENER]   %s\n", domain)
	}
	l.server.directTunnelMu.Unlock()

	if directTunnel {
		// This connection should use direct tunnel mode
		fmt.Printf("[DEBUG-DIRECT-TUNNEL-LISTENER] Original destination IP %s is marked for direct tunnel mode\n", origDestIP)
		fmt.Printf("[DEBUG-DIRECT-TUNNEL-LISTENER] Using direct TCP tunnel for connection from %s to %s:%d\n",
			debugConn.clientIP, origDestIP, origDestPort)

		// Get a request ID for this connection
		reqID := l.server.logger.GetRequestID(debugConn.clientIP, origDestIP)

		// Log that we're starting a direct TCP tunnel
		l.server.logger.InfoWithRequestIDf(reqID, "[TUNNEL-TCP-DIRECT] Starting direct TCP tunnel from %s to %s:%d",
			debugConn.clientIP, origDestIP, origDestPort)

		// Create a destination string for logging and dialing
		destAddr := net.JoinHostPort(origDestIP, strconv.Itoa(origDestPort))

		// Connect directly to the target server
		fmt.Printf("[DEBUG-DIRECT-TUNNEL-LISTENER] Connecting to %s\n", destAddr)
		targetConn, err := net.DialTimeout("tcp", destAddr, 30*time.Second)
		if err != nil {
			l.server.logger.ErrorWithRequestIDf(reqID, "[ERROR] Failed to connect to target %s: %v", destAddr, err)
			fmt.Printf("[DEBUG-DIRECT-TUNNEL-LISTENER] Connection failed to %s: %v\n", destAddr, err)
			conn.Close()

			// Return a dummy connection to prevent the HTTP server from exiting with an error
			return &DummyConnection{
				clientAddr: conn.RemoteAddr(),
				localAddr:  conn.LocalAddr(),
			}, nil
		}

		fmt.Printf("[DEBUG-DIRECT-TUNNEL-LISTENER] Successfully connected to %s (local: %s, remote: %s)\n",
			destAddr, targetConn.LocalAddr(), targetConn.RemoteAddr())

		// Log that we're starting a pure TCP passthrough tunnel
		l.server.logger.InfoWithRequestIDf(reqID, "[TUNNEL-TCP-DIRECT] Starting pure TCP passthrough tunnel between client %s and target %s",
			debugConn.clientIP, destAddr)

		// IMPORTANT: In direct tunnel mode, we do not inspect or modify any data
		l.server.logger.InfoWithRequestIDf(reqID, "[TUNNEL-TCP-DIRECT] Pure passthrough mode - no data inspection or modification")

		// Start a goroutine to handle the direct tunnel
		go func() {
			defer conn.Close()
			defer targetConn.Close()

			// Create a WaitGroup to wait for both copy operations to complete
			var wg sync.WaitGroup
			wg.Add(2)

			// Copy from client to target
			go func() {
				defer wg.Done()
				io.Copy(targetConn, conn)
			}()

			// Copy from target to client
			go func() {
				defer wg.Done()
				io.Copy(conn, targetConn)
			}()

			// Wait for both copy operations to complete
			wg.Wait()

			l.server.logger.InfoWithRequestIDf(reqID, "[TUNNEL-TCP-DIRECT] Direct TCP tunnel closed between %s and %s",
				debugConn.clientIP, destAddr)
			fmt.Printf("[DEBUG-DIRECT-TUNNEL-LISTENER] Direct TCP tunnel closed between %s and %s\n",
				debugConn.clientIP, destAddr)
		}()

		// Return a dummy connection to prevent the HTTP server from exiting with an error
		return &DummyConnection{
			clientAddr: conn.RemoteAddr(),
			localAddr:  conn.LocalAddr(),
		}, nil
	}

	// If this connection is not marked for direct tunnel mode, just return it as-is
	return conn, nil
}

// DummyConnection is a dummy connection that does nothing
// It's used to return a connection from Accept when we've already handled the connection
// This prevents the HTTP server from exiting with an error
type DummyConnection struct {
	clientAddr net.Addr
	localAddr  net.Addr
}

// Read implements the net.Conn interface
func (c *DummyConnection) Read(b []byte) (n int, err error) {
	// Always return EOF to indicate that the connection is closed
	return 0, io.EOF
}

// Write implements the net.Conn interface
func (c *DummyConnection) Write(b []byte) (n int, err error) {
	// Always return EOF to indicate that the connection is closed
	return 0, io.EOF
}

// Close implements the net.Conn interface
func (c *DummyConnection) Close() error {
	// Do nothing
	return nil
}

// LocalAddr implements the net.Conn interface
func (c *DummyConnection) LocalAddr() net.Addr {
	return c.localAddr
}

// RemoteAddr implements the net.Conn interface
func (c *DummyConnection) RemoteAddr() net.Addr {
	return c.clientAddr
}

// SetDeadline implements the net.Conn interface
func (c *DummyConnection) SetDeadline(t time.Time) error {
	// Do nothing
	return nil
}

// SetReadDeadline implements the net.Conn interface
func (c *DummyConnection) SetReadDeadline(t time.Time) error {
	// Do nothing
	return nil
}

// SetWriteDeadline implements the net.Conn interface
func (c *DummyConnection) SetWriteDeadline(t time.Time) error {
	// Do nothing
	return nil
}

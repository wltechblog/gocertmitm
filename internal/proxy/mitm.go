package proxy

import (
	"net"
	"sync"
	"time"
)

// copyData copies data between two connections
// This is a simpler version of the data copying logic used in handleDirectTunnel
// It's used for regular MITM connections
func copyData(dst, src net.Conn) {
	defer dst.Close()
	defer src.Close()

	// Use a larger buffer for better performance
	buf := make([]byte, 64*1024)
	bytesTransferred := int64(0)

	for {
		// Set read timeout
		src.SetReadDeadline(time.Now().Add(30 * time.Second))

		// Read from source
		n, err := src.Read(buf)
		if n > 0 {
			bytesTransferred += int64(n)

			// Set write timeout
			dst.SetWriteDeadline(time.Now().Add(30 * time.Second))

			// Write to destination
			_, writeErr := dst.Write(buf[:n])
			if writeErr != nil {
				// Write error
				break
			}
		}

		if err != nil {
			// Read error (EOF is normal)
			break
		}
	}
}

// Note: We're using the copyData function instead of copyBuffer

// ConnectionTracker tracks connections
type ConnectionTracker struct {
	connections map[string]int
	mu          sync.Mutex
}

// NewConnectionTracker creates a new connection tracker
func NewConnectionTracker() *ConnectionTracker {
	return &ConnectionTracker{
		connections: make(map[string]int),
	}
}

// Track tracks a connection
func (c *ConnectionTracker) Track(clientIP string, isConnect bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if isConnect {
		c.connections[clientIP]++
	} else {
		c.connections[clientIP]--
		if c.connections[clientIP] <= 0 {
			delete(c.connections, clientIP)
		}
	}
}

// Count returns the number of connections for a client
func (c *ConnectionTracker) Count(clientIP string) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.connections[clientIP]
}

// GetAll returns all connections
func (c *ConnectionTracker) GetAll() map[string]int {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Create a copy of the connections map
	connections := make(map[string]int, len(c.connections))
	for k, v := range c.connections {
		connections[k] = v
	}

	return connections
}

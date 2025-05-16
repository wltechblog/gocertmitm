package proxy

import (
	"io"
	"net"
	"sync"
	"time"

	"github.com/gocertmitm/internal/certificates"
)

// copyData copies data between two connections with an inactivity timeout
// It's used for regular MITM connections
func copyData(dst, src net.Conn, reqID string, domain string, server *Server) {
	defer dst.Close()
	defer src.Close()

	// Use a larger buffer for better performance
	buf := make([]byte, 64*1024)

	// Create a channel to signal activity
	activity := make(chan struct{}, 1)

	// Create a channel to signal when the connection should be closed due to inactivity
	closeConn := make(chan struct{}, 1)

	// Start a goroutine to monitor for inactivity
	go func() {
		inactivityTimeout := 10 * time.Second
		timer := time.NewTimer(inactivityTimeout)
		defer timer.Stop()

		for {
			select {
			case <-activity:
				// Reset the timer when there's activity
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(inactivityTimeout)
			case <-timer.C:
				// Timeout occurred - close the connection and record as a test failure
				if server != nil && domain != "" && reqID != "" {
					// Get the current test type for this domain
					testType := server.tester.GetNextTest(domain)

					// Record the timeout as a test failure if we're not already in direct tunnel mode
					if testType != certificates.DirectTunnel {
						server.logger.InfoWithRequestIDf(reqID, "[TIMEOUT] No activity for %s on MITM connection for %s - closing connection",
							inactivityTimeout, domain)
						server.logger.InfoWithRequestIDf(reqID, "[TIMEOUT] Recording timeout as a test failure for %s with test type %s",
							domain, testType.GetTestTypeName())

						// Record the failure and get the next test type
						nextTest := server.tester.RecordTestResult(domain, testType, false)

						server.logger.InfoWithRequestIDf(reqID, "[NEXT] Moving to next test for %s due to timeout: %s",
							domain, nextTest.GetTestTypeName())
					}
				}

				closeConn <- struct{}{}
				return
			}
		}
	}()

	// Copy loop with activity signaling and timeout checking
	for {
		// Check if we should close due to inactivity
		select {
		case <-closeConn:
			return
		default:
			// Continue with normal operation
		}

		// Set a read deadline to ensure we can check for the close signal periodically
		src.SetReadDeadline(time.Now().Add(1 * time.Second))

		// Read from source
		n, err := src.Read(buf)
		if n > 0 {
			// Signal activity
			select {
			case activity <- struct{}{}:
			default:
				// Channel buffer is full, which is fine
			}

			// Write to destination
			_, writeErr := dst.Write(buf[:n])
			if writeErr != nil {
				// Write error
				return
			}
		}

		if err != nil {
			if err == io.EOF {
				// Normal end of connection
				return
			} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// This is just our read deadline - continue the loop
				continue
			} else {
				// Other read error
				return
			}
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

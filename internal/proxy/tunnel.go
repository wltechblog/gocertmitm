package proxy

import (
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// handleDirectTunnel creates a direct tunnel between the client and the target server
// This is used when all MITM tests have failed and we want to allow the connection to proceed
func (s *Server) handleDirectTunnel(w http.ResponseWriter, r *http.Request) {
	// Declare variables we'll use throughout the function
	var err error

	// Get client IP
	clientIP := getClientIP(r)

	// Extract the host and port
	host := r.Host
	var hostWithoutPort string

	if strings.Contains(host, ":") {
		var splitErr error
		hostWithoutPort, _, splitErr = net.SplitHostPort(host)
		if splitErr != nil {
			hostWithoutPort = host
		}
	} else {
		hostWithoutPort = host
	}

	// Resolve the destination IP from the host
	var destIP string

	// Check if the host is already an IP address
	if net.ParseIP(hostWithoutPort) != nil {
		destIP = hostWithoutPort
	} else {
		// Resolve the domain to an IP address
		ips, resolveErr := net.LookupIP(hostWithoutPort)
		if resolveErr != nil {
			// Continue with the domain name even if we can't resolve it
		} else if len(ips) > 0 {
			// Use the first IP address
			destIP = ips[0].String()
		}
	}

	// Get a request ID for this connection
	reqID := s.logger.GetRequestID(clientIP, hostWithoutPort)

	// Log the destination IP if available
	if destIP != "" {
		s.logger.DebugWithRequestIDf(reqID, "[TUNNEL] Resolved host %s to IP %s", hostWithoutPort, destIP)
	}

	// Hijack the connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		s.logger.ErrorWithRequestIDf(reqID, "[ERROR] Hijacking not supported for client %s", clientIP)
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, clientBuf, hijackErr := hijacker.Hijack()
	if hijackErr != nil {
		s.logger.ErrorWithRequestIDf(reqID, "[ERROR] Failed to hijack connection from %s: %v", clientIP, hijackErr)
		http.Error(w, hijackErr.Error(), http.StatusServiceUnavailable)
		return
	}

	// Set a deadline for the client connection
	if err := clientConn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		s.logger.ErrorWithRequestIDf(reqID, "[ERROR] Failed to set deadline for client connection: %v", err)
	}

	// Connect directly to the target server
	s.logger.DebugWithRequestIDf(reqID, "[TUNNEL] Connecting directly to target server: %s", r.Host)
	targetConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		s.logger.ErrorWithRequestIDf(reqID, "[ERROR] Failed to connect to target %s: %v", r.Host, err)
		clientConn.Close()
		return
	}

	// Set a deadline for the target connection
	if err := targetConn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		s.logger.ErrorWithRequestIDf(reqID, "[ERROR] Failed to set deadline for target connection: %v", err)
	}

	// Respond to the client that the connection is established
	s.logger.DebugWithRequestIDf(reqID, "[TUNNEL] Sending 200 Connection established to client %s", clientIP)
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	if err != nil {
		s.logger.ErrorWithRequestIDf(reqID, "[ERROR] Failed to write to client %s: %v", clientIP, err)
		clientConn.Close()
		targetConn.Close()
		return
	}

	// Check if there's any buffered data from the client
	if clientBuf != nil && clientBuf.Reader.Buffered() > 0 {
		// Read the buffered data
		bufferedData := make([]byte, clientBuf.Reader.Buffered())
		_, err := clientBuf.Read(bufferedData)
		if err != nil {
			s.logger.ErrorWithRequestIDf(reqID, "[ERROR] Failed to read buffered data from client %s: %v", clientIP, err)
		} else {
			s.logger.DebugWithRequestIDf(reqID, "[TUNNEL] Forwarding %d bytes of buffered data from client %s to target %s",
				len(bufferedData), clientIP, r.Host)

			// Forward the buffered data to the target
			_, err = targetConn.Write(bufferedData)
			if err != nil {
				s.logger.ErrorWithRequestIDf(reqID, "[ERROR] Failed to forward buffered data to target %s: %v", r.Host, err)
				clientConn.Close()
				targetConn.Close()
				return
			}
		}
	}

	// Start proxying data between client and target
	s.logger.InfoWithRequestIDf(reqID, "[TUNNEL] Starting direct tunnel between client %s and target %s", clientIP, r.Host)

	// Create a WaitGroup to wait for both goroutines to complete
	var wg sync.WaitGroup
	wg.Add(2)

	// Forward data from target to client
	go func() {
		defer wg.Done()
		defer clientConn.Close()
		defer targetConn.Close()

		// Use a larger buffer for better performance
		buf := make([]byte, 64*1024)
		bytesTransferred := int64(0)

		for {
			// Set read timeout
			targetConn.SetReadDeadline(time.Now().Add(30 * time.Second))

			// Read from target
			n, err := targetConn.Read(buf)
			if n > 0 {
				bytesTransferred += int64(n)

				// Set write timeout
				clientConn.SetWriteDeadline(time.Now().Add(30 * time.Second))

				// Write to client
				_, writeErr := clientConn.Write(buf[:n])
				if writeErr != nil {
					s.logger.DebugWithRequestIDf(reqID, "[ERROR] Write error to client: %v", writeErr)
					break
				}
			}

			if err != nil {
				if err != io.EOF {
					s.logger.DebugWithRequestIDf(reqID, "[ERROR] Read error from target: %v", err)
				}
				break
			}
		}

		s.logger.DebugWithRequestIDf(reqID, "[TUNNEL] Finished proxying data from target %s to client %s (%d bytes)",
			r.Host, clientIP, bytesTransferred)
	}()

	// Forward data from client to target
	go func() {
		defer wg.Done()
		defer clientConn.Close()
		defer targetConn.Close()

		// Use a larger buffer for better performance
		buf := make([]byte, 64*1024)
		bytesTransferred := int64(0)

		for {
			// Set read timeout
			clientConn.SetReadDeadline(time.Now().Add(30 * time.Second))

			// Read from client
			n, err := clientConn.Read(buf)
			if n > 0 {
				bytesTransferred += int64(n)

				// Set write timeout
				targetConn.SetWriteDeadline(time.Now().Add(30 * time.Second))

				// Write to target
				_, writeErr := targetConn.Write(buf[:n])
				if writeErr != nil {
					s.logger.DebugWithRequestIDf(reqID, "[ERROR] Write error to target: %v", writeErr)
					break
				}
			}

			if err != nil {
				if err != io.EOF {
					s.logger.DebugWithRequestIDf(reqID, "[ERROR] Read error from client: %v", err)
				}
				break
			}
		}

		s.logger.DebugWithRequestIDf(reqID, "[TUNNEL] Finished proxying data from client %s to target %s (%d bytes)",
			clientIP, r.Host, bytesTransferred)
	}()

	// Wait for both goroutines to complete (this will block until the connection is closed)
	// We don't actually wait here since this would block the HTTP handler
	// The goroutines will clean up the connections when they're done
}

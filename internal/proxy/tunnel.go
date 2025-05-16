package proxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// isMQTTPacket checks if the data looks like an MQTT packet
// MQTT packets start with a control packet type in the first byte
// The first 4 bits of the first byte indicate the packet type
// MQTT CONNECT packet has type 1 (0001xxxx)
func isMQTTPacket(data []byte) bool {
	// Check if we have enough data
	if len(data) < 2 {
		return false
	}

	// Extract the packet type (first 4 bits of the first byte)
	packetType := (data[0] & 0xF0) >> 4

	// MQTT CONNECT packet has type 1
	// Other common MQTT packet types: PUBLISH (3), SUBSCRIBE (8), etc.
	if packetType == 1 {
		// This is likely a CONNECT packet, which is the first packet in an MQTT connection
		// Additional validation could be done here if needed
		return true
	}

	// Check for other common MQTT packet types
	// This helps identify MQTT traffic that might not start with a CONNECT packet
	if packetType >= 1 && packetType <= 14 {
		// These are all valid MQTT packet types
		// We could do more validation here, but this is a good first check
		return true
	}

	return false
}

// parseTLSClientHello attempts to extract the SNI from a TLS ClientHello message
// It returns the SNI hostname if found, or an empty string if not found or if the data is not a valid ClientHello
// This function doesn't use the bytes package to avoid import issues
func parseTLSClientHello(data []byte) string {
	// Check if we have enough data for a TLS record
	if len(data) < 5 {
		return ""
	}

	// Check if this is a TLS handshake record (type 22)
	if data[0] != 22 {
		return ""
	}

	// Check TLS version (should be 3.1 for TLS 1.0 or higher)
	if data[1] < 3 || (data[1] == 3 && data[2] == 0) {
		return ""
	}

	// Get the length of the TLS record
	recordLength := int(data[3])<<8 | int(data[4])
	if len(data) < recordLength+5 {
		return ""
	}

	// Move to the handshake message
	data = data[5:]
	if len(data) < 4 {
		return ""
	}

	// Check if this is a ClientHello message (type 1)
	if data[0] != 1 {
		return ""
	}

	// Get the length of the handshake message
	handshakeLength := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) < handshakeLength+4 {
		return ""
	}

	// Move to the ClientHello message body
	data = data[4:]
	if len(data) < 34 {
		return ""
	}

	// Skip client version (2 bytes)
	data = data[2:]

	// Skip client random (32 bytes)
	data = data[32:]
	if len(data) < 1 {
		return ""
	}

	// Skip session ID
	sessionIDLength := int(data[0])
	data = data[1:]
	if len(data) < sessionIDLength {
		return ""
	}
	data = data[sessionIDLength:]
	if len(data) < 2 {
		return ""
	}

	// Skip cipher suites
	cipherSuitesLength := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if len(data) < cipherSuitesLength {
		return ""
	}
	data = data[cipherSuitesLength:]
	if len(data) < 1 {
		return ""
	}

	// Skip compression methods
	compressionMethodsLength := int(data[0])
	data = data[1:]
	if len(data) < compressionMethodsLength {
		return ""
	}
	data = data[compressionMethodsLength:]
	if len(data) < 2 {
		return ""
	}

	// Check if we have extensions
	if len(data) < 2 {
		return ""
	}
	extensionsLength := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if len(data) < extensionsLength {
		return ""
	}

	// Parse extensions
	extensionsEnd := extensionsLength
	for pos := 0; pos < extensionsEnd; {
		if pos+4 > extensionsEnd {
			return ""
		}

		// Get extension type and length
		extensionType := int(data[pos])<<8 | int(data[pos+1])
		extensionLength := int(data[pos+2])<<8 | int(data[pos+3])
		pos += 4

		if pos+extensionLength > extensionsEnd {
			return ""
		}

		// Check if this is the server name extension (type 0)
		if extensionType == 0 {
			// Parse the server name extension
			if extensionLength < 2 {
				return ""
			}

			// Get the server name list length
			listLength := int(data[pos])<<8 | int(data[pos+1])
			pos += 2

			if listLength > extensionLength-2 {
				return ""
			}

			// Parse each server name entry
			listEnd := pos + listLength
			for pos < listEnd {
				if pos+3 > listEnd {
					return ""
				}

				// Check if this is a hostname (type 0)
				nameType := data[pos]
				nameLength := int(data[pos+1])<<8 | int(data[pos+2])
				pos += 3

				if pos+nameLength > listEnd {
					return ""
				}

				if nameType == 0 {
					// This is a hostname, return it
					return string(data[pos : pos+nameLength])
				}

				pos += nameLength
			}
		}

		pos += extensionLength
	}

	return ""
}

// handleDirectTunnelTCP creates a direct tunnel between the client and the target server at the TCP level
// This is used when a connection is immediately identified as needing direct tunnel mode
func (s *Server) handleDirectTunnelTCP(clientConn net.Conn, destIP string, destPort int) {
	// Get client IP for logging
	clientIP, _, _ := net.SplitHostPort(clientConn.RemoteAddr().String())

	// Create a destination string for logging and dialing
	// Use net.JoinHostPort to properly handle IPv6 addresses
	destAddr := net.JoinHostPort(destIP, strconv.Itoa(destPort))

	// Get a request ID for this connection
	reqID := s.logger.GetRequestID(clientIP, destIP)

	// Log that we're starting a direct TCP tunnel
	s.logger.InfoWithRequestIDf(reqID, "[TUNNEL-TCP] Starting direct TCP tunnel from %s to %s", clientIP, destAddr)
	s.logger.DebugWithRequestIDf(reqID, "[DIRECT-TUNNEL-TCP] Starting direct TCP tunnel from %s to %s", clientIP, destAddr)

	// IMPORTANT: We need to establish the outbound connection BEFORE reading any data from the client
	// This ensures that we can immediately forward any data we read from the client to the target

	// Connect directly to the target server
	s.logger.DebugWithRequestIDf(reqID, "[DIRECT-TUNNEL-TCP] Connecting to %s", destAddr)
	targetConn, err := net.DialTimeout("tcp", destAddr, 30*time.Second)
	if err != nil {
		s.logger.ErrorWithRequestIDf(reqID, "[ERROR] Failed to connect to target %s: %v", destAddr, err)
		s.logger.DebugWithRequestIDf(reqID, "[DIRECT-TUNNEL-TCP] Connection failed to %s: %v", destAddr, err)
		clientConn.Close()
		return
	}

	s.logger.DebugWithRequestIDf(reqID, "[DIRECT-TUNNEL-TCP] Successfully connected to %s (local: %s, remote: %s)",
		destAddr, targetConn.LocalAddr(), targetConn.RemoteAddr())

	// Log that we're starting a pure TCP passthrough tunnel
	s.logger.InfoWithRequestIDf(reqID, "[TUNNEL-TCP] Starting pure TCP passthrough tunnel between client %s and target %s",
		clientIP, destAddr)

	// IMPORTANT: In direct tunnel mode, we do not inspect or modify any data
	// We simply establish the outgoing connection and forward packets between
	// the client and server without any inspection or modification
	s.logger.InfoWithRequestIDf(reqID, "[TUNNEL-TCP] Pure passthrough mode - no data inspection or modification")

	// Use io.Copy for simple, efficient bidirectional copying
	// This is more efficient than our custom loop and less prone to errors

	// Create a channel to signal when the connection is closed
	done := make(chan struct{}, 2)

	// Copy from client to target
	go func(connReqID string) {
		// Use io.Copy for efficient copying
		n, err := io.Copy(targetConn, clientConn)
		if err != nil && err != io.EOF {
			s.logger.DebugWithRequestIDf(connReqID, "[TUNNEL-TCP] Error copying from client to target: %v", err)
		} else {
			s.logger.DebugWithRequestIDf(connReqID, "[TUNNEL-TCP] Copied %d bytes from client to target", n)
		}

		// Signal that we're done
		done <- struct{}{}
	}(reqID)

	// Copy from target to client
	go func(connReqID string) {
		// Use io.Copy for efficient copying
		n, err := io.Copy(clientConn, targetConn)
		if err != nil && err != io.EOF {
			s.logger.DebugWithRequestIDf(connReqID, "[TUNNEL-TCP] Error copying from target to client: %v", err)
		} else {
			s.logger.DebugWithRequestIDf(connReqID, "[TUNNEL-TCP] Copied %d bytes from target to client", n)
		}

		// Signal that we're done
		done <- struct{}{}
	}(reqID)

	// Wait for either goroutine to finish
	<-done

	// Close both connections
	clientConn.Close()
	targetConn.Close()

	// Wait for the other goroutine to finish (it will finish quickly once the connections are closed)
	<-done

	s.logger.InfoWithRequestIDf(reqID, "[TUNNEL-TCP] Direct TCP tunnel closed between %s and %s", clientIP, destAddr)
	s.logger.DebugWithRequestIDf(reqID, "[DIRECT-TUNNEL-TCP] Direct TCP tunnel closed between %s and %s", clientIP, destAddr)
}

// handleDirectTunnel creates a direct tunnel between the client and the target server
// This is used when all MITM tests have failed and we want to allow the connection to proceed
func (s *Server) handleDirectTunnel(w http.ResponseWriter, r *http.Request) {
	// Declare variables we'll use throughout the function
	var err error

	// Get client IP
	clientIP := getClientIP(r)

	// Get a request ID for this connection
	reqID := s.logger.GetRequestID(clientIP, r.Host)

	// Print immediate debug information about the direct tunnel request
	s.logger.DebugWithRequestIDf(reqID, "[DIRECT-TUNNEL] New direct tunnel request from %s to %s",
		clientIP, r.Host)

	// Log all request headers for debugging
	s.logger.DebugWithRequestIDf(reqID, "[DIRECT-TUNNEL-HEADERS] Request headers from %s:", clientIP)
	for name, values := range r.Header {
		for _, value := range values {
			s.logger.DebugWithRequestIDf(reqID, "[DIRECT-TUNNEL-HEADERS]   %s: %s", name, value)
		}
	}

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

	// Update the request ID with the hostname
	reqID = s.logger.GetRequestID(clientIP, hostWithoutPort)

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

	// If this is a DebugConnection, set the domain and client IP
	if debugConn, ok := clientConn.(*DebugConnection); ok {
		debugConn.SetDomain(hostWithoutPort)
		debugConn.SetClientIP(clientIP)
		debugConn.SetRequestID(reqID)

		s.logger.DebugWithRequestIDf(reqID, "[DIRECT-TUNNEL] Set domain %s and client IP %s on connection %s",
			hostWithoutPort, clientIP, clientConn.RemoteAddr())
	}

	// Try to get the original destination using SO_ORIGINAL_DST
	// This is useful for transparent proxy mode
	var originalDest *OriginalDestination
	if tcpConn, ok := clientConn.(*net.TCPConn); ok {
		s.logger.DebugWithRequestIDf(reqID, "[TUNNEL] Attempting to get original destination for connection from %s (Host: %s)",
			clientIP, r.Host)

		var err error
		originalDest, err = GetOriginalDst(tcpConn)
		if err == nil {
			// Log both the hostname from the request and the original destination IP
			s.logger.InfoWithRequestIDf(reqID, "[ORIGINAL-DST] Original destination for client %s: %s (Host header: %s)",
				clientIP, originalDest.HostPort, r.Host)

			s.logger.DebugWithRequestIDf(reqID, "[TUNNEL] Successfully got original destination: %s for client %s (Host header: %s)",
				originalDest.HostPort, clientIP, r.Host)

			// Always use the original destination IP:port from SO_ORIGINAL_DST
			// This ensures we're connecting to the correct destination regardless of DNS
			if originalDest.HostPort != r.Host {
				s.logger.InfoWithRequestIDf(reqID, "[ORIGINAL-DST] Using original destination %s instead of Host header %s",
					originalDest.HostPort, r.Host)

				s.logger.DebugWithRequestIDf(reqID, "[TUNNEL] Original destination %s differs from Host header %s - using original destination",
					originalDest.HostPort, r.Host)

				// Store the original hostname for logging purposes
				originalHostname := r.Host

				// Update the request host to use the original destination IP:port
				r.Host = originalDest.HostPort

				// Extract IP without port for domain tracking
				hostWithoutPort := originalDest.IPString

				// Update the request ID with the new host but include the original hostname in logs
				reqID = s.logger.GetRequestID(clientIP, hostWithoutPort)
				s.logger.InfoWithRequestIDf(reqID, "[ORIGINAL-DST] Direct tunnel for hostname %s directed to IP %s",
					originalHostname, originalDest.IPString)

				s.logger.DebugWithRequestIDf(reqID, "[TUNNEL] Updated request host to %s (original hostname: %s)",
					r.Host, originalHostname)
			} else {
				s.logger.DebugWithRequestIDf(reqID, "[TUNNEL] Original destination matches Host header: %s", r.Host)
			}
		} else {
			s.logger.DebugWithRequestIDf(reqID, "[ORIGINAL-DST] Failed to get original destination: %v", err)
			s.logger.DebugWithRequestIDf(reqID, "[TUNNEL] Failed to get original destination for client %s: %v",
				clientIP, err)
		}
	} else {
		s.logger.DebugWithRequestIDf(reqID, "[TUNNEL] Connection is not a TCP connection, cannot get original destination")
	}

	// Store the destination information for this client IP
	s.clientDestMu.Lock()
	s.clientDestinations[clientIP] = r.Host
	s.logger.DebugWithRequestIDf(reqID, "[DEST] Stored destination %s for client %s", r.Host, clientIP)
	s.clientDestMu.Unlock()

	// Connect directly to the target server
	s.logger.InfoWithRequestIDf(reqID, "[TUNNEL] Attempting direct TCP connection to %s", r.Host)

	// Parse the host and port
	var targetHost, targetPort string
	var dialErr error

	if strings.Contains(r.Host, ":") {
		targetHost, targetPort, dialErr = net.SplitHostPort(r.Host)
		if dialErr != nil {
			s.logger.ErrorWithRequestIDf(reqID, "[ERROR] Failed to parse host and port from %s: %v", r.Host, dialErr)
			targetHost = r.Host
			targetPort = "443" // Default to port 443 if we can't parse
		}
	} else {
		targetHost = r.Host
		targetPort = "443" // Default to port 443 if no port is specified
	}

	s.logger.DebugWithRequestIDf(reqID, "[TUNNEL] Connecting to host %s on port %s", targetHost, targetPort)

	// Attempt to connect with an increased timeout
	s.logger.DebugWithRequestIDf(reqID, "[DIRECT-TUNNEL] Attempting to connect to %s:%s (timeout: 30s)",
		targetHost, targetPort)

	targetConn, err := net.DialTimeout("tcp", net.JoinHostPort(targetHost, targetPort), 30*time.Second)
	if err != nil {
		s.logger.ErrorWithRequestIDf(reqID, "[ERROR] Failed to connect to target %s: %v", r.Host, err)
		s.logger.DebugWithRequestIDf(reqID, "[DIRECT-TUNNEL] Connection failed to %s:%s: %v",
			targetHost, targetPort, err)

		// Send an error response to the client
		errorMsg := fmt.Sprintf("HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nFailed to connect to target server: %v\r\n", err)
		clientConn.Write([]byte(errorMsg))
		clientConn.Close()
		return
	}

	s.logger.DebugWithRequestIDf(reqID, "[DIRECT-TUNNEL] Successfully connected to %s:%s (local: %s, remote: %s)",
		targetHost, targetPort, targetConn.LocalAddr(), targetConn.RemoteAddr())

	s.logger.InfoWithRequestIDf(reqID, "[TUNNEL] Successfully established direct TCP connection to %s", r.Host)

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

	// Check if this is an MQTT connection based on the URL format or hostname
	isMQTTConnection := strings.HasPrefix(strings.ToLower(hostWithoutPort), "ssl://") ||
		strings.HasPrefix(strings.ToLower(hostWithoutPort), "mqtts://") ||
		strings.Contains(strings.ToLower(hostWithoutPort), "mqtt")

	// If this is an MQTT connection, log it clearly
	if isMQTTConnection {
		s.logger.InfoWithRequestIDf(reqID, "[MQTT-ALERT] *** MQTT CONNECTION IN DIRECT TUNNEL MODE: %s - MQTT connections are persistent and may not show activity ***", hostWithoutPort)
	}

	// Log that we're starting a pure TCP passthrough tunnel
	s.logger.InfoWithRequestIDf(reqID, "[TUNNEL] Starting pure TCP passthrough tunnel between client %s and target %s", clientIP, r.Host)

	// IMPORTANT: In direct tunnel mode, we do not inspect or modify any data
	// We simply establish the outgoing connection and forward packets between
	// the client and server without any inspection or modification
	s.logger.InfoWithRequestIDf(reqID, "[TUNNEL] Pure passthrough mode - no data inspection or modification")

	// Create a WaitGroup to wait for both goroutines to complete
	var wg sync.WaitGroup
	wg.Add(2)

	// Simple bidirectional copy without any protocol inspection or deadlines
	// This is a true passthrough tunnel that just copies bytes in both directions

	// Forward data from target to client
	go func(connReqID string) {
		defer wg.Done()
		defer clientConn.Close()
		defer targetConn.Close()

		// Use a large buffer for better performance
		buf := make([]byte, 64*1024)

		// Simple io.Copy loop without any deadlines or protocol inspection
		for {
			// Read from target without any deadline
			n, err := targetConn.Read(buf)
			if n > 0 {
				// Write to client immediately without any processing
				_, writeErr := clientConn.Write(buf[:n])
				if writeErr != nil {
					s.logger.DebugWithRequestIDf(connReqID, "[TUNNEL] Write error to client: %v", writeErr)
					return
				}

				// Log data flow periodically (only for large transfers)
				if n > 1024 {
					s.logger.DebugWithRequestIDf(connReqID, "[TUNNEL] Forwarded %d bytes from target to client", n)
				}
			}

			if err != nil {
				if err != io.EOF {
					s.logger.DebugWithRequestIDf(connReqID, "[TUNNEL] Read error from target: %v", err)
				}
				return
			}
		}
	}(reqID)

	// Forward data from client to target
	go func(connReqID string) {
		defer wg.Done()
		defer clientConn.Close()
		defer targetConn.Close()

		// Use a large buffer for better performance
		buf := make([]byte, 64*1024)

		// Simple io.Copy loop without any deadlines or protocol inspection
		for {
			// Read from client without any deadline
			n, err := clientConn.Read(buf)
			if n > 0 {
				// Write to target immediately without any processing
				_, writeErr := targetConn.Write(buf[:n])
				if writeErr != nil {
					s.logger.DebugWithRequestIDf(connReqID, "[TUNNEL] Write error to target: %v", writeErr)
					return
				}

				// Log data flow periodically (only for large transfers)
				if n > 1024 {
					s.logger.DebugWithRequestIDf(connReqID, "[TUNNEL] Forwarded %d bytes from client to target", n)
				}
			}

			if err != nil {
				if err != io.EOF {
					s.logger.DebugWithRequestIDf(connReqID, "[TUNNEL] Read error from client: %v", err)
				}
				return
			}
		}
	}(reqID)

	// Log that we've established the tunnel
	s.logger.InfoWithRequestIDf(reqID, "[TUNNEL] Established direct tunnel from %s to %s (IP: %s)",
		clientIP, hostWithoutPort, destIP)

	// Wait for both goroutines to complete
	wg.Wait()
	s.logger.InfoWithRequestIDf(reqID, "[TUNNEL] Direct tunnel between client %s and target %s completed", clientIP, r.Host)

	// Close connections (these might already be closed by the copy goroutines)
	if clientConn != nil {
		clientConn.Close()
	}
	if targetConn != nil {
		targetConn.Close()
	}
}

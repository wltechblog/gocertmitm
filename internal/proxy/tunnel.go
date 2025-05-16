package proxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
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

	// Try to get the original destination using SO_ORIGINAL_DST
	// This is useful for transparent proxy mode
	var originalDest *OriginalDestination
	if tcpConn, ok := clientConn.(*net.TCPConn); ok {
		var err error
		originalDest, err = GetOriginalDst(tcpConn)
		if err == nil {
			// Log both the hostname from the request and the original destination IP
			s.logger.InfoWithRequestIDf(reqID, "[ORIGINAL-DST] Original destination for client %s: %s (Host header: %s)",
				clientIP, originalDest.HostPort, r.Host)

			// Always use the original destination IP:port from SO_ORIGINAL_DST
			// This ensures we're connecting to the correct destination regardless of DNS
			if originalDest.HostPort != r.Host {
				s.logger.InfoWithRequestIDf(reqID, "[ORIGINAL-DST] Using original destination %s instead of Host header %s",
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
			}
		} else {
			s.logger.DebugWithRequestIDf(reqID, "[ORIGINAL-DST] Failed to get original destination: %v", err)
		}
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
	targetConn, err := net.DialTimeout("tcp", net.JoinHostPort(targetHost, targetPort), 30*time.Second)
	if err != nil {
		s.logger.ErrorWithRequestIDf(reqID, "[ERROR] Failed to connect to target %s: %v", r.Host, err)
		// Send an error response to the client
		errorMsg := fmt.Sprintf("HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nFailed to connect to target server: %v\r\n", err)
		clientConn.Write([]byte(errorMsg))
		clientConn.Close()
		return
	}
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

	// Create a WaitGroup to wait for both goroutines to complete
	var wg sync.WaitGroup
	wg.Add(2)

	// Simple bidirectional copy without any protocol inspection or deadlines
	// This is a true passthrough tunnel that just copies bytes in both directions

	// Forward data from target to client
	go func() {
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
					s.logger.DebugWithRequestIDf(reqID, "[TUNNEL] Write error to client: %v", writeErr)
					return
				}

				// Log data flow periodically (only for large transfers)
				if n > 1024 {
					s.logger.DebugWithRequestIDf(reqID, "[TUNNEL] Forwarded %d bytes from target to client", n)
				}
			}

			if err != nil {
				if err != io.EOF {
					s.logger.DebugWithRequestIDf(reqID, "[TUNNEL] Read error from target: %v", err)
				}
				return
			}
		}
	}()

	// Forward data from client to target
	go func() {
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
					s.logger.DebugWithRequestIDf(reqID, "[TUNNEL] Write error to target: %v", writeErr)
					return
				}

				// Log data flow periodically (only for large transfers)
				if n > 1024 {
					s.logger.DebugWithRequestIDf(reqID, "[TUNNEL] Forwarded %d bytes from client to target", n)
				}
			}

			if err != nil {
				if err != io.EOF {
					s.logger.DebugWithRequestIDf(reqID, "[TUNNEL] Read error from client: %v", err)
				}
				return
			}
		}
	}()

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

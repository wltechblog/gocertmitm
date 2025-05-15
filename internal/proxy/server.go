package proxy

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gocertmitm/internal/certificates"
	"github.com/gocertmitm/internal/logging"
)

// Server represents a proxy server
type Server struct {
	httpAddr         string
	httpsAddr        string
	certManager      *certificates.Manager
	logger           *logging.Logger
	payloadLogger    *logging.PayloadLogger
	httpServer       *http.Server
	httpsServer      *http.Server
	testType         certificates.TestType
	connections      map[string]int
	connectionMu     sync.Mutex
	savePayloads     bool
	tester           *Tester
	autoTest         bool                                      // Whether to automatically test all methods
	failedHandshakes map[string]map[certificates.TestType]bool // Track failed handshakes
	handshakesMu     sync.Mutex                                // Mutex for failedHandshakes
	recentDomains    []string                                  // Track recently accessed domains
	recentDomainsMu  sync.Mutex                                // Mutex for recentDomains
}

// NewServer creates a new proxy server
func NewServer(httpAddr, httpsAddr string, certManager *certificates.Manager, logger *logging.Logger, retryPeriod ...time.Duration) (*Server, error) {
	// Create payload logger
	payloadLogger, err := logging.NewPayloadLogger("./payloads")
	if err != nil {
		return nil, fmt.Errorf("failed to create payload logger: %v", err)
	}

	// Create tester with default test type (will be updated later)
	// If retryPeriod is provided, use it, otherwise use default (1 hour)
	var tester *Tester
	if len(retryPeriod) > 0 {
		tester = NewTesterWithRetryPeriod(logger, certificates.SelfSigned, retryPeriod[0])
	} else {
		tester = NewTester(logger, certificates.SelfSigned)
	}

	server := &Server{
		httpAddr:         httpAddr,
		httpsAddr:        httpsAddr,
		certManager:      certManager,
		logger:           logger,
		payloadLogger:    payloadLogger,
		testType:         certificates.SelfSigned, // Default test type
		connections:      make(map[string]int),
		savePayloads:     true, // Enable payload saving by default
		tester:           tester,
		autoTest:         true, // Enable automatic testing by default
		failedHandshakes: make(map[string]map[certificates.TestType]bool),
		recentDomains:    make([]string, 0, 10), // Track up to 10 recent domains
	}

	// Create HTTP server
	httpHandler := http.HandlerFunc(server.handleHTTP)
	server.httpServer = &http.Server{
		Addr:         httpAddr,
		Handler:      httpHandler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Create HTTPS server
	httpsHandler := http.HandlerFunc(server.handleHTTPS)
	server.httpsServer = &http.Server{
		Addr:    httpsAddr,
		Handler: httpsHandler,
		TLSConfig: &tls.Config{
			GetCertificate:     certManager.GetCertificateFunc(server.testType),
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: false,            // We want clients to validate our certificates
			ClientAuth:         tls.NoClientCert, // Don't require client certificates
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			},
			PreferServerCipherSuites: true,
		},
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
		// Add error logger to capture TLS handshake errors
		ErrorLog: log.New(&tlsErrorLogger{server: server}, "", log.Lshortfile),
	}

	server.logger.Debugf("HTTPS server configured with TLS and certificate manager")

	return server, nil
}

// Start starts the proxy server
func (s *Server) Start() error {
	// Start HTTP server
	go func() {
		s.logger.Infof("Starting HTTP proxy on %s", s.httpAddr)
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Errorf("HTTP server error: %v", err)
		}
	}()

	// Start HTTPS server
	s.logger.Infof("Starting HTTPS proxy on %s", s.httpsAddr)
	if err := s.httpsServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("HTTPS server error: %v", err)
	}

	return nil
}

// Stop stops the proxy server
func (s *Server) Stop() error {
	// Stop HTTP server
	if err := s.httpServer.Close(); err != nil {
		s.logger.Errorf("Error stopping HTTP server: %v", err)
	}

	// Stop HTTPS server
	if err := s.httpsServer.Close(); err != nil {
		s.logger.Errorf("Error stopping HTTPS server: %v", err)
		return err
	}

	return nil
}

// SetTestType sets the test type
func (s *Server) SetTestType(testType certificates.TestType) {
	s.testType = testType

	// Update the tester's test order to start with this test type
	s.tester.UpdateTestOrder(testType)

	// If auto-testing is disabled, update the certificate function
	if !s.autoTest {
		s.httpsServer.TLSConfig.GetCertificate = s.certManager.GetCertificateFunc(testType)
	}

	// Reset the failed handshakes map
	s.handshakesMu.Lock()
	s.failedHandshakes = make(map[string]map[certificates.TestType]bool)
	s.handshakesMu.Unlock()

	// Log the test type change
	s.logger.Infof("Test type set to: %s", testType.GetTestTypeName())
}

// SetAutoTest enables or disables automatic testing
func (s *Server) SetAutoTest(enabled bool) {
	s.autoTest = enabled

	if enabled {
		// When auto-testing is enabled, use a custom certificate function
		s.httpsServer.TLSConfig.GetCertificate = s.getAutoTestCertificateFunc()
		s.logger.Infof("Automatic testing enabled - will try all test types for each domain")
	} else {
		// When auto-testing is disabled, use the standard certificate function
		s.httpsServer.TLSConfig.GetCertificate = s.certManager.GetCertificateFunc(s.testType)
		s.logger.Infof("Automatic testing disabled - using fixed test type: %s", s.testType.GetTestTypeName())
	}
}

// RecordFailedHandshake records a failed handshake for a domain and test type
func (s *Server) RecordFailedHandshake(domain string, testType certificates.TestType, reqID string) certificates.TestType {
	// Get the domain test status before recording the failure
	domainStatus := s.tester.GetTestStatus(domain)
	if domainStatus != nil {
		s.logger.DebugWithRequestIDf(reqID, "[DOMAIN] Before recording failure - Domain %s status: CurrentTestIndex=%d, TestsCompleted=%v, SuccessfulTestSet=%v",
			domain, domainStatus.CurrentTestIndex, domainStatus.TestsCompleted, domainStatus.SuccessfulTestSet)
	}

	// Record the failure in the failedHandshakes map
	s.handshakesMu.Lock()
	if _, exists := s.failedHandshakes[domain]; !exists {
		s.failedHandshakes[domain] = make(map[certificates.TestType]bool)
	}
	s.failedHandshakes[domain][testType] = true
	s.handshakesMu.Unlock()

	// Record the failure in the tester and get the next test to try
	nextTest := s.tester.RecordTestResult(domain, testType, false)
	s.logger.InfoWithRequestIDf(reqID, "[FAILURE] Recorded failed handshake for %s with %s, next test: %s",
		domain, testType.GetTestTypeName(), nextTest.GetTestTypeName())

	// Get the domain test status after recording the failure
	domainStatus = s.tester.GetTestStatus(domain)
	if domainStatus != nil {
		s.logger.DebugWithRequestIDf(reqID, "[DOMAIN] After recording failure - Domain %s status: CurrentTestIndex=%d, TestsCompleted=%v, SuccessfulTestSet=%v",
			domain, domainStatus.CurrentTestIndex, domainStatus.TestsCompleted, domainStatus.SuccessfulTestSet)
	}

	// Make sure the next test is marked as not failed yet
	if nextTest != certificates.DirectTunnel {
		s.handshakesMu.Lock()
		// Reset all test types to ensure we don't have stale failure data
		for testType := range s.failedHandshakes[domain] {
			s.failedHandshakes[domain][testType] = false
		}
		// Mark the current test as failed
		s.failedHandshakes[domain][testType] = true
		s.handshakesMu.Unlock()
		s.logger.DebugWithRequestIDf(reqID, "[TEST] Reset failure status for all tests for domain %s", domain)
	}

	return nextTest
}

// getAutoTestCertificateFunc returns a certificate function that automatically tests all methods
func (s *Server) getAutoTestCertificateFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		// Get the server name from the client hello
		serverName := clientHello.ServerName
		if serverName == "" {
			serverName = "default.example.com"
		}

		// Get the client IP
		clientIP := "unknown"
		if clientHello.Conn != nil {
			clientIP, _, _ = net.SplitHostPort(clientHello.Conn.RemoteAddr().String())
		}

		// Add to recent domains list
		s.AddRecentDomain(serverName)

		// Get a request ID for this connection
		reqID := s.logger.GetRequestID(clientIP, serverName)

		// Resolve the server name to an IP address
		var destIP string
		if net.ParseIP(serverName) != nil {
			destIP = serverName
		} else {
			// Resolve the domain to an IP address
			ips, resolveErr := net.LookupIP(serverName)
			if resolveErr == nil && len(ips) > 0 {
				// Use the first IP address
				destIP = ips[0].String()
				s.logger.DebugWithRequestIDf(reqID, "[TEST] Resolved server name %s to IP %s", serverName, destIP)
			}
		}

		// Get the next test to try for this domain or IP
		var testType certificates.TestType
		if destIP != "" {
			// Try to get the test by IP first
			testType = s.tester.GetNextTestByIP(destIP)
			s.logger.DebugWithRequestIDf(reqID, "[TEST] Initial test type for IP %s: %s", destIP, testType.GetTestTypeName())
		} else {
			// Fall back to domain-based lookup
			testType = s.tester.GetNextTest(serverName)
			s.logger.DebugWithRequestIDf(reqID, "[TEST] Initial test type for domain %s: %s", serverName, testType.GetTestTypeName())
		}

		// If we should use a direct tunnel, return nil to indicate failure
		// This will cause the TLS handshake to fail, and the client will fall back to direct connection
		if testType == certificates.DirectTunnel {
			s.logger.InfoWithRequestIDf(reqID, "[TUNNEL] Using direct tunnel for %s - all tests failed", serverName)
			return nil, fmt.Errorf("all tests failed for %s, using direct tunnel", serverName)
		}

		// Check if this test has already failed for this connection
		s.handshakesMu.Lock()
		if _, exists := s.failedHandshakes[serverName]; !exists {
			s.failedHandshakes[serverName] = make(map[certificates.TestType]bool)
		}

		// Check the domain test status to ensure we're using the correct test
		domainStatus := s.tester.GetTestStatus(serverName)
		if domainStatus != nil {
			s.logger.DebugWithRequestIDf(reqID, "[DOMAIN] %s status: CurrentTestIndex=%d, TestsCompleted=%v, SuccessfulTestSet=%v",
				serverName, domainStatus.CurrentTestIndex, domainStatus.TestsCompleted, domainStatus.SuccessfulTestSet)

			// Make sure we're using the correct test type based on the domain status
			if !domainStatus.TestsCompleted && !domainStatus.SuccessfulTestSet &&
				domainStatus.CurrentTestIndex < len(s.tester.GetTestOrder()) {
				correctTestType := s.tester.GetTestOrder()[domainStatus.CurrentTestIndex]
				if testType != correctTestType {
					s.logger.DebugWithRequestIDf(reqID, "[TEST] Correcting test type from %s to %s based on domain status",
						testType.GetTestTypeName(), correctTestType.GetTestTypeName())
					testType = correctTestType
				}
			}
		}

		if s.failedHandshakes[serverName][testType] {
			// This test has already failed, move to the next one
			nextTest := s.tester.RecordTestResult(serverName, testType, false)
			s.handshakesMu.Unlock()

			if nextTest == certificates.DirectTunnel {
				s.logger.InfoWithRequestIDf(reqID, "[TUNNEL] Using direct tunnel for %s - all tests failed", serverName)
				return nil, fmt.Errorf("all tests failed for %s, using direct tunnel", serverName)
			}

			// Try the next test
			s.logger.InfoWithRequestIDf(reqID, "[TEST] Test %s failed for %s, trying %s", testType.GetTestTypeName(), serverName, nextTest.GetTestTypeName())
			testType = nextTest
		} else {
			s.handshakesMu.Unlock()
		}

		// Log the test being performed
		s.logger.InfoWithRequestIDf(reqID, "[TEST] Testing %s from %s with %s", serverName, clientIP, testType.GetTestTypeName())

		// Get the certificate for this test
		cert, err := s.certManager.GetCertificate(serverName, testType)
		if err != nil {
			s.logger.ErrorWithRequestIDf(reqID, "[ERROR] Failed to get certificate for %s: %v", serverName, err)

			// Record the failure and try the next test
			s.handshakesMu.Lock()
			s.failedHandshakes[serverName][testType] = true
			s.handshakesMu.Unlock()

			nextTest := s.tester.RecordTestResult(serverName, testType, false)
			if nextTest == certificates.DirectTunnel {
				s.logger.InfoWithRequestIDf(reqID, "[TUNNEL] Using direct tunnel for %s - all tests failed", serverName)
				return nil, fmt.Errorf("all tests failed for %s, using direct tunnel", serverName)
			}

			// Try the next test by calling this function again with the same clientHello
			s.logger.InfoWithRequestIDf(reqID, "[TEST] Test %s failed for %s, trying %s", testType.GetTestTypeName(), serverName, nextTest.GetTestTypeName())
			return s.getAutoTestCertificateFunc()(clientHello)
		}

		// Mark this test as attempted but not yet failed
		// We'll only know if it failed when we get a TLS handshake error
		s.handshakesMu.Lock()
		s.failedHandshakes[serverName][testType] = false
		s.handshakesMu.Unlock()

		s.logger.DebugWithRequestIDf(reqID, "[CERT] Successfully got certificate for %s with test type %s",
			serverName, testType.GetTestTypeName())

		return cert, nil
	}
}

// SetSavePayloads enables or disables saving of request and response payloads
func (s *Server) SetSavePayloads(save bool) {
	s.savePayloads = save
}

// SetPayloadDir sets the directory for saving payloads
func (s *Server) SetPayloadDir(dir string) error {
	payloadLogger, err := logging.NewPayloadLogger(dir)
	if err != nil {
		return fmt.Errorf("failed to create payload logger: %v", err)
	}
	s.payloadLogger = payloadLogger
	return nil
}

// AddRecentDomain adds a domain to the list of recently accessed domains
func (s *Server) AddRecentDomain(domain string) {
	s.recentDomainsMu.Lock()
	defer s.recentDomainsMu.Unlock()

	// Skip empty domains or IP addresses
	if domain == "" || isIPAddress(domain) {
		return
	}

	// Check if the domain is already in the list
	found := false
	for i, d := range s.recentDomains {
		if d == domain {
			// If found, move it to the end of the list (most recent)
			if i < len(s.recentDomains)-1 {
				// Remove from current position
				s.recentDomains = append(s.recentDomains[:i], s.recentDomains[i+1:]...)
				// Add to the end
				s.recentDomains = append(s.recentDomains, domain)
				s.logger.Debugf("Moved domain to end of recent list: %s", domain)
			}
			found = true
			break
		}
	}

	// If not found, add the domain to the list
	if !found {
		s.recentDomains = append(s.recentDomains, domain)
		s.logger.Debugf("Added domain to recent list: %s", domain)
	}

	// If the list is too long, remove the oldest domain
	if len(s.recentDomains) > 10 {
		s.recentDomains = s.recentDomains[1:]
	}
}

// GetRecentDomains returns the list of recently accessed domains
func (s *Server) GetRecentDomains() []string {
	s.recentDomainsMu.Lock()
	defer s.recentDomainsMu.Unlock()

	// Return a copy of the list
	domains := make([]string, len(s.recentDomains))
	copy(domains, s.recentDomains)

	return domains
}

// handleHTTP handles HTTP requests
func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Get client IP
	clientIP := getClientIP(r)

	// Extract the host and port
	host := r.Host
	var hostWithoutPort string

	if strings.Contains(host, ":") {
		var splitErr error
		hostWithoutPort, _, splitErr = net.SplitHostPort(host)
		if splitErr != nil {
			s.logger.Errorf("Failed to split host and port: %v", splitErr)
			hostWithoutPort = host
		}
	} else {
		hostWithoutPort = host
	}

	// Add to recent domains list if it's a domain (not an IP)
	s.AddRecentDomain(hostWithoutPort)

	// Resolve the destination IP from the host
	var destIP string

	// Check if the host is already an IP address
	if net.ParseIP(hostWithoutPort) != nil {
		destIP = hostWithoutPort
	} else {
		// Resolve the domain to an IP address
		ips, err := net.LookupIP(hostWithoutPort)
		if err != nil {
			// Continue with the domain name even if we can't resolve it
		} else if len(ips) > 0 {
			// Use the first IP address
			destIP = ips[0].String()
			s.logger.Debugf("Resolved host %s to IP %s", hostWithoutPort, destIP)
		}
	}

	// Log request
	s.logger.LogRequest(clientIP, r.Method, r.Host, r.URL.Path, false)

	// Track connection
	s.trackConnection(clientIP, true)
	defer s.trackConnection(clientIP, false)

	// Check if this is a CONNECT request (for HTTPS)
	if r.Method == http.MethodConnect {
		s.logger.Debugf("Handling CONNECT request for %s from %s", r.Host, clientIP)
		s.handleConnect(w, r)
		return
	}

	// Handle regular HTTP request
	s.handleRegularHTTP(w, r)
}

// handleHTTPS handles HTTPS requests
func (s *Server) handleHTTPS(w http.ResponseWriter, r *http.Request) {
	// Get client IP
	clientIP := getClientIP(r)

	// Extract the host and port
	host := r.Host
	var hostWithoutPort string

	if strings.Contains(host, ":") {
		var splitErr error
		hostWithoutPort, _, splitErr = net.SplitHostPort(host)
		if splitErr != nil {
			s.logger.Errorf("Failed to split host and port: %v", splitErr)
			hostWithoutPort = host
		}
	} else {
		hostWithoutPort = host
	}

	// Add to recent domains list if it's a domain (not an IP)
	s.AddRecentDomain(hostWithoutPort)

	// Resolve the destination IP from the host
	var destIP string

	// Check if the host is already an IP address
	if net.ParseIP(hostWithoutPort) != nil {
		destIP = hostWithoutPort
	} else {
		// Resolve the domain to an IP address
		ips, err := net.LookupIP(hostWithoutPort)
		if err != nil {
			s.logger.Errorf("Failed to resolve host %s: %v", hostWithoutPort, err)
			// Continue with the domain name even if we can't resolve it
		} else if len(ips) > 0 {
			// Use the first IP address
			destIP = ips[0].String()
			s.logger.Debugf("Resolved host %s to IP %s", hostWithoutPort, destIP)
		}
	}

	// Log request
	s.logger.LogRequest(clientIP, r.Method, r.Host, r.URL.Path, true)

	// Track connection
	s.trackConnection(clientIP, true)
	defer s.trackConnection(clientIP, false)

	// If auto-testing is enabled, record a successful test
	if s.autoTest {
		// Record successful test for this domain or IP
		// We know the test was successful because we're handling an HTTPS request
		var currentTest certificates.TestType
		var nextTest certificates.TestType

		if destIP != "" {
			// Use IP-based lookup first
			currentTest = s.tester.GetNextTestByIP(destIP)
			nextTest = s.tester.RecordTestResult(destIP, currentTest, true)
			s.logger.Infof("Successful MITM for IP %s (host: %s) using %s", destIP, hostWithoutPort, currentTest.GetTestTypeName())
		} else {
			// Fall back to domain-based lookup
			currentTest = s.tester.GetNextTest(hostWithoutPort)
			nextTest = s.tester.RecordTestResult(hostWithoutPort, currentTest, true)
			s.logger.Infof("Successful MITM for domain %s using %s", hostWithoutPort, currentTest.GetTestTypeName())
		}

		// If the next test is different, update the certificate function
		if nextTest != currentTest {
			s.logger.Infof("Moving to next test for %s: %s", host, nextTest.GetTestTypeName())
		}
	}

	// Handle regular HTTP request (but over HTTPS)
	s.handleRegularHTTP(w, r)
}

// handleConnect handles CONNECT requests (for HTTPS)
func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
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
			s.logger.Errorf("Failed to split host and port: %v", splitErr)
			hostWithoutPort = host
		}
	} else {
		hostWithoutPort = host
	}

	// Add to recent domains list if it's a domain (not an IP)
	s.AddRecentDomain(hostWithoutPort)

	// Resolve the destination IP from the host
	var destIP string

	// Check if the host is already an IP address
	if net.ParseIP(hostWithoutPort) != nil {
		destIP = hostWithoutPort
	} else {
		// Resolve the domain to an IP address
		ips, err := net.LookupIP(hostWithoutPort)
		if err != nil {
			s.logger.Errorf("Failed to resolve host %s: %v", hostWithoutPort, err)
			// Continue with the domain name even if we can't resolve it
		} else if len(ips) > 0 {
			// Use the first IP address
			destIP = ips[0].String()
			s.logger.Debugf("Resolved host %s to IP %s", hostWithoutPort, destIP)
		}
	}

	// Get a request ID for this connection
	reqID := s.logger.GetRequestID(clientIP, hostWithoutPort)

	// Check if we should use a direct tunnel based on IP or domain
	useTunnel := false
	if s.autoTest {
		if destIP != "" {
			// Use IP-based lookup first
			useTunnel = s.tester.ShouldUseTunnelByIP(destIP)
			s.logger.DebugWithRequestIDf(reqID, "Checking tunnel status for IP %s: %v", destIP, useTunnel)
		}

		// If we couldn't determine by IP or it's not a tunnel, check by domain
		if destIP == "" || !useTunnel {
			domainTunnel := s.tester.ShouldUseTunnel(hostWithoutPort)
			if domainTunnel {
				useTunnel = true
			}
			s.logger.DebugWithRequestIDf(reqID, "Checking tunnel status for domain %s: %v", hostWithoutPort, domainTunnel)
		}
	}

	if useTunnel {
		s.logger.InfoWithRequestIDf(reqID, "CONNECT request for %s from %s - using direct tunnel (all tests failed)", r.Host, clientIP)
		s.handleDirectTunnel(w, r)
		return
	}

	// Log CONNECT request with test type
	testType := s.testType
	if s.autoTest {
		testType = s.tester.GetNextTest(host)
	}
	s.logger.InfoWithRequestIDf(reqID, "[CONNECT] Request for %s from %s (Test: %s)", r.Host, clientIP, testType.GetTestTypeName())

	// Hijack the connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		s.logger.Errorf("Hijacking not supported for client %s", clientIP)
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, hijackErr := hijacker.Hijack()
	if hijackErr != nil {
		s.logger.Errorf("Failed to hijack connection from %s: %v", clientIP, hijackErr)
		http.Error(w, hijackErr.Error(), http.StatusServiceUnavailable)
		return
	}

	// Set a deadline for the client connection
	if err := clientConn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		s.logger.Errorf("Failed to set deadline for client connection: %v", err)
	}

	// Connect to the target server
	s.logger.Debugf("Connecting to target server: %s", r.Host)

	// Variable to hold the connection to the target server
	var targetConn net.Conn

	// For HTTPS connections, we need to use TLS with InsecureSkipVerify
	// to accept any certificate presented by the server
	if strings.HasSuffix(r.Host, ":443") || strings.Contains(r.Host, ":443/") {
		s.logger.Debugf("Using TLS connection with InsecureSkipVerify for %s", r.Host)

		// First establish a TCP connection
		tcpConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
		if err != nil {
			s.logger.Errorf("Failed to connect to target %s: %v", r.Host, err)
			clientConn.Close()
			return
		}

		// Then upgrade to TLS with InsecureSkipVerify
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
		}

		// Extract hostname without port for ServerName
		host, _, err := net.SplitHostPort(r.Host)
		if err == nil {
			tlsConfig.ServerName = host
		}

		tlsConn := tls.Client(tcpConn, tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			s.logger.Errorf("TLS handshake failed with %s: %v", r.Host, err)
			tcpConn.Close()
			clientConn.Close()
			return
		}

		targetConn = tlsConn
	} else {
		// For non-HTTPS connections, use regular TCP
		targetConn, err = net.DialTimeout("tcp", r.Host, 10*time.Second)
		if err != nil {
			s.logger.Errorf("Failed to connect to target %s: %v", r.Host, err)
			clientConn.Close()
			return
		}
	}

	// Set a deadline for the target connection
	if err := targetConn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		s.logger.Errorf("Failed to set deadline for target connection: %v", err)
	}

	// Respond to the client that the connection is established
	s.logger.Debugf("Sending 200 Connection established to client %s", clientIP)
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	if err != nil {
		s.logger.Errorf("Failed to write to client %s: %v", clientIP, err)
		clientConn.Close()
		targetConn.Close()
		return
	}

	// Start proxying data between client and target
	s.logger.Debugf("Starting to proxy data between client %s and target %s", clientIP, r.Host)
	go func() {
		defer clientConn.Close()
		defer targetConn.Close()
		copyData(targetConn, clientConn)
		s.logger.Debugf("Finished proxying data from target %s to client %s", r.Host, clientIP)
	}()

	go func() {
		defer clientConn.Close()
		defer targetConn.Close()
		copyData(clientConn, targetConn)
		s.logger.Debugf("Finished proxying data from client %s to target %s", clientIP, r.Host)
	}()
}

// handleRegularHTTP handles regular HTTP requests
func (s *Server) handleRegularHTTP(w http.ResponseWriter, r *http.Request) {
	// Get client IP and host
	clientIP := getClientIP(r)
	host := r.Host

	s.logger.Debugf("Handling request from %s to %s", clientIP, host)

	// Create a copy of the request body for logging
	var requestBodyCopy []byte
	if r.Body != nil {
		requestBodyCopy, _ = io.ReadAll(r.Body)
		// Restore the body for further processing
		r.Body = io.NopCloser(bytes.NewReader(requestBodyCopy))
	}

	// Log request payload if enabled
	if s.savePayloads {
		// Create a copy of the request for logging
		reqCopy := *r
		if requestBodyCopy != nil {
			reqCopy.Body = io.NopCloser(bytes.NewReader(requestBodyCopy))
		}

		if err := s.payloadLogger.LogRequest(clientIP, host, &reqCopy); err != nil {
			s.logger.Errorf("Failed to log request payload: %v", err)
		}
	}

	// Construct a proper URL with scheme
	targetURL := fmt.Sprintf("https://%s%s", host, r.URL.Path)
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	s.logger.Debugf("Constructed target URL: %s", targetURL)

	// Create a new request to the target server
	var targetReq *http.Request
	var err error
	if requestBodyCopy != nil {
		targetReq, err = http.NewRequest(r.Method, targetURL, bytes.NewReader(requestBodyCopy))
	} else {
		targetReq, err = http.NewRequest(r.Method, targetURL, nil)
	}

	if err != nil {
		s.logger.Errorf("Failed to create target request: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Copy headers
	for key, values := range r.Header {
		for _, value := range values {
			targetReq.Header.Add(key, value)
		}
	}

	// Create HTTP client with transport that accepts any certificate
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Accept any certificate presented by the server
		},
		DisableCompression: true,
		// Add more aggressive timeouts
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
		// Don't follow redirects automatically
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	s.logger.Debugf("Created HTTP client with InsecureSkipVerify=true for %s", host)

	s.logger.Debugf("Sending request to target server: %s %s", r.Method, r.URL.String())

	// Send request to target server
	targetResp, err := client.Do(targetReq)
	if err != nil {
		s.logger.Errorf("Failed to send request to target server: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer targetResp.Body.Close()

	s.logger.Debugf("Received response from target server: %d %s", targetResp.StatusCode, targetResp.Status)

	// Read the response body
	responseBody, err := io.ReadAll(targetResp.Body)
	if err != nil {
		s.logger.Errorf("Failed to read response body: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Restore the response body for further processing
	targetResp.Body = io.NopCloser(bytes.NewReader(responseBody))

	// Log response payload if enabled
	if s.savePayloads {
		// Create a copy of the response for logging
		respCopy := *targetResp
		respCopy.Body = io.NopCloser(bytes.NewReader(responseBody))

		if err := s.payloadLogger.LogResponse(clientIP, host, &respCopy); err != nil {
			s.logger.Errorf("Failed to log response payload: %v", err)
		}
	}

	// Copy response headers
	for key, values := range targetResp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Set response status code
	w.WriteHeader(targetResp.StatusCode)

	// Write response body
	if _, err := w.Write(responseBody); err != nil {
		s.logger.Errorf("Failed to write response body: %v", err)
	}

	// Log successful MITM with test type
	var testType certificates.TestType

	if s.autoTest {
		// Extract the host without port
		var hostWithoutPort string
		if strings.Contains(host, ":") {
			hostWithoutPort, _, _ = net.SplitHostPort(host)
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
			ips, err := net.LookupIP(hostWithoutPort)
			if err == nil && len(ips) > 0 {
				// Use the first IP address
				destIP = ips[0].String()
			}
		}

		// Get the current test type from the tester
		if destIP != "" {
			testType = s.tester.GetNextTestByIP(destIP)
			s.logger.Infof("Successfully intercepted request from %s to %s (IP: %s) (Test: %s)",
				clientIP, host, destIP, testType.GetTestTypeName())
		} else {
			testType = s.tester.GetNextTest(hostWithoutPort)
			s.logger.Infof("Successfully intercepted request from %s to %s (Test: %s)",
				clientIP, host, testType.GetTestTypeName())
		}
	} else {
		testType = s.testType
		s.logger.Infof("Successfully intercepted request from %s to %s (Test: %s)",
			clientIP, host, testType.GetTestTypeName())
	}
}

// trackConnection tracks client connections
func (s *Server) trackConnection(clientIP string, isConnect bool) {
	s.connectionMu.Lock()
	defer s.connectionMu.Unlock()

	if isConnect {
		s.connections[clientIP]++
	} else {
		s.connections[clientIP]--
		if s.connections[clientIP] <= 0 {
			delete(s.connections, clientIP)
		}
	}
}

// getClientIP gets the client IP address
func getClientIP(r *http.Request) string {
	// Check for X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For can contain multiple IPs, use the first one
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check for X-Real-IP header
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		return xrip
	}

	// Get IP from RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// isIPAddress checks if a string is an IP address
func isIPAddress(s string) bool {
	return net.ParseIP(s) != nil
}

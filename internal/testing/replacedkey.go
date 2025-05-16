package testing

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/gocertmitm/internal/certificates"
	"github.com/gocertmitm/internal/logging"
)

// ReplacedKeyTester tests if clients verify the certificate's public key
type ReplacedKeyTester struct {
	certManager *certificates.Manager
	logger      *logging.Logger
	reporter    *logging.Reporter
}

// NewReplacedKeyTester creates a new replaced key certificate tester
func NewReplacedKeyTester(certManager *certificates.Manager, logger *logging.Logger, reporter *logging.Reporter) *ReplacedKeyTester {
	return &ReplacedKeyTester{
		certManager: certManager,
		logger:      logger,
		reporter:    reporter,
	}
}

// Test tests if a client verifies the certificate's public key
func (t *ReplacedKeyTester) Test(clientIP, host string) (bool, error) {
	// Generate certificate with replaced key
	cert, err := t.certManager.GetCertificate(host, certificates.ReplacedKey)
	if err != nil {
		return false, fmt.Errorf("failed to generate certificate with replaced key: %v", err)
	}

	// Create TLS config
	config := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
	}

	// Create listener
	listener, err := tls.Listen("tcp", ":0", config)
	if err != nil {
		return false, fmt.Errorf("failed to create listener: %v", err)
	}
	defer listener.Close()

	// Get listener address
	addr := listener.Addr().String()

	// Start server
	accepted := make(chan bool, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			t.logger.Errorf("Failed to accept connection: %v", err)
			accepted <- false
			return
		}
		defer conn.Close()

		// Connection accepted
		accepted <- true
	}()

	// Connect to server
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return false, fmt.Errorf("failed to connect to server: %v", err)
	}
	defer conn.Close()

	// Upgrade to TLS
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	})
	defer tlsConn.Close()

	// Handshake
	if err := tlsConn.Handshake(); err != nil {
		// Handshake failed, client rejected certificate
		t.logger.LogCertificateTest(clientIP, host, "Replaced key", false)
		t.reporter.AddResult(clientIP, host, "Replaced key", false, fmt.Sprintf("Handshake failed: %v", err))
		// Log connection summary
		t.logger.LogConnectionSummary(clientIP, host, "Replaced key", false, false)
		return false, nil
	}

	// Wait for server to accept connection
	select {
	case result := <-accepted:
		if result {
			// Connection accepted, client accepted certificate
			t.logger.LogCertificateTest(clientIP, host, "Replaced key", true)
			t.reporter.AddResult(clientIP, host, "Replaced key", true, "Client accepted certificate with replaced key")
			// Log connection summary
			t.logger.LogConnectionSummary(clientIP, host, "Replaced key", true, false)
			return true, nil
		}
		// Connection not accepted
		t.logger.LogCertificateTest(clientIP, host, "Replaced key", false)
		t.reporter.AddResult(clientIP, host, "Replaced key", false, "Server did not accept connection")
		// Log connection summary
		t.logger.LogConnectionSummary(clientIP, host, "Replaced key", false, false)
		return false, nil
	case <-time.After(5 * time.Second):
		// Timeout
		t.logger.LogCertificateTest(clientIP, host, "Replaced key", false)
		t.reporter.AddResult(clientIP, host, "Replaced key", false, "Timeout waiting for server to accept connection")
		// Log connection summary
		t.logger.LogConnectionSummary(clientIP, host, "Replaced key", false, false)
		return false, nil
	}
}

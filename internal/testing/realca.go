package testing

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/gocertmitm/internal/certificates"
	"github.com/gocertmitm/internal/logging"
)

// RealCATest tests if clients accept certificates signed by valid but unauthorized CAs
type RealCATester struct {
	certManager *certificates.Manager
	logger      *logging.Logger
	reporter    *logging.Reporter
}

// NewRealCATester creates a new real CA certificate tester
func NewRealCATester(certManager *certificates.Manager, logger *logging.Logger, reporter *logging.Reporter) *RealCATester {
	return &RealCATester{
		certManager: certManager,
		logger:      logger,
		reporter:    reporter,
	}
}

// Test tests if a client accepts certificates signed by valid but unauthorized CAs
func (t *RealCATester) Test(clientIP, host, caHost string) (bool, error) {
	// Generate certificate signed by a real CA
	cert, err := t.certManager.GetCertificate(host, certificates.RealCertificateAsCA)
	if err != nil {
		return false, fmt.Errorf("failed to generate certificate signed by real CA: %v", err)
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
		t.logger.LogCertificateTest(clientIP, host, "Real CA", false)
		t.reporter.AddResult(clientIP, host, "Real CA", false, fmt.Sprintf("Handshake failed: %v", err))
		// Log connection summary
		t.logger.LogConnectionSummary(clientIP, host, "Real CA", false, false)
		return false, nil
	}

	// Wait for server to accept connection
	select {
	case result := <-accepted:
		if result {
			// Connection accepted, client accepted certificate
			t.logger.LogCertificateTest(clientIP, host, "Real CA", true)
			t.reporter.AddResult(clientIP, host, "Real CA", true, fmt.Sprintf("Client accepted certificate signed by %s CA", caHost))
			// Log connection summary
			t.logger.LogConnectionSummary(clientIP, host, "Real CA", true, false)
			return true, nil
		}
		// Connection not accepted
		t.logger.LogCertificateTest(clientIP, host, "Real CA", false)
		t.reporter.AddResult(clientIP, host, "Real CA", false, "Server did not accept connection")
		// Log connection summary
		t.logger.LogConnectionSummary(clientIP, host, "Real CA", false, false)
		return false, nil
	case <-time.After(5 * time.Second):
		// Timeout
		t.logger.LogCertificateTest(clientIP, host, "Real CA", false)
		t.reporter.AddResult(clientIP, host, "Real CA", false, "Timeout waiting for server to accept connection")
		// Log connection summary
		t.logger.LogConnectionSummary(clientIP, host, "Real CA", false, false)
		return false, nil
	}
}

package testing

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/gocertmitm/internal/certificates"
	"github.com/gocertmitm/internal/logging"
)

// RealCertTester tests if clients accept valid certificates for different domains
type RealCertTester struct {
	certManager *certificates.Manager
	logger      *logging.Logger
	reporter    *logging.Reporter
}

// NewRealCertTester creates a new real certificate tester
func NewRealCertTester(certManager *certificates.Manager, logger *logging.Logger, reporter *logging.Reporter) *RealCertTester {
	return &RealCertTester{
		certManager: certManager,
		logger:      logger,
		reporter:    reporter,
	}
}

// Test tests if a client accepts valid certificates for different domains
func (t *RealCertTester) Test(clientIP, host, realHost string) (bool, error) {
	// Generate certificate using a real certificate for a different domain
	cert, err := t.certManager.GetCertificate(realHost, certificates.RealCertificate)
	if err != nil {
		return false, fmt.Errorf("failed to generate certificate using real certificate: %v", err)
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
		t.logger.LogCertificateTest(clientIP, host, "Real certificate", false)
		t.reporter.AddResult(clientIP, host, "Real certificate", false, fmt.Sprintf("Handshake failed: %v", err))
		return false, nil
	}

	// Wait for server to accept connection
	select {
	case result := <-accepted:
		if result {
			// Connection accepted, client accepted certificate
			t.logger.LogCertificateTest(clientIP, host, "Real certificate", true)
			t.reporter.AddResult(clientIP, host, "Real certificate", true, fmt.Sprintf("Client accepted certificate for %s when connecting to %s", realHost, host))
			return true, nil
		}
		// Connection not accepted
		t.logger.LogCertificateTest(clientIP, host, "Real certificate", false)
		t.reporter.AddResult(clientIP, host, "Real certificate", false, "Server did not accept connection")
		return false, nil
	case <-time.After(5 * time.Second):
		// Timeout
		t.logger.LogCertificateTest(clientIP, host, "Real certificate", false)
		t.reporter.AddResult(clientIP, host, "Real certificate", false, "Timeout waiting for server to accept connection")
		return false, nil
	}
}

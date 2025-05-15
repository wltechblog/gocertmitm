package certificates

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// getTestTypeCertDir returns the directory for storing certificates of a specific test type
func (m *Manager) getTestTypeCertDir(testType TestType) string {
	var dirName string

	switch testType {
	case SelfSigned:
		dirName = "self-signed"
	case ReplacedKey:
		dirName = "replaced-key"
	case RealCertificateAsCA:
		dirName = "real-ca"
	default:
		dirName = "unknown"
	}

	return filepath.Join(m.CertDir, dirName)
}

// saveCertificate saves a certificate to disk for future use
func (m *Manager) saveCertificate(domain string, testType TestType, certPair *CertificatePair) error {
	// Skip saving for certain test types
	if testType == RealCertificate || testType == DirectTunnel {
		return nil
	}

	// Get the directory for this test type
	certDir := m.getTestTypeCertDir(testType)

	// Create domain directory
	domainDir := filepath.Join(certDir, domain)
	if err := os.MkdirAll(domainDir, 0755); err != nil {
		return fmt.Errorf("failed to create domain directory: %v", err)
	}

	// Save certificate
	certPath := filepath.Join(domainDir, "cert.pem")
	certOut, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to create certificate file: %v", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certPair.Certificate.Raw}); err != nil {
		return fmt.Errorf("failed to write certificate: %v", err)
	}

	// Save private key
	keyPath := filepath.Join(domainDir, "key.pem")
	keyOut, err := os.Create(keyPath)
	if err != nil {
		return fmt.Errorf("failed to create key file: %v", err)
	}
	defer keyOut.Close()

	privBytes := x509.MarshalPKCS1PrivateKey(certPair.PrivateKey)
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}); err != nil {
		return fmt.Errorf("failed to write private key: %v", err)
	}

	m.logger.Debugf("Saved certificate for %s (test type: %s)", domain, testType.GetTestTypeName())
	return nil
}

// ensureCertDirs ensures that all certificate directories exist
func (m *Manager) ensureCertDirs() error {
	// Create main certificate directory
	if err := os.MkdirAll(m.CertDir, 0755); err != nil {
		return fmt.Errorf("failed to create certificate directory: %v", err)
	}

	// Create directories for each test type
	testTypes := []struct {
		Type TestType
		Dir  string
	}{
		{SelfSigned, "self-signed"},
		{ReplacedKey, "replaced-key"},
		{RealCertificate, "real"},
		{RealCertificateAsCA, "real-ca"},
	}

	for _, tt := range testTypes {
		dir := filepath.Join(m.CertDir, tt.Dir)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create %s directory: %v", tt.Dir, err)
		}
	}

	return nil
}

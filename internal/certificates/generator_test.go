package certificates

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateCA(t *testing.T) {
	// Create temporary directory for certificates
	tempDir, err := os.MkdirTemp("", "certmitm-test")
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create certificate manager
	manager := &Manager{
		CertDir:   tempDir,
		CertCache: make(map[string]*CertificatePair),
	}

	// Generate CA
	ca, err := manager.GenerateCA()
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	// Check if CA certificate and private key were created
	if ca == nil {
		t.Fatal("CA is nil")
	}
	if ca.Certificate == nil {
		t.Fatal("CA certificate is nil")
	}
	if ca.PrivateKey == nil {
		t.Fatal("CA private key is nil")
	}

	// Check if CA certificate and private key were saved
	if _, err := os.Stat(filepath.Join(tempDir, "ca.crt")); os.IsNotExist(err) {
		t.Fatal("CA certificate file was not created")
	}
	if _, err := os.Stat(filepath.Join(tempDir, "ca.key")); os.IsNotExist(err) {
		t.Fatal("CA private key file was not created")
	}
}

func TestGenerateCertificate(t *testing.T) {
	// Create temporary directory for certificates
	tempDir, err := os.MkdirTemp("", "certmitm-test")
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create certificate manager
	manager := &Manager{
		CertDir:   tempDir,
		CertCache: make(map[string]*CertificatePair),
	}

	// Generate CA
	ca, err := manager.GenerateCA()
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}
	manager.CA = ca

	// Test domains
	domains := []string{
		"example.com",
		"test.example.com",
		"localhost",
		"127.0.0.1",
	}

	// Test certificate types
	testTypes := []TestType{
		SelfSigned,
		ReplacedKey,
		RealCertificate,
		RealCertificateAsCA,
	}

	// Generate certificates
	for _, domain := range domains {
		for _, testType := range testTypes {
			cert, err := manager.GenerateCertificate(domain, testType)
			if err != nil {
				t.Fatalf("Failed to generate certificate for %s with test type %d: %v", domain, testType, err)
			}

			// Check if certificate was created
			if cert == nil {
				t.Fatalf("Certificate for %s with test type %d is nil", domain, testType)
			}
			if cert.Certificate == nil {
				t.Fatalf("Certificate for %s with test type %d has nil certificate", domain, testType)
			}
			if cert.PrivateKey == nil {
				t.Fatalf("Certificate for %s with test type %d has nil private key", domain, testType)
			}
			if cert.TLSCert.Certificate == nil {
				t.Fatalf("Certificate for %s with test type %d has nil TLS certificate", domain, testType)
			}

			// Check if certificate is in cache
			cachedCert, ok := manager.CertCache[domain]
			if !ok {
				t.Fatalf("Certificate for %s with test type %d is not in cache", domain, testType)
			}
			if cachedCert != cert {
				t.Fatalf("Cached certificate for %s with test type %d is not the same as the generated certificate", domain, testType)
			}
		}
	}
}

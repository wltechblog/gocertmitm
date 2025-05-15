package proxy

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gocertmitm/internal/certificates"
	"github.com/gocertmitm/internal/logging"
)

// DomainTestStatus tracks the test status for a domain
type DomainTestStatus struct {
	Domain            string
	IP                string   // IP address associated with the domain
	IPs               []string // Multiple IP addresses that may be associated with the domain
	CurrentTestIndex  int
	TestResults       map[certificates.TestType]bool
	LastTested        time.Time
	TestsCompleted    bool
	SuccessfulTest    certificates.TestType
	SuccessfulTestSet bool
}

// domainTestStatusJSON is used for JSON serialization
type domainTestStatusJSON struct {
	Domain            string          `json:"domain"`
	IP                string          `json:"ip,omitempty"`
	IPs               []string        `json:"ips,omitempty"`
	CurrentTestIndex  int             `json:"current_test_index"`
	TestResults       map[string]bool `json:"test_results"`
	LastTested        time.Time       `json:"last_tested"`
	TestsCompleted    bool            `json:"tests_completed"`
	SuccessfulTest    string          `json:"successful_test,omitempty"`
	SuccessfulTestSet bool            `json:"successful_test_set"`
}

// testerJSON is used for JSON serialization
type testerJSON struct {
	Domains map[string]domainTestStatusJSON `json:"domains"`
}

// Tester manages the testing process for domains
type Tester struct {
	domains      map[string]*DomainTestStatus // Domain name -> status
	ipToDomain   map[string]string            // IP address -> domain name mapping
	mu           sync.RWMutex
	logger       *logging.Logger
	testOrder    []certificates.TestType
	retestPeriod time.Duration
	jsonFilePath string
}

// NewTester creates a new tester with default retry period (1 hour)
func NewTester(logger *logging.Logger, initialTestType certificates.TestType) *Tester {
	return NewTesterWithRetryPeriod(logger, initialTestType, 1*time.Hour)
}

// NewTesterWithRetryPeriod creates a new tester with a custom retry period
func NewTesterWithRetryPeriod(logger *logging.Logger, initialTestType certificates.TestType, retryPeriod time.Duration) *Tester {
	// Create the test order, starting with the initial test type
	testOrder := []certificates.TestType{
		initialTestType,
	}

	// Add the remaining test types in order, skipping the initial test type
	for _, testType := range []certificates.TestType{
		certificates.SelfSigned,
		certificates.ReplacedKey,
		certificates.RealCertificate,
		certificates.RealCertificateAsCA,
	} {
		if testType != initialTestType {
			testOrder = append(testOrder, testType)
		}
	}

	logger.Infof("Test order: %v", testOrder)
	logger.Infof("Retest period: %s", retryPeriod)

	// Create the JSON file path
	jsonFilePath := filepath.Join("./data", "domain_results.json")

	// Create the data directory if it doesn't exist
	os.MkdirAll(filepath.Dir(jsonFilePath), 0755)

	tester := &Tester{
		domains:      make(map[string]*DomainTestStatus),
		ipToDomain:   make(map[string]string),
		logger:       logger,
		testOrder:    testOrder,
		retestPeriod: retryPeriod,
		jsonFilePath: jsonFilePath,
	}

	// Load domain results from JSON file
	if err := tester.LoadFromJSON(); err != nil {
		logger.Infof("No previous domain results found or error loading: %v", err)
	} else {
		logger.Infof("Loaded domain results from %s", jsonFilePath)
	}

	return tester
}

// GetNextTest returns the next test to perform for a domain
func (t *Tester) GetNextTest(domain string) certificates.TestType {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Check if this is an IP address
	isIP := net.ParseIP(domain) != nil

	// If it's not an IP and not a valid domain, skip it
	if !isIP && !isValidDomain(domain) {
		t.logger.Debugf("Skipping invalid domain: %s", domain)
		return certificates.DirectTunnel
	}

	// Check if we have a status for this domain
	status, exists := t.domains[domain]
	if !exists {
		// Try to resolve the domain to an IP if it's not already an IP
		var ip string
		var ips []string
		var err error

		if !isIP {
			// Resolve domain to IP
			ip, err = t.resolveDomainToIP(domain)
			if err != nil {
				t.logger.Debugf("[DOMAIN] Failed to resolve domain %s: %v", domain, err)
				// Continue with the domain name even if we can't resolve it
			} else {
				t.logger.Debugf("[DOMAIN] Resolved domain %s to IP %s", domain, ip)
				// Map the IP to the domain
				t.ipToDomain[ip] = domain

				// Try to get all IPs for this domain
				ips, err = t.resolveDomainToAllIPs(domain)
				if err != nil {
					t.logger.Debugf("[DOMAIN] Failed to resolve all IPs for domain %s: %v", domain, err)
				} else {
					// Map all IPs to this domain
					for _, ipAddr := range ips {
						t.ipToDomain[ipAddr] = domain
					}
				}
			}
		} else {
			// It's already an IP
			ip = domain
		}

		// Create a new status for this domain
		status = &DomainTestStatus{
			Domain:           domain,
			IP:               ip,
			IPs:              ips,
			CurrentTestIndex: 0,
			TestResults:      make(map[certificates.TestType]bool),
			LastTested:       time.Now(),
			TestsCompleted:   false,
		}
		t.domains[domain] = status
		t.logger.Infof("[DOMAIN] Starting tests for new domain/IP: %s", domain)
		t.logger.Debugf("[DOMAIN] New domain/IP %s - using test %s (index 0)",
			domain, t.testOrder[0].GetTestTypeName())

		// Save the updated domain results to JSON
		if err := t.SaveToJSON(); err != nil {
			t.logger.Errorf("[ERROR] Failed to save domain results to JSON: %v", err)
		}

		return t.testOrder[0]
	}

	// Check if we need to retest
	if time.Since(status.LastTested) > t.retestPeriod {
		t.logger.Infof("[DOMAIN] Retesting domain after %s: %s", t.retestPeriod, domain)
		status.CurrentTestIndex = 0
		status.TestResults = make(map[certificates.TestType]bool)
		status.TestsCompleted = false
		status.SuccessfulTestSet = false
		status.LastTested = time.Now()
		t.logger.Debugf("[DOMAIN] Retest for domain %s - using test %s (index 0)",
			domain, t.testOrder[0].GetTestTypeName())

		// Save the updated domain results to JSON
		if err := t.SaveToJSON(); err != nil {
			t.logger.Errorf("[ERROR] Failed to save domain results to JSON: %v", err)
		}

		return t.testOrder[0]
	}

	// If we already have a successful test, use it
	if status.SuccessfulTestSet {
		t.logger.Debugf("[TEST] Domain %s has successful test: %s",
			domain, status.SuccessfulTest.GetTestTypeName())
		return status.SuccessfulTest
	}

	// If all tests are completed and none succeeded, return DirectTunnel
	if status.TestsCompleted && !status.SuccessfulTestSet {
		t.logger.Debugf("[TUNNEL] Domain %s has completed all tests with no success, using DirectTunnel", domain)
		return certificates.DirectTunnel
	}

	// Validate the current test index
	if status.CurrentTestIndex < 0 || status.CurrentTestIndex >= len(t.testOrder) {
		t.logger.Errorf("[ERROR] Invalid CurrentTestIndex %d for domain %s, resetting to 0",
			status.CurrentTestIndex, domain)
		status.CurrentTestIndex = 0
	}

	// Return the current test
	currentTest := t.testOrder[status.CurrentTestIndex]
	t.logger.Debugf("[TEST] Domain %s - using current test %s (index %d)",
		domain, currentTest.GetTestTypeName(), status.CurrentTestIndex)
	return currentTest
}

// RecordTestResult records the result of a test
func (t *Tester) RecordTestResult(domain string, testType certificates.TestType, success bool) certificates.TestType {
	t.mu.Lock()
	defer t.mu.Unlock()

	status, exists := t.domains[domain]
	if !exists {
		t.logger.Errorf("[ERROR] Trying to record result for unknown domain: %s", domain)
		return testType
	}

	// Record the result
	status.TestResults[testType] = success
	t.logger.Infof("[TEST] Result for %s with %s: %v", domain, testType.GetTestTypeName(), success)

	// If the test was successful, remember it and return the same test
	if success {
		status.SuccessfulTest = testType
		status.SuccessfulTestSet = true
		t.logger.Infof("[SUCCESS] Found successful test for %s: %s", domain, testType.GetTestTypeName())

		// Save the updated domain results to JSON
		if err := t.SaveToJSON(); err != nil {
			t.logger.Errorf("[ERROR] Failed to save domain results to JSON: %v", err)
		}

		return testType
	}

	// Verify that the current test type matches the one we're recording a result for
	// This ensures we're incrementing the correct test
	currentTest := t.testOrder[status.CurrentTestIndex]
	if currentTest != testType {
		t.logger.Debugf("[TEST] Warning: Recording failure for %s but current test is %s (index %d)",
			testType.GetTestTypeName(), currentTest.GetTestTypeName(), status.CurrentTestIndex)

		// Find the index of the test type we're recording a result for
		foundIndex := -1
		for i, test := range t.testOrder {
			if test == testType {
				foundIndex = i
				break
			}
		}

		if foundIndex != -1 {
			t.logger.Debugf("[TEST] Found test %s at index %d, updating CurrentTestIndex",
				testType.GetTestTypeName(), foundIndex)
			status.CurrentTestIndex = foundIndex
		}
	}

	// Move to the next test
	status.CurrentTestIndex++
	t.logger.Debugf("[TEST] Incremented CurrentTestIndex to %d for domain %s", status.CurrentTestIndex, domain)

	// If we've tried all tests, mark as completed
	if status.CurrentTestIndex >= len(t.testOrder) {
		status.TestsCompleted = true
		t.logger.Infof("[COMPLETE] All tests completed for %s, no successful tests found", domain)

		// Save the updated domain results to JSON
		if err := t.SaveToJSON(); err != nil {
			t.logger.Errorf("[ERROR] Failed to save domain results to JSON: %v", err)
		}

		return certificates.DirectTunnel // Special value indicating direct tunnel
	}

	// Return the next test
	nextTest := t.testOrder[status.CurrentTestIndex]
	t.logger.Infof("[NEXT] Moving to next test for %s: %s", domain, nextTest.GetTestTypeName())

	// Save the updated domain results to JSON
	if err := t.SaveToJSON(); err != nil {
		t.logger.Errorf("[ERROR] Failed to save domain results to JSON: %v", err)
	}

	return nextTest
}

// ShouldUseTunnel checks if we should use a direct tunnel for a domain
func (t *Tester) ShouldUseTunnel(domain string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	// Skip invalid domains
	if !isValidDomain(domain) {
		t.logger.Debugf("[DOMAIN] Skipping invalid domain: %s", domain)
		return false
	}

	status, exists := t.domains[domain]
	if !exists {
		t.logger.Debugf("[TUNNEL] No test status for domain %s, not using tunnel", domain)
		return false // Haven't tested yet, so don't use tunnel
	}

	// If we've completed all tests and none succeeded, use tunnel
	shouldUseTunnel := status.TestsCompleted && !status.SuccessfulTestSet

	if shouldUseTunnel {
		t.logger.Infof("[TUNNEL] Using direct tunnel for %s - all tests completed with no success", domain)
	} else if status.TestsCompleted {
		t.logger.Debugf("[TUNNEL] Not using tunnel for %s - tests completed with success", domain)
	} else {
		t.logger.Debugf("[TUNNEL] Not using tunnel for %s - tests not completed yet (index: %d)",
			domain, status.CurrentTestIndex)
	}

	return shouldUseTunnel
}

// GetTestStatus returns the test status for a domain
func (t *Tester) GetTestStatus(domain string) *DomainTestStatus {
	t.mu.RLock()
	defer t.mu.RUnlock()

	status, exists := t.domains[domain]
	if !exists {
		return nil
	}

	return status
}

// GetTestOrder returns the current test order
func (t *Tester) GetTestOrder() []certificates.TestType {
	t.mu.RLock()
	defer t.mu.RUnlock()

	// Return a copy of the test order
	testOrder := make([]certificates.TestType, len(t.testOrder))
	copy(testOrder, t.testOrder)

	return testOrder
}

// GetAllDomains returns all domains being tested
func (t *Tester) GetAllDomains() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	domains := make([]string, 0, len(t.domains))
	for domain := range t.domains {
		domains = append(domains, domain)
	}

	return domains
}

// isValidDomain checks if a string is a valid domain name
// It filters out filenames and other invalid domains
func isValidDomain(domain string) bool {
	// Check if it's a filename
	if strings.HasSuffix(domain, ".go") || strings.HasSuffix(domain, ".js") ||
		strings.HasSuffix(domain, ".py") || strings.HasSuffix(domain, ".c") ||
		strings.HasSuffix(domain, ".h") || strings.HasSuffix(domain, ".cpp") ||
		strings.HasSuffix(domain, ".java") || strings.HasSuffix(domain, ".html") ||
		strings.HasSuffix(domain, ".css") || strings.HasSuffix(domain, ".md") {
		return false
	}

	// Check if it has at least one dot and is not an IP address
	if strings.Contains(domain, ".") && net.ParseIP(domain) == nil {
		// Check if it has a valid TLD (at least 2 characters)
		parts := strings.Split(domain, ".")
		if len(parts) >= 2 && len(parts[len(parts)-1]) >= 2 {
			return true
		}
	}

	return false
}

// isSimpleIPAddress checks if a string is an IP address using a simple format check
func isSimpleIPAddress(s string) bool {
	// Simple check for IPv4 address format
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}

	for _, part := range parts {
		// Check if each part is a number between 0 and 255
		if len(part) == 0 || len(part) > 3 {
			return false
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return false
			}
		}
		num := 0
		for _, c := range part {
			num = num*10 + int(c-'0')
		}
		if num > 255 {
			return false
		}
	}

	return true
}

// UpdateTestOrder updates the test order to start with the specified test type
func (t *Tester) UpdateTestOrder(initialTestType certificates.TestType) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Create the test order, starting with the initial test type
	testOrder := []certificates.TestType{
		initialTestType,
	}

	// Add the remaining test types in order, skipping the initial test type
	for _, testType := range []certificates.TestType{
		certificates.SelfSigned,
		certificates.ReplacedKey,
		certificates.RealCertificate,
		certificates.RealCertificateAsCA,
	} {
		if testType != initialTestType {
			testOrder = append(testOrder, testType)
		}
	}

	t.logger.Infof("Updated test order: %v", testOrder)
	t.testOrder = testOrder

	// Reset all domain test statuses
	for _, status := range t.domains {
		status.CurrentTestIndex = 0
		status.TestResults = make(map[certificates.TestType]bool)
		status.TestsCompleted = false
		status.SuccessfulTestSet = false
		status.LastTested = time.Now()
	}

	// Save the updated domain results to JSON
	if err := t.SaveToJSON(); err != nil {
		t.logger.Errorf("[ERROR] Failed to save domain results to JSON: %v", err)
	}
}

// SaveToJSON saves the domain test results to a JSON file
func (t *Tester) SaveToJSON() error {
	// Create a JSON-friendly version of the data
	jsonData := testerJSON{
		Domains: make(map[string]domainTestStatusJSON),
	}

	for domain, status := range t.domains {
		// Convert TestResults to use string keys
		testResults := make(map[string]bool)
		for testType, result := range status.TestResults {
			testResults[testType.GetTestTypeName()] = result
		}

		// Convert SuccessfulTest to string
		successfulTest := ""
		if status.SuccessfulTestSet {
			successfulTest = status.SuccessfulTest.GetTestTypeName()
		}

		jsonData.Domains[domain] = domainTestStatusJSON{
			Domain:            status.Domain,
			IP:                status.IP,
			IPs:               status.IPs,
			CurrentTestIndex:  status.CurrentTestIndex,
			TestResults:       testResults,
			LastTested:        status.LastTested,
			TestsCompleted:    status.TestsCompleted,
			SuccessfulTest:    successfulTest,
			SuccessfulTestSet: status.SuccessfulTestSet,
		}
	}

	// Create the data directory if it doesn't exist
	os.MkdirAll(filepath.Dir(t.jsonFilePath), 0755)

	// Marshal to JSON
	jsonBytes, err := json.MarshalIndent(jsonData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal domain results to JSON: %v", err)
	}

	// Write to file
	if err := os.WriteFile(t.jsonFilePath, jsonBytes, 0644); err != nil {
		return fmt.Errorf("failed to write domain results to JSON file: %v", err)
	}

	t.logger.Debugf("Saved domain results to %s", t.jsonFilePath)
	return nil
}

// LoadFromJSON loads domain test results from a JSON file
func (t *Tester) LoadFromJSON() error {
	// Check if the file exists
	if _, err := os.Stat(t.jsonFilePath); os.IsNotExist(err) {
		return fmt.Errorf("domain results file does not exist: %s", t.jsonFilePath)
	}

	// Read the file
	jsonBytes, err := os.ReadFile(t.jsonFilePath)
	if err != nil {
		return fmt.Errorf("failed to read domain results from JSON file: %v", err)
	}

	// Unmarshal from JSON
	var jsonData testerJSON
	if err := json.Unmarshal(jsonBytes, &jsonData); err != nil {
		return fmt.Errorf("failed to unmarshal domain results from JSON: %v", err)
	}

	// Convert JSON data to domain test statuses
	for domain, jsonStatus := range jsonData.Domains {
		// Convert TestResults to use TestType keys
		testResults := make(map[certificates.TestType]bool)
		for testTypeStr, result := range jsonStatus.TestResults {
			var testType certificates.TestType
			switch testTypeStr {
			case "Self-Signed":
				testType = certificates.SelfSigned
			case "Replaced Key":
				testType = certificates.ReplacedKey
			case "Real Certificate":
				testType = certificates.RealCertificate
			case "Real Certificate as CA":
				testType = certificates.RealCertificateAsCA
			default:
				t.logger.Errorf("Unknown test type in JSON: %s", testTypeStr)
				continue
			}
			testResults[testType] = result
		}

		// Convert SuccessfulTest from string
		var successfulTest certificates.TestType
		if jsonStatus.SuccessfulTestSet {
			switch jsonStatus.SuccessfulTest {
			case "Self-Signed":
				successfulTest = certificates.SelfSigned
			case "Replaced Key":
				successfulTest = certificates.ReplacedKey
			case "Real Certificate":
				successfulTest = certificates.RealCertificate
			case "Real Certificate as CA":
				successfulTest = certificates.RealCertificateAsCA
			default:
				t.logger.Errorf("Unknown successful test type in JSON: %s", jsonStatus.SuccessfulTest)
			}
		}

		// Create the domain status
		status := &DomainTestStatus{
			Domain:            jsonStatus.Domain,
			IP:                jsonStatus.IP,
			IPs:               jsonStatus.IPs,
			CurrentTestIndex:  jsonStatus.CurrentTestIndex,
			TestResults:       testResults,
			LastTested:        jsonStatus.LastTested,
			TestsCompleted:    jsonStatus.TestsCompleted,
			SuccessfulTest:    successfulTest,
			SuccessfulTestSet: jsonStatus.SuccessfulTestSet,
		}

		t.domains[domain] = status

		// Update the IP to domain mapping
		if jsonStatus.IP != "" {
			t.ipToDomain[jsonStatus.IP] = domain
		}

		// Update the IP to domain mapping for all IPs
		for _, ip := range jsonStatus.IPs {
			if ip != "" {
				t.ipToDomain[ip] = domain
			}
		}
	}

	t.logger.Infof("Loaded %d domain results from %s", len(t.domains), t.jsonFilePath)
	return nil
}

// We're using the isSimpleIPAddress function for backward compatibility
// and the standard library's net.ParseIP for more accurate IP detection

// resolveDomainToIP resolves a domain name to its IP address
func (t *Tester) resolveDomainToIP(domain string) (string, error) {
	// Skip if it's already an IP address
	if net.ParseIP(domain) != nil {
		return domain, nil
	}

	// Resolve the domain name to IP addresses
	ips, err := net.LookupIP(domain)
	if err != nil {
		return "", fmt.Errorf("failed to resolve domain %s: %v", domain, err)
	}

	// Use the first IPv4 address
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4.String(), nil
		}
	}

	// If no IPv4 address is found, use the first IP address
	if len(ips) > 0 {
		return ips[0].String(), nil
	}

	return "", fmt.Errorf("no IP address found for domain %s", domain)
}

// resolveDomainToAllIPs resolves a domain name to all its IP addresses
func (t *Tester) resolveDomainToAllIPs(domain string) ([]string, error) {
	// Skip if it's already an IP address
	if net.ParseIP(domain) != nil {
		return []string{domain}, nil
	}

	// Resolve the domain name to IP addresses
	ips, err := net.LookupIP(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve domain %s: %v", domain, err)
	}

	// Convert IP addresses to strings
	ipStrings := make([]string, 0, len(ips))
	for _, ip := range ips {
		ipStrings = append(ipStrings, ip.String())
	}

	return ipStrings, nil
}

// GetDomainByIP returns the domain name associated with an IP address
func (t *Tester) GetDomainByIP(ip string) string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	domain, exists := t.ipToDomain[ip]
	if !exists {
		return ip // If no domain is found, return the IP itself
	}

	return domain
}

// GetTestStatusByIP returns the test status for an IP address
func (t *Tester) GetTestStatusByIP(ip string) *DomainTestStatus {
	t.mu.RLock()
	defer t.mu.RUnlock()

	// First, check if we have a domain mapping for this IP
	domain, exists := t.ipToDomain[ip]
	if !exists {
		// If no domain mapping exists, check if the IP itself is a key in domains
		status, exists := t.domains[ip]
		if !exists {
			return nil
		}
		return status
	}

	// Get the status for the domain
	status, exists := t.domains[domain]
	if !exists {
		return nil
	}

	return status
}

// GetNextTestByIP returns the next test to perform for an IP address
func (t *Tester) GetNextTestByIP(ip string) certificates.TestType {
	// First, try to get the domain for this IP
	domain := t.GetDomainByIP(ip)

	// If we found a domain, use it to get the next test
	if domain != ip {
		return t.GetNextTest(domain)
	}

	// Otherwise, treat the IP as a domain
	return t.GetNextTest(ip)
}

// ShouldUseTunnelByIP checks if we should use a direct tunnel for an IP address
func (t *Tester) ShouldUseTunnelByIP(ip string) bool {
	// First, try to get the domain for this IP
	domain := t.GetDomainByIP(ip)

	// If we found a domain, use it to check if we should use a tunnel
	if domain != ip {
		return t.ShouldUseTunnel(domain)
	}

	// Otherwise, treat the IP as a domain
	return t.ShouldUseTunnel(ip)
}

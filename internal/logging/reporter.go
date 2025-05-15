package logging

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// TestResult represents the result of a certificate test
type TestResult struct {
	Timestamp   time.Time `json:"timestamp"`
	ClientIP    string    `json:"client_ip"`
	Host        string    `json:"host"`
	TestType    string    `json:"test_type"`
	Accepted    bool      `json:"accepted"`
	Description string    `json:"description"`
}

// Reporter handles reporting of test results
type Reporter struct {
	logDir     string
	results    []TestResult
	resultFile *os.File
	mu         sync.Mutex
}

// NewReporter creates a new reporter
func NewReporter(logDir string) (*Reporter, error) {
	// Create log directory if it doesn't exist
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %v", err)
	}

	// Create result file
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	resultPath := filepath.Join(logDir, fmt.Sprintf("results_%s.json", timestamp))
	resultFile, err := os.Create(resultPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create result file: %v", err)
	}

	return &Reporter{
		logDir:     logDir,
		results:    make([]TestResult, 0),
		resultFile: resultFile,
	}, nil
}

// Close closes the result file
func (r *Reporter) Close() error {
	if r.resultFile != nil {
		// Write results to file
		if err := r.SaveResults(); err != nil {
			return err
		}
		return r.resultFile.Close()
	}
	return nil
}

// AddResult adds a test result
func (r *Reporter) AddResult(clientIP, host, testType string, accepted bool, description string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	result := TestResult{
		Timestamp:   time.Now(),
		ClientIP:    clientIP,
		Host:        host,
		TestType:    testType,
		Accepted:    accepted,
		Description: description,
	}

	r.results = append(r.results, result)
}

// SaveResults saves the results to the result file
func (r *Reporter) SaveResults() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Reset file
	if err := r.resultFile.Truncate(0); err != nil {
		return fmt.Errorf("failed to truncate result file: %v", err)
	}
	if _, err := r.resultFile.Seek(0, 0); err != nil {
		return fmt.Errorf("failed to seek result file: %v", err)
	}

	// Write results to file
	encoder := json.NewEncoder(r.resultFile)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(r.results); err != nil {
		return fmt.Errorf("failed to encode results: %v", err)
	}

	return nil
}

// GetResults returns the results
func (r *Reporter) GetResults() []TestResult {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.results
}

// GenerateReport generates a report of the results
func (r *Reporter) GenerateReport() (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Count results by test type and acceptance
	counts := make(map[string]map[bool]int)
	for _, result := range r.results {
		if _, ok := counts[result.TestType]; !ok {
			counts[result.TestType] = make(map[bool]int)
		}
		counts[result.TestType][result.Accepted]++
	}

	// Generate report
	report := "# CertMITM Test Report\n\n"
	report += fmt.Sprintf("Generated: %s\n\n", time.Now().Format(time.RFC1123))
	report += "## Summary\n\n"
	report += "| Test Type | Accepted | Rejected | Total |\n"
	report += "|-----------|----------|----------|-------|\n"

	for testType, count := range counts {
		accepted := count[true]
		rejected := count[false]
		total := accepted + rejected
		report += fmt.Sprintf("| %s | %d | %d | %d |\n", testType, accepted, rejected, total)
	}

	report += "\n## Details\n\n"
	for _, result := range r.results {
		status := "REJECTED"
		if result.Accepted {
			status = "ACCEPTED"
		}
		report += fmt.Sprintf("- %s: %s test for %s from %s: %s\n", result.Timestamp.Format(time.RFC1123), result.TestType, result.Host, result.ClientIP, status)
		if result.Description != "" {
			report += fmt.Sprintf("  - %s\n", result.Description)
		}
	}

	return report, nil
}

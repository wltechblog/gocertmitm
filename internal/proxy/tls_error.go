package proxy

import (
	"net"
	"regexp"
	"strings"

	"github.com/gocertmitm/internal/certificates"
)

// tlsErrorLogger is a custom logger that captures TLS handshake errors
// and records them as failed tests
type tlsErrorLogger struct {
	server *Server
}

// Write implements the io.Writer interface
func (l *tlsErrorLogger) Write(p []byte) (n int, err error) {
	// Get the log message
	msg := string(p)

	// Check if this is a direct tunnel error
	if strings.Contains(msg, "direct tunnel requested for") || strings.Contains(msg, "direct tunnel established for") {
		// This is expected when we're using a direct tunnel, so we don't need to log it as an error
		l.server.logger.Debugf("[TUNNEL-TLS-ERROR] Detected direct tunnel error: %s", msg)
		return len(p), nil
	}

	// Check if this is a TLS handshake error or connection reset
	if strings.Contains(msg, "TLS handshake error") ||
		strings.Contains(msg, "connection reset by peer") ||
		strings.Contains(msg, "broken pipe") {
		// Extract the client IP
		ipRe := regexp.MustCompile(`from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)`)
		ipMatches := ipRe.FindStringSubmatch(msg)

		if len(ipMatches) < 2 {
			// If we can't extract the client IP, just return
			return len(p), nil
		}

		clientIP := ipMatches[1]

		// Try to extract the domain from the error message
		domain := extractDomainFromErrorMessage(msg)
		if domain == "" {
			// Try to extract the domain from the server name in the error message
			domain = extractServerNameFromErrorMessage(msg)
		}

		// Try to extract the SNI field directly
		if domain == "" && strings.Contains(msg, "tls: unknown certificate") {
			// Look for SNI field in the format "sni=domain.com"
			sniRe := regexp.MustCompile(`sni=([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z0-9.-]+)`)
			sniMatches := sniRe.FindStringSubmatch(msg)

			if len(sniMatches) >= 2 {
				domain = sniMatches[1]
				l.server.logger.Debugf("Extracted domain from SNI field: %s", domain)
			}
		}

		// If we still couldn't find a domain, try to extract it from the port
		if domain == "" {
			// Extract the port number
			portRe := regexp.MustCompile(`from [0-9.]+:([0-9]+)`)
			portMatches := portRe.FindStringSubmatch(msg)

			if len(portMatches) >= 2 {
				port := portMatches[1]
				l.server.logger.Debugf("Extracted port %s from TLS handshake error", port)

				// Look up the domain being tested for this client IP and port
				// This is a workaround since we can't directly extract the domain
				domain = l.findDomainForClientIP(clientIP)

				if domain != "" {
					l.server.logger.Debugf("Found domain %s for client IP %s", domain, clientIP)
				}
			}
		}

		// If we still couldn't find a domain, log and return
		if domain == "" {
			l.server.logger.Debugf("Could not extract domain from TLS handshake error: %s", msg)
			return len(p), nil
		}

		// Make sure the domain is not an IP address
		if isIPAddress(domain) {
			l.server.logger.Debugf("Extracted domain is an IP address, skipping: %s", domain)
			return len(p), nil
		}

		// Check if this domain is in the direct tunnel map
		// If it is, we should ignore this error as we're not actually trying to do a TLS handshake
		l.server.directTunnelMu.Lock()
		isDirectTunnel := l.server.directTunnelDomains[domain]
		l.server.directTunnelMu.Unlock()

		if isDirectTunnel {
			// This is a direct tunnel connection, so we should ignore TLS handshake errors
			// as we're not actually trying to do a TLS handshake
			l.server.logger.Debugf("Ignoring TLS handshake error for domain %s as it's in direct tunnel mode", domain)

			// For direct tunnel connections, we should never record handshake failures
			// or try to do any TLS-related operations
			return len(p), nil
		}

		// Get the domain test status before recording the failure
		domainStatus := l.server.tester.GetTestStatus(domain)
		if domainStatus != nil {
			l.server.logger.Debugf("Before failure - Domain %s status: CurrentTestIndex=%d, TestsCompleted=%v, SuccessfulTestSet=%v",
				domain, domainStatus.CurrentTestIndex, domainStatus.TestsCompleted, domainStatus.SuccessfulTestSet)

			// If we've already completed all tests with no success, we should be in direct tunnel mode
			if domainStatus.TestsCompleted && !domainStatus.SuccessfulTestSet {
				// Make sure this domain is in the direct tunnel map
				l.server.directTunnelMu.Lock()
				l.server.directTunnelDomains[domain] = true
				l.server.directTunnelMu.Unlock()

				l.server.logger.Debugf("Domain %s has already completed all tests with no success, ignoring TLS handshake error and using DirectTunnel", domain)

				// We need to find the connection for this client IP and domain
				// Since we don't have direct access to the connection in the TLS error handler,
				// we'll just make sure the domain is marked for direct tunnel mode
				// Future connections to this domain will use direct tunnel mode automatically

				// Get a request ID for this connection
				reqID := l.server.logger.GetRequestID(clientIP, domain)
				l.server.logger.InfoWithRequestIDf(reqID, "[TUNNEL-TLS-ERROR] Domain %s marked for direct tunnel mode", domain)

				return len(p), nil
			}
		}

		// Get the current test type for this domain
		testType := l.server.tester.GetNextTest(domain)

		// Check if the current test type is DirectTunnel
		if testType == certificates.DirectTunnel {
			// We're already in direct tunnel mode, so we should ignore this error
			l.server.logger.Debugf("Ignoring TLS handshake error for domain %s as test type is DirectTunnel", domain)

			// Make sure this domain is in the direct tunnel map
			l.server.directTunnelMu.Lock()
			l.server.directTunnelDomains[domain] = true
			l.server.directTunnelMu.Unlock()

			return len(p), nil
		}

		// Get a request ID for this connection
		reqID := l.server.logger.GetRequestID(clientIP, domain)

		// Record the handshake failure
		l.server.logger.InfoWithRequestIDf(reqID, "[TLS] Handshake error from %s for %s with test type %s",
			clientIP, domain, testType.GetTestTypeName())

		// Record the failure and get the next test type
		nextTest := l.server.RecordFailedHandshake(domain, testType, reqID)

		// Get the domain test status after recording the failure
		domainStatus = l.server.tester.GetTestStatus(domain)
		if domainStatus != nil {
			l.server.logger.DebugWithRequestIDf(reqID, "[DOMAIN] After failure - Domain %s status: CurrentTestIndex=%d, TestsCompleted=%v, SuccessfulTestSet=%v",
				domain, domainStatus.CurrentTestIndex, domainStatus.TestsCompleted, domainStatus.SuccessfulTestSet)
		}

		l.server.logger.InfoWithRequestIDf(reqID, "[NEXT] Moving to next test for %s: %s", domain, nextTest.GetTestTypeName())
	}

	// Return the number of bytes written
	return len(p), nil
}

// findDomainForClientIP tries to find the domain being tested for a client IP
// This is a workaround for when we can't extract the domain from the error message
func (l *tlsErrorLogger) findDomainForClientIP(clientIP string) string {
	// First, check if we have a stored destination for this client IP
	l.server.clientDestMu.Lock()
	destination, exists := l.server.clientDestinations[clientIP]
	l.server.clientDestMu.Unlock()

	if exists {
		// Extract the host without port
		var hostWithoutPort string
		if strings.Contains(destination, ":") {
			var splitErr error
			hostWithoutPort, _, splitErr = net.SplitHostPort(destination)
			if splitErr == nil {
				// For IP addresses, we want to use the IP directly
				if net.ParseIP(hostWithoutPort) != nil {
					l.server.logger.Debugf("Found stored IP destination for client %s: %s", clientIP, hostWithoutPort)
					return hostWithoutPort
				} else if isValidDomain(hostWithoutPort) {
					l.server.logger.Debugf("Found stored domain destination for client %s: %s", clientIP, hostWithoutPort)
					return hostWithoutPort
				}
			}
		} else if net.ParseIP(destination) != nil {
			// If it's an IP without port, use it directly
			l.server.logger.Debugf("Found stored IP destination for client %s: %s", clientIP, destination)
			return destination
		} else if isValidDomain(destination) {
			l.server.logger.Debugf("Found stored domain destination for client %s: %s", clientIP, destination)
			return destination
		}
	}

	// If no stored destination, check the recent domains list
	recentDomains := l.server.GetRecentDomains()
	if len(recentDomains) > 0 {
		// Use the most recent domain as it's likely the one being tested
		for i := len(recentDomains) - 1; i >= 0; i-- {
			domain := recentDomains[i]
			if isValidDomain(domain) {
				l.server.logger.Debugf("Using recent domain: %s", domain)
				return domain
			}
		}
	}

	// If no recent domains, get all domains being tested
	domains := l.server.tester.GetAllDomains()

	// Filter out invalid domains
	validDomains := make([]string, 0, len(domains))
	for _, domain := range domains {
		if isValidDomain(domain) {
			validDomains = append(validDomains, domain)
		}
	}

	// If there's only one valid domain being tested, return it
	if len(validDomains) == 1 {
		l.server.logger.Debugf("Only one valid domain being tested: %s", validDomains[0])
		return validDomains[0]
	}

	// If there are multiple domains, check the most recent logs to find which domain
	// was being tested for this client IP
	l.server.logger.Debugf("Looking for domain being tested by client IP %s among %d valid domains",
		clientIP, len(validDomains))

	// First, look for domains that are still being tested (not completed)
	for _, domain := range validDomains {
		// Get the test status for this domain
		status := l.server.tester.GetTestStatus(domain)
		if status != nil && !status.TestsCompleted && !status.SuccessfulTestSet {
			// This domain is still being tested and hasn't succeeded yet, so it's a good candidate
			l.server.logger.Debugf("Found domain %s still being tested", domain)
			return domain
		}
	}

	// If we can't determine the domain, return the first valid one as a fallback
	if len(validDomains) > 0 {
		l.server.logger.Debugf("Using first valid domain as fallback: %s", validDomains[0])
		return validDomains[0]
	}

	return ""
}

// extractDomainFromErrorMessage extracts the domain from a TLS handshake error message
func extractDomainFromErrorMessage(msg string) string {
	// Try to extract the domain from the error message
	// First, look for a domain in the format "domain.tld"
	domainRe := regexp.MustCompile(`TLS handshake error from [0-9.:]+ for ([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z0-9.-]+)`)
	domainMatches := domainRe.FindStringSubmatch(msg)

	if len(domainMatches) < 2 {
		return ""
	}

	// Validate the domain - it should have at least one dot and not be a filename
	domain := domainMatches[1]
	if strings.Contains(domain, ".") && !strings.HasSuffix(domain, ".go") &&
		!strings.HasSuffix(domain, ".js") && !strings.HasSuffix(domain, ".py") &&
		!strings.HasSuffix(domain, ".c") && !strings.HasSuffix(domain, ".h") {
		return domain
	}

	return ""
}

// extractServerNameFromErrorMessage extracts the server name from a TLS handshake error message
func extractServerNameFromErrorMessage(msg string) string {
	// Try to extract the server name from the error message
	// Look for patterns like "unknown certificate" or "certificate is not trusted"
	if strings.Contains(msg, "unknown certificate") {
		// Extract the server name from the SNI field
		sniRe := regexp.MustCompile(`sni=([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z0-9.-]+)`)
		sniMatches := sniRe.FindStringSubmatch(msg)

		if len(sniMatches) >= 2 {
			// Validate the domain
			domain := sniMatches[1]
			if isValidDomain(domain) {
				return domain
			}
		}
	}

	// Try to extract from the certificate subject
	subjectRe := regexp.MustCompile(`subject=([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z0-9.-]+)`)
	subjectMatches := subjectRe.FindStringSubmatch(msg)

	if len(subjectMatches) >= 2 {
		// Validate the domain
		domain := subjectMatches[1]
		if isValidDomain(domain) {
			return domain
		}
	}

	// Try to extract from the server name in the error message
	// This pattern looks for any domain-like string in the error message
	domainRe := regexp.MustCompile(`([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z0-9.-]+)`)
	domainMatches := domainRe.FindAllStringSubmatch(msg, -1)

	// If we found any domains, return the first one that's not an IP address and is a valid domain
	for _, match := range domainMatches {
		if len(match) >= 2 && !isIPAddress(match[1]) {
			domain := match[1]
			// Skip common subdomains that might be part of error messages and validate the domain
			if domain != "golang.org" && domain != "example.com" &&
				!strings.HasSuffix(domain, ".local") && isValidDomain(domain) {
				return domain
			}
		}
	}

	return ""
}

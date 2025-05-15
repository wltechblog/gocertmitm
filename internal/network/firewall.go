package network

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/gocertmitm/internal/logging"
)

// Firewall manages iptables rules
type Firewall struct {
	logger *logging.Logger
	rules  []string
}

// NewFirewall creates a new firewall manager
func NewFirewall(logger *logging.Logger) *Firewall {
	return &Firewall{
		logger: logger,
		rules:  make([]string, 0),
	}
}

// RedirectHTTPS redirects HTTPS traffic to the proxy
func (f *Firewall) RedirectHTTPS(proxyPort string) error {
	// Check if iptables is available
	if _, err := exec.LookPath("iptables"); err != nil {
		return fmt.Errorf("iptables not found: %v", err)
	}

	// Save current rules
	if err := f.saveCurrentRules(); err != nil {
		return fmt.Errorf("failed to save current rules: %v", err)
	}

	// Add rules to redirect HTTPS traffic
	rules := []string{
		fmt.Sprintf("-t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port %s", proxyPort),
		fmt.Sprintf("-t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port %s", proxyPort),
	}

	// Apply rules
	for _, rule := range rules {
		cmd := exec.Command("iptables", strings.Split(rule, " ")...)
		if err := cmd.Run(); err != nil {
			f.logger.Errorf("Failed to apply iptables rule: %v", err)
			f.Restore()
			return fmt.Errorf("failed to apply iptables rule: %v", err)
		}
		f.logger.Debugf("Applied iptables rule: %s", rule)
	}

	return nil
}

// Restore restores the original iptables rules
func (f *Firewall) Restore() error {
	// Check if iptables is available
	if _, err := exec.LookPath("iptables"); err != nil {
		return fmt.Errorf("iptables not found: %v", err)
	}

	// Clear all rules
	cmd := exec.Command("iptables", "-t", "nat", "-F")
	if err := cmd.Run(); err != nil {
		f.logger.Errorf("Failed to clear iptables rules: %v", err)
		return fmt.Errorf("failed to clear iptables rules: %v", err)
	}

	// Restore original rules
	for _, rule := range f.rules {
		cmd := exec.Command("iptables", strings.Split(rule, " ")...)
		if err := cmd.Run(); err != nil {
			f.logger.Errorf("Failed to restore iptables rule: %v", err)
			return fmt.Errorf("failed to restore iptables rule: %v", err)
		}
		f.logger.Debugf("Restored iptables rule: %s", rule)
	}

	return nil
}

// saveCurrentRules saves the current iptables rules
func (f *Firewall) saveCurrentRules() error {
	// Get current rules
	cmd := exec.Command("iptables-save")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to save iptables rules: %v", err)
	}

	// Parse rules
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "-A") {
			f.rules = append(f.rules, line[3:])
		}
	}

	return nil
}

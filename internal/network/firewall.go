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
	// The nat table rules added by this tool; they are removed with a
	// per-rule delete on Restore instead of flushing the table, which would
	// also delete unrelated rules such as those created by Docker
	rules []string
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

	// Add rules to redirect HTTPS traffic
	f.rules = []string{
		fmt.Sprintf("-t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port %s", proxyPort),
		fmt.Sprintf("-t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port %s", proxyPort),
	}

	// Apply rules
	for _, rule := range f.rules {
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

// Restore removes the redirect rules this tool added to the nat table
func (f *Firewall) Restore() error {
	// Check if iptables is available
	if _, err := exec.LookPath("iptables"); err != nil {
		return fmt.Errorf("iptables not found: %v", err)
	}

	// Delete the rules that were added, one by one. Deleting a missing rule
	// is not an error here; the goal is to leave just these rules removed.
	for _, rule := range f.rules {
		args := strings.Split(rule, " ")
		deleteArgs := make([]string, 0, len(args))
		for _, arg := range args {
			if arg == "-A" {
				deleteArgs = append(deleteArgs, "-D")
			} else {
				deleteArgs = append(deleteArgs, arg)
			}
		}

		cmd := exec.Command("iptables", deleteArgs...)
		if err := cmd.Run(); err != nil {
			f.logger.Errorf("Failed to remove iptables rule %q: %v", rule, err)
			return fmt.Errorf("failed to remove iptables rule %q: %v", rule, err)
		}
		f.logger.Debugf("Removed iptables rule: %s", rule)
	}

	return nil
}

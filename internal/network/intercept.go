package network

import (
	"fmt"
	"net"
	"strings"

	"github.com/gocertmitm/internal/logging"
)

// Interceptor manages traffic interception
type Interceptor struct {
	logger   *logging.Logger
	firewall *Firewall
	gateway  *Gateway
}

// NewInterceptor creates a new interceptor
func NewInterceptor(logger *logging.Logger, iface string) (*Interceptor, error) {
	// Create firewall
	firewall := NewFirewall(logger)

	// Create gateway
	gateway, err := NewGateway(logger, iface)
	if err != nil {
		return nil, fmt.Errorf("failed to create gateway: %v", err)
	}

	return &Interceptor{
		logger:   logger,
		firewall: firewall,
		gateway:  gateway,
	}, nil
}

// Start starts traffic interception
func (i *Interceptor) Start(proxyPort string) error {
	// Enable gateway
	if err := i.gateway.Enable(); err != nil {
		return fmt.Errorf("failed to enable gateway: %v", err)
	}

	// Redirect HTTPS traffic
	if err := i.firewall.RedirectHTTPS(proxyPort); err != nil {
		i.gateway.Disable()
		return fmt.Errorf("failed to redirect HTTPS traffic: %v", err)
	}

	i.logger.Infof("Started traffic interception on interface %s", i.gateway.GetInterface())
	i.logger.Infof("Gateway IP address: %s", i.gateway.GetIPAddress())

	return nil
}

// Stop stops traffic interception
func (i *Interceptor) Stop() error {
	// Restore firewall rules
	if err := i.firewall.Restore(); err != nil {
		i.logger.Errorf("Failed to restore firewall rules: %v", err)
	}

	// Disable gateway
	if err := i.gateway.Disable(); err != nil {
		i.logger.Errorf("Failed to disable gateway: %v", err)
		return fmt.Errorf("failed to disable gateway: %v", err)
	}

	i.logger.Infof("Stopped traffic interception")

	return nil
}

// GetClientIP gets the client IP address from a connection
func (i *Interceptor) GetClientIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

// IsLocalIP checks if an IP address is local
func (i *Interceptor) IsLocalIP(ip string) bool {
	// Check if IP is localhost
	if ip == "127.0.0.1" || ip == "::1" {
		return true
	}

	// Check if IP is the gateway IP
	if ip == i.gateway.GetIPAddress() {
		return true
	}

	// Get all local IP addresses
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		i.logger.Errorf("Failed to get interface addresses: %v", err)
		return false
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.String() == ip {
				return true
			}
		}
	}

	return false
}

// GetHostFromRequest gets the host from an HTTP request
func (i *Interceptor) GetHostFromRequest(host string) string {
	// Remove port if present
	if strings.Contains(host, ":") {
		host, _, _ = net.SplitHostPort(host)
	}
	return host
}

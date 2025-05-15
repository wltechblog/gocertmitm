package network

import (
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/gocertmitm/internal/logging"
)

// Gateway manages network gateway functionality
type Gateway struct {
	logger        *logging.Logger
	interfaceName string
	ipAddress     string
	originalIPv4  bool
}

// NewGateway creates a new gateway manager
func NewGateway(logger *logging.Logger, iface string) (*Gateway, error) {
	// Get interface
	netInterface, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("interface not found: %v", err)
	}

	// Get IP address
	addrs, err := netInterface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("failed to get interface addresses: %v", err)
	}

	var ipAddress string
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ipAddress = ipnet.IP.String()
				break
			}
		}
	}

	if ipAddress == "" {
		return nil, fmt.Errorf("no IPv4 address found for interface %s", iface)
	}

	// Check if IPv4 forwarding is enabled
	cmd := exec.Command("sysctl", "net.ipv4.ip_forward")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to check IPv4 forwarding: %v", err)
	}

	originalIPv4 := strings.TrimSpace(string(output)) == "net.ipv4.ip_forward = 1"

	return &Gateway{
		logger:        logger,
		interfaceName: iface,
		ipAddress:     ipAddress,
		originalIPv4:  originalIPv4,
	}, nil
}

// Enable enables the gateway
func (g *Gateway) Enable() error {
	// Enable IPv4 forwarding
	cmd := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to enable IPv4 forwarding: %v", err)
	}
	g.logger.Debugf("Enabled IPv4 forwarding")

	return nil
}

// Disable disables the gateway
func (g *Gateway) Disable() error {
	// Restore IPv4 forwarding
	value := "0"
	if g.originalIPv4 {
		value = "1"
	}
	cmd := exec.Command("sysctl", "-w", fmt.Sprintf("net.ipv4.ip_forward=%s", value))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to restore IPv4 forwarding: %v", err)
	}
	g.logger.Debugf("Restored IPv4 forwarding to %s", value)

	return nil
}

// GetIPAddress returns the IP address of the gateway
func (g *Gateway) GetIPAddress() string {
	return g.ipAddress
}

// GetInterface returns the interface of the gateway
func (g *Gateway) GetInterface() string {
	return g.interfaceName
}

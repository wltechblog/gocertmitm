package netutils

import (
	"fmt"
	"net"
	"strings"
)

// GetLocalIP returns the local IP address
func GetLocalIP() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", fmt.Errorf("failed to get interface addresses: %v", err)
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String(), nil
			}
		}
	}

	return "", fmt.Errorf("no IP address found")
}

// GetInterfaceIP returns the IP address of an interface
func GetInterfaceIP(iface string) (string, error) {
	netInterface, err := net.InterfaceByName(iface)
	if err != nil {
		return "", fmt.Errorf("interface not found: %v", err)
	}

	addrs, err := netInterface.Addrs()
	if err != nil {
		return "", fmt.Errorf("failed to get interface addresses: %v", err)
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String(), nil
			}
		}
	}

	return "", fmt.Errorf("no IPv4 address found for interface %s", iface)
}

// GetInterfaces returns a list of network interfaces
func GetInterfaces() ([]string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get interfaces: %v", err)
	}

	var result []string
	for _, iface := range interfaces {
		// Skip loopback and interfaces without addresses
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		if len(addrs) == 0 {
			continue
		}
		result = append(result, iface.Name)
	}

	return result, nil
}

// IsLocalIP checks if an IP address is local
func IsLocalIP(ip string) bool {
	// Check if IP is localhost
	if ip == "127.0.0.1" || ip == "::1" {
		return true
	}

	// Get all local IP addresses
	addrs, err := net.InterfaceAddrs()
	if err != nil {
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

// GetHostFromAddress gets the host from an address
func GetHostFromAddress(addr string) string {
	// Remove port if present
	if strings.Contains(addr, ":") {
		host, _, _ := net.SplitHostPort(addr)
		return host
	}
	return addr
}

// IsValidIP checks if a string is a valid IP address
func IsValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// IsValidPort checks if a string is a valid port
func IsValidPort(port string) bool {
	// Parse port
	p, err := net.LookupPort("tcp", port)
	if err != nil {
		return false
	}
	return p > 0 && p < 65536
}

package proxy

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// SO_ORIGINAL_DST is the Linux socket option to get the original destination address
const SO_ORIGINAL_DST = 80

// OriginalDestination contains information about the original destination of a connection
type OriginalDestination struct {
	IP       net.IP
	Port     int
	IPString string
	HostPort string
}

// GetOriginalDst gets the original destination IP:port from a TCP connection
// This is used in transparent proxy mode where the connection has been redirected
func GetOriginalDst(conn *net.TCPConn) (*OriginalDestination, error) {
	// Get the local and remote addresses for debugging
	localAddr := conn.LocalAddr().String()
	remoteAddr := conn.RemoteAddr().String()

	fmt.Printf("[DEBUG] GetOriginalDst called for connection from %s to %s\n", remoteAddr, localAddr)

	file, err := conn.File()
	if err != nil {
		fmt.Printf("[ERROR] Failed to get file descriptor for connection %s -> %s: %v\n", remoteAddr, localAddr, err)
		return nil, fmt.Errorf("failed to get file descriptor: %v", err)
	}
	defer file.Close()

	fd := int(file.Fd())
	fmt.Printf("[DEBUG] Got file descriptor %d for connection %s -> %s\n", fd, remoteAddr, localAddr)

	// Get original destination using SO_ORIGINAL_DST socket option
	// This works for connections redirected by iptables REDIRECT or TPROXY
	fmt.Printf("[DEBUG] Calling GetsockoptIPv6Mreq with fd=%d, IPPROTO_IP=%d, SO_ORIGINAL_DST=%d\n",
		fd, unix.IPPROTO_IP, SO_ORIGINAL_DST)

	addr, err := unix.GetsockoptIPv6Mreq(fd, unix.IPPROTO_IP, SO_ORIGINAL_DST)
	if err != nil {
		fmt.Printf("[ERROR] getsockopt SO_ORIGINAL_DST failed for connection %s -> %s: %v\n",
			remoteAddr, localAddr, err)
		return nil, fmt.Errorf("getsockopt SO_ORIGINAL_DST failed: %v", err)
	}

	// Extract IP and port from the sockaddr structure
	// The sockaddr_in structure is:
	// struct sockaddr_in {
	//     sa_family_t    sin_family; /* address family: AF_INET */
	//     in_port_t      sin_port;   /* port in network byte order */
	//     struct in_addr sin_addr;   /* internet address */
	// };

	// Debug the raw sockaddr data
	fmt.Printf("[DEBUG] Raw sockaddr data: family=%d, port=%d,%d, addr=%d,%d,%d,%d\n",
		addr.Multiaddr[1], addr.Multiaddr[2], addr.Multiaddr[3],
		addr.Multiaddr[4], addr.Multiaddr[5], addr.Multiaddr[6], addr.Multiaddr[7])

	ip := net.IPv4(
		addr.Multiaddr[4],
		addr.Multiaddr[5],
		addr.Multiaddr[6],
		addr.Multiaddr[7],
	)

	// Convert port from network byte order (big endian)
	port := int(addr.Multiaddr[2])<<8 | int(addr.Multiaddr[3])

	// Create the result structure
	result := &OriginalDestination{
		IP:       ip,
		Port:     port,
		IPString: ip.String(),
		HostPort: fmt.Sprintf("%s:%d", ip.String(), port),
	}

	fmt.Printf("[DEBUG] Original destination determined: %s:%d (IP: %s) for connection %s -> %s\n",
		ip.String(), port, ip.String(), remoteAddr, localAddr)

	return result, nil
}

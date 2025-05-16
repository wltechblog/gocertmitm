#!/bin/bash
# Script to debug network redirection issues

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

# Define variables
TARGET_IP="192.168.82.118"
PROXY_PORT=9900
PROXY_IP="127.0.0.1"

# Parse command line arguments
while [[ "$#" -gt 0 ]]; do
  case $1 in
    -t|--target) TARGET_IP="$2"; shift ;;
    -p|--port) PROXY_PORT="$2"; shift ;;
    -i|--ip) PROXY_IP="$2"; shift ;;
    *) echo "Unknown parameter: $1"; exit 1 ;;
  esac
  shift
done

echo "=== Network Debugging Tool ==="
echo "Target IP: $TARGET_IP"
echo "Proxy: $PROXY_IP:$PROXY_PORT"
echo ""

# Check if proxy is running
echo "=== Checking if proxy is running ==="
if command -v netstat &> /dev/null; then
  netstat -tuln | grep $PROXY_PORT
elif command -v ss &> /dev/null; then
  ss -tuln | grep $PROXY_PORT
else
  echo "Neither netstat nor ss found, skipping port check."
fi
echo ""

# Check network interfaces
echo "=== Network Interfaces ==="
ip -br addr show
echo ""

# Check routing table
echo "=== Routing Table ==="
ip route
echo ""

# Check NAT table
echo "=== NAT Table (PREROUTING) ==="
iptables -t nat -L PREROUTING -v -n
echo ""

echo "=== NAT Table (POSTROUTING) ==="
iptables -t nat -L POSTROUTING -v -n
echo ""

# Check connection tracking
echo "=== Connection Tracking ==="
if command -v conntrack &> /dev/null; then
  echo "Active connections to port 443:"
  conntrack -L | grep "dport=443"
  echo ""
  echo "Active connections from target IP:"
  conntrack -L | grep $TARGET_IP
else
  echo "conntrack not found, skipping connection tracking check."
fi
echo ""

# Test packet flow with tcpdump
echo "=== Testing packet flow with tcpdump ==="
echo "Starting tcpdump in the background (will run for 10 seconds)..."
tcpdump -i any -n "host $TARGET_IP and tcp port 443 or tcp port $PROXY_PORT" -c 20 &
TCPDUMP_PID=$!

echo "Please generate some traffic from $TARGET_IP to port 443 now..."
sleep 10
kill $TCPDUMP_PID 2>/dev/null
echo ""

# Test direct connection to the proxy
echo "=== Testing direct connection to proxy ==="
echo "Attempting to connect to $PROXY_IP:$PROXY_PORT..."
if command -v nc &> /dev/null; then
  timeout 5 nc -v $PROXY_IP $PROXY_PORT
elif command -v telnet &> /dev/null; then
  echo "open $PROXY_IP $PROXY_PORT" | timeout 5 telnet
else
  echo "Neither nc nor telnet found, skipping direct connection test."
fi
echo ""

# Check if IP forwarding is enabled
echo "=== IP Forwarding ==="
cat /proc/sys/net/ipv4/ip_forward
echo ""

# Check if TPROXY is available
echo "=== TPROXY Support ==="
if lsmod | grep -q "xt_TPROXY"; then
  echo "TPROXY module is loaded."
else
  echo "TPROXY module is not loaded."
fi
echo ""

# Check for any firewall issues
echo "=== Firewall Rules ==="
iptables -L -v -n
echo ""

# Recommendations
echo "=== Recommendations ==="
echo "1. Ensure the proxy is running and listening on $PROXY_IP:$PROXY_PORT"
echo "2. Verify that IP forwarding is enabled (should be 1)"
echo "3. Check that the NAT rules are correctly redirecting traffic from $TARGET_IP port 443 to $PROXY_IP:$PROXY_PORT"
echo "4. Make sure there are no firewall rules blocking the redirected traffic"
echo "5. Consider using TPROXY instead of DNAT if available"
echo "6. Try running tcpdump on both the original destination port (443) and the proxy port ($PROXY_PORT) to see where the traffic is going"
echo ""

echo "=== Debug Complete ==="

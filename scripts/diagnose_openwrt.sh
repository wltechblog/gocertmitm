#!/bin/bash
# Script to diagnose OpenWRT router configuration for GoCertMITM

# Define variables
PROXY_PORT=9900
PROXY_IP="127.0.0.1"
VERBOSE=1

# Parse command line arguments
while [[ "$#" -gt 0 ]]; do
  case $1 in
    -p|--port) PROXY_PORT="$2"; shift ;;
    -i|--ip) PROXY_IP="$2"; shift ;;
    *) echo "Unknown parameter: $1"; exit 1 ;;
  esac
  shift
done

echo "=== OpenWRT Router Configuration Diagnosis ==="
echo "Proxy address: $PROXY_IP:$PROXY_PORT"

# Check if we're running on OpenWRT
if [ -f /etc/openwrt_release ]; then
  echo "Running on OpenWRT: $(cat /etc/openwrt_release | grep DISTRIB_RELEASE)"
else
  echo "Not running on OpenWRT. This script is designed for OpenWRT routers."
  echo "Continuing with general network diagnostics..."
fi

# Get network interfaces
echo -e "\n=== Network Interfaces ==="
ip -br addr show

# Get routing table
echo -e "\n=== Routing Table ==="
ip route

# Check if proxy is listening
echo -e "\n=== Proxy Port Check ==="
if command -v netstat &> /dev/null; then
  echo "Checking if proxy port is listening (netstat):"
  netstat -tuln | grep $PROXY_PORT
elif command -v ss &> /dev/null; then
  echo "Checking if proxy port is listening (ss):"
  ss -tuln | grep $PROXY_PORT
else
  echo "Neither netstat nor ss found, skipping port check."
fi

# Check firewall rules
echo -e "\n=== Firewall Rules ==="
if command -v iptables &> /dev/null; then
  echo "NAT table PREROUTING chain:"
  iptables -t nat -L PREROUTING -v -n
  echo -e "\nNAT table OUTPUT chain:"
  iptables -t nat -L OUTPUT -v -n
  echo -e "\nNAT table POSTROUTING chain:"
  iptables -t nat -L POSTROUTING -v -n
  echo -e "\nFilter table INPUT chain:"
  iptables -L INPUT -v -n
else
  echo "iptables not found, skipping rules check."
fi

# Check if IP forwarding is enabled
echo -e "\n=== IP Forwarding ==="
if [ -f /proc/sys/net/ipv4/ip_forward ]; then
  echo "IP forwarding: $(cat /proc/sys/net/ipv4/ip_forward)"
else
  echo "IP forwarding status not available."
fi

# Test connectivity to proxy
echo -e "\n=== Proxy Connectivity Test ==="
if command -v nc &> /dev/null; then
  echo "Testing connection to proxy using netcat..."
  if nc -z -w 2 $PROXY_IP $PROXY_PORT; then
    echo "Success: Proxy is reachable at $PROXY_IP:$PROXY_PORT"
  else
    echo "Warning: Proxy is not reachable at $PROXY_IP:$PROXY_PORT"
  fi
else
  echo "Netcat not found, skipping connectivity test."
fi

# Test DNS resolution
echo -e "\n=== DNS Resolution Test ==="
if command -v dig &> /dev/null; then
  echo "Testing DNS resolution using dig:"
  dig +short example.com
elif command -v nslookup &> /dev/null; then
  echo "Testing DNS resolution using nslookup:"
  nslookup example.com | grep -A 2 "Name:"
else
  echo "Neither dig nor nslookup found, skipping DNS test."
fi

# Check for common OpenWRT firewall issues
echo -e "\n=== OpenWRT Specific Checks ==="
if [ -f /etc/config/firewall ]; then
  echo "OpenWRT firewall configuration exists."
  echo "Checking for zone forwarding rules:"
  grep -A 5 "config forwarding" /etc/config/firewall
else
  echo "OpenWRT firewall configuration not found."
fi

# Suggest fixes
echo -e "\n=== Recommendations ==="
echo "1. Ensure IP forwarding is enabled (should be 1)"
echo "2. Check that the proxy is running and listening on $PROXY_IP:$PROXY_PORT"
echo "3. Verify that the OpenWRT router has a DNAT rule to redirect port 443 to the proxy"
echo "4. Make sure the proxy machine's IP is correctly configured in the firewall rules"
echo "5. Check that the proxy machine is set as the default gateway for clients"
echo "6. Ensure the proxy can establish outbound connections to port 443"

echo -e "\n=== Diagnosis Complete ==="

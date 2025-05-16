#!/bin/bash
# Script to set up firewall rules for GoCertMITM
# This script redirects HTTPS traffic (port 443) to localhost:9900

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

# Define variables
PROXY_PORT=9900
ORIGINAL_RULES_FILE="/tmp/iptables_rules_backup.txt"
ORIGINAL_IPV4_FORWARD_FILE="/tmp/ipv4_forward_backup.txt"

# Save current iptables rules
echo "Saving current iptables rules..."
iptables-save > "$ORIGINAL_RULES_FILE"
echo "Original rules saved to $ORIGINAL_RULES_FILE"

# Save current IPv4 forwarding setting
echo "Saving current IPv4 forwarding setting..."
cat /proc/sys/net/ipv4/ip_forward > "$ORIGINAL_IPV4_FORWARD_FILE"
echo "Original IPv4 forwarding setting saved to $ORIGINAL_IPV4_FORWARD_FILE"

# Enable IPv4 forwarding
echo "Enabling IPv4 forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward
sysctl -w net.ipv4.ip_forward=1

# Add iptables rules to redirect HTTPS traffic
echo "Setting up iptables rules to redirect port 443 to localhost:$PROXY_PORT..."

# Redirect incoming HTTPS traffic to the proxy
iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port $PROXY_PORT

# Redirect locally-generated HTTPS traffic to the proxy
iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port $PROXY_PORT

echo "Firewall setup complete. All traffic to port 443 is now redirected to localhost:$PROXY_PORT"
echo "To restore original settings, run the teardown_firewall.sh script"

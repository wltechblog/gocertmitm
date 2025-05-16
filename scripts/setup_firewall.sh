#!/bin/bash
# Script to set up firewall rules for GoCertMITM
# This script transparently redirects HTTPS traffic (port 443) to localhost:9900
# using DNAT and IP masquerading for proper transparent proxying

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

# Define variables
PROXY_PORT=9900
PROXY_IP="127.0.0.1"
ORIGINAL_RULES_FILE="/tmp/iptables_rules_backup.txt"
ORIGINAL_IPV4_FORWARD_FILE="/tmp/ipv4_forward_backup.txt"

# Get the primary network interface
PRIMARY_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n 1)
if [ -z "$PRIMARY_INTERFACE" ]; then
  echo "Error: Could not determine primary network interface"
  exit 1
fi
echo "Detected primary network interface: $PRIMARY_INTERFACE"

# Get the local IP address of the primary interface
LOCAL_IP=$(ip -4 addr show $PRIMARY_INTERFACE | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n 1)
if [ -z "$LOCAL_IP" ]; then
  echo "Warning: Could not determine local IP address, using 127.0.0.1"
  LOCAL_IP="127.0.0.1"
fi
echo "Detected local IP address: $LOCAL_IP"

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

# Add iptables rules for transparent proxying
echo "Setting up iptables rules for transparent proxying of port 443 to $PROXY_IP:$PROXY_PORT..."

# Set up IP masquerading for outgoing traffic
echo "Setting up IP masquerading for outgoing traffic..."
iptables -t nat -A POSTROUTING -o $PRIMARY_INTERFACE -j MASQUERADE

# Use DNAT to redirect only routed HTTPS traffic to the proxy (not local traffic)
echo "Setting up DNAT for routed HTTPS traffic only..."
# Exclude both loopback and the local IP address from being redirected
iptables -t nat -A PREROUTING -p tcp --dport 443 ! -s 127.0.0.1 ! -s $LOCAL_IP -j DNAT --to-destination $PROXY_IP:$PROXY_PORT

# Note: We're not redirecting locally-generated HTTPS traffic as per requirements

# Add a rule to mark connections for routing
echo "Setting up connection marking for proper routing..."
iptables -t mangle -A PREROUTING -p tcp --dport $PROXY_PORT -j MARK --set-mark 1

echo "Firewall setup complete. All traffic to port 443 is now transparently redirected to $PROXY_IP:$PROXY_PORT"
echo "To restore original settings, run the teardown_firewall.sh script"

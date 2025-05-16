#!/bin/bash
# Script to tear down firewall rules for GoCertMITM
# This script restores the original iptables rules and IPv4 forwarding setting

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

# Define variables
ORIGINAL_RULES_FILE="/tmp/iptables_rules_backup.txt"
ORIGINAL_IPV4_FORWARD_FILE="/tmp/ipv4_forward_backup.txt"

# Check if backup files exist
if [ ! -f "$ORIGINAL_RULES_FILE" ]; then
  echo "Error: Original iptables rules file not found at $ORIGINAL_RULES_FILE"
  echo "Manually removing rules instead..."
  
  # Remove the specific rules we added
  iptables -t nat -D PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 9900 2>/dev/null
  iptables -t nat -D OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 9900 2>/dev/null
  
  echo "Rules removed."
else
  # Restore original iptables rules
  echo "Restoring original iptables rules..."
  iptables-restore < "$ORIGINAL_RULES_FILE"
  echo "Original rules restored from $ORIGINAL_RULES_FILE"
  
  # Remove the backup file
  rm -f "$ORIGINAL_RULES_FILE"
  echo "Removed backup file $ORIGINAL_RULES_FILE"
fi

# Restore original IPv4 forwarding setting if backup exists
if [ -f "$ORIGINAL_IPV4_FORWARD_FILE" ]; then
  echo "Restoring original IPv4 forwarding setting..."
  cat "$ORIGINAL_IPV4_FORWARD_FILE" > /proc/sys/net/ipv4/ip_forward
  ORIGINAL_SETTING=$(cat "$ORIGINAL_IPV4_FORWARD_FILE")
  sysctl -w net.ipv4.ip_forward=$ORIGINAL_SETTING
  echo "Original IPv4 forwarding setting ($ORIGINAL_SETTING) restored"
  
  # Remove the backup file
  rm -f "$ORIGINAL_IPV4_FORWARD_FILE"
  echo "Removed backup file $ORIGINAL_IPV4_FORWARD_FILE"
else
  echo "Warning: Original IPv4 forwarding setting file not found at $ORIGINAL_IPV4_FORWARD_FILE"
  echo "IPv4 forwarding setting not changed"
fi

echo "Firewall teardown complete. Original network settings have been restored."

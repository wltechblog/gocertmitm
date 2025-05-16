#!/bin/bash
# Script to tear down firewall rules for GoCertMITM
# This script restores the original iptables rules and IPv4 forwarding setting

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
  echo "Warning: Could not determine primary network interface"
fi

# Get the local IP address of the primary interface
LOCAL_IP=$(ip -4 addr show $PRIMARY_INTERFACE 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n 1)
if [ -z "$LOCAL_IP" ]; then
  echo "Warning: Could not determine local IP address, using 127.0.0.1"
  LOCAL_IP="127.0.0.1"
fi

# Check if backup files exist
if [ ! -f "$ORIGINAL_RULES_FILE" ]; then
  echo "Error: Original iptables rules file not found at $ORIGINAL_RULES_FILE"
  echo "Manually removing rules instead..."

  # Remove the specific rules we added
  echo "Removing DNAT rules..."
  iptables -t nat -D PREROUTING -p tcp --dport 443 ! -s 127.0.0.1 ! -s $LOCAL_IP -j DNAT --to-destination $PROXY_IP:$PROXY_PORT 2>/dev/null

  echo "Removing MASQUERADE rules..."
  if [ ! -z "$PRIMARY_INTERFACE" ]; then
    iptables -t nat -D POSTROUTING -o $PRIMARY_INTERFACE -j MASQUERADE 2>/dev/null
  fi

  echo "Removing connection marking rules..."
  iptables -t mangle -D PREROUTING -p tcp --dport $PROXY_PORT -j MARK --set-mark 1 2>/dev/null

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

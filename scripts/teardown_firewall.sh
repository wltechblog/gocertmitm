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
VERBOSE=0

# Parse command line arguments
while [[ "$#" -gt 0 ]]; do
  case $1 in
    -v|--verbose) VERBOSE=1 ;;
    -p|--port) PROXY_PORT="$2"; shift ;;
    -i|--ip) PROXY_IP="$2"; shift ;;
    *) echo "Unknown parameter: $1"; exit 1 ;;
  esac
  shift
done

# Function to print verbose messages
verbose() {
  if [ "$VERBOSE" -eq 1 ]; then
    echo "[VERBOSE] $1"
  fi
}

verbose "Starting firewall teardown for proxy at $PROXY_IP:$PROXY_PORT"

# Get the primary network interface
PRIMARY_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n 1)
if [ -z "$PRIMARY_INTERFACE" ]; then
  echo "Warning: Could not determine primary network interface"
fi
verbose "Primary network interface: $PRIMARY_INTERFACE"

# Get the local IP address of the primary interface
LOCAL_IP=$(ip -4 addr show $PRIMARY_INTERFACE 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n 1)
if [ -z "$LOCAL_IP" ]; then
  echo "Warning: Could not determine local IP address, using 127.0.0.1"
  LOCAL_IP="127.0.0.1"
fi
verbose "Local IP address: $LOCAL_IP"

# Check if backup files exist
if [ ! -f "$ORIGINAL_RULES_FILE" ]; then
  echo "Error: Original iptables rules file not found at $ORIGINAL_RULES_FILE"
  echo "Manually removing rules instead..."

  # Display current rules before removal if verbose
  if [ "$VERBOSE" -eq 1 ]; then
    echo "[VERBOSE] Current iptables rules before removal:"
    echo "[VERBOSE] NAT table:"
    iptables -t nat -L -v -n
    echo "[VERBOSE] Mangle table:"
    iptables -t mangle -L -v -n
  fi

  # Remove the specific rules we added
  echo "Removing DNAT rules..."
  iptables -t nat -D PREROUTING -p tcp --dport 443 -j DNAT --to-destination $PROXY_IP:$PROXY_PORT 2>/dev/null
  verbose "Removed PREROUTING DNAT rule"

  iptables -t nat -D PREROUTING -p tcp --dport 443 -s $LOCAL_IP -j RETURN 2>/dev/null
  verbose "Removed PREROUTING RETURN rule for $LOCAL_IP"

  iptables -t nat -D PREROUTING -p tcp --dport 443 -s 127.0.0.1 -j RETURN 2>/dev/null
  verbose "Removed PREROUTING RETURN rule for 127.0.0.1"

  echo "Removing MASQUERADE rules..."
  if [ ! -z "$PRIMARY_INTERFACE" ]; then
    iptables -t nat -D POSTROUTING -o $PRIMARY_INTERFACE -j MASQUERADE 2>/dev/null
    verbose "Removed POSTROUTING MASQUERADE rule for $PRIMARY_INTERFACE"
  fi

  echo "Removing connection marking rules..."
  iptables -t mangle -D PREROUTING -p tcp --dport $PROXY_PORT -j MARK --set-mark 1 2>/dev/null
  verbose "Removed PREROUTING MARK rule"

  echo "Removing INPUT rule for proxy port..."
  iptables -D INPUT -p tcp --dport $PROXY_PORT -j ACCEPT 2>/dev/null
  verbose "Removed INPUT ACCEPT rule for port $PROXY_PORT"

  echo "Rules removed."

  # Display current rules after removal if verbose
  if [ "$VERBOSE" -eq 1 ]; then
    echo "[VERBOSE] Current iptables rules after removal:"
    echo "[VERBOSE] NAT table:"
    iptables -t nat -L -v -n
    echo "[VERBOSE] Mangle table:"
    iptables -t mangle -L -v -n
  fi
else
  # Restore original iptables rules
  echo "Restoring original iptables rules..."
  iptables-restore < "$ORIGINAL_RULES_FILE"
  echo "Original rules restored from $ORIGINAL_RULES_FILE"

  # Display restored rules if verbose
  if [ "$VERBOSE" -eq 1 ]; then
    echo "[VERBOSE] Restored iptables rules:"
    echo "[VERBOSE] NAT table:"
    iptables -t nat -L -v -n
    echo "[VERBOSE] Mangle table:"
    iptables -t mangle -L -v -n
  fi

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

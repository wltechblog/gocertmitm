#!/bin/bash
# Script to test if the proxy is listening correctly

# Define variables
PROXY_PORT=9900
PROXY_IP="127.0.0.1"

echo "Testing proxy connection to $PROXY_IP:$PROXY_PORT..."

# Try to connect to the proxy using netcat
echo "Attempting to connect using netcat..."
if command -v nc &> /dev/null; then
    # Send a simple HTTP CONNECT request and wait for 2 seconds
    (echo -e "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"; sleep 2) | nc -v $PROXY_IP $PROXY_PORT
    echo "Netcat test completed."
else
    echo "Netcat not found, skipping test."
fi

# Try to connect using curl
echo "Attempting to connect using curl..."
if command -v curl &> /dev/null; then
    # Use curl to send a CONNECT request to the proxy
    curl -v -x $PROXY_IP:$PROXY_PORT https://example.com
    echo "Curl test completed."
else
    echo "Curl not found, skipping test."
fi

# Check if the proxy port is open
echo "Checking if proxy port is open..."
if command -v netstat &> /dev/null; then
    netstat -tuln | grep $PROXY_PORT
elif command -v ss &> /dev/null; then
    ss -tuln | grep $PROXY_PORT
else
    echo "Neither netstat nor ss found, skipping port check."
fi

# Check iptables rules
echo "Checking iptables rules..."
if command -v iptables &> /dev/null; then
    echo "NAT table PREROUTING chain:"
    sudo iptables -t nat -L PREROUTING -v -n
    echo "NAT table OUTPUT chain:"
    sudo iptables -t nat -L OUTPUT -v -n
    echo "NAT table POSTROUTING chain:"
    sudo iptables -t nat -L POSTROUTING -v -n
else
    echo "iptables not found, skipping rules check."
fi

echo "Test completed."

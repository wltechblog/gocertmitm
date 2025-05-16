#!/bin/bash
# Script to test if redirection is working correctly

# Define variables
TARGET_IP="192.168.82.118"
PROXY_PORT=9900
TEST_HOST="1.1.1.1"
TEST_PORT=443

# Parse command line arguments
while [[ "$#" -gt 0 ]]; do
  case $1 in
    -t|--target) TARGET_IP="$2"; shift ;;
    -p|--port) PROXY_PORT="$2"; shift ;;
    -h|--host) TEST_HOST="$2"; shift ;;
    *) echo "Unknown parameter: $1"; exit 1 ;;
  esac
  shift
done

echo "=== Redirection Test Tool ==="
echo "Target IP: $TARGET_IP"
echo "Proxy Port: $PROXY_PORT"
echo "Test Host: $TEST_HOST:$TEST_PORT"
echo ""

# Check if we have netcat
if ! command -v nc &> /dev/null; then
  echo "Error: netcat (nc) is required for this test."
  exit 1
fi

# Check if we have tcpdump
if ! command -v tcpdump &> /dev/null; then
  echo "Error: tcpdump is required for this test."
  exit 1
fi

# Start a simple listener on the proxy port
echo "Starting a listener on port $PROXY_PORT..."
nc -l -p $PROXY_PORT > /tmp/nc_output.txt &
NC_PID=$!

# Give it a moment to start
sleep 1

# Check if the listener is running
if ! netstat -tuln | grep -q ":$PROXY_PORT "; then
  echo "Error: Failed to start listener on port $PROXY_PORT."
  exit 1
fi

echo "Listener started on port $PROXY_PORT (PID: $NC_PID)"
echo ""

# Start tcpdump to capture traffic
echo "Starting tcpdump to capture traffic..."
tcpdump -i any -n "host $TARGET_IP and tcp port $TEST_PORT or tcp port $PROXY_PORT" -c 10 > /tmp/tcpdump_output.txt 2>&1 &
TCPDUMP_PID=$!

echo "tcpdump started (PID: $TCPDUMP_PID)"
echo ""

# Now try to connect to the test host from the target IP
echo "Please run the following command from the device with IP $TARGET_IP:"
echo "  telnet $TEST_HOST $TEST_PORT"
echo ""
echo "Or if you have curl:"
echo "  curl -v https://$TEST_HOST/"
echo ""
echo "Press Enter when you've initiated the connection..."
read

# Wait a moment for the connection to be established
sleep 5

# Check if we received any data on our listener
echo "Checking if our listener received any data..."
if [ -s /tmp/nc_output.txt ]; then
  echo "Success! Data received on port $PROXY_PORT:"
  cat /tmp/nc_output.txt
else
  echo "No data received on port $PROXY_PORT."
fi
echo ""

# Check tcpdump output
echo "Checking tcpdump output..."
if [ -s /tmp/tcpdump_output.txt ]; then
  echo "tcpdump captured traffic:"
  cat /tmp/tcpdump_output.txt
else
  echo "No traffic captured by tcpdump."
fi
echo ""

# Clean up
echo "Cleaning up..."
kill $NC_PID 2>/dev/null
kill $TCPDUMP_PID 2>/dev/null
rm -f /tmp/nc_output.txt /tmp/tcpdump_output.txt

echo "Test completed."

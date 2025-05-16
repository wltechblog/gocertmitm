#!/bin/bash
# Script to compile and run the TCP test server

# Check if go is installed
if ! command -v go &> /dev/null; then
  echo "Error: go is required to compile the TCP test server."
  exit 1
fi

# Compile the TCP test server
echo "Compiling TCP test server..."
go build -o tcptest cmd/tcptest/main.go

if [ $? -ne 0 ]; then
  echo "Error: Compilation failed."
  exit 1
fi

echo "Compilation successful."

# Run the TCP test server
echo "Running TCP test server..."
./tcptest "$@"

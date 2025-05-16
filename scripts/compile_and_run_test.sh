#!/bin/bash
# Script to compile and run the SO_ORIGINAL_DST test

# Check if gcc is installed
if ! command -v gcc &> /dev/null; then
  echo "Error: gcc is required to compile the test."
  exit 1
fi

# Compile the test
echo "Compiling test_so_original_dst.c..."
gcc -o test_so_original_dst scripts/test_so_original_dst.c

if [ $? -ne 0 ]; then
  echo "Error: Compilation failed."
  exit 1
fi

echo "Compilation successful."

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Warning: This test should be run as root to access SO_ORIGINAL_DST."
  echo "Running with sudo..."
  sudo ./test_so_original_dst "$@"
else
  # Run the test
  ./test_so_original_dst "$@"
fi

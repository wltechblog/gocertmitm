#!/bin/bash
# Script to set up the payload directory structure for GoCertMITM

# Create the main payload directory
mkdir -p payloads

# Create example domain directories
mkdir -p payloads/example.com
mkdir -p payloads/other-domain.com

echo "Payload directory structure created successfully."
echo ""
echo "Directory structure:"
echo "payloads/"
echo "├── example.com/       # Domain-specific directory"
echo "│   ├── req_*.meta     # Request metadata will be saved here"
echo "│   ├── req_*.body     # Request bodies will be saved here"
echo "│   ├── resp_*.meta    # Response metadata will be saved here"
echo "│   └── resp_*.body    # Response bodies will be saved here"
echo "└── other-domain.com/  # Another domain"
echo ""
echo "Note: Additional domain directories will be created automatically as needed."
echo "Payload logging is enabled by default but can be disabled with -savepayloads=false."

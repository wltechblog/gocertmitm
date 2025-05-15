#!/bin/bash
# Script to set up the certificate directory structure for GoCertMITM

# Create the main certificate directory
mkdir -p certs

# Create directories for real certificates
mkdir -p certs/real/example.com
mkdir -p certs/real/other-domain.com

# Create directories for CA certificates
mkdir -p certs/real-ca/example-ca.com
mkdir -p certs/real-ca/other-ca.com

# Create directories for self-signed certificates
mkdir -p certs/self-signed/example.com
mkdir -p certs/self-signed/other-domain.com

# Create directories for replaced-key certificates
mkdir -p certs/replaced-key/example.com
mkdir -p certs/replaced-key/other-domain.com

echo "Certificate directory structure created successfully."
echo ""
echo "Directory structure:"
echo "certs/"
echo "├── ca.crt                # The GoCertMITM root CA certificate (auto-generated on first run)"
echo "├── ca.key                # The GoCertMITM root CA private key (auto-generated on first run)"
echo "├── self-signed/          # Self-signed certificates"
echo "│   ├── example.com/      # Domain-specific directory"
echo "│   │   ├── cert.pem      # Generated certificate"
echo "│   │   └── key.pem       # Private key"
echo "│   └── other-domain.com/"
echo "│       ├── cert.pem"
echo "│       └── key.pem"
echo "├── replaced-key/         # Replaced key certificates"
echo "│   ├── example.com/"
echo "│   │   ├── cert.pem"
echo "│   │   └── key.pem"
echo "│   └── other-domain.com/"
echo "│       ├── cert.pem"
echo "│       └── key.pem"
echo "├── real/                 # Real certificates for different domains"
echo "│   ├── example.com/"
echo "│   │   ├── cert.pem      # Place leaf certificate here"
echo "│   │   ├── fullchain.pem # Place full certificate chain here"
echo "│   │   └── key.pem       # Place private key here"
echo "│   └── other-domain.com/"
echo "│       ├── cert.pem"
echo "│       ├── fullchain.pem"
echo "│       └── key.pem"
echo "└── real-ca/              # Real certificates used as CAs"
echo "    ├── example-ca.com/"
echo "    │   ├── cert.pem      # Place CA certificate here"
echo "    │   └── key.pem       # Place CA private key here"
echo "    └── other-ca.com/"
echo "        ├── cert.pem"
echo "        └── key.pem"
echo ""
echo "Note: The CA certificate and key will be automatically generated on first run if they don't exist."
echo "Place your real certificates and CA certificates in the appropriate directories as shown above."
echo ""
echo "IMPORTANT: For real certificates, the fullchain.pem file is strongly recommended."
echo "It should contain the complete certificate chain (leaf + intermediates) in PEM format."

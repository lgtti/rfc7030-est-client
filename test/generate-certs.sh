#!/bin/bash

# Script to generate test certificates for EST server
# This creates a simple CA and server certificate for testing purposes

set -e

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="$SCRIPT_DIR/config"
mkdir -p "$CERT_DIR"

cd "$CERT_DIR"

# Generate CA private key
openssl genrsa -out ca-key.pem 2048

# Generate CA certificate
openssl req -new -x509 -days 365 -key ca-key.pem -out ca-cert.pem -subj "/C=US/ST=CA/L=San Francisco/O=Test CA/CN=test-ca"

# Generate server private key
openssl genrsa -out server-key.pem 2048

# Generate server certificate request
openssl req -new -key server-key.pem -out server.csr -subj "/C=US/ST=CA/L=San Francisco/O=Test EST Server/CN=localhost"

# Generate server certificate signed by CA
openssl x509 -req -days 365 -in server.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out server-cert.pem

# Clean up
rm server.csr

echo "Certificates generated successfully in $CERT_DIR"
echo "Files created:"
echo "  - ca-cert.pem (CA certificate)"
echo "  - ca-key.pem (CA private key)"
echo "  - server-cert.pem (Server certificate)"
echo "  - server-key.pem (Server private key)"

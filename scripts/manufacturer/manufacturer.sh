#!/bin/sh

# EST Client Manufacturer Script
# Usage: ./manufacturer.sh <csr_directory> <est_server_url> <est_server_port> <p12_filename> <p12_pin>

set -e

if [ $# -ne 5 ]; then
    echo "Usage: $0 <csr_directory> <est_server_url> <est_server_port> <p12_filename> <p12_pin>"
    echo "Example: $0 /path/to/csr/files testrfc7030.com 8443 preenrollment.p12 12345"
    exit 1
fi

CSR_DIR="$1"
EST_SERVER="$2"
EST_PORT="$3"
P12_FILENAME="$4"
P12_PIN="$5"

EST_CLIENT="./build/bin/rfc7030-est-client"

# Verify CSR format
verify_csr() {
    local csr_file="$1"
    [ -f "$csr_file" ] && [ -r "$csr_file" ] && \
    head -1 "$csr_file" | grep -q "-----BEGIN CERTIFICATE REQUEST-----" && \
    tail -1 "$csr_file" | grep -q "-----END CERTIFICATE REQUEST-----"
}

# Find P12 file
find_p12_file() {
    local csr_name="$1"
    local p12_file="$CSR_DIR/$csr_name/$P12_FILENAME"
    [ -f "$p12_file" ] && echo "$p12_file" || return 1
}

# Launch EST client
launch_est_client() {
    local csr_file="$1"
    local p12_file="$2"
    local csr_name=$(basename "$csr_file" .csr)
    
    echo "Processing: $csr_name"
    
    "$EST_CLIENT" \
        -s "$EST_SERVER" \
        -p "$EST_PORT" \
        --csr "$csr_file" \
        --p12 "$p12_file" \
        --p12-password "$P12_PIN" \
        --output-ca "${csr_name}_cachain.pem" \
        --output-crt "${csr_name}_certificate.pem" \
        enroll
}


# Main processing
csr_files=$(find "$CSR_DIR" -name "*.csr" -type f)

for csr_file in $csr_files; do
    csr_name=$(basename "$csr_file" .csr)
    
    verify_csr "$csr_file" || {
        echo "Skipping invalid CSR: $csr_name"
        continue
    }
    
    p12_file=$(find_p12_file "$csr_name") || {
        echo "P12 not found for: $csr_name"
        continue
    }
    
    launch_est_client "$csr_file" "$p12_file" || echo "Failed: $csr_name"
done

echo "Completed!"
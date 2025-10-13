# EST Client Manufacturer Script

This script automates the process of enrolling multiple devices using the RFC7030 EST client.

## Overview

The script processes CSR (Certificate Signing Request) files and automatically enrolls them using the EST protocol. All CSRs use the same P12 file for authentication.

## Usage

```bash
./manufacturer.sh <csr_directory> <est_server_url> <est_server_port> <p12_filename> <p12_pin>
```

### Parameters

- `<csr_directory>` - Directory containing CSR files and their corresponding P12 directories
- `<est_server_url>` - EST server hostname or IP address
- `<est_server_port>` - EST server port (typically 8443 for TLS or 9443 for mTLS)
- `<p12_filename>` - Name of the P12 file (e.g., "preenrollment.p12")
- `<p12_pin>` - PIN/password for the P12 file

### Example

```bash
./manufacturer.sh ./csr_files testrfc7030.com 8443 preenrollment.p12 12345
```

## Directory Structure

The script expects the following structure:

```
csr_directory/
├── device1.csr                  # CSR file for device1
├── device2.csr                  # CSR file for device2
├── device3.csr                  # CSR file for device3
└── preenrollment.p12            # Single P12 file for all CSRs
```

## Requirements

- CSR files must be in PEM PKCS#10 format
- The directory must contain the specified P12 file
- The EST client must be built and available at `./build/bin/rfc7030-est-client`

## Output

For each successful enrollment, the script generates:
- `{csr_name}_certificate.pem` - The issued certificate
- `{csr_name}_cachain.pem` - The CA certificate chain

## Error Handling

The script will:
- Skip invalid CSR files (not in PEM PKCS#10 format)
- Skip CSRs without corresponding P12 files
- Continue processing remaining CSRs if one fails
- Display error messages for failed operations

## Notes

- The script uses the EST client's `enroll` command
- All CSRs use the same P12 file with the same PIN
- The script processes all CSR files found in the directory
- Failed enrollments are logged but don't stop the overall process

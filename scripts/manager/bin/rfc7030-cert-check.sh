#!/bin/bash
#
# rfc7030-cert-check - Certificate enrollment and renewal script for EST (RFC 7030)
#
# This script checks if a certificate needs enrollment or renewal and
# performs the appropriate action using the rfc7030_est_client.
#
# Configuration is read from $RFC7030_HOME/.rfc7030
#
# Exit codes:
#   0 - Success (no action needed or operation completed)
#   1 - Configuration error
#   2 - Enrollment/Renewal failed
#

set -euo pipefail

# Logging functions
log_info() {
    echo "[INFO] $(date '+%Y-%m-%d %H:%M:%S') - $*"
}

log_error() {
    echo "[ERROR] $(date '+%Y-%m-%d %H:%M:%S') - $*" >&2
}

log_warn() {
    echo "[WARN] $(date '+%Y-%m-%d %H:%M:%S') - $*"
}

# Cleanup function for temporary files
cleanup() {
    if [[ -n "${TMP_P12_FILE:-}" && -f "$TMP_P12_FILE" ]]; then
        rm -f "$TMP_P12_FILE"
        log_info "Cleaned up temporary P12 file"
    fi
}

trap cleanup EXIT

# Check if RFC7030_HOME is set
if [[ -z "${RFC7030_HOME:-}" ]]; then
    log_error "RFC7030_HOME environment variable is not set"
    exit 1
fi

# Check if config file exists
CONFIG_FILE="${RFC7030_HOME}/.rfc7030"
if [[ ! -f "$CONFIG_FILE" ]]; then
    log_error "Configuration file not found: $CONFIG_FILE"
    exit 1
fi

# Load configuration
log_info "Loading configuration from $CONFIG_FILE"
# shellcheck source=/dev/null
source "$CONFIG_FILE"

# Validate required configuration variables
REQUIRED_VARS=(
    "EST_SERVER"
    "EST_PORT"
    "EST_SERVER_CHAIN"
    "CERT_CSR"
    "CERT_KEY"
    "CERT_CRT"
    "P12_FILE"
    "P12_PASSWORD"
    "RENEWAL_DAYS"
)

for var in "${REQUIRED_VARS[@]}"; do
    if [[ -z "${!var:-}" ]]; then
        log_error "Required configuration variable $var is not set"
        exit 1
    fi
done

# Set defaults for optional variables
EST_LABEL="${EST_LABEL:-}"
EST_CLIENT="${EST_CLIENT:-rfc7030_est_client}"

# Verify EST client is available
if ! command -v "$EST_CLIENT" &> /dev/null; then
    log_error "EST client not found: $EST_CLIENT"
    exit 1
fi

# Verify OpenSSL is available
if ! command -v openssl &> /dev/null; then
    log_error "OpenSSL is required but not found"
    exit 1
fi

# Function to check if certificate expires within N days
check_cert_expiry() {
    local cert_file="$1"
    local days="$2"
    local seconds=$((days * 86400))
    
    if openssl x509 -checkend "$seconds" -noout -in "$cert_file" &> /dev/null; then
        return 1  # Certificate is NOT expiring within the threshold
    else
        return 0  # Certificate IS expiring within the threshold
    fi
}

# Function to perform enrollment
do_enrollment() {
    log_info "Performing certificate enrollment..."
    
    # Check required files exist
    if [[ ! -f "$EST_SERVER_CHAIN" ]]; then
        log_error "Server chain file not found: $EST_SERVER_CHAIN"
        return 1
    fi
    
    if [[ ! -f "$CERT_CSR" ]]; then
        log_error "CSR file not found: $CERT_CSR"
        return 1
    fi
    
    if [[ ! -f "$P12_FILE" ]]; then
        log_error "P12 file not found: $P12_FILE"
        return 1
    fi
    
    # Build EST client command
    local cmd=(
        "$EST_CLIENT"
        -s "$EST_SERVER"
        -p "$EST_PORT"
        --server-chain "$EST_SERVER_CHAIN"
        --csr "$CERT_CSR"
        --p12 "$P12_FILE"
        --p12-password "$P12_PASSWORD"
        --output-crt "$CERT_CRT"
    )
    
    # Add optional label
    if [[ -n "$EST_LABEL" ]]; then
        cmd+=(--label "$EST_LABEL")
    fi
    
    # Add the command
    cmd+=(enroll)
    
    log_info "Executing: ${cmd[*]}"
    
    if "${cmd[@]}"; then
        log_info "Enrollment completed successfully"
        return 0
    else
        log_error "Enrollment failed"
        return 1
    fi
}

# Function to perform renewal
do_renewal() {
    log_info "Performing certificate renewal..."
    
    local backup_file="${CERT_CRT}.bak"
    
    # Create backup of current certificate
    log_info "Creating backup: $backup_file"
    if ! cp "$CERT_CRT" "$backup_file"; then
        log_error "Failed to create backup"
        return 1
    fi
    
    # Check required files exist
    if [[ ! -f "$EST_SERVER_CHAIN" ]]; then
        log_error "Server chain file not found: $EST_SERVER_CHAIN"
        mv "$backup_file" "$CERT_CRT"
        return 1
    fi
    
    if [[ ! -f "$CERT_CSR" ]]; then
        log_error "CSR file not found: $CERT_CSR"
        mv "$backup_file" "$CERT_CRT"
        return 1
    fi
    
    if [[ ! -f "$CERT_KEY" ]]; then
        log_error "Private key file not found: $CERT_KEY"
        mv "$backup_file" "$CERT_CRT"
        return 1
    fi
    
    # Create temporary P12 from current certificate and key
    TMP_P12_FILE=$(mktemp --suffix=.p12)
    TMP_P12_PASS=$(openssl rand -base64 32)
    
    log_info "Creating temporary P12 for renewal authentication"
    if ! openssl pkcs12 -export \
        -out "$TMP_P12_FILE" \
        -inkey "$CERT_KEY" \
        -in "$CERT_CRT" \
        -passout "pass:${TMP_P12_PASS}"; then
        log_error "Failed to create temporary P12"
        mv "$backup_file" "$CERT_CRT"
        return 1
    fi
    
    # Build EST client command
    local cmd=(
        "$EST_CLIENT"
        -s "$EST_SERVER"
        -p "$EST_PORT"
        --server-chain "$EST_SERVER_CHAIN"
        --csr "$CERT_CSR"
        --p12 "$TMP_P12_FILE"
        --p12-password "$TMP_P12_PASS"
        --output-crt "$CERT_CRT"
    )
    
    # Add optional label
    if [[ -n "$EST_LABEL" ]]; then
        cmd+=(--label "$EST_LABEL")
    fi
    
    # Add the command
    cmd+=(renew)
    
    log_info "Executing renewal command"
    
    if "${cmd[@]}"; then
        log_info "Renewal completed successfully"
        # Remove backup on success
        rm -f "$backup_file"
        log_info "Backup removed"
        return 0
    else
        log_error "Renewal failed, restoring backup"
        mv "$backup_file" "$CERT_CRT"
        log_info "Certificate restored from backup"
        return 1
    fi
}

# Main logic
main() {
    log_info "Starting certificate check for $CERT_CRT"
    
    # Check if certificate exists
    if [[ ! -f "$CERT_CRT" ]]; then
        log_info "Certificate does not exist, performing enrollment"
        if do_enrollment; then
            log_info "Enrollment successful"
            exit 0
        else
            log_error "Enrollment failed"
            exit 2
        fi
    fi
    
    # Certificate exists, check expiry
    log_info "Certificate exists, checking expiry (threshold: $RENEWAL_DAYS days)"
    
    if check_cert_expiry "$CERT_CRT" "$RENEWAL_DAYS"; then
        log_info "Certificate is expiring within $RENEWAL_DAYS days, performing renewal"
        if do_renewal; then
            log_info "Renewal successful"
            exit 0
        else
            log_error "Renewal failed"
            exit 2
        fi
    else
        log_info "Certificate is valid and not expiring within $RENEWAL_DAYS days, no action needed"
        exit 0
    fi
}

main "$@"

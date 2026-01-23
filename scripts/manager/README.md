# Systemd Timer for EST Certificate Management

This directory contains systemd unit files for automated certificate enrollment and renewal using the RFC 7030 EST protocol.

## Overview

The systemd timer runs daily to check if a certificate needs enrollment (if it doesn't exist) or renewal (if it's expiring soon). It uses the `rfc7030_est_client` binary from this repository.

## Files

| File | Description |
|------|-------------|
| `rfc7030-cert-check.timer` | Systemd timer unit (runs daily at 03:00) |
| `rfc7030-cert-check.service` | Systemd service unit |
| `rfc7030.conf.example` | Example configuration file |
| `../bin/rfc7030-cert-check.sh` | The main script (to be installed in `/usr/local/bin`) |

## Installation

### 1. Install the EST client binary

First, build and install the `rfc7030_est_client` binary:

```bash
# Build the project
cmake -Ssrc -Bbuild
cd build
make

# Install the binary
sudo cp bin/rfc7030_est_client /usr/local/bin/
sudo chmod +x /usr/local/bin/rfc7030_est_client
```

### 2. Install the certificate check script

```bash
sudo cp scripts/bin/rfc7030-cert-check.sh /usr/local/bin/rfc7030-cert-check
sudo chmod +x /usr/local/bin/rfc7030-cert-check
```

### 3. Create the configuration directory and file

```bash
# Create configuration directory
sudo mkdir -p /etc/rfc7030

# Copy and edit the example configuration
sudo cp scripts/systemd/rfc7030.conf.example /etc/rfc7030/.rfc7030
sudo chmod 600 /etc/rfc7030/.rfc7030
sudo vi /etc/rfc7030/.rfc7030
```

### 4. Install the systemd units

```bash
sudo cp scripts/systemd/rfc7030-cert-check.timer /etc/systemd/system/
sudo cp scripts/systemd/rfc7030-cert-check.service /etc/systemd/system/
sudo systemctl daemon-reload
```

### 5. Configure the service (optional)

If your `RFC7030_HOME` is different from `/etc/rfc7030`, create a drop-in file:

```bash
sudo mkdir -p /etc/systemd/system/rfc7030-cert-check.service.d/
cat << EOF | sudo tee /etc/systemd/system/rfc7030-cert-check.service.d/override.conf
[Service]
Environment="RFC7030_HOME=/custom/path"
EOF
sudo systemctl daemon-reload
```

If the certificate files are in a location other than the default, add write permissions:

```bash
cat << EOF | sudo tee /etc/systemd/system/rfc7030-cert-check.service.d/paths.conf
[Service]
ReadWritePaths=/path/to/certificates
EOF
sudo systemctl daemon-reload
```

### 6. Enable and start the timer

```bash
sudo systemctl enable rfc7030-cert-check.timer
sudo systemctl start rfc7030-cert-check.timer
```

## Configuration

The configuration file (`$RFC7030_HOME/.rfc7030`) is a shell-sourceable file containing:

| Variable | Description |
|----------|-------------|
| `EST_SERVER` | EST server hostname |
| `EST_PORT` | EST server port |
| `EST_SERVER_CHAIN` | Path to server CA chain (PEM) |
| `EST_LABEL` | Optional EST path label |
| `CERT_CSR` | Path to CSR file (PEM) |
| `CERT_KEY` | Path to private key file |
| `CERT_CRT` | Path to certificate file (output) |
| `P12_FILE` | Bootstrap P12 for initial enrollment |
| `P12_PASSWORD` | Password for P12 file |
| `RENEWAL_DAYS` | Days before expiry to renew |
| `EST_CLIENT` | Optional: path to EST client binary |

See `rfc7030.conf.example` for a complete example.

## Usage

### Manual execution

To run the certificate check manually:

```bash
# Set the environment variable
export RFC7030_HOME=/etc/rfc7030

# Run the script
/usr/local/bin/rfc7030-cert-check
```

Or run via systemd:

```bash
sudo systemctl start rfc7030-cert-check.service
```

### Check timer status

```bash
# View timer status
systemctl status rfc7030-cert-check.timer

# View when the timer will next trigger
systemctl list-timers rfc7030-cert-check.timer

# View service logs
journalctl -u rfc7030-cert-check.service
```

## How It Works

1. **No certificate exists**: Performs initial enrollment using the bootstrap P12 file (`P12_FILE`)
2. **Certificate exists and is valid**: No action taken
3. **Certificate expires within `RENEWAL_DAYS`**: 
   - Creates a backup of the current certificate
   - Creates a temporary P12 from the current certificate and key
   - Performs renewal using the temporary P12
   - On success: removes the backup
   - On failure: restores the certificate from backup

## Security Considerations

- The configuration file contains sensitive data (P12 password). Ensure proper permissions (`chmod 600`)
- The systemd service runs with security hardening options enabled
- Temporary P12 files are created in a private temp directory and cleaned up automatically
- The backup mechanism ensures certificate availability even if renewal fails

## Troubleshooting

### View logs

```bash
journalctl -u rfc7030-cert-check.service -f
```

### Test configuration

```bash
export RFC7030_HOME=/etc/rfc7030
source $RFC7030_HOME/.rfc7030
echo "Server: $EST_SERVER:$EST_PORT"
echo "Certificate: $CERT_CRT"
```

### Verify certificate expiry manually

```bash
openssl x509 -enddate -noout -in /path/to/certificate.crt
```

### Check if certificate needs renewal

```bash
# Check if certificate expires within 30 days
openssl x509 -checkend $((30*86400)) -noout -in /path/to/certificate.crt
echo $?  # 0 = expiring, 1 = valid
```

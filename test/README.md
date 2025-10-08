# EST Server Docker Setup for Integration Testing

This directory contains Docker configuration files to run a Cisco libest EST server for integration testing with the RFC7030 EST client.

## Files

- `Dockerfile` - Builds the Cisco libest EST server
- `docker-compose.yml` - Orchestrates the EST server container
- `generate-certs.sh` - Script to generate test certificates
- `run-integration-tests.sh` - **Automated script to start server and run integration tests**
- `config/` - Directory containing server configuration and certificates
  - `estserver.conf` - EST server configuration
  - `ca-cert.pem` - CA certificate
  - `ca-key.pem` - CA private key
  - `server-cert.pem` - Server certificate
  - `server-key.pem` - Server private key
  - `cacerts.pem` - CA certificates response file
  - `ca.conf` - OpenSSL CA configuration
  - `serial`, `crlnumber`, `index.txt` - CA database files (initialized automatically)
- `logs/` - Directory for server logs
- `ca-database` - **Persistent Docker volume** for CA database (preserves certificates across container restarts)

## Prerequisites

Before starting the EST server, you need to generate the required certificates:

1. Generate test certificates:
   ```bash
   chmod +x generate-certs.sh
   ./generate-certs.sh
   ```

This will create all necessary certificates in the `config/` directory.

## Quick Start

### Option 1: Automated Integration Tests (Recommended)

Run the complete integration test suite with a single command:

```bash
./run-integration-tests.sh
```

This script will:
- Build the EST server Docker image
- Start the EST server
- Wait for the server to be ready
- Run all integration tests
- Show results and server logs

### Option 2: Manual Setup

#### Using Docker Compose

1. Build and start the EST server:
   ```bash
   docker-compose up -d
   ```

2. Check if the server is running:
   ```bash
   docker-compose ps
   ```

3. View server logs:
   ```bash
   docker-compose logs -f est-server
   ```

4. Stop the server:
   ```bash
   docker-compose down
   ```

### Using Docker directly

1. Build the image:
   ```bash
   docker build -t est-server-test .
   ```

2. Run the container:
   ```bash
   docker run -d -p 8443:8443 -p 9443:9443 --name est-server est-server-test
   ```

3. Check logs:
   ```bash
   docker logs est-server
   ```

## Configuration

The EST server runs on two ports:
- **Port 8443**: TLS server (standard HTTPS)
- **Port 9443**: mTLS server (mutual TLS authentication)

The EST server configuration is located in `config/estserver.conf`. You can modify this file to adjust server settings such as:

- SSL/TLS certificates
- Authentication mode
- Logging level
- EST endpoints

## Testing

### Using curl (Quick Test)

Test both servers with curl:

```bash
# Test TLS server (port 8443)
curl -k -v https://localhost:8443/.well-known/est/cacerts

# Test mTLS server (port 9443)
curl -k -v https://localhost:9443/.well-known/est/cacerts
```

### Using RFC7030 EST Client

Once the server is running, you can test it using the RFC7030 EST client:

```bash
# Test CACerts endpoint (TLS)
./rfc7030-est-client -s localhost -p 8443 --server-chain config/ca-cert.pem --output cachain.pem cacerts

# Test SimpleEnroll endpoint (TLS)
./rfc7030-est-client -s localhost -p 8443 --server-chain config/ca-cert.pem --output cert.pem simpleenroll

# Test CACerts endpoint (mTLS)
./rfc7030-est-client -s localhost -p 9443 --server-chain config/ca-cert.pem --client-cert config/client-cert.pem --client-key config/client-key.pem --output cachain.pem cacerts

# Test SimpleEnroll endpoint (mTLS)
./rfc7030-est-client -s localhost -p 9443 --server-chain config/ca-cert.pem --client-cert config/client-cert.pem --client-key config/client-key.pem --output cert.pem simpleenroll
```

**Note**: For mTLS testing, you'll need to generate client certificates first. You can use the same CA to create client certificates.

## Server Configuration Details

### Ports
- **Port 8443**: TLS server (standard HTTPS with HTTP Basic authentication)
- **Port 9443**: mTLS server (mutual TLS authentication, HTTP auth disabled)

### Authentication
- **TLS Server (8443)**: Uses HTTP Basic authentication (username: `estuser`, password: `estpwd`)
- **mTLS Server (9443)**: Requires client certificate authentication (no HTTP auth)

### Environment Variables
The server uses these environment variables:
- `EST_CACERTS_RESP`: Path to CA certificates response file (`/etc/est/cacerts.pem`)
- `EST_TRUSTED_CERTS`: Path to trusted certificates file (`/etc/est/ca-cert.pem`)

### Logs
- Server logs are written to the `logs/` directory
- Use `docker-compose logs -f est-server` to view real-time logs

## Troubleshooting

### Server won't start
1. Check Docker logs: `docker-compose logs est-server`
2. Verify configuration file syntax
3. Ensure required certificates are present in `config/` directory
4. Check port availability (8443, 9443)

### Certificate issues
1. Regenerate certificates: `./generate-certs.sh`
2. Verify certificate files exist in `config/` directory
3. Check certificate validity: `openssl x509 -in config/server-cert.pem -text -noout`

### Connection issues
1. Verify server is running: `docker-compose ps`
2. Test connectivity: `curl -k https://localhost:8443/.well-known/est/cacerts`
3. Check firewall settings
4. Verify Docker port mapping

### mTLS authentication issues
1. Ensure client certificates are properly generated
2. Verify client certificate is signed by the same CA as server certificates
3. Check that client certificate is not expired
4. Test with curl using client certificate: `curl -k --cert client-cert.pem --key client-key.pem https://localhost:9443/.well-known/est/cacerts`

## Additional Information

### EST Endpoints
The server provides the following EST endpoints on both ports:
- `/.well-known/est/cacerts` - Get CA certificates
- `/.well-known/est/simpleenroll` - Certificate enrollment
- `/.well-known/est/simplereenroll` - Certificate re-enrollment

### Docker Commands Reference
```bash
# Build image
docker-compose build

# Start services
docker-compose up -d

# Stop services
docker-compose down

# View logs
docker-compose logs -f est-server

# Check status
docker-compose ps

# Rebuild without cache
docker-compose build --no-cache
```

### CA Database Management

The EST server uses a persistent Docker volume (`ca-database`) to store the CA database files:

- **Persistent Storage**: CA database persists across container restarts and rebuilds
- **Automatic Initialization**: Database is automatically initialized on first run
- **No Rebuild Required**: You can modify server configuration without losing issued certificates
- **Reset Database**: To reset the CA database, remove the volume:
  ```bash
  docker-compose down
  docker volume rm test_ca-database
  docker-compose up -d
  ```

### Security Notes
- This setup is for **testing purposes only**
- Certificates are self-signed and not suitable for production
- Default credentials are hardcoded (change for production use)
- Consider using proper CA infrastructure for production deployments

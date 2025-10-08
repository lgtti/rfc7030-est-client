#!/bin/sh

# Set environment variables
export EST_CACERTS_RESP=/etc/est/config/ca-cert.pem
export EST_TRUSTED_CERTS=/etc/est/config/ca-cert.pem
export EST_OPENSSL_CACONFIG=/etc/est/config/ca.conf
# Start EST server with mTLS (disable HTTP auth, require TLS client auth)
estserver -p 9443 -c /etc/est/config/server-cert.pem -k /etc/est/config/server-key.pem -n
#!/bin/sh

# Set environment variables
export EST_CACERTS_RESP=/etc/est/config/ca-cert.pem
export EST_TRUSTED_CERTS=/etc/est/config/ca-cert.pem
export EST_OPENSSL_CACONFIG=/etc/est/config/ca.conf
# Start EST server with automatic enrollment (no -m option)
estserver -p 10443 -c /etc/est/config/server-cert.pem -k /etc/est/config/server-key.pem -t
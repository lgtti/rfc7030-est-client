# Dockerfile for Cisco libest EST Server for Integration Testing
FROM ubuntu:20.04

# Set maintainer
LABEL maintainer="EST Integration Test"

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies and required packages
RUN apt-get update && \
    apt-get install -y \
    build-essential \
    git \
    cmake \
    libssl-dev \
    libcurl4-openssl-dev \
    libp11-dev \
    pkg-config \
    autotools-dev \
    autoconf \
    automake \
    libtool \
    && rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /opt/libest

# Clone the Cisco libest repository
RUN git clone https://github.com/cisco/libest.git .

# Configure and build libest with examples
RUN ./configure --prefix=/usr/local \
    --disable-safec \
    && make -j$(nproc) \
    && make install

# Build the EST server example
WORKDIR /opt/libest/example/server
RUN make estserver
RUN cp .libs/estserver /usr/local/bin/

# Copy required libraries
RUN cp /opt/libest/src/est/.libs/libest-3.2.0p.so /usr/local/lib/
RUN cp /opt/libest/safe_c_stub/lib/libsafe_lib.a /usr/local/lib/
RUN ldconfig

# Create directory for EST server configuration
RUN mkdir -p /etc/est/config
RUN mkdir -p /etc/est/database
RUN mkdir -p /etc/est/certs

# Copy CA configuration files to config directory
COPY config/ca.conf /etc/est/config/

# Copy CA database initialization script
COPY init-ca-database.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/init-ca-database.sh

# Create startup script for TLS server (port 8443)
RUN echo '#!/bin/bash\n\
# Set environment variables\n\
export EST_CACERTS_RESP=/etc/est/config/cacerts.pem\n\
export EST_TRUSTED_CERTS=/etc/est/config/ca-cert.pem\n\
export EST_OPENSSL_CACONFIG=/etc/est/config/ca.conf\n\
# Start EST server with automatic enrollment (no -m option)\n\
estserver -p 8443 -c /etc/est/config/server-cert.pem -k /etc/est/config/server-key.pem\n\
' > /usr/local/bin/start-est-server-tls.sh && \
    chmod +x /usr/local/bin/start-est-server-tls.sh

# Create startup script for mTLS server (port 9443)
RUN echo '#!/bin/bash\n\
# Set environment variables\n\
export EST_CACERTS_RESP=/etc/est/config/cacerts.pem\n\
export EST_TRUSTED_CERTS=/etc/est/config/ca-cert.pem\n\
export EST_OPENSSL_CACONFIG=/etc/est/config/ca.conf\n\
# Start EST server with mTLS (disable HTTP auth, require TLS client auth)\n\
estserver -p 9443 -c /etc/est/config/server-cert.pem -k /etc/est/config/server-key.pem -n\n\
' > /usr/local/bin/start-est-server-mtls.sh && \
    chmod +x /usr/local/bin/start-est-server-mtls.sh

# Create main startup script that runs both servers
RUN echo '#!/bin/bash\n\
# Initialize CA database if needed\n\
/usr/local/bin/init-ca-database.sh\n\
echo "Starting EST servers..."\n\
echo "Starting TLS server on port 8443..."\n\
/usr/local/bin/start-est-server-tls.sh &\n\
echo "Starting mTLS server on port 9443..."\n\
/usr/local/bin/start-est-server-mtls.sh &\n\
echo "Both servers started. Waiting..."\n\
wait\n\
' > /usr/local/bin/start-est-server.sh && \
    chmod +x /usr/local/bin/start-est-server.sh

# Expose EST server ports
EXPOSE 8443 9443

# Set default command
CMD ["/usr/local/bin/start-est-server.sh"]

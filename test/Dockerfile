# Dockerfile for Cisco libest EST Server for Integration Testing
FROM ubuntu:24.04

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

# Copy our custom certificates
COPY config/ca-cert.pem /etc/est/config/
COPY config/server-cert.pem /etc/est/config/
COPY config/server-key.pem /etc/est/config/
COPY config/ca-key.pem /etc/est/config/
COPY config/ca.conf /etc/est/config/
COPY config/server.csr /etc/est/config/
COPY config/preenrollment.p12 /etc/est/config/

# Copy CA database initialization script
COPY init-ca-database.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/init-ca-database.sh

# Create startup script for TLS server (port 8443)
COPY tls-server.sh /usr/local/bin/start-est-server-tls.sh
RUN chmod +x /usr/local/bin/start-est-server-tls.sh

# Create startup script for mTLS server (port 9443)
COPY mtls-server.sh /usr/local/bin/start-est-server-mtls.sh
RUN chmod +x /usr/local/bin/start-est-server-mtls.sh

# Create startup script for TLS POP server (port 10443)
COPY pop-tls-server.sh /usr/local/bin/start-est-server-pop-tls.sh
RUN chmod +x /usr/local/bin/start-est-server-pop-tls.sh

# Create main startup script that runs both servers
COPY start.sh /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/start.sh

# Expose EST server ports
EXPOSE 8443 9443 10443

# Set default command
CMD ["/usr/local/bin/start.sh"]

ARG OS=ubuntu
ARG VERSION=20.04

FROM ${OS}:${VERSION} AS builder

RUN export DEBIAN_FRONTEND=noninteractive \ 
    && apt-get update \
    && apt-get install -y \
          build-essential \
          cmake \
          libssl-dev \
          libcurl4-openssl-dev \
          pkg-config \
          git \
    && rm -rf /var/lib/apt/lists/*

COPY src /etc/rfc7030-client/src
COPY deploy/docker/build.sh /etc/rfc7030-client/build.sh

WORKDIR /etc/rfc7030-client

RUN chmod +x /etc/rfc7030-client/build.sh \
    && /etc/rfc7030-client/build.sh

FROM ${OS}:${VERSION}

COPY --from=builder /etc/rfc7030-client/build/bin/rfc7030-est-client /usr/local/bin/rfc7030-est-client

RUN export DEBIAN_FRONTEND=noninteractive \ 
    && apt-get update \
    && apt-get install -y \
          openssl \
    && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/usr/local/bin/rfc7030-est-client"]
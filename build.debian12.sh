#!/bin/sh

set -e

docker build  -f Dockerfile.apt -t rfc7030-debian12 --build-arg OS=debian --build-arg VERSION=12 .
docker run  --rm -v .:/etc/rfc7030-client rfc7030-debian12
docker image rm rfc7030-debian12

mkdir -p dist/debian12
cp build/bin/rfc7030-est-client dist/debian12/
sudo rm -rf build

set +e
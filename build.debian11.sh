#!/bin/sh

set -e

docker build  -f Dockerfile.apt -t rfc7030-debian11 --build-arg OS=debian --build-arg VERSION=11 .
docker run  --rm -v .:/etc/rfc7030-client rfc7030-debian11
docker image rm rfc7030-debian11

mkdir -p dist/debian11
cp build/bin/rfc7030-est-client dist/debian11/
sudo rm -rf build

set +e
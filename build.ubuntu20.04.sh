#!/bin/sh

set -e

docker build  -f Dockerfile.apt -t rfc7030-ubuntu2004 --build-arg OS=ubuntu --build-arg VERSION=20.04 .
docker run  --rm -v .:/etc/rfc7030-client rfc7030-ubuntu2004
docker image rm rfc7030-ubuntu2004

mkdir -p dist/ubuntu2004
cp build/bin/rfc7030-est-client dist/ubuntu2004/
sudo rm -rf build

set +e
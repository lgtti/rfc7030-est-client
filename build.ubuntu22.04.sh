#!/bin/sh

set -e

docker build  -f Dockerfile.apt -t rfc7030-ubuntu2204 --build-arg OS=ubuntu --build-arg VERSION=22.04 .
docker run  --rm -v .:/etc/rfc7030-client rfc7030-ubuntu2204
docker image rm rfc7030-ubuntu2204

mkdir -p dist/ubuntu2204
cp build/bin/rfc7030-est-client dist/ubuntu2204/
sudo rm -rf build

set +e
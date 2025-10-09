#!/bin/sh

set -e

docker build  -f Dockerfile.apt -t rfc7030-ubuntu1804 --build-arg OS=ubuntu --build-arg VERSION=18.04 .
docker run  --rm -v .:/etc/rfc7030-client rfc7030-ubuntu1804
docker image rm rfc7030-ubuntu1804

mkdir -p dist/ubuntu1804
cp build/bin/rfc7030-est-client dist/ubuntu1804/
sudo rm -rf build

set +e
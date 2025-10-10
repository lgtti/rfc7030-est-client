#!/bin/sh

set -e

mkdir -p build
cd build 

cmake ../src \
    -DBUILD_CLONE_SUBMODULES=ON \
    -DUSE_OPENSSL=ON

make -j$(nproc) 

./bin/rfc7030-est-client-tests

set +e
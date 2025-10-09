#!/bin/sh

set -e

cmake -Ssrc -Bbuild \
          -DBUILD_CLONE_SUBMODULES=ON \
          -DUSE_OPENSSL=ON
cd build 
make -j$(nproc) 

./bin/rfc7030-est-client-tests

set +e
#!/usr/bin/env bash

echo "Installing some dependencies we need to build"
apk add --no-cache build-base cmake autoconf libtool pkgconf git mercurial file linux-headers wget libc-dev

(
cd /tmp

# Building openssl statically (Requirement for libssh)
export OPENSSL_VERSION=1.1.1d
echo "Downloading OpenSSL version ${OPENSSL_VERSION}"
wget https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz && tar xf openssl-${OPENSSL_VERSION}.tar.gz

echo "Building and installing OpenSSL version ${OPENSSL_VERSION}"
cd openssl-${OPENSSL_VERSION} && ./config -fPIC && make && make install_sw
)

# Building CidSSH
rm -rf build
cmake -S . -B build
cmake --build build --config Release

# For Op
#RUN mkdir build && cd build && cmake -DCMAKE_BUILD_TYPE=Release -DPASSWORD_AUTH="xxxxxxxxxx" -DC2_IP="XX.XX.XX.XX" .. && make 


#!/usr/bin/env bash

echo "Installing some dependencies we need to build"
apk add --no-cache \
    build-base \
    cmake \
    autoconf \
    libtool \
    pkgconf \
    git \
    mercurial \
    file \
    linux-headers \
    wget \
    libc-dev \
    boost-dev \
    boost-static \
    boost-system \
    openssl \
    openssl-libs-static \
    openssl-dev

# Building CidSSH
rm -rf build
cmake -S . -B build
cmake --build build --config Release

# For Op
#RUN mkdir build && cd build && cmake -DCMAKE_BUILD_TYPE=Release -DPASSWORD_AUTH="xxxxxxxxxx" -DC2_IP="XX.XX.XX.XX" .. && make 


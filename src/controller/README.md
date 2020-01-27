## Cid-Controller
Either with the normal or websocket version, **CidSSH** C2 will receive standard reverse SSH connections. You can see mentioned connections by running `netstat -pln` in the C2. The problem about `netstat` is that if you receive multiple connections from different victims you won't know which binded local port corresponds with each of the victims. To overcome this problem `Cid-SSH` provides `Cid-Controller`. It is used for:

- Log information sent by the victims when they get infected. This is done by setting the `anonymous` shell to be `Cid-controller`.
- As a dashboard to list a history of victims and a way to easily jump into a shell in them.

To use it you just need to set the C2 user shell used by the malware (by default it is `anonymous`) to `Cid-Controller`. You can do that with:

```
sudo usermod -s /path/to/Cid-Controller anonymous
```

`Cid-Controller` relies on `lsof` to get the info about the existent connections. Since `lsof` needs to be run as root to provide the information we need, we have to set the setgid bit to `lsof`. To do so:

```
sudo chmod +s /usr/bin/lsof
```


To list and interact with active connections you just have to call the same `Cid-Controller` binary:

```
/path/to/Cid-Controller
```


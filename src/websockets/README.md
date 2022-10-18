# Websocket version

The code in this folder is used when compiling `Cid-SSH` with websocket support. Using the compiled websocket version will make `Cid-SSH` use secure websocket in the communications with the a `websocket server` that which code can be reviewed [here](../wsproxyserver/README.md).

The websocket server will parse websocket communications and forward it to the C2 SSH server. This server can reside in the same system than the `websocket server` or in a different one. 

This code uses a modified version of `libproxy` to try to detect HTTP/S proxies running in the victim to use them when connecting to the `websocket server`. For more information see [this](libproxy/README.md).


# libproxy

This is a modified version of [libproxy](https://github.com/libproxy/libproxy) that adds support for [duktape](https://github.com/svaarala/duktape) as a JS renderer to run [PAC files](https://en.wikipedia.org/wiki/Proxy_auto-config). 

A PAC file contains a JavaScript function `FindProxyForURL(url, host)`. This function returns a string with one or more access method specifications
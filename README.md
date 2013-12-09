fgfw-lite
============

fgfw-lite is a HTTP proxy server help to get around the Great Firewall. It dectets websites blocked by GFW automatically, and forward the request to a uncensored proxy server.

requirements under openSUSE:

    zypper install python-tornado python-ipaddr

to work with shadowsocks, require either of the following:

1. [python2.7](http://www.python.org/getit/) and [M2Crypto](http://chandlerproject.org/Projects/MeTooCrypto#Downloads) is installed.
2. [shadowsocks-nodejs](https://github.com/clowwindy/shadowsocks-nodejs) or [shadowsocks-libev](https://github.com/madeye/shadowsocks-libev) is installed.(won't work on Windows XP)
3. compiled shadowsocks client binary in ./shadowsocks folder.

goagent https://code.google.com/p/goagent/

shadowsocks https://github.com/clowwindy/shadowsocks

snova https://code.google.com/p/snova/

pybuild https://github.com/goagent/pybuild

chnroutes.py https://github.com/fivesheep/chnroutes

cow https://github.com/cyfdecyf/cow

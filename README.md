FGFW-Lite
============

The toolkit I am using to get around the Great Firewall. FGFW-Lite dectets websites blocked by GFW automatically, and forward the request to a uncensored proxy server. Like COW, but with goagent and shadowsocks built in, support AutoProxy rules.

For windows users, [download](https://github.com/v3aqb/fgfw-lite/archive/master.zip), edit userconf.ini as needed, and run FGFW_Lite.exe.

requirements under openSUSE:

    zypper install python-tornado python-repoze.lru python-futures
    zypper install python-gtk python-vte python-notify  # for gui
    zypper install python-M2Crypto  # shadowsocks
    zypper install python-pyOpenSSL python-gevent  # goagent

goagent https://code.google.com/p/goagent/

shadowsocks https://github.com/clowwindy/shadowsocks

snova https://code.google.com/p/snova/

pybuild https://github.com/goagent/pybuild

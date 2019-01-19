## fwlite for windows

A anti-censorship HTTP proxy with builtin shadowsocks support.

Portable package of fwlite-cli and fwlite-gui for windows.

Executables of supported plugins included.

v5.0-beta5

####Features

- System proxy configuration (windows)
- Detect blocked sites automatically
  - gfwlist
  - user-defined rules
  - connect timeout
  - read timeout
  - connection reset
- Multiple work mode
- Support Network which require a proxy ([issue #39](https://github.com/v3aqb/fwlite/issues/39))
- Supprot proxy chain
- Supported proxy protocol
  - HTTP Proxy
  - Socks5 Proxy
  - [hxsocks2]
  - [Shadowsocks] by @clowwindy
- Supported SIP003 plugins
  - simple-obfs
  - kcptun
  - GoQuiet
- Prioritize proxy by response time
- User-defined redirector
- Simple PAC for WPAD

#### Download

Download the latest release from [release page].

#### Requirements

Windows 7 or higher. If you are running Windows XP, check the [old version].

#### License

[GPLv3]

#### Open Source Components / Libraries

```
fwlite-cli (GPLv3)     https://github.com/v3aqb/fwlite-cli
fwlite-gui (GPLv3)     https://github.com/v3aqb/fwlite-gui
hxcrypto (LGPL)      https://github.com/v3aqb/hxcrypto
asn1crypto (MIT)       https://pypi.org/project/asn1crypto/
cffi (MIT)             https://pypi.org/project/cffi/
chardet (LGPL)         https://pypi.org/project/chardet/
cryptography (Apache)  https://cryptography.io/
gfwlist (LGPL)         https://github.com/gfwlist/gfwlist
idna (BSD)             https://pypi.org/project/idna/
PyQt5 (GPLv3)          https://pypi.org/project/PyQt5/
repoze.lru (BSD)       https://pypi.org/project/repoze.lru/
six (MIT)              https://pypi.org/project/six/
python (PSFL)          https://python.org/
simple-obfs (GPLv3)    https://github.com/shadowsocks/simple-obfs
kcptun (MIT)           https://github.com/xtaci/kcptun
GoQuiet (GPLv3)        https://github.com/cbeuw/GoQuiet
```

[release page]: https://github.com/v3aqb/fwlite/releases
[old version]: https://github.com/v3aqb/fwlite/tree/0.4
[GPLv3]: https://www.gnu.org/licenses/gpl-3.0.txt

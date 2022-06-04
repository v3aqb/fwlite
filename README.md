## fwlite for windows

### 🇺🇦 Слава Україні! Смерть загарбнику!

A anti-censorship HTTP proxy with builtin shadowsocks support.

Portable package of fwlite-cli and fwlite-gui for windows.

Executables of supported plugins included.

2022.6.4 v5.3.2

#### Features

- System proxy configuration (windows)
- Detect blocked sites automatically
  - gfwlist
  - user-defined rules
  - connect timeout
  - read timeout
  - connection reset
- Multiple work profile
  - 0: direct
  - 1: auto (gfwlist)
  - 3: bypass ip in china
  - 4: bypass ip in LAN
  - 5: bypass localhost
- Support Network require a proxy ([fwlite #39](https://github.com/v3aqb/fwlite/issues/39))
- Supported proxy protocol
  - HTTP Proxy
  - Socks5
  - hxsocks2
  - hxsocks3
  - Shadowsocks by @clowwindy
- SIP003 plugin ([fwlite-cli #1](https://github.com/v3aqb/fwlite-cli/issues/1))
- Support Shadowsocks Subscription (test pending)
- Supprot proxy chain
- Hosts based AdBlock
- Port Forwarding
- Prioritize proxy by response time
- User-defined redirector
- Simple PAC for WPAD

#### Requirements

Windows 7 or higher.

[Microsoft Visual C++ 2015 Redistributable] (x86) installed.

#### Download

Download the latest release from [release page].

#### License

[GPLv3]

#### Open Source Components / Libraries

```
fwlite-cli (GPLv3)     https://github.com/v3aqb/fwlite-cli
fwlite-gui (GPLv3)     https://github.com/v3aqb/fwlite-gui
hxcrypto (LGPLv3)      https://github.com/v3aqb/hxcrypto
asn1crypto (MIT)       https://pypi.org/project/asn1crypto/
cffi (MIT)             https://pypi.org/project/cffi/
chardet (LGPLv2.1)     https://pypi.org/project/chardet/
cryptography (Apache)  https://cryptography.io/
gfwlist (LGPLv2.1)     https://github.com/gfwlist/gfwlist
idna (BSD)             https://pypi.org/project/idna/
PyQt5 (GPLv3)          https://pypi.org/project/PyQt5/
repoze.lru (BSD)       https://pypi.org/project/repoze.lru/
six (MIT)              https://pypi.org/project/six/
python (PSFL)          https://python.org/
simple-obfs (GPLv3)    https://github.com/shadowsocks/simple-obfs
kcptun (MIT)           https://github.com/xtaci/kcptun
GoQuiet (GPLv3)        https://github.com/cbeuw/GoQuiet
Cloak (GPLv3)          https://github.com/cbeuw/Cloak
v2ray-plugin (MIT)     https://github.com/teddysun/v2ray-plugin
xray-plugin (MIT)      https://github.com/teddysun/xray-plugin
```

[release page]: https://github.com/v3aqb/fwlite/releases
[GPLv3]: https://www.gnu.org/licenses/gpl-3.0.txt
[Microsoft Visual C++ 2015 Redistributable]: https://www.microsoft.com/en-us/download/details.aspx?id=52685

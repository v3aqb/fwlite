
## fwlite for windows

### 🇺🇦 Слава Україні! Смерть диктатору!

FWLite across the GreatFireWall, we can reach every corner of the world.

A intelligent HTTP/Socks5 proxy, detect and circumvent censorship automatically.

Portable package of `fwlite-cli` and `fwlite-gui` for windows.

Executables of supported plugins included.

2024.2.18 v5.10

**If you are experiencing chash after update, delete /lib directory and update again.**

**This problem is caused by python-cryptography , they do not support update by overwrite.**

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
  - 4: bypass ip in china and LAN
  - 5: bypass localhost only
- Support Network require a proxy ([fwlite #39](https://github.com/v3aqb/fwlite/issues/39))
- Supported proxy protocol
  - HTTP Proxy
  - Socks5
  - hxsocks2
  - hxsocks3
  - hxsocks4
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
x86 release

    Windows 7 or higher.

x86-64 release

    Windows 8 or higher.

[Microsoft Visual C++ 2015 Redistributable] installed.

You may want to turn on *tcp timestamps*.

For Windows, start PowerShell with Administrator Privilege, run this command:

    `netsh interface tcp set global timestamps=enabled`

#### Download

Download the latest release from [release page].

#### Quickstart

run `FWLite.exe`

set parent proxy in `ProxyList` page.

set system proxy setting to `127.0.0.1:8118`.

enjoy.

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
kcptun (MIT)           https://github.com/xtaci/kcptun
Cloak (GPLv3)          https://github.com/cbeuw/Cloak
v2ray-plugin (MIT)     https://github.com/teddysun/v2ray-plugin
xray-plugin (MIT)      https://github.com/teddysun/xray-plugin
```

[release page]: https://github.com/v3aqb/fwlite/releases
[GPLv3]: https://www.gnu.org/licenses/gpl-3.0.txt
[Microsoft Visual C++ 2015 Redistributable]: https://www.microsoft.com/en-us/download/details.aspx?id=52685

FGFW-Lite
=========
FGFW-Lite是一个辅助突破网络审查的HTTP代理服务器。它能自动检查网站是否被墙，使用二级代理。

##功能

- 符合HTTP1.1标准的HTTP代理服务器
- 自动设置系统代理(仅限Windows)
- 使用多种方法检测网站是否被墙，并转发到二级代理
  - autoproxy-gfwlist
  - 连接超时
  - 读操作超时
  - 连接被重置
- 多种自定义规则
- 默认设置即可无障碍访问部分Google服务(GoAgent FORWARD)
- 支持的二级代理
  - HTTP
  - HTTP over SSL (SSL Proxy, SSLEdge)
  - Socks5
  - GoAgent
  - Shadowsocks
  - Snova

##快速开始

FGFW-Lite是便携软件，直接[下载](https://github.com/v3aqb/fgfw-lite/archive/0.4.zip)，解压即用。注意，**路径只支持英文，不能有空格**。

配置文件userconf.ini，参考userconf.sample.ini，添加二级代理。

windows系统：运行FGFW_Lite.exe

Linux系统：运行fgfwlite-gtk.pyw

requirements under openSUSE:

    zypper install python-repoze.lru python-gevent # for better performance
    zypper install python-gtk python-vte python-notify  # gui
    zypper install python-M2Crypto  # advanced encryption for shadowsocks
    zypper install python-pyOpenSSL  # goagent fake https

##自定义规则(./fgfw-lite/local.txt)

FGFW-Lite兼容[autoproxy规则](https://autoproxy.org/zh-CN/Rules)，不同之处：

对特定网址不使用规则。用于阻止对国内的网站误用代理，以及gfwlist中可直连的网站。

    @@||example.com

forcehttps

    |http://zh.wikipedia.com/search forcehttps

重定向

    http://www.baidu.com http://www.google.com

重定向(正则表达式)

    /^http://www.baidu.com/.*wd=([^&]*).*$/ /https://www.google.com/search?q=\1&ie=gb2312/

阻止访问特定网站

    ||dongtaiwang.com 403

为特定网站指定二级代理

    ||bbc.co.uk shadowsocks-uk
    ||weibo.com direct

##其他相关

cow https://github.com/cyfdecyf/cow

goagent https://code.google.com/p/goagent/

shadowsocks https://github.com/clowwindy/shadowsocks

snova https://code.google.com/p/snova/

pybuild https://github.com/goagent/pybuild

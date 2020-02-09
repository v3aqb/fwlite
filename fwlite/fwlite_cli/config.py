#!/usr/bin/env python

# Copyright (C) 2014-2019 v3aqb

# This file is part of fwlite-cli.

# Fwlite-cli is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# Fwlite-cli is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with fwlite-cli.  If not, see <https://www.gnu.org/licenses/>.

import os
import sys
import socket
import logging
import logging.handlers
import traceback
from collections import defaultdict, deque

from ipaddress import IPv4Address, ip_address

from .parent_proxy import ParentProxyList, ParentProxy
from .get_proxy import get_proxy
from .redirector import redirector
from .util import SConfigParser, parse_hostport
from .resolver import Resolver
from .plugin_manager import plugin_register
from .port_forward import ForwardManager
from .plugin_manager import PluginManager


PAC = r'''
var wall_proxy = "__PROXY__";
var direct = "DIRECT;";

/*
 * Copyright (C) 2014 breakwa11
 * https://github.com/breakwa11/gfw_whitelist
 */

var subnetIpRangeList = [
0,1,
167772160,184549376,    //10.0.0.0/8
2886729728,2887778304,  //172.16.0.0/12
3232235520,3232301056,  //192.168.0.0/16
2130706432,2130706688   //127.0.0.0/24
];

var hasOwnProperty = Object.hasOwnProperty;

function check_ipv4(host) {
    // check if the ipv4 format (TODO: ipv6)
    //   http://home.deds.nl/~aeron/regex/
    var re_ipv4 = /^\d+\.\d+\.\d+\.\d+$/g;
    if (re_ipv4.test(host)) {
        // in theory, we can add chnroutes test here.
        // but that is probably too much an overkill.
        return true;
    }
}
function convertAddress(ipchars) {
    var bytes = ipchars.split('.');
    var result = (bytes[0] << 24) |
    (bytes[1] << 16) |
    (bytes[2] << 8) |
    (bytes[3]);
    return result >>> 0;
}
function isInSubnetRange(ipRange, intIp) {
    for ( var i = 0; i < 10; i += 2 ) {
        if ( ipRange[i] <= intIp && intIp < ipRange[i+1] )
            return true;
    }
}
function getProxyFromDirectIP(strIp) {
    var intIp = convertAddress(strIp);
    if ( isInSubnetRange(subnetIpRangeList, intIp) ) {
        return direct;
    }
    return wall_proxy;
}
function isInDomains(domain_dict, host) {
    var suffix;
    var pos1 = host.lastIndexOf('.');

    suffix = host.substring(pos1 + 1);
    if (suffix == "cn") {
        return true;
    }

    var domains = domain_dict[suffix];
    if ( domains === undefined ) {
        return false;
    }
    host = host.substring(0, pos1);
    var pos = host.lastIndexOf('.');

    while(1) {
        if (pos <= 0) {
            if (hasOwnProperty.call(domains, host)) {
                return true;
            } else {
                return false;
            }
        }
        suffix = host.substring(pos + 1);
        if (hasOwnProperty.call(domains, suffix)) {
            return true;
        }
        pos = host.lastIndexOf('.', pos - 1);
    }
}
function FindProxyForURL(url, host) {
    url=""+url;
    host=""+host;
    if ( isPlainHostName(host) === true ) {
        return direct;
    }
    if ( check_ipv4(host) === true ) {
        return getProxyFromDirectIP(host);
    }
    return wall_proxy;
}

'''


def url_retreive(url, path, proxy):
    import urllib.request
    if proxy.proxy:
        if proxy.scheme == 'http' and '|' not in proxy.proxy:
            proxy_handler = urllib.request.ProxyHandler(
                {'http': proxy.proxy,
                 'https': proxy.proxy})
        else:
            # proxy not supported
            with open(path, 'w') as localfile:
                localfile.write('\n')
            return
    else:
        proxy_handler = urllib.request.ProxyHandler({})
    opener = urllib.request.build_opener(proxy_handler)
    urlopen = opener.open

    req = urlopen(url)
    data = req.read()
    if req.getcode() == 200 and data:
        with open(path, 'wb') as localfile:
            localfile.write(data)


class _stderr:
    # replace stderr
    def __init__(self, maxlen=100):
        self.store = deque(maxlen=maxlen)

    def write(self, data):
        sys.__stderr__.write(data)
        lines = data.strip().splitlines()
        self.store.extend(lines)

    def flush(self):
        sys.__stderr__.flush()

    def getvalue(self):
        data = '\r\n'.join(self.store)
        # self.store.clear()
        return data


class Config:
    def __init__(self, conf_path, gui):
        self.patch_stderr()

        self.logger = logging.getLogger('config')
        self.logger.setLevel(logging.INFO)
        hdr = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                                      datefmt='%H:%M:%S')
        hdr.setFormatter(formatter)
        self.logger.addHandler(hdr)

        ParentProxy.conf = self

        self._started = False
        self.GUI = gui
        self.loop = None
        self.conf_path = conf_path

        self.userconf = SConfigParser(interpolation=None)

        self.hello()
        self.reload()

    def init(self):
        self.timeout = 4
        self.profile = '134'
        self.maxretry = 4
        self.rproxy = False
        self.remoteapi = False
        self.remotepass = ''

        self.listen = '8118'

        self.gate = 2

        self.plugin_manager = None  # PluginManager(self)
        self.port_forward = None  # ForwardManager(self)
        self.parentlist = None  # ParentProxyList(self)

        self.HOSTS = defaultdict(list)
        self.local_ip = '127.0.0.1'

        self.PAC = b''

        self.REDIRECTOR = None  # redirector(self)
        self.GET_PROXY = None  # get_proxy(self)
        self.resolver = None  # Resolver(self.GET_PROXY, bad_ip)

    def addhost(self, host, ip):
        try:
            ipo = ip_address(ip)
            if isinstance(ipo, IPv4Address):
                self.HOSTS[host].append((2, ip))
            else:
                self.HOSTS[host].append((10, ip))
        except Exception:
            self.logger.error('unsupported host: %s', ip)
            self.logger.error(traceback.format_exc())

    def reload(self, conf_path=None):
        self.init()
        self.conf_path = os.path.abspath(conf_path or self.conf_path)
        self.conf_dir = os.path.dirname(self.conf_path)
        os.chdir(self.conf_dir)
        self.local_path = os.path.join(self.conf_dir, 'local.txt')
        self.gfwlist_path = os.path.join(self.conf_dir, 'gfwlist.txt')
        self.china_ip_path = os.path.join(self.conf_dir, 'china_ip_list.txt')
        self.adblock_path = os.path.join(self.conf_dir, 'adblock.txt')

        self.userconf.read(self.conf_path)

        self.timeout = self.userconf.dgetint('FWLite', 'timeout', 4)
        self.profile = self.userconf.dget('FWLite', 'profile', '134')
        if '1' not in self.profile:
            self.profile += '1'
        if '3' not in self.profile:
            self.profile += '3'
        self.maxretry = self.userconf.dgetint('FWLite', 'maxretry', 4)
        self.rproxy = self.userconf.dgetbool('FWLite', 'rproxy', False)
        self.remoteapi = self.userconf.dgetbool('FWLite', 'remoteapi', False)
        self.remotepass = self.userconf.dget('FWLite', 'remotepass', '')
        if self.remoteapi and not self.remotepass:
            self.logger.warning('Remote API Enabled WITHOUT password protection!')

        listen = self.userconf.dget('FWLite', 'listen', '8118')
        if listen.isdigit():
            self.listen = ('127.0.0.1', int(listen))
        else:
            self.listen = (listen.rsplit(':', 1)[0], int(listen.rsplit(':', 1)[1]))

        ParentProxy.DEFAULT_TIMEOUT = self.timeout

        self.gate = self.userconf.dgetint('FWLite', 'gate', 2)
        if self.gate < 0:
            self.logger.warning('gate < 0, set to 0')
            self.gate = 0
        ParentProxy.GATE = self.gate

        for key, val in self.userconf.items('plugin'):
            plugin_register(key, val)

        self.plugin_manager = PluginManager(self)
        self.port_forward = ForwardManager(self)
        self.parentlist = ParentProxyList(self)

        self.HOSTS = defaultdict(list)

        for host, ip_ in self.userconf.items('hosts'):
            self.addhost(host, ip_)

        if not os.path.exists(self.local_path):
            self.logger.warning('"local.txt" not found! creating...')
            with open(self.local_path, 'w') as f:
                f.write('''\
! local gfwlist config
! rules: https://autoproxy.org/zh-CN/Rules
! /^http://www.baidu.com/.*wd=([^&]*).*$/ /https://www.google.com/search?q=\1/
''')

        # prep PAC
        try:
            csock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            csock.connect(('8.8.8.8', 53))
            (addr, _) = csock.getsockname()
            csock.close()
            self.local_ip = addr
        except socket.error:
            self.local_ip = '127.0.0.1'

        self.PAC = PAC.replace('__PROXY__', 'PROXY %s:%s' % (self.local_ip, self.listen[1]))
        if self.userconf.dget('FWLite', 'pac', ''):
            if os.path.isfile(self.userconf.dget('FWLite', 'pac', '')):
                self.PAC = open(self.userconf.dget('FWLite', 'pac', '')).read()

        self.PAC = self.PAC.encode()

        self.REDIRECTOR = redirector(self)
        self.GET_PROXY = get_proxy(self)
        bad_ip = set(self.userconf.dget('dns', 'bad_ip', '').split('|'))
        apf = None if self.rproxy else self.GET_PROXY
        self.resolver = Resolver(apf, bad_ip)

    def confsave(self):
        with open(self.conf_path, 'w') as conf_file:
            self.userconf.write(conf_file)

    def register_proxy_n_forward(self):
        # add proxy created my fwlite self
        for i, profile in enumerate(self.profile):
            self.addparentproxy('FWLITE:%s' % profile, 'http://127.0.0.1:%d' % (self.listen[1] + i))

        if self.userconf.dget('FWLite', 'parentproxy', ''):
            self.addparentproxy('_D1R3CT_', '%s 0' % self.userconf.dget('FWLite', 'parentproxy'))
        else:
            self.addparentproxy('_D1R3CT_', 'direct 0')

        for key, val in self.userconf.items('parents'):
            if key in ('_D1R3CT_', '_L0C4L_'):
                self.logger.error('proxy name %s is protected!', key)
                continue
            try:
                self.add_proxy(key, val)
            except Exception as err:
                self.logger.error('add proxy failed! %r', err)

        if not self.rproxy and not [parent for parent in self.parentlist.parents() if parent.priority < 100]:
            self.logger.warning('No parent proxy available!')

        for port, target_proxy in self.userconf.items('port_forward'):
            # default using proxy FWLITE:1
            try:
                target, _, proxy = target_proxy.partition(' ')
                target = (target.rsplit(':', 1)[0], int(target.rsplit(':', 1)[1]))
                proxy = proxy or ('FWLITE:' + self.profile[0])
                port = int(port)
                self.port_forward.add(target, proxy, port)
            except Exception as err:
                self.logger.error(repr(err))
                self.logger.error(traceback.format_exc())

    def addparentproxy(self, name, proxy):
        self.parentlist.addstr(name, proxy)

    def stdout(self, text=''):
        if text == 'all':
            self._started = True
        if not self._started:
            return
        if self.GUI:
            sys.stdout.write(text + '\n')
            sys.stdout.flush()

    async def download(self):
        proxy = self.parentlist.get('FWLITE:' + self.profile[0])

        file_list = {self.gfwlist_path: self.userconf.dget('FWLite', 'gfwlist_url', 'https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt'),
                     self.china_ip_path: 'https://github.com/17mon/china_ip_list/raw/master/china_ip_list.txt',
                     self.adblock_path: self.userconf.dget('FWLite', 'adblock_url', 'https://raw.githubusercontent.com/v3aqb/gfwlist/master/adblock_hosts.txt')
                     }

        def _dl(path, url, proxy):
            file_name = os.path.basename(path)
            self.logger.warning('"%s" not found! downloading...', file_name)
            try:
                url_retreive(url, path, proxy)
            except Exception:
                self.logger.warning('download "%s" failed!', file_name)
                open(path, 'a').close()

        task_list = []
        import asyncio
        loop = asyncio.get_event_loop()

        for path, url in file_list.items():
            if not os.path.exists(path) or not open(path).read():
                task = loop.run_in_executor(None, _dl, path, url, proxy)
                task_list.append(task)

        await asyncio.gather(*task_list)

    def load(self):
        self.GET_PROXY.load()
        self.REDIRECTOR.load()

    async def post_start(self):
        await self.download()
        self.load()
        self.stdout('all')

    @property
    def adblock_enable(self):
        return self.userconf.dgetbool('FWLite', 'adblock', False)

    @adblock_enable.setter
    def adblock_enable(self, val):
        self.userconf.set('FWLite', 'adblock', '1' if val else '0')
        self.confsave()
        self.stdout('setting')

    @property
    def gfwlist_enable(self):
        return self.userconf.dgetbool('FWLite', 'gfwlist', True)

    @gfwlist_enable.setter
    def gfwlist_enable(self, val):
        self.userconf.set('FWLite', 'gfwlist', '1' if val else '0')
        self.confsave()
        self.stdout('setting')

    def patch_stderr(self):
        self.stderr = _stderr()
        sys.stderr = self.stderr

    def get_log(self):
        return self.stderr.getvalue()

    def list_localrule(self):
        return [(rule, self.GET_PROXY.local.expire[rule]) for rule in self.GET_PROXY.local.rules]

    def add_localrule(self, rule, expire):
        self.GET_PROXY.add_temp(rule, expire)

    def del_localrule(self, rule):
        self.GET_PROXY.local.remove(rule)
        self.stdout('local')

    def list_redir(self):
        return self.REDIRECTOR.list()

    def add_redir(self, rule, dest):
        self.GET_PROXY.add_redirect(rule, dest)
        self.stdout('redir')

    def del_redir(self, rule):
        self.REDIRECTOR.remove(rule)
        self.stdout('redir')

    def list_proxy(self):
        data = [(p.name, p.short, p.priority, p.get_avg_resp_time())
                for _, p in self.parentlist.dict.items()]
        data = sorted(data, key=lambda item: item[0])
        data = sorted(data, key=lambda item: item[2])
        return data

    def add_proxy(self, name, proxy):
        if 'FWLITE:' in name:
            raise ValueError
        if name == '_L0C4L_':
            raise ValueError
        self.addparentproxy(name, proxy)
        if name not in ('_D1R3CT_', '_L0C4L_'):
            self.userconf.set('parents', name, proxy)
            self.confsave()

    def del_proxy(self, name):
        self.parentlist.remove(name)
        if self.userconf.has_option('parents', name):
            self.userconf.remove_option('parents', name)
            self.confsave()

    def get_proxy(self, name):
        proxy = self.parentlist.get(name)
        return proxy.proxy

    def list_forward(self):
        return [('%s:%s' % target, proxy, port)
                for target, proxy, port in self.port_forward.list()]

    def add_forward(self, target, proxy, port):
        target = parse_hostport(target)
        self.port_forward.add(target, proxy, port)

    def del_forward(self, port):
        self.port_forward.stop(port)

    def on_exit(self):
        self.plugin_manager.cleanup()
        self.loop.stop()

    def start_dns_server(self):
        if self.userconf.dgetbool('dns', 'enable', False):
            loop = self.loop
            import asyncio
            from .dns_server import TcpDnsHandler
            dns_server = parse_hostport(self.userconf.dget('dns', 'server', '8.8.8.8:53'), 53)
            listen = parse_hostport(self.userconf.dget('dns', 'listen', '127.0.0.1:53'), 53)
            proxy = self.parentlist.get('FWLITE:1')
            handler = TcpDnsHandler(dns_server, proxy, self)
            server = asyncio.start_server(handler.handle, listen[0], listen[1], loop=loop)
            loop.run_until_complete(server)

    def start_server(self):
        import asyncio
        from .proxy_handler import handler_factory, http_handler
        loop = self.loop
        addr, port = self.listen
        for i, profile in enumerate(self.profile):
            profile = int(profile)
            handler = handler_factory(addr, port + i, http_handler, profile, self)
            server = asyncio.start_server(handler.handle, handler.addr, handler.port, loop=loop)
            loop.run_until_complete(server)

    def set_loop(self):
        import asyncio
        loop = asyncio.get_event_loop()
        if sys.platform == 'win32' and not isinstance(loop, asyncio.ProactorEventLoop):
            self.logger.info('set ProactorEventLoop for windows')
            loop = asyncio.ProactorEventLoop()
            asyncio.set_event_loop(loop)
        self.loop = loop

    def start(self):
        self.set_loop()
        self.register_proxy_n_forward()
        self.start_dns_server()
        self.start_server()
        self.loop.run_until_complete(self.post_start())
        self.loop.run_forever()
        self.logger.info('start() ended')

    def hello(self):
        from . import __version__
        hello = 'FWLite %s with asyncio, ' % __version__
        import platform
        hello += 'python %s %s' % (platform.python_version(), platform.architecture()[0])

        if self.GUI:
            hello += ' with GUI'

        sys.stderr.write(hello + '\n')

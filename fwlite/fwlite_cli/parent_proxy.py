#!/usr/bin/env python
# coding:utf-8

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

import time
import logging

import urllib
from urllib.parse import unquote

logger = logging.getLogger('parent_proxy')


def set_logger():
    logger.setLevel(logging.INFO)
    hdr = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                                  datefmt='%H:%M:%S')
    hdr.setFormatter(formatter)
    logger.addHandler(hdr)


set_logger()


class DefaultDict(dict):
    def __init__(self, default):
        self.default = default
        super().__init__(self)

    def __missing__(self, key):
        return self.default


class ParentProxy:
    VIA = None
    DIRECT = None
    DEFAULT_TIMEOUT = 8
    GATE = 0
    conf = None

    def __init__(self, name, proxy):
        '''
        name: str, name of parent proxy
        proxy: "http://127.0.0.1:8087<|more proxies> <optional int: priority>"
        '''
        proxy, _, priority = proxy.partition(' ')
        priority = priority or 99
        if name == '_D1R3CT_':
            priority = 0
        if name == '_L0C4L_':
            priority = -1
            proxy = ''
        if name.startswith('FWLITE:'):
            priority = -1

        if proxy == 'direct':
            proxy = ''
        elif proxy and '//' not in proxy:
            proxy = 'http://' + proxy
        self.name = name
        proxy_list = proxy.split('|')
        self.proxy = proxy
        if len(proxy_list) > 1:
            self.VIA = ParentProxy('via', '|'.join(proxy_list[1:]))
            self.VIA.name = '%s://%s:%s' % (self.VIA.scheme, self.VIA.hostname, self.VIA.port)
        self.parse = urllib.parse.urlparse(proxy_list[0])

        self.scheme = self.parse.scheme
        self.username = unquote(self.parse.username) if self.parse.username else None
        self.password = unquote(self.parse.password) if self.parse.password else None
        self.hostname = self.parse.hostname
        self.port = self.parse.port
        self._host_port = (self.hostname, self.port)  # for plugin only
        if self.proxy:
            self.short = '%s://%s:%s' % (self.scheme, self._host_port[0], self._host_port[1])
        else:
            self.short = 'direct'

        self.query = urllib.parse.parse_qs(self.parse.query)
        plugin = self.query.get('plugin', [None, ])[0]
        self.plugin_info = plugin.split(';') if plugin else None
        if self.plugin_info:
            self.port = self.conf.plugin_manager.add(self._host_port, self.plugin_info, self.VIA)
            self.hostname = '127.0.0.1'

        self.priority = int(float(priority))
        self.timeout = self.DEFAULT_TIMEOUT
        self.gate = self.GATE

        self.avg_resp_time = self.gate
        self.avg_resp_time_ts = 0
        self.avg_resp_time_by_host = DefaultDict(self.gate)
        self.avg_resp_time_by_host_ts = DefaultDict(0)

        self.country_code = self.query.get('location', [''])[0] or None
        self.last_ckeck = 0

    def get_priority(self, method=None, host=None):
        result = self.priority

        score = self.get_avg_resp_time() + self.get_avg_resp_time(host)
        logger.debug('penalty %s to %s: %.2f', self.name, host, score * 2)
        result += score * 2
        logger.debug('proxy %s to %s expected response time: %.3f', self.name, host, score)
        return result

    def log(self, host, rtime):
        self.avg_resp_time = 0.87 * self.get_avg_resp_time() + (1 - 0.87) * rtime
        self.avg_resp_time_by_host[host] = 0.87 * self.avg_resp_time_by_host[host] + (1 - 0.87) * rtime
        self.avg_resp_time_ts = self.avg_resp_time_by_host_ts[host] = time.time()
        logger.debug('%s to %s: %.3fs avg: %.3fs %.3fs', self.name, host, rtime,
                     self.avg_resp_time, self.avg_resp_time_by_host[host])
        self.conf.stdout('proxy')

    def get_avg_resp_time(self, host=None):
        if host is None:
            if time.time() - self.avg_resp_time_ts > 360:
                if self.avg_resp_time > self.gate:
                    self.avg_resp_time *= 0.93
                self.avg_resp_time_ts = time.time()
            return self.avg_resp_time
        if time.time() - self.avg_resp_time_by_host_ts[host] > 360:
            if self.avg_resp_time_by_host[host] > self.gate:
                self.avg_resp_time_by_host[host] *= 0.93
            self.avg_resp_time_by_host_ts[host] = time.time()
        return self.avg_resp_time_by_host[host] or self.avg_resp_time

    @classmethod
    def set_via(cls, proxy):
        cls.VIA = proxy
        cls.DIRECT = cls('_DIRECT', 'direct -1')

    def get_via(self):
        if self.VIA == self or self.plugin_info:
            return self.DIRECT
        if self.DIRECT == self:
            return None
        return self.VIA

    def __str__(self):
        return self.name or self.short

    def __repr__(self):
        return '<ParentProxy: %s %s>' % (self.name, self.priority)


class ParentProxyList:
    def __init__(self, conf):
        self.conf = conf
        self.direct = None
        self.local = None
        self._parents = set()
        self.dict = {}

    def addstr(self, name, proxy):
        self.add(ParentProxy(name, proxy))
        self.conf.stdout('proxy')

    def add(self, parentproxy):
        assert isinstance(parentproxy, ParentProxy)
        if parentproxy.parse.scheme:
            pxy = '%s://%s:%s' % (parentproxy.parse.scheme, parentproxy.parse.hostname,
                                  parentproxy.parse.port)
        else:
            pxy = 'None'
        if parentproxy.name in self.dict:
            logger.warning('%s already in ParentProxyList, overwrite', parentproxy.name)
            self.remove(parentproxy.name)
        logger.info('add parent: %s: %s', parentproxy.name, pxy)
        if parentproxy.name not in ('_L0C4L_', ):
            self.dict[parentproxy.name] = parentproxy
        if parentproxy.name == '_D1R3CT_':
            self.direct = parentproxy
            ParentProxy.set_via(self.direct)
            if parentproxy.proxy:
                self.addstr('_L0C4L_', 'direct -1')
            return
        if parentproxy.name == '_L0C4L_':
            self.local = parentproxy
            return

        if 0 <= parentproxy.priority <= 100:
            self._parents.add(parentproxy)

    def remove(self, name):
        if name in ('_D1R3CT_', '_L0C4L_') or name not in self.dict:
            return
        if 'FWLITE:' in name:
            return
        pxy = self.dict.get(name)
        del self.dict[name]
        self._parents.discard(pxy)
        self.conf.stdout('proxy')

    def parents(self):
        return list(self._parents)

    def get(self, key):
        return self.dict.get(key)

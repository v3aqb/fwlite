#!/usr/bin/env python
# coding:utf-8

# Copyright (C) 2014-2018 v3aqb

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

import base64
import logging

from repoze.lru import lru_cache


class get_proxy:
    """docstring for parent_proxy"""
    logger = logging.getLogger('get_proxy')
    logger.setLevel(logging.INFO)
    hdr = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                                  datefmt='%H:%M:%S')
    hdr.setFormatter(formatter)
    logger.addHandler(hdr)

    def __init__(self, conf, load_local=None):
        self.conf = conf
        from .apfilter import ap_filter
        self.gfwlist = ap_filter()
        self.local = ap_filter()
        self.ignore = ap_filter()  # used by rules like "||twimg.com auto"
        self.china_ip_list = []

        if load_local is not None:
            iter_ = load_local
        else:
            iter_ = open(self.conf.local_path)
        for line in iter_:
            if line.startswith('!'):
                continue
            rule, _, dest = line.strip().partition(' ')
            if dest:  # |http://www.google.com/url forcehttps
                self.add_redirect(rule, dest)
            else:
                self.add_temp(line)

    def load(self, gfwlist=None, china_ip_list=None):
        if self.conf.rproxy:
            return

        self.load_gfwlist(gfwlist)
        self.load_china_ip_list(china_ip_list)

    def load_gfwlist(self, gfwlist):
        self.logger.info('loading gfwlist...')
        from .apfilter import ap_filter
        self.gfwlist = ap_filter()
        if gfwlist is not None:
            for line in gfwlist:
                self.gfwlist.add(line)
        else:
            try:
                with open(self.conf.gfwlist_path) as f:
                    data = f.read()
                    if '!' not in data:
                        data = ''.join(data.split())
                        data = base64.b64decode(data).decode()
                    for line in data.splitlines():
                        self.gfwlist.add(line)
            except Exception as e:
                self.logger.warning('gfwlist is corrupted! %r', e)

        dns_server_list = [
            # google
            '8.8.8.8',
            '8.8.4.4',
            # OpenDNS
            '208.67.222.222',
            '208.67.220.220',
            '208.67.222.123',
            '208.67.220.123',
            # Norton DNS
            '198.153.192.1',
            '198.153.194.1',
            # Verisign
            '64.6.64.6',
            '64.6.65.6',
            # Comodo
            '8.26.56.26',
            '8.20.247.20',
            # Cloudflare
            '1.1.1.1',
            '1.0.0.1',
        ]

        for dns_server in dns_server_list:
            self.gfwlist.add('||' + dns_server)

    def load_china_ip_list(self, china_ip_list):
        self.logger.info('loading china_ip_list.txt...')
        self.china_ip_list = []
        from ipaddress import ip_network
        if china_ip_list is not None:
            for ipn_ in china_ip_list:
                ipn = ip_network(ipn_)
                self.china_ip_list.append(ipn)
        else:
            with open(self.conf.china_ip_path) as f:
                for line in f:
                    if line:
                        ipn = ip_network(line.strip())
                        self.china_ip_list.append(ipn)
        self.china_ip_list = sorted(self.china_ip_list, key=lambda ipn: ipn.network_address)

    def redirect(self, hdlr):
        return self.conf.REDIRECTOR.redirect(hdlr)

    def add_redirect(self, rule, dest):
        return self.conf.REDIRECTOR.add_redirect(rule, dest, self)

    def bad302(self, uri):
        return self.conf.REDIRECTOR.bad302(uri)

    def add_ignore(self, rule):
        '''called by redirector'''
        from .apfilter import ap_rule
        self.ignore.add(ap_rule(rule))

    @lru_cache(1024)
    def ip_in_china(self, host, ip):
        def binary_search(arr, hkey):
            if not arr:
                return 0
            start = 0
            end = len(arr) - 1
            while start <= end:
                mid = start + (end - start) // 2

                if arr[mid].network_address < hkey:
                    start = mid + 1
                elif arr[mid].network_address > hkey:
                    end = mid - 1
                else:
                    return mid
            return start

        if ip.version == 6:
            # TODO: ipv6 support
            return None

        index = binary_search(self.china_ip_list, ip)
        if index == 0:
            return False
        if ip in self.china_ip_list[index - 1]:
            self.logger.info('%s in china', host)
            return True
        return False

    def isgfwed_resolver(self, host, uri=None):
        if not uri:
            uri = 'http://%s/' % host
        result = self.local.match(uri, host)
        if result is not None:
            return result

        if self.ignore.match(uri, host):
            return None

        if self.conf.gfwlist_enable and self.gfwlist.match(uri, host):
            return True
        return None

    def isgfwed(self, uri, host, port, ip, level=1):
        if level == 0:
            return False

        if self.conf.rproxy:
            return None

        if int(ip) == 0:
            return True

        if ip.is_loopback:
            return False

        if level == 5:
            return True

        if int(ip) and ip.is_private:
            return False

        if level == 4:
            return True

        result = self.local.match(uri, host)
        if result is not None:
            return result

        if self.ignore.match(uri, host):
            return None

        if self.conf.gfwlist_enable and\
                uri.startswith('http://') and\
                self.gfwlist.match('http://%s/' % host, host):
            return True

        if self.ip_in_china(host, ip):
            return None

        if level == 2 and uri.startswith('http://'):
            return True

        if level == 3:
            return True

        if self.conf.HOSTS.get(host):
            return None

        if self.conf.gfwlist_enable and self.gfwlist.match(uri, host):
            return True
        return None

    def get_proxy(self, uri, host, command, ip, level=1):
        '''
            decide which parentproxy to use.
            url:  'www.google.com:443'
                  'http://www.inxian.com'
            host: ('www.google.com', 443)
            level: 0 -- direct
                   1 -- auto:        proxy if local_rule, direct if ip in china or override, proxy if gfwlist
                   2 -- encrypt all: proxy if local_rule, direct if ip in china or override, proxy if gfwlist or not https
                   3 -- chnroute:    proxy if local_rule, direct if ip in china or override, proxy for all
                   4 -- global:      proxy if not local
                   5 -- global:      proxy if not localhost
        '''
        host, port = host

        gfwed = self.isgfwed(uri, host, port, ip, level)

        if gfwed is False:
            if ip and ip.is_private:
                return [self.conf.parentlist.local or self.conf.parentlist.direct]
            return [self.conf.parentlist.direct]

        parentlist = self.conf.parentlist.parents()

        def priority(parent):
            return parent.get_priority(command, host)

        if len(parentlist) > 1:
            # random.shuffle(parentlist)
            parentlist = sorted(parentlist, key=priority)

        if gfwed:
            if not parentlist:
                self.logger.warning('No parent proxy available.')
                return []
        else:
            parentlist.insert(0, self.conf.parentlist.direct)

        if len(parentlist) > self.conf.maxretry + 1:
            parentlist = parentlist[:self.conf.maxretry + 1]
        return parentlist

    def notify(self, command, url, requesthost, success, failed_parents, current_parent):
        self.logger.debug('notify: %s %s %s, failed_parents: %r, final: %s', command, url, 'Success' if success else 'Failed', failed_parents, current_parent or 'None')
        failed_parents = [k for k in failed_parents if 'pooled' not in k]
        if success:
            if '_D1R3CT_' in failed_parents:
                rule = '||%s' % requesthost[0]
                if rule not in self.local.rules:
                    resp_time = self.conf.parentlist.direct.get_avg_resp_time(requesthost[0])
                    exp = pow(resp_time, 2.5) if resp_time > 1 else 1
                    self.add_temp(rule, min(exp, 60))

    def add_temp(self, rule, exp=None):
        # add temp rule for &exp minutes
        rule = rule.strip()
        if rule not in self.local.rules:
            self.local.add(rule, (exp * 60) if exp else None)
            self.logger.info('add autoproxy rule: %s%s', rule, (' expire in %.1f min' % exp) if exp else '')
            self.conf.stdout('local')

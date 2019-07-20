#!/usr/bin/env python
# -*- coding: UTF-8 -*-

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


from __future__ import print_function, division

import sys
import re
import time
from threading import Thread
from collections import defaultdict
import urllib.parse
import logging

from .util import parse_hostport

logger = logging.getLogger('apfilter')


def set_logger():
    logger.setLevel(logging.INFO)
    hdr = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                                  datefmt='%H:%M:%S')
    hdr.setFormatter(formatter)
    logger.addHandler(hdr)


set_logger()


class ExpiredError(Exception):
    def __init__(self, rule):
        self.rule = rule
        super().__init__()


class ap_rule(object):

    def __init__(self, rule, msg=None, expire=None):
        super(ap_rule, self).__init__()
        self.rule = rule.strip()
        if len(self.rule) < 3 or self.rule.startswith(('!', '[')) or '#' in self.rule or ' ' in self.rule:
            raise ValueError("invalid abp_rule: %s" % self.rule)
        self.msg = msg
        self.expire = expire
        self.override = self.rule.startswith('@@')
        self._regex = self._parse()

    def _parse(self):
        def parse(rule):
            if rule.startswith('||'):
                regex = rule.replace('.', r'\.').replace('/', '').replace('*', '[^/]*').replace('||', r'^(?:https?://)?(?:[^/]+\.)?') + r'(?:[:/]|$)'
                return re.compile(regex)
            if rule.startswith('/') and rule.endswith('/'):
                return re.compile(rule[1:-1])
            if rule.startswith('|https://'):
                index = rule.find('/', 9)
                regex = rule[9:] if index == -1 else rule[9:index]
                regex = r'^(?:https://)?%s(?:[:/])' % regex.replace('.', r'\.').replace('*', '[^/]*')
                return re.compile(regex)

            regex = rule.replace('.', r'\.').replace('?', r'\?').replace('*', '.*').replace('^', r'[\/:]')
            regex = re.sub(r'^\|', r'^', regex)
            regex = re.sub(r'\|$', r'$', regex)
            if not rule.startswith(('|', 'http://')):
                regex = re.sub(r'^', r'^http://.*', regex)
            return re.compile(regex)

        return parse(self.rule[2:]) if self.override else parse(self.rule)

    def match(self, uri):
        if self.expire and self.expire < time.time():
            raise ExpiredError(self)
        return self._regex.search(uri)

    def __repr__(self):
        if self.expire:
            return '<ap_rule: %s exp @ %s>' % (self.rule, self.expire)
        return '<ap_rule: %s>' % self.rule


class ap_filter(object):
    KEYLEN = 6

    def __init__(self, lst=None):
        self.excludes = []
        self.slow = []
        self.domains = set()
        self.exclude_domains = set()
        self.url_startswith = tuple()
        self.fast = defaultdict(list)
        self.rules = set()
        self.expire = {}
        if lst:
            for rule in lst:
                self.add(rule)

    def add(self, rule, expire=None):
        rule = rule.strip()
        if len(rule) < 3 or rule.startswith(('!', '[')) or '#' in rule:
            return
        if rule in self.rules:
            logger.warning('%s already in filter', rule)
            return
        if '||' in rule and '/' in rule[:-1]:
            self.add(rule.replace('||', '|http://'))
            return
        if rule.startswith('||') and '*' not in rule:
            self._add_domain(rule)
        elif rule.startswith('@@||') and '*' not in rule:
            self._add_exclude_domain(rule)
        elif rule.startswith(('|https://', '@', '/')):
            self._add_slow(rule)
        elif rule.startswith('|http://') and any(len(s) > (self.KEYLEN) for s in rule.split('*')):
            self._add_fast(rule)
        elif rule.startswith('|http://') and '*' not in rule:
            self._add_urlstartswith(rule)
        elif any(len(s) > (self.KEYLEN) for s in rule.split('*')):
            self._add_fast(rule)
        else:
            self._add_slow(rule)
        self.rules.add(rule)
        self.expire[rule] = expire
        if expire:
            Thread(target=self.remove, args=(rule, expire)).start()

    def _add_urlstartswith(self, rule):
        temp = set(self.url_startswith)
        temp.add(rule[1:])
        self.url_startswith = tuple(temp)

    def _add_fast(self, rule):
        rule_t = rule[1:] if rule.startswith('|') else rule
        lst = [s for s in rule_t.split('*') if len(s) > self.KEYLEN]
        rule_o = ap_rule(rule)
        key = lst[-1][self.KEYLEN * -1:]
        self.fast[key].append(rule_o)

    def _add_slow(self, rule):
        rule_o = ap_rule(rule)
        lst = self.excludes if rule_o.override else self.slow
        lst.append(rule_o)

    def _add_exclude_domain(self, rule):
        rule = rule.rstrip('/^')
        self.exclude_domains.add(rule[4:])

    def _add_domain(self, rule):
        rule = rule.rstrip('/^')
        self.domains.add(rule[2:])

    def match(self, url, host=None, domain_only=False):
        if host is None:
            if '://' in url:
                host = urllib.parse.urlparse(url).hostname
            else:  # www.google.com:443
                host = parse_hostport(url)[0]
        if '://' not in url:
            url = 'https://%s/' % host
        if self._listmatch(self.excludes, url):
            return False
        if self._domainmatch(host) is not None:
            return self._domainmatch(host)
        if domain_only:
            return None
        if url.startswith(self.url_startswith):
            return True
        if self._fastmatch(url):
            return True
        if self._listmatch(self.slow, url):
            return True
        return None

    def _domainmatch(self, host):
        lst = ['.'.join(host.split('.')[i:]) for i in range(len(host.split('.')))]
        if any(host in self.exclude_domains for host in lst):
            return False
        if any(host in self.domains for host in lst):
            return True
        return None

    def _fastmatch(self, url):
        if url.startswith('http://'):
            i, j = 0, self.KEYLEN
            while j <= len(url):
                key = url[i:j]
                if key in self.fast:
                    if self._listmatch(self.fast[key], url):
                        return True
                i, j = i + 1, j + 1
        return None

    @staticmethod
    def _listmatch(lst, url):
        return any(r.match(url) for r in lst)

    def remove(self, rule, delay=None):
        if delay:
            time.sleep(delay)
        if rule not in self.rules:
            return
        if rule.startswith('||') and '*' not in rule:
            rule = rule.rstrip('/')
            self.domains.discard(rule[2:])
        elif rule.startswith('@@||') and '*' not in rule:
            rule = rule.rstrip('/')
            self.exclude_domains.discard(rule[4:])
        elif rule.startswith(('|https://', '@', '/')):
            lst = self.excludes if rule.startswith('@') else self.slow
            for rule_o in lst[:]:
                if rule_o.rule == rule:
                    lst.remove(rule_o)
                    break
        elif rule.startswith('|http://') and any(len(s) > (self.KEYLEN) for s in rule[1:].split('*')):
            rule_t = rule[1:]
            lst = [s for s in rule_t.split('*') if len(s) > self.KEYLEN]
            key = lst[-1][self.KEYLEN * -1:]
            for rule_o in self.fast[key][:]:
                if rule_o.rule == rule:
                    self.fast[key].remove(rule_o)
                    if not self.fast[key]:
                        del self.fast[key]
                    break
        elif rule.startswith('|http://') and '*' not in rule:
            temp = set(self.url_startswith)
            temp.discard(rule[1:])
            self.url_startswith = tuple(temp)
        elif any(len(s) > (self.KEYLEN) for s in rule.split('*')):
            lst = [s for s in rule.split('*') if len(s) > self.KEYLEN]
            key = lst[-1][self.KEYLEN * -1:]
            for rule_o in self.fast[key][:]:
                if rule_o.rule == rule:
                    self.fast[key].remove(rule_o)
                    if not self.fast[key]:
                        del self.fast[key]
                    break
        else:
            lst = self.excludes if rule.startswith('@') else self.slow
            for rule_o in lst[:]:
                if rule_o.rule == rule:
                    lst.remove(rule_o)
                    break
        self.rules.discard(rule)
        del self.expire[rule]
        if '-GUI' in sys.argv:
            sys.stdout.write('local\n')
            sys.stdout.flush()


def test():
    gfwlist = ap_filter()
    t = time.clock()
    with open('gfwlist.txt') as f:
        data = f.read()
        if '!' not in data:
            import base64
            data = ''.join(data.split())
            data = base64.b64decode(data).decode()
        for line in data.splitlines():
            # if line.startswith('||'):
            try:
                gfwlist.add(line)
            except Exception:
                pass
        del data
    print('loading: %fs' % (time.clock() - t))
    print('result for inxian: %r' % gfwlist.match('http://www.inxian.com', 'www.inxian.com'))
    print('result for twitter: %r' % gfwlist.match('twitter.com:443', 'twitter.com'))
    print('result for 163: %r' % gfwlist.match('http://www.163.com', 'www.163.com'))
    print('result for alipay: %r' % gfwlist.match('www.alipay.com:443', 'www.alipay.com'))
    print('result for qq: %r' % gfwlist.match('http://www.qq.com', 'www.qq.com'))
    print('result for keyword: %r' % gfwlist.match('http://www.test.com/iredmail.org', 'www.test.com'))
    print('result for url_startswith: %r' % gfwlist.match('http://itweet.net/whatever', 'itweet.net'))
    print('result for google.com.au: %r' % gfwlist.match('www.google.com.au:443', 'www.google.com.au'))
    print('result for riseup.net:443: %r' % gfwlist.match('riseup.net:443', 'riseup.net'))

    url = sys.argv[1] if len(sys.argv) > 1 else 'http://news.163.com/16/1226/18/C97U4AI50001875N.html'
    host = urllib.parse.urlparse(url).hostname
    print('%s, %s' % (url, host))
    print(gfwlist.match(url, host))
    t = time.clock()
    for _ in range(10000):
        gfwlist.match(url, host)
    print('KEYLEN = %d' % gfwlist.KEYLEN)
    print('10000 query for %s, %fs' % (url, time.clock() - t))
    print('O(1): %d' % (len(gfwlist.rules) - (len(gfwlist.excludes) + len(gfwlist.slow) + len(gfwlist.url_startswith))))
    print('O(n): %d' % (len(gfwlist.excludes) + len(gfwlist.slow) + len(gfwlist.url_startswith)))
    print('total: %d' % len(gfwlist.rules))
    fast_key_list = gfwlist.fast.keys()
    fast_key_list = sorted(fast_key_list, key=lambda x: len(gfwlist.fast[x]))
    for key in fast_key_list[-10:]:
        print('%r : %d' % (key, len(gfwlist.fast[key])))


if __name__ == "__main__":
    test()

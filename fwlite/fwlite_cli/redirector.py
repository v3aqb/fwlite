#!/usr/bin/env python
# coding: UTF-8

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

import logging

logger = logging.getLogger('redirector')


def set_logger():
    logger.setLevel(logging.INFO)
    hdr = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                                  datefmt='%H:%M:%S')
    hdr.setFormatter(formatter)
    logger.addHandler(hdr)


set_logger()


class redirector:
    def __init__(self, conf):
        from .apfilter import ap_filter
        self.conf = conf

        self._bad302 = ap_filter()
        self.reset = ap_filter()
        self.adblock = set()
        self.redirlst = []

    def redirect(self, hdlr):
        if self.reset.match(hdlr.path):
            return 'reset'
        if self.conf.adblock_enable and hdlr.request_host[0] in self.adblock:
            return 'adblock'
        for rule, result in self.redirlst:
            if rule.match(hdlr.path):
                logger.debug('Match redirect rule %s, %s', rule.rule, result)
                if rule.override:
                    break
                if result == 'forcehttps':
                    return hdlr.path.replace('http://', 'https://', 1)
                if result.startswith('/') and result.endswith('/'):
                    return rule._regex.sub(result[1:-1], hdlr.path)
                return result
        return None

    def bad302(self, uri):
        return self._bad302.match(uri)

    def add_redirect(self, rule, dest, getp=None):
        from .apfilter import ap_rule
        logger.info('add redir: %s %s', rule, dest)
        if getp is None:
            # in case GET_PROXY is initializing
            getp = self.conf.GET_PROXY
        try:
            if rule in [a.rule for a, b in self.redirlst]:
                logger.warning('multiple redirector rule! %s', rule)
                return
            if dest.lower() == 'auto':
                getp.add_ignore(rule)
                return
            if dest.lower() == 'bad302':
                self._bad302.add(rule)
                return
            if dest.lower() == 'reset':
                self.reset.add(rule)
                return
            if dest.lower() == 'adblock':
                self.adblock.add(rule)
                return
            self.redirlst.append((ap_rule(rule), dest))
        except ValueError as err:
            logger.error('add redirect rule failed: %s', err)

    def load(self, adblock=None):
        logger.info('loading adblock.txt')
        if adblock is not None:
            iter_ = adblock
        else:
            iter_ = open(self.conf.adblock_path)
        for line in iter_:
            if not line.strip():
                continue
            if line.startswith('#'):
                continue
            if 'loopback' in line:
                continue
            if 'localhost' in line:
                continue
            if " " in line:
                # "127.0.0.1 114so.cn\r\n"
                _, _, host = line.strip().partition(' ')
            else:
                host = line.strip()
            self.adblock.add(host)

    def list(self):
        result = []
        for rule, dst in self.redirlst:
            result.append('%s %s' % (rule.rule, dst))
        for rule in self.reset.rules:
            result.append('%s reset' % rule)
        return result

    def remove(self, redir_rule):
        logger.info('remove redir: %s', redir_rule)
        rule, _, dst = redir_rule.partition(' ')
        if dst == 'reset':
            self.reset.remove(rule)
            return

        target = None
        for _rule, _dst in self.redirlst:
            if _rule.rule == rule and _dst == dst:
                target = (_rule, _dst)
                break
        if target:
            self.redirlst.remove(target)
            return
        raise ValueError('rule not exist')

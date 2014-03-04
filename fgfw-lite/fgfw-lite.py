#!/usr/bin/env python2.7
#-*- coding: UTF-8 -*-
#
# FGFW_Lite.py A Proxy Server help go around the Great Firewall
#
# Copyright (C) 2012-2013 Jiang Chao <sgzz.cj@gmail.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, see <http://www.gnu.org/licenses>.

from __future__ import print_function, unicode_literals, division

__version__ = '0.4.0.0'

import sys
import os
import glob
sys.path.append(os.path.dirname(os.path.abspath(__file__).replace('\\', '/')))
sys.path += glob.glob('%s/*.egg' % os.path.dirname(os.path.abspath(__file__)))
from collections import defaultdict
import subprocess
import shlex
import time
import re
import errno
import atexit
import platform
import base64
import ftplib
import select
import socket
import struct
from threading import Thread
import urllib2
import urlparse
import pygeoip
from repoze.lru import lru_cache
try:
    from concurrent.futures import ThreadPoolExecutor
except ImportError:
    ThreadPoolExecutor = None
from SocketServer import ThreadingMixIn
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
try:
    import configparser
except ImportError:
    import ConfigParser as configparser
configparser.RawConfigParser.OPTCRE = re.compile(r'(?P<option>[^=\s][^=]*)\s*(?P<vi>[=])\s*(?P<value>.*)$')

import logging
logging.basicConfig(level=logging.INFO,
                    format='FGFW-Lite %(asctime)s %(levelname)s %(message)s',
                    datefmt='%H:%M:%S', filemode='a+')

WORKINGDIR = '/'.join(os.path.dirname(os.path.abspath(__file__).replace('\\', '/')).split('/')[:-1])
if ' ' in WORKINGDIR:
    logging.error('no spacebar allowed in path')
    sys.exit()
os.chdir(WORKINGDIR)

if sys.platform.startswith('win'):
    PYTHON2 = '%s/Python27/python27.exe' % WORKINGDIR
else:
    for cmd in ('python2.7', 'python27', 'python2'):
        if subprocess.call(shlex.split('which %s' % cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0:
            PYTHON2 = cmd
            break

UPSTREAM_POOL = defaultdict(list)
HOSTS = defaultdict(list)
ctimer = []
rtimer = []
CTIMEOUT = 5
RTIMEOUT = 5


def prestart():
    print('FGFW_Lite %s' % __version__)

    if not os.path.isfile('./userconf.ini'):
        with open('./userconf.ini', 'w') as f:
            f.write(open('./userconf.sample.ini').read())

    if not os.path.isfile('./fgfw-lite/local.txt'):
        with open('./fgfw-lite/local.txt', 'w') as f:
            f.write('! local gfwlist config\n! rules: https://autoproxy.org/zh-CN/Rules\n')

    for item in ['./userconf.ini', './fgfw-lite/local.txt']:
        with open(item) as f:
            data = open(item).read()
        with open(item, 'w') as f:
            f.write(data)
prestart()


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    pass


class HTTPRequestHandler(BaseHTTPRequestHandler):

    def redirect(self, url):
        self.send_response(302)
        self.send_header("Location", url)
        self.end_headers()

    def handle_expect_100(self):
        """Decide what to do with an "Expect: 100-continue" header.

        If the client is expecting a 100 Continue response, we must
        respond with either a 100 Continue or a final response before
        waiting for the request body. The default is to always respond
        with a 100 Continue. You can behave differently (for example,
        reject unauthorized requests) by overriding this method.

        This method should either return True (possibly after sending
        a 100 Continue response) or send an error response and return
        False.

        """
        return True


class ProxyHandler(HTTPRequestHandler):
    server_version = "HTTPProxy/" + __version__
    protocol = "HTTP/1.1"
    rbufsize = 0  # self.rfile Be unbuffered
    timeout = 10
    allowed_clients = ()
    LOCALHOST = ('127.0.0.1', '::1', 'localhost')

    def handle(self):
        ip, port = self.client_address
        logging.debug("Request from %s" % ip)
        if self.allowed_clients and ip not in self.allowed_clients:
            self.raw_requestline = self.rfile.readline()
            if self.parse_request():
                self.send_error(403)
        else:
            BaseHTTPRequestHandler.handle(self)

    def _getparent(self, level=1):
        if not self._proxylist:
            self._proxylist = PARENT_PROXY.parentproxy(self.path, self.headers['Host'].rsplit(':', 1)[0], level)
        self.ppname = self._proxylist.pop(0)
        self.pproxy = conf.parentdict.get(self.ppname)
        self.pproxyparse = urlparse.urlparse(self.pproxy)
        logging.info('{} {} via {}'.format(self.command, self.path, self.ppname))

    def getparent(self, level=1):
        self._getparent(level)

    def do_GET(self):
        if self.path.lower().startswith('ftp://'):
            return self.do_FTP()
        # transparent proxy
        if self.path.startswith('/') and 'Host' in self.headers:
            self.request.uri = 'http://%s%s' % (self.headers['Host'], self.path)
        if self.path.startswith('/'):
            self.send_error(403)
            return
        # redirector
        new_url = REDIRECTOR.get(self.path)
        if new_url:
            logging.info('redirecting to %s' % new_url)
            if new_url.startswith('403'):
                self.send_error(403)
            else:
                self.redirect(new_url)
            return

        # try to get host from uri
        if 'Host' not in self.headers:
            self.headers['Host'] = self.path.split('/')[2] if '//' in self.path else self.path

        if any(host == self.headers['Host'].rsplit(':', 1)[0] for host in self.LOCALHOST):
            self.send_error(403)
            return
        self._proxylist = []
        self.getparent()
        try:
            soc = self._connect_via_proxy(self.headers['Host'])
        except Exception as e:
            logging.warning(e)
            return
        try:
            if self.pproxy.startswith('http'):
                s = '%s %s %s\r\n' % (self.command, self.path, self.request_version)
            else:
                s = '%s /%s %s\r\n' % (self.command, '/'.join(self.path.split('/')[3:]), self.request_version)
            self.headers['Connection'] = 'close'
            del self.headers['Proxy-Connection']
            for key_val in self.headers.items():
                s += "%s: %s\r\n" % key_val
            s += "\r\n"
            soc.sendall(s)
            self._read_write(soc)
        finally:
            soc.close()
            self.connection.close()

    do_OPTIONS = do_POST = do_DELETE = do_TRACE = do_HEAD = do_PUT = do_GET

    def do_CONNECT(self):
        self._proxylist = []
        self.getparent()
        try:
            soc = self._connect_via_proxy(self.path)
        except Exception as e:
            logging.warning(e)
            return
        try:
            if not self.pproxy.startswith('http'):
                self.wfile.write(self.protocol_version +
                                 " 200 Connection established\r\n")
                self.wfile.write("Proxy-agent: %s\r\n" % self.version_string())
                self.wfile.write("\r\n")
            else:
                s = [b'%s %s %s\r\n' % (self.command, self.path, self.request_version), ]
                s.append(b'\r\n'.join(['%s: %s' % (key, value) for key, value in self.headers.items()]))
                s.append(b'\r\n\r\n')
                soc.sendall(b''.join(s))
            self._read_write(soc, 300)
        finally:
            soc.close()
            self.connection.close()

    def _connect_via_proxy(self, netloc):
        if ':' in netloc:
            host, port = netloc.rsplit(':', 1)
        else:
            host, port = netloc, 80
        logging.debug("Connect to %s:%s" % (host, port))
        if not self.pproxy:
            return socket.create_connection((host, int(port)))
        elif self.pproxy.startswith('http://'):
            return socket.create_connection((self.pproxyparse.hostname, self.pproxyparse.port))

    def _read_write(self, soc, max_idling=20):
        iw = [self.connection, soc]
        ow = []
        count = 0
        while True:
            try:
                count += 1
                (ins, _, exs) = select.select(iw, ow, iw, 1)
                if exs:
                    break
                if ins:
                    for i in ins:
                        out = self.connection if i is soc else soc
                        data = i.recv(4096)
                        if data:
                            out.sendall(data)
                            count = 0
                        else:
                            break
                if count > max_idling:
                    break
            except socket.error as e:
                logging.debug('socket error: %s' % e)

    def handle_one_request(self):
        try:
            BaseHTTPRequestHandler.handle_one_request(self)
        except socket.error, e:
            if e.errno == errno.ECONNRESET:
                pass  # ignore the error
            else:
                raise

    def do_FTP(self):
        # fish out user and password information
        scm, netloc, path, params, query, fragment = urlparse.urlparse(
            self.path, 'http')
        if '@' in netloc:
            login_info, netloc = netloc.split('@', 1)
            try:
                user, passwd = login_info.split(':', 1)
            except ValueError:
                user, passwd = "anonymous", None
        else:
            user, passwd = "anonymous", None
        try:
            ftp = ftplib.FTP(netloc)
            ftp.login(user, passwd)
            if self.command == "GET":
                ftp.retrbinary("RETR %s" % path, self.connection.send)
            ftp.quit()
        except Exception as e:
            logging.warning("FTP Exception: %s" % e)


class ExpiredError(Exception):
    pass


class autoproxy_rule(object):
    def __init__(self, arg, expire=None):
        super(autoproxy_rule, self).__init__()
        if not isinstance(arg, str):
            arg = str(arg)
        self.rule = arg.strip()
        if len(self.rule) < 3 or self.rule.startswith('!') or self.rule.startswith('[') or '#' in self.rule:
            raise TypeError("invalid autoproxy_rule: %s" % self.rule)
        self.expire = expire
        self._ptrn = self._autopxy_rule_parse(self.rule)

    def _autopxy_rule_parse(self, rule):
        def parse(rule):
            if rule.startswith('||'):
                regex = rule.replace('.', r'\.').replace('?', r'\?').replace('/', '').replace('*', '[^/]*').replace('^', r'[^\w%._-]').replace('||', '^(?:https?://)?(?:[^/]+\.)?') + r'(?:[:/]|$)'
                return re.compile(regex)
            elif rule.startswith('/') and rule.endswith('/'):
                return re.compile(rule[1:-1])
            elif rule.startswith('|https://'):
                i = rule.find('/', 9)
                regex = rule[9:] if i == -1 else rule[9:i]
                regex = r'^(?:https://)?%s(?:[:/])' % regex.replace('.', r'\.').replace('*', '[^/]*')
                return re.compile(regex)
            else:
                regex = rule.replace('.', r'\.').replace('?', r'\?').replace('*', '.*').replace('^', r'[^\w%._-]')
                regex = re.sub(r'^\|', r'^', regex)
                regex = re.sub(r'\|$', r'$', regex)
                if not rule.startswith('|'):
                    regex = re.sub(r'^', r'^http://.*', regex)
                return re.compile(regex)

        if rule.startswith('@@'):
            self.override = True
            return parse(rule[2:])
        else:
            self.override = False
            return parse(rule)

    def match(self, uri):
        if self.expire and self.expire < time.time():
            raise ExpiredError
        return self._ptrn.search(uri)


class redirector(object):
    """docstring for redirector"""
    def __init__(self):
        self.lst = []

    def get(self, uri, host=None):
        searchword = re.match(r'^http://([\w-]+)/$', uri)
        if searchword:
            q = searchword.group(1)
            if 'xn--' in q:
                q = q.decode('idna')
            logging.debug('Match redirect rule addressbar-search')
            return 'https://www.google.com/search?q=%s&ie=utf-8&oe=utf-8&aq=t&rls=org.mozilla:zh-CN:official' % urllib2.quote(q.encode('utf-8'))
        for rule, result in self.lst:
            if rule.match(uri):
                logging.debug('Match redirect rule {}, {}'.format(rule.rule, result))
                if rule.override:
                    return None
                if result == 'forcehttps':
                    return uri.replace('http://', 'https://', 1)
                if result.startswith('/') and result.endswith('/'):
                    return rule._ptrn.sub(result[1:-1], uri)
                return result

REDIRECTOR = redirector()


def ip_from_string(ip):
    # https://github.com/fqrouter/fqsocks/blob/master/fqsocks/china_ip.py#L35
    return struct.unpack(b'!i', socket.inet_aton(ip))[0]


class parent_proxy(object):
    """docstring for parent_proxy"""
    def config(self):
        self.gfwlist = []
        self.override = []
        self.gfwlist_force = []
        self.localnet = []
        self.temp_rules = set()
        REDIRECTOR.lst = []

        def add_rule(line, force=False):
            line = line.strip()
            if len(line.split()) == 2:  # |http://www.google.com/url forcehttps
                try:
                    rule, result = line.split()
                    REDIRECTOR.lst.append((autoproxy_rule(rule), result))
                except TypeError as e:
                    logging.debug('create autoproxy rule failed: %s' % e)
            else:
                try:
                    o = autoproxy_rule(line)
                except TypeError as e:
                    logging.debug('create autoproxy rule failed: %s' % e)
                else:
                    if o.override:
                        self.override.append(o)
                    elif force:
                        self.gfwlist_force.append(o)
                    else:
                        self.gfwlist.append(o)

        for line in open('./fgfw-lite/local.txt'):
            add_rule(line, force=True)

        for line in open('./fgfw-lite/cloud.txt'):
            add_rule(line, force=True)

        with open('./fgfw-lite/gfwlist.txt') as f:
            try:
                data = ''.join(f.read().split())
                if len(data) % 4:
                    data += '=' * (4 - len(data) % 4)
                for line in base64.b64decode(data).splitlines():
                    add_rule(line)
            except TypeError:
                logging.warning('./fgfw-lite/gfwlist.txt is corrupted!')

        self.localnet.append((ip_from_string('192.168.0.0'), ip_from_string('192.168.0.0') + 2 ** (32 - 16)))
        self.localnet.append((ip_from_string('172.16.0.0'), ip_from_string('172.16.0.0') + 2 ** (32 - 12)))
        self.localnet.append((ip_from_string('10.0.0.0'), ip_from_string('10.0.0.0') + 2 ** (32 - 8)))
        self.localnet.append((ip_from_string('127.0.0.0'), ip_from_string('127.0.0.0') + 2 ** (32 - 8)))

        self.geoip = pygeoip.GeoIP('./fgfw-lite/GeoIP.dat')

    @lru_cache(256, timeout=120)
    def ifhost_in_local(self, host):
        try:
            i = ip_from_string(socket.gethostbyname(host))
            if any(a[0] <= i < a[1] for a in self.localnet):
                return True
            return False
        except socket.error:
            return None

    @lru_cache(256, timeout=120)
    def ifhost_in_china(self, host):
        try:
            if self.geoip.country_name_by_name(host) in ('China', ):
                logging.info('%s in china' % host)
                return True
            return False
        except socket.error:
            return None

    def if_gfwlist_force(self, uri, level):
        if level == 3:
            return True
        for rule in self.gfwlist_force:
            try:
                if rule.match(uri):
                    return True
            except ExpiredError:
                logging.info('%s expired' % rule.rule)
                self.gfwlist_force.remove(rule)
                self.temp_rules.discard(rule.rule)
        return False

    def gfwlist_match(self, uri):
        for i, rule in enumerate(self.gfwlist):
            if rule.match(uri):
                if i > 300:
                    self.gfwlist.insert(0, self.gfwlist.pop(i))
                return True

    def ifgfwed(self, uri, host, level=1):

        if level == 0:
            return False
        elif level == 2:
            forceproxy = True
        else:
            forceproxy = False

        gfwlist_force = self.if_gfwlist_force(uri, level)

        if self.ifhost_in_local(host):
            return False

        if any(rule.match(uri) for rule in self.override):
            return None

        if not gfwlist_force and (HOSTS.get(host) or self.ifhost_in_china(host)):
            return None

        if gfwlist_force or forceproxy or self.gfwlist_match(uri):
            return True

    @lru_cache(256, timeout=120)
    def no_goagent(self, uri):
        r = re.match(r'^([^/]+):\d+$', uri)
        s = set(conf.parentlist) - set(['goagent', 'goagent-php', 'direct', 'local'])
        if r and s:
            if r.groups()[0] in ['play.google.com', 'ssl.gstatic.com', 'mail-attachment.googleusercontent.com', 'webcache.googleusercontent.com', 's1.googleusercontent.com', 's2.googleusercontent.com', 'images1-focus-opensocial.googleusercontent.com', 'images2-focus-opensocial.googleusercontent.com', 'images3-focus-opensocial.googleusercontent.com', 'lh0.googleusercontent.com', 'lh1.googleusercontent.com', 'lh2.googleusercontent.com', 'lh3.googleusercontent.com', 'lh4.googleusercontent.com', 'lh5.googleusercontent.com', 'lh6.googleusercontent.com', 'lh7.googleusercontent.com', 'lh8.googleusercontent.com', 'lh9.googleusercontent.com', 'lh10.googleusercontent.com', 'lh11.googleusercontent.com', 'lh12.googleusercontent.com']:
                return True
            if any(r.groups()[0].endswith(path) for path in ['.google.com', '.google.com.hk', '.googleapis.com', '.android.com', '.appspot.com', '.googlegroups.com', '.googlesource.com', '.googleusercontent.com', '.google-analytics.com', '.googlecode.com', '.gstatic.com']):
                return False
            return True

    def parentproxy(self, uri, host, level=1):
        '''
            decide which parentproxy to use.
            url:  'https://www.google.com'
            host: 'www.google.com'
            level: 0 -- direct
                   1 -- proxy if force, direct if ip in china or override, proxy if gfwlist
                   2 -- proxy if force, direct if ip in china or override, proxy if all
                   3 -- proxy if not override
        '''

        f = self.ifgfwed(uri, host, level)
        parentlist = conf.parentlist[:]
        if self.no_goagent(uri):
            if 'goagent' in parentlist:
                parentlist.remove('goagent')
            if 'goagent-php' in parentlist:
                parentlist.remove('goagent-php')

        if f is False:
            return ['direct']
        if f is True:
            parentlist.remove('direct')
            if parentlist:
                return parentlist
            else:
                logging.warning('No parent proxy available, direct connection is used')
                return ['direct']
        return parentlist

    def add_temp_rule(self, rule):
        if rule not in self.temp_rules:
            logging.info('add autoproxy rule: %s' % rule)
            self.gfwlist_force.append(autoproxy_rule(rule, expire=time.time() + 60 * 10))
            self.temp_rules.add(rule)

PARENT_PROXY = parent_proxy()
PARENT_PROXY.config()


def updater():
    while 1:
        time.sleep(30)
        if conf.userconf.dgetbool('FGFW_Lite', 'autoupdate'):
            lastupdate = conf.version.dgetfloat('Update', 'LastUpdate', 0)
            if time.time() - lastupdate > conf.UPDATE_INTV * 60 * 60:
                update(auto=True)
        global CTIMEOUT, ctimer, RTIMEOUT, rtimer
        if ctimer:
            logging.info('max connection time: %ss in %s' % (max(ctimer), len(ctimer)))
            CTIMEOUT = (min(max(3, max(ctimer) * 5), 15) * 2 + RTIMEOUT) / 3
            logging.info('conn timeout set to: %s' % CTIMEOUT)
            ctimer = []
        if rtimer:
            logging.info('max read time: %ss in %s' % (max(rtimer), len(rtimer)))
            RTIMEOUT = max((min(max(4, max(rtimer) * 10), 15) * 2 + RTIMEOUT) / 3, CTIMEOUT)
            logging.info('read timeout set to: %s' % RTIMEOUT)
            rtimer = []


def update(auto=False):
    conf.version.set('Update', 'LastUpdate', str(time.time()))
    for item in FGFWProxyHandler.ITEMS:
        if item.enableupdate:
            item.update()
    restart()


def restart():
    conf.confsave()
    for item in FGFWProxyHandler.ITEMS:
        item.config()
        item.restart()
    PARENT_PROXY.config()


class FGFWProxyHandler(object):
    """docstring for FGFWProxyHandler"""
    ITEMS = []

    def __init__(self):
        FGFWProxyHandler.ITEMS.append(self)
        self.subpobj = None
        self.cmd = ''
        self.cwd = ''
        self.filelist = []
        self.enable = True
        self.enableupdate = True

        self.config()
        self.daemon = Thread(target=self.start)
        self.daemon.daemon = True
        self.daemon.start()

    def config(self):
        pass

    def start(self):
        while 1:
            if self.enable:
                logging.info('starting %s' % self.cmd)
                self.subpobj = subprocess.Popen(shlex.split(self.cmd), cwd=self.cwd, stdin=subprocess.PIPE)
                self.subpobj.wait()
            time.sleep(3)

    def restart(self):
        try:
            self.subpobj.terminate()
        except Exception:
            pass

    def stop(self):
        self.enable = False
        self.restart()

    def _update(self):
        self._listfileupdate()

    def update(self):
        if self.enable and self.enableupdate:
            self._update()

    def _listfileupdate(self):
        if len(self.filelist) > 0:
            for url, path in self.filelist:
                etag = conf.version.dget('Update', path.replace('./', '').replace('/', '-'), '')
                self.updateViaHTTP(url, etag, path)

    def updateViaHTTP(self, url, etag, path):
        req = urllib2.Request(url)
        req.add_header('If-None-Match', etag)
        try:
            r = urllib2.urlopen(req)
        except Exception as e:
            logging.info('{} NOT updated. Reason: {}'.format(path, e))
        else:
            data = r.read()
            if r.getcode() == 200 and data:
                with open(path, 'wb') as localfile:
                    localfile.write(data)
                conf.version.set('Update', path.replace('./', '').replace('/', '-'), r.info().getheader('ETag'))
                conf.confsave()
                logging.info('%s Updated.' % path)
            else:
                logging.info('{} NOT updated. Reason: {}'.format(path, str(r.getcode())))


class goagentHandler(FGFWProxyHandler):
    """docstring for ClassName"""
    def __init__(self):
        FGFWProxyHandler.__init__(self)

    def config(self):
        self.filelist = [('https://github.com/goagent/goagent/raw/3.0/local/proxy.py', './goagent/proxy.py'),
                         ('https://github.com/goagent/goagent/raw/3.0/local/proxy.ini', './goagent/proxy.sample.ini'),
                         ('https://github.com/goagent/goagent/raw/3.0/local/cacert.pem', './goagent/cacert.pem'),
                         ]
        self.cwd = '%s/goagent' % WORKINGDIR
        self.cmd = '{} {}/goagent/proxy.py'.format(PYTHON2, WORKINGDIR)
        self.enable = conf.userconf.dgetbool('goagent', 'enable', True)
        self.enableupdate = conf.userconf.dgetbool('goagent', 'update', True)
        t = open('%s/goagent/proxy.py' % WORKINGDIR, 'rb').read()
        with open('%s/goagent/proxy.py' % WORKINGDIR, 'wb') as f:
            f.write(t.replace(b'sys.stdout.write', b'sys.stderr.write'))
        if self.enable:
            self._config()

    def _config(self):
        goagent = SConfigParser()
        goagent.read('./goagent/proxy.sample.ini')

        if conf.userconf.dget('goagent', 'GAEAppid', 'goagent') != 'goagent':
            goagent.set('gae', 'profile', conf.userconf.dget('goagent', 'profile', 'ipv4'))
            goagent.set('gae', 'mode', conf.userconf.dget('goagent', 'mode', 'https'))
            goagent.set('gae', 'appid', conf.userconf.dget('goagent', 'GAEAppid', 'goagent'))
            goagent.set("gae", "password", conf.userconf.dget('goagent', 'GAEpassword', ''))
            goagent.set('gae', 'obfuscate', conf.userconf.dget('goagent', 'obfuscate', '0'))
            goagent.set('gae', 'validate', conf.userconf.dget('goagent', 'validate', '0'))
            goagent.set('gae', 'options', conf.userconf.dget('goagent', 'options', ''))
            conf.addparentproxy('goagent', 'http://127.0.0.1:8087')
        else:
            goagent.set('gae', 'appid', 'dummy')

        if conf.userconf.dget('goagent', 'paasfetchserver'):
            goagent.set('php', 'enable', '1')
            goagent.set('php', 'password', conf.userconf.dget('goagent', 'phppassword', '123456'))
            goagent.set('php', 'fetchserver', conf.userconf.dget('goagent', 'phpfetchserver', 'http://.com/'))
            conf.addparentproxy('goagent-php', 'http://127.0.0.1:8088')
        else:
            goagent.set('php', 'enable', '0')

        goagent.set('pac', 'enable', '0')

        if conf.userconf.dget('goagent', 'proxy'):
            goagent.set('proxy', 'enable', '1')
            host, port = conf.userconf.dget('goagent', 'proxy').rsplit(':')
            goagent.set('proxy', 'host', host)
            goagent.set('proxy', 'port', port)
        if '-hide' in sys.argv[1:]:
            goagent.set('listen', 'visible', '0')
        else:
            goagent.set('listen', 'visible', '1')

        with open('./goagent/proxy.ini', 'w') as configfile:
            goagent.write(configfile)

        if not os.path.isfile('./goagent/CA.crt'):
            self.createCA()

    def createCA(self):
        '''
        ripped from goagent 2.1.14 with modification
        '''
        import OpenSSL
        key = OpenSSL.crypto.PKey()
        key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
        ca = OpenSSL.crypto.X509()
        ca.set_serial_number(0)
        ca.set_version(2)
        subj = ca.get_subject()
        subj.countryName = 'CN'
        subj.stateOrProvinceName = 'Internet'
        subj.localityName = 'Cernet'
        subj.organizationName = 'GoAgent'
        subj.organizationalUnitName = 'GoAgent Root'
        subj.commonName = 'GoAgent CA'
        ca.gmtime_adj_notBefore(0)
        ca.gmtime_adj_notAfter(24 * 60 * 60 * 3652)
        ca.set_issuer(ca.get_subject())
        ca.set_pubkey(key)
        ca.add_extensions([
            OpenSSL.crypto.X509Extension(b'basicConstraints', True, b'CA:TRUE'),
            OpenSSL.crypto.X509Extension(b'keyUsage', False, b'keyCertSign, cRLSign'),
            OpenSSL.crypto.X509Extension(b'subjectKeyIdentifier', False, b'hash', subject=ca), ])
        ca.sign(key, 'sha1')
        with open('./goagent/CA.crt', 'wb') as fp:
            fp.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, ca))
            fp.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key))
        import shutil
        if os.path.isdir('./goagent/certs'):
            shutil.rmtree('./goagent/certs')
        self.import_ca()

    def import_ca(self):
        '''
        ripped from goagent 3.1.0
        '''
        certfile = os.path.abspath('./goagent/CA.crt')
        dirname, basename = os.path.split(certfile)
        commonname = 'GoAgent CA'
        if sys.platform.startswith('win'):
            import ctypes
            with open(certfile, 'rb') as fp:
                certdata = fp.read()
                if certdata.startswith(b'-----'):
                    begin = b'-----BEGIN CERTIFICATE-----'
                    end = b'-----END CERTIFICATE-----'
                    certdata = base64.b64decode(b''.join(certdata[certdata.find(begin) + len(begin):certdata.find(end)].strip().splitlines()))
                crypt32 = ctypes.WinDLL(b'crypt32.dll'.decode())
                store_handle = crypt32.CertOpenStore(10, 0, 0, 0x4000 | 0x10000, b'ROOT'.decode())
                if not store_handle:
                    return -1
                ret = crypt32.CertAddEncodedCertificateToStore(store_handle, 0x1, certdata, len(certdata), 4, None)
                crypt32.CertCloseStore(store_handle, 0)
                del crypt32
                return 0 if ret else -1
        elif sys.platform == 'darwin':
            return os.system(('security find-certificate -a -c "%s" | grep "%s" >/dev/null || security add-trusted-cert -d -r trustRoot -k "/Library/Keychains/System.keychain" "%s"' % (commonname, commonname, certfile.decode('utf-8'))).encode('utf-8'))
        elif sys.platform.startswith('linux'):
            platform_distname = platform.dist()[0]
            if platform_distname == 'Ubuntu':
                pemfile = "/etc/ssl/certs/%s.pem" % commonname
                new_certfile = "/usr/local/share/ca-certificates/%s.crt" % commonname
                if not os.path.exists(pemfile):
                    return os.system('cp "%s" "%s" && update-ca-certificates' % (certfile, new_certfile))
            elif any(os.path.isfile('%s/certutil' % x) for x in os.environ['PATH'].split(os.pathsep)):
                return os.system('certutil -L -d sql:$HOME/.pki/nssdb | grep "%s" || certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "%s" -i "%s"' % (commonname, commonname, certfile))
            else:
                logging.warning('please install *libnss3-tools* package to import GoAgent root ca')
        return 0


class snovaHandler(FGFWProxyHandler):
    """docstring for ClassName"""
    def __init__(self, arg=''):
        FGFWProxyHandler.__init__(self)
        self.arg = arg

    def config(self):
        self.cmd = '%s/snova/bin/start.%s' % (WORKINGDIR, 'bat' if sys.platform.startswith('win') else 'sh')
        self.cwd = '%s/snova' % WORKINGDIR
        self.enable = conf.userconf.dgetbool('snova', 'enable', False)
        self.enableupdate = False
        if self.enable:
            self._config()

    def _config(self):
        proxy = SConfigParser()
        proxy.optionxform = str
        proxy.read('./snova/conf/snova.conf')

        proxy.set('GAE', 'Enable', '0')

        worknodes = conf.userconf.get('snova', 'C4worknodes')
        if worknodes:
            worknodes = worknodes.split('|')
            for i, v in enumerate(worknodes):
                proxy.set('C4', 'WorkerNode[%s]' % i, v)
            proxy.set('C4', 'Enable', '1')
            fgfwproxy.addparentproxy('snova-c4', 'http://127.0.0.1:48102')
        else:
            proxy.set('C4', 'Enable', '0')

        proxy.set('SPAC', 'Enable', '0')
        proxy.set('Misc', 'RC4Key', conf.userconf.dget('snova', 'RC4Key', '8976501f8451f03c5c4067b47882f2e5'))
        with open('./snova/conf/snova.conf', 'w') as configfile:
            proxy.write(configfile)


class fgfwproxy(FGFWProxyHandler):
    """docstring for ClassName"""
    def __init__(self, arg=''):
        FGFWProxyHandler.__init__(self)
        self.arg = arg

    def config(self):
        self.filelist = [('https://autoproxy-gfwlist.googlecode.com/svn/trunk/gfwlist.txt', './fgfw-lite/gfwlist.txt'),
                         # ('https://github.com/v3aqb/fgfw-lite/raw/master/fgfw-lite/fgfw-lite.py', './fgfw-lite/fgfw-lite.py'),
                         ('https://github.com/v3aqb/fgfw-lite/raw/master/fgfw-lite/cloud.txt', './fgfw-lite/cloud.txt'),
                         ('https://github.com/v3aqb/fgfw-lite/raw/master/userconf.sample.ini', './userconf.sample.ini'),
                         ('https://github.com/v3aqb/fgfw-lite/raw/master/README.md', './README.md'),
                         ('https://github.com/v3aqb/fgfw-lite/raw/master/Python27/python27.zip', './Python27/python27.zip'),
                         ('https://github.com/v3aqb/fgfw-lite/raw/master/fgfw-lite/encrypt.py', './fgfw-lite/encrypt.py')
                         ]
        self.enable = conf.userconf.dgetbool('fgfwproxy', 'enable', True)
        self.enableupdate = conf.userconf.dgetbool('fgfwproxy', 'update', True)
        self.listen = conf.userconf.dget('fgfwproxy', 'listen', '8118')
        if conf.userconf.dgetbool('FGFW_Lite', 'debuginfo', False):
            logging.basicConfig(level=logging.DEBUG)

    def start(self):
        while True:
            if self.enable:
                if self.listen.isdigit():
                    port = self.listen
                    addr = '127.0.0.1'
                else:
                    addr, port = self.listen.rsplit(':', 1)
                logging.info("Starting HTTP proxy on port {}".format(port))
                self.server = ThreadingHTTPServer((addr, int(port)), ProxyHandler)
                self.server.serve_forever()
            time.sleep(3)

    def restart(self):
        try:
            self.server.shutdown()
        except Exception:
            pass

    def purge(self):
        for k, v in UPSTREAM_POOL.items():
            vcopy = v[:]
            for item in vcopy:
                if item.last_active < time.time() - 15:
                    if not item.closed():
                        item.close()
                    v.remove(item)


class SConfigParser(configparser.ConfigParser):
    """docstring for SSafeConfigParser"""
    def dget(self, section, option, default=None):
        if default is None:
            default = ''
        value = self.get(section, option)
        if not value:
            value = default
        return value

    def dgetfloat(self, section, option, default=0):
        try:
            value = self.getfloat(section, option)
        except Exception:
            value = float(default)
        return value

    def dgetint(self, section, option, default=0):
        try:
            value = self.getint(section, option)
        except Exception:
            value = int(default)
        return value

    def dgetbool(self, section, option, default=False):
        try:
            value = self.getboolean(section, option)
        except Exception:
            value = bool(default)
        return value

    def get(self, section, option, raw=False, vars=None):
        try:
            value = configparser.ConfigParser.get(self, section, option, raw, vars)
            if value is None:
                raise Exception
        except Exception:
            value = ''
        return value

    def items(self, section):
        try:
            value = configparser.ConfigParser.items(self, section)
        except Exception:
            value = []
        return value

    def set(self, section, option, value):
        if not self.has_section(section):
            self.add_section(section)
        configparser.ConfigParser.set(self, section, option, value)


class Config(object):
    def __init__(self):
        self.version = SConfigParser()
        self.userconf = SConfigParser()
        self.reload()
        self.UPDATE_INTV = 6
        self.BACKUP_INTV = 24
        self.parentdict = {}
        self.parentlist = []

        if 'hosts' not in self.userconf.sections():
            self.userconf.add_section('hosts')
            self.userconf.write(open('userconf.ini', 'w'))
        for host, ip in self.userconf.items('hosts'):
            if ip not in HOSTS.get(host, []):
                HOSTS[host].append(ip)

        if os.path.isfile('./fgfw-lite/hosts'):
            for line in open('./fgfw-lite/hosts'):
                line = line.strip()
                if line and not line.startswith('#'):
                    try:
                        ip, host = line.split()
                        if ip not in HOSTS.get(host, []):
                            HOSTS[host].append(ip)
                    except Exception as e:
                        logging.warning('%s %s' % (e, line))

    def reload(self):
        self.version.read('version.ini')
        self.userconf.read('userconf.ini')

    def confsave(self):
        self.version.write(open('version.ini', 'w'))
        self.userconf.read('userconf.ini')

    def addparentproxy(self, name, proxy):
        '''
        {
            'direct': '',
            'goagent': 'http://127.0.0.1:8087'
        }
        '''
        self.parentdict[name] = proxy
        self.parentlist.append(name)

conf = Config()
conf.addparentproxy('direct', '')


@atexit.register
def atexit_do():
    for item in FGFWProxyHandler.ITEMS:
        item.stop()


def main():
    fgfwproxy()
    goagentHandler()
    snovaHandler()
    for k, v in conf.userconf.items('parents'):
        conf.addparentproxy(k, v)
    updatedaemon = Thread(target=updater)
    updatedaemon.daemon = True
    updatedaemon.start()
    while 1:
        try:
            exec(raw_input().strip())
        except Exception as e:
            logging.info(repr(e))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)

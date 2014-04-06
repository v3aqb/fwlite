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
WORKINGDIR = '/'.join(os.path.dirname(os.path.abspath(__file__).replace('\\', '/')).split('/')[:-1])
if ' ' in WORKINGDIR:
    print('no spacebar allowed in path')
    sys.exit()
os.chdir(WORKINGDIR)
sys.path.append(os.path.dirname(os.path.abspath(__file__).replace('\\', '/')))
sys.path += glob.glob('%s/goagent/*.egg' % WORKINGDIR)
try:
    import gevent
    import gevent.socket
    import gevent.server
    import gevent.queue
    import gevent.monkey
    gevent.monkey.patch_all(subprocess=True)
except ImportError:
    gevent = None
except TypeError:
    gevent.monkey.patch_all()
from collections import defaultdict
import subprocess
import shlex
import time
import re
import errno
import email
import atexit
import platform
import base64
import ftplib
import encrypt
import random
import select
import shutil
import socket
import struct
import ssl
from threading import Thread
import urllib2
import urlparse
import pygeoip
try:
    from repoze.lru import lru_cache
except ImportError:
    def lru_cache(size=0, timeout=0):
        def decorator(func):
            return func
        return decorator
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

if sys.platform.startswith('win'):
    PYTHON2 = '%s/Python27/python27.exe' % WORKINGDIR
else:
    for cmd in ('python2.7', 'python27', 'python2'):
        if subprocess.call(shlex.split('which %s' % cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0:
            PYTHON2 = cmd
            break

HOSTS = defaultdict(list)
ctimer = []
CTIMEOUT = 5
NetWorkIOError = (socket.error, ssl.SSLError, OSError)


def prestart():
    s = 'FGFW_Lite ' + __version__ + ' with gevent' if gevent else ''
    logging.info(s)

    if not os.path.isfile('./userconf.ini'):
        shutil.copyfile('./userconf.sample.ini', './userconf.ini')

    if not os.path.isfile('./fgfw-lite/local.txt'):
        with open('./fgfw-lite/local.txt', 'w') as f:
            f.write('! local gfwlist config\n! rules: https://autoproxy.org/zh-CN/Rules\n')

    for item in ['./userconf.ini', './fgfw-lite/local.txt', './userconf.sample.ini', './README.md']:
        with open(item) as f:
            data = f.read()
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

    def log_message(self, format, *args):
        pass

    def finish(self):
        """make python2 BaseHTTPRequestHandler happy"""
        try:
            BaseHTTPRequestHandler.finish(self)
        except (IOError, OSError) as e:
            if e[0] not in (errno.ECONNABORTED, errno.ECONNRESET, errno.EPIPE):
                raise


class ProxyHandler(HTTPRequestHandler):
    server_version = "FGFW-Lite/" + __version__
    protocol_version = "HTTP/1.1"
    rbufsize = 0  # self.rfile Be unbuffered
    timeout = 10
    allowed_clients = ()
    LOCALHOST = ('127.0.0.1', '::1', 'localhost')

    def handle_one_request(self):
        self._proxylist = None
        self.retryable = True
        self.rbuffer = b''
        self.wbuffer = b''
        self.retrycount = 0
        try:
            BaseHTTPRequestHandler.handle_one_request(self)
        except socket.error, e:
            if e.errno in (errno.ECONNABORTED, errno.ECONNRESET, errno.EPIPE):
                self.close_connection = 1
            else:
                raise

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
        if self._proxylist is None:
            self._proxylist = PARENT_PROXY.parentproxy(self.path, self.headers['Host'].rsplit(':', 1)[0], level)
        if not self._proxylist:
            return 1
        self.ppname = self._proxylist.pop(0)
        self.pproxy = conf.parentdict.get(self.ppname)[0]
        self.pproxyparse = urlparse.urlparse(self.pproxy)
        logging.info('{} {} via {}'.format(self.command, self.path, self.ppname))

    def getparent(self, level=1):
        return self._getparent(level)

    def do_GET(self):
        if self.path.lower().startswith('ftp://'):
            return self.do_FTP()
        # transparent proxy
        if self.path.startswith('/') and 'Host' in self.headers:
            self.path = 'http://%s%s' % (self.headers['Host'], self.path)
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

        if not 'Host' in self.headers:
            self.headers['Host'] = urlparse.urlparse(self.path).hostname

        if any(host == self.headers['Host'].rsplit(':', 1)[0] for host in self.LOCALHOST):
            self.send_response(200)
            msg = 'Hello World !'
            self.send_header('Content-type', 'text/html')
            self.send_header('Content-Length', str(len(msg)))
            self.send_header('Connection', 'keep_alive')
            self.end_headers()
            # Send the html message
            self.wfile.write(msg)
            return
        self._do_GET()

    def wfile_write(self, data):
        if self.retryable:
            self.wbuffer += data
            if len(self.wbuffer) > 102400:
                self.retryable = False
        else:
            if self.wbuffer:
                self.wfile.write(self.wbuffer)
                self.wbuffer = b''
            self.wfile.write(data)

    def _do_GET(self, retry=False):
        if self.getparent():
            self.send_error(504)
            return
        if not self.retryable:
            self.close_connection = 1
            return
        if retry:
            self.retrycount += 1
        try:
            remotesoc = self._connect_via_proxy(self.headers['Host'])
        except NetWorkIOError as e:
            return self.on_GET_Error(e)
        self.wbuffer = b''
        try:
            if self.pproxy.startswith('http'):
                s = '%s %s %s\r\n' % (self.command, self.path, self.request_version)
            else:
                s = '%s /%s %s\r\n' % (self.command, '/'.join(self.path.split('/')[3:]), self.request_version)
            del self.headers['Proxy-Connection']
            for key_val in self.headers.items():
                s += "%s: %s\r\n" % key_val
            s += "\r\n"
            try:
                remotesoc.sendall(s.encode('latin'))
            except NetWorkIOError as e:
                return self.on_GET_Error(e)
            logging.debug('request header sent')
            # send request body
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length:
                if content_length > 102400:
                    self.retryable = False
                if self.rbuffer:
                    content_length -= len(self.rbuffer)
                    try:
                        remotesoc.sendall(self.rbuffer)
                    except NetWorkIOError as e:
                        return self.on_GET_Error(e)
                while content_length:
                    data = self.rfile.read(min(8096, content_length))
                    content_length -= len(data)
                    if self.retryable:
                        self.rbuffer += data
                    try:
                        remotesoc.sendall(data)
                    except NetWorkIOError as e:
                        return self.on_GET_Error(e)
                logging.debug('request body sent')
            # read response line
            remoterfile = remotesoc if isinstance(remotesoc, sssocket) else remotesoc.makefile('rb', 0)
            try:
                s = response_line = remoterfile.readline()
                if not s:
                    raise ValueError('empty response line')
            except (socket.error, ssl.SSLError, OSError, ValueError) as e:
                return self.on_GET_Error(e)
            logging.debug('respinse line read')
            protocol_version, _, response_status = response_line.rstrip('\r\n').partition(' ')
            response_status, _, response_reason = response_status.partition(' ')
            response_status = int(response_status)
            header_data = b''
            try:
                while True:
                    line = remoterfile.readline()
                    header_data += line
                    if not line.strip():
                        break
            except NetWorkIOError as e:
                return self.on_GET_Error(e)
            logging.debug('response header read')
            response_header = email.message_from_string(header_data)
            conntype = response_header.get('Connection', "")
            if protocol_version >= "HTTP/1.1":
                self.close_connection = conntype.lower() == 'close'
            else:
                self.close_connection = conntype.lower() != 'keep_alive'

            if "Content-Length" in response_header:
                if "," in response_header["Content-Length"]:
                    # Proxies sometimes cause Content-Length headers to get
                    # duplicated.  If all the values are identical then we can
                    # use them but if they differ it's an error.
                    pieces = re.split(r',\s*', response_header["Content-Length"])
                    if any(i != pieces[0] for i in pieces):
                        raise ValueError("Multiple unequal Content-Lengths: %r" %
                                         response_header["Content-Length"])
                    response_header["Content-Length"] = pieces[0]
                content_length = int(response_header["Content-Length"])
            else:
                content_length = None
            self.wfile_write(s + header_data)
            if self.command == 'HEAD' or 100 <= response_status < 200 or response_status in (204, 304):
                pass
            elif response_header.get("Transfer-Encoding") and response_header.get("Transfer-Encoding") != "identity":
                while 1:
                    try:
                        trunk_lenth = remoterfile.readline()
                    except NetWorkIOError as e:
                        return self.on_GET_Error(e)
                    self.wfile_write(trunk_lenth)
                    trunk_lenth = int(trunk_lenth.strip(), 16) + 2
                    flag = True if trunk_lenth == 2 else False
                    while trunk_lenth:
                        try:
                            data = remotesoc.recv(min(4096, trunk_lenth))
                        except NetWorkIOError as e:
                            return self.on_GET_Error(e)
                        trunk_lenth -= len(data)
                        self.wfile_write(data)
                    if flag:
                        break
            elif content_length is not None:
                while content_length:
                    try:
                        data = remotesoc.recv(min(4096, content_length))
                    except NetWorkIOError as e:
                        return self.on_GET_Error(e)
                    content_length -= len(data)
                    self.wfile_write(data)
            else:
                self.close_connection = 1
                self.retryable = False
                while 1:
                    try:
                        data = remotesoc.recv(4096)
                        if not data:
                            raise
                        self.wfile_write(data)
                    except Exception:
                        break
            if self.wbuffer:
                self.retryable = False
                self.wfile.write(self.wbuffer)
                self.wbuffer = b''
            if self.retrycount and response_status < 400:
                PARENT_PROXY.add_temp_rule('|http://%s' % self.headers['Host'].split(':')[0])
        finally:
            remotesoc.close()

    def on_GET_Error(self, e):
        logging.warning('{} {} failed! {}'.format(self.command, self.path, repr(e)))
        return self._do_GET(True)

    do_OPTIONS = do_POST = do_DELETE = do_TRACE = do_HEAD = do_PUT = do_GET

    def do_CONNECT(self):
        self.close_connection = 1
        if not 'Host' in self.headers:
            self.headers['Host'] = self.path
        self.wfile.write(self.protocol_version + " 200 Connection established\r\n\r\n")
        self._do_CONNECT()

    def _do_CONNECT(self, retry=False):
        if not self.retryable or self.getparent():
            return
        if retry:
            self.retrycount += 1
        try:
            remotesoc = self._connect_via_proxy(self.path)
        except NetWorkIOError as e:
            logging.warning('{} {} failed! {}'.format(self.command, self.path, e))
            return self._do_CONNECT()

        if self.pproxy.startswith('http'):
            s = [b'%s %s %s\r\n' % (self.command, self.path, self.request_version), ]
            s.append(b'\r\n'.join(['%s: %s' % (key, value) for key, value in self.headers.items()]))
            s.append(b'\r\n\r\n')
            remotesoc.sendall(b''.join(s))
            remoterfile = remotesoc.makefile('rb', 0)
            data = remoterfile.readline()
            if '200' not in data:
                logging.warning('{} {} failed! 200 not in response'.format(self.command, self.path))
                return self._do_CONNECT(True)
            while data.strip():
                data = remoterfile.readline()
        if self.rbuffer:
            remotesoc.sendall(self.rbuffer)
        if self._proxylist:
            for i in range(30):
                try:
                    (ins, _, exs) = select.select([self.connection, remotesoc], [], [self.connection, remotesoc], 0.2)
                    if exs:
                        break
                    for i in ins:
                        data = i.recv(4096)
                        if data:
                            if i is remotesoc:
                                self.retryable = False
                                self.wfile.write(data)
                            else:
                                if self.retryable:
                                    self.rbuffer += data
                                remotesoc.sendall(data)
                        else:
                            break
                    if not self.retryable:
                        break
                except socket.error as e:
                    logging.warning('socket error: %s' % e)
                    break
            if self.retryable:
                logging.warning('{} {} failed! read timed out'.format(self.command, self.path))
                return self._do_CONNECT(True)
        if self.retrycount:
            PARENT_PROXY.add_temp_rule('|https://%s' % self.path.rsplit(':', 1)[0])
        self._read_write(remotesoc, 300)
        remotesoc.close()
        self.connection.close()

    def _connect_via_proxy(self, netloc):
        timeout = None if self._proxylist else 20

        if ':' in netloc:
            host, port = netloc.rsplit(':', 1)
        else:
            host, port = netloc, 80
        logging.debug("Connect to %s:%s" % (host, port))
        if not self.pproxy:
            return socket.create_connection((host, int(port)), timeout or 5)
        elif self.pproxy.startswith('http://'):
            return socket.create_connection((self.pproxyparse.hostname, self.pproxyparse.port), timeout or 10)
        elif self.pproxy.startswith('https://'):
            s = socket.create_connection((self.pproxyparse.hostname, self.pproxyparse.port), timeout or 10)
            s = ssl.wrap_socket(s)
            s.do_handshake()
            return s
        elif self.pproxy.startswith('ss://'):
            s = sssocket(self.pproxy, timeout or 10)
            s.connect((host, int(port)))
            return s
        elif self.pproxy.startswith('socks5://'):
            s = socket.create_connection((self.pproxyparse.hostname, self.pproxyparse.port), timeout or 10)
            s.sendall(b"\x05\x02\x00\x02" if self.pproxyparse.username else b"\x05\x01\x00")
            data = s.recv(2)
            if data == b'\x05\x02':  # basic auth
                s.sendall(b''.join([b"\x01",
                                    chr(len(self.pproxyparse.username)).encode(),
                                    self.pproxyparse.username.encode(),
                                    chr(len(self.pproxyparse.password)).encode(),
                                    self.pproxyparse.password.encode()]))
                data = s.recv(2)
            assert data[1] == b'\x00'  # no auth needed or auth passed
            s.sendall(b''.join([b"\x05\x01\x00\x03",
                                chr(len(host)).encode(),
                                host.encode(),
                                struct.pack(b">H", int(port))]))
            data = s.recv(4)
            assert data[1] == b'\x00'
            if data[3] == b'\x01':  # read ipv4 addr
                s.recv(4)
            elif data[3] == b'\x03':  # read host addr
                s.recv(ord(s.recv(1)))
            elif data[3] == b'\x04':  # read ipv6 addr
                s.recv(16)
            s.recv(2)  # read port
            return s

    def _read_write(self, soc, max_idling=20):
        iw = [self.connection, soc]
        count = 0
        while True:
            try:
                (ins, _, exs) = select.select(iw, [], iw, 1)
                if exs:
                    break
                for i in ins:
                    data = i.recv(4096)
                    if data:
                        method = self.wfile.write if i is soc else soc.sendall
                        method(data)
                        count = 0
                    else:
                        break
                if count > max_idling:
                    break
                count += 1
            except socket.error as e:
                logging.debug('socket error: %s' % e)
                break

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
                ftp.retrbinary("RETR %s" % path, self.wfile.write)
            ftp.quit()
        except Exception as e:
            logging.warning("FTP Exception: %s" % e)


class sssocket(object):
    def __init__(self, ssServer, timeout=10):
        p = urlparse.urlparse(ssServer)
        _, sshost, ssport, ssmethod, sspassword = (p.scheme, p.hostname, p.port, p.username, p.password)
        self._sock = socket.create_connection((sshost, ssport), timeout)
        self.crypto = encrypt.Encryptor(sspassword, ssmethod)

    def connect(self, address):
        host, port = address
        data = b''.join([b'\x03',
                        chr(len(host)).encode(),
                        host.encode(),
                        struct.pack(b">H", port)])
        self.sendall(data)

    def recv(self, size):
        if self.crypto.decipher is None:
            size += self.crypto.get_cipher_len(self.crypto.method)[1]
        return self.crypto.decrypt(self._sock.recv(size))

    def sendall(self, data):
        self._sock.sendall(self.crypto.encrypt(data))

    def readline(self, bufsize=0):
        buf = b''
        while True:
            data = self.recv(1)
            buf += data
            if bufsize and len(buf) == bufsize:
                break
            if b'\n' in buf:
                break
        return buf

    def close(self):
        self._sock.close()

    def fileno(self):
        return self._sock.fileno()


class ExpiredError(Exception):
    pass


class autoproxy_rule(object):
    def __init__(self, arg, expire=None):
        super(autoproxy_rule, self).__init__()
        if not isinstance(arg, str):
            arg = str(arg)
        self.rule = arg.strip()
        logging.debug('parsing autoproxy rule: %r' % self.rule)
        if len(self.rule) < 3 or self.rule.startswith(('!', '[')) or '#' in self.rule:
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
        self.proxy_by_rule = []
        REDIRECTOR.lst = []

        def add_rule(line, force=False):
            line = line.strip()
            if len(line.split()) == 2:  # |http://www.google.com/url forcehttps
                try:
                    rule, result = line.split()
                    if result in conf.parentdict.keys():
                        self.proxy_by_rule.append((autoproxy_rule(rule), result))
                    else:
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

        try:
            with open('./fgfw-lite/gfwlist.txt') as f:
                data = f.read()
                if not '!' in data:
                    data = ''.join(f.read().split())
                    if len(data) % 4:
                        data += '=' * (4 - len(data) % 4)
                    data = base64.b64decode(data)
                data = data.splitlines()
                for line in data:
                    add_rule(line)
        except TypeError:
            logging.warning('./fgfw-lite/gfwlist.txt is corrupted!')

        self.localnet.append((ip_from_string('192.168.0.0'), ip_from_string('192.168.0.0') + 2 ** (32 - 16)))
        self.localnet.append((ip_from_string('172.16.0.0'), ip_from_string('172.16.0.0') + 2 ** (32 - 12)))
        self.localnet.append((ip_from_string('10.0.0.0'), ip_from_string('10.0.0.0') + 2 ** (32 - 8)))
        self.localnet.append((ip_from_string('127.0.0.0'), ip_from_string('127.0.0.0') + 2 ** (32 - 8)))

        self.geoip = pygeoip.GeoIP('./goagent/GeoIP.dat')

    @lru_cache(256, timeout=120)
    def ifhost_in_local(self, host):
        try:
            i = ip_from_string(socket.gethostbyname(host))
            if any(a[0] <= i < a[1] for a in self.localnet):
                return True
            return False
        except socket.error as e:
            logging.warning('resolve %s failed! %s' % (host, repr(e)))

    @lru_cache(256, timeout=120)
    def ifhost_in_region(self, host):
        try:
            code = self.geoip.country_code_by_name(host)
            if code in conf.region:
                logging.info('%s in %s' % (host, code))
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

        if not gfwlist_force and (HOSTS.get(host) or self.ifhost_in_region(host)):
            return None

        if gfwlist_force or forceproxy or self.gfwlist_match(uri):
            return True

    @lru_cache(256, timeout=120)
    def no_goagent(self, uri, host):
        s = set(conf.parentdict.keys()) - set(['goagent', 'goagent-php', 'direct', 'local'])
        a = conf.userconf.dget('goagent', 'GAEAppid', 'goagent') == 'goagent'
        if s or a:  # two reasons not to use goagent
            if re.match(r'^([^/]+):\d+$', uri):  # connect method
                    if host in ['play.google.com', 'ssl.gstatic.com', 'mail-attachment.googleusercontent.com', 'webcache.googleusercontent.com', 's1.googleusercontent.com', 's2.googleusercontent.com', 'images1-focus-opensocial.googleusercontent.com', 'images2-focus-opensocial.googleusercontent.com', 'images3-focus-opensocial.googleusercontent.com', 'lh0.googleusercontent.com', 'lh1.googleusercontent.com', 'lh2.googleusercontent.com', 'lh3.googleusercontent.com', 'lh4.googleusercontent.com', 'lh5.googleusercontent.com', 'lh6.googleusercontent.com', 'lh7.googleusercontent.com', 'lh8.googleusercontent.com', 'lh9.googleusercontent.com', 'lh10.googleusercontent.com', 'lh11.googleusercontent.com', 'lh12.googleusercontent.com']:
                        return True
                    if host.endswith(('.google.com', '.google.com.hk', '.googleapis.com', '.android.com', '.appspot.com', '.googlegroups.com', '.googlesource.com', '.googleusercontent.com', '.google-analytics.com', '.googlecode.com', '.gstatic.com')):
                        return False
                    return True
            else:  # get method
                return a

    def select_proxy_by_rule(self, uri):
        '''return a parentproxy name, like: 'shadowsocks-uk' '''
        for rule in self.proxy_by_rule:
            if rule[0].match(uri):
                return rule[1]

    def parentproxy(self, uri, host, level=1):
        '''
            decide which parentproxy to use.
            url:  'www.google.com:443'
                  'http://www.inxian.com'
            host: 'www.google.com' (no port number is allowed)
            level: 0 -- direct
                   1 -- proxy if force, direct if ip in region or override, proxy if gfwlist
                   2 -- proxy if force, direct if ip in region or override, proxy if all
                   3 -- proxy if not override
        '''

        p = self.select_proxy_by_rule(uri)
        if p:
            return [p]
        f = self.ifgfwed(uri, host, level)

        if f is False:
            return ['direct']

        parentlist = conf.parentdict.keys()
        random.shuffle(parentlist)
        parentlist = sorted(parentlist, key=lambda item: conf.parentdict[item][1])

        if self.no_goagent(uri, host):
            logging.debug('skip goagent')
            if 'goagent' in parentlist:
                parentlist.remove('goagent')
            if 'goagent-php' in parentlist and re.match(r'^([^/]+):\d+$', uri):
                parentlist.remove('goagent-php')

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


def updater():
    while 1:
        time.sleep(30)
        if conf.userconf.dgetbool('FGFW_Lite', 'autoupdate'):
            lastupdate = conf.version.dgetfloat('Update', 'LastUpdate', 0)
            if time.time() - lastupdate > conf.UPDATE_INTV * 60 * 60:
                update(auto=True)
        global CTIMEOUT, ctimer
        if ctimer:
            logging.info('max connection time: %ss in %s' % (max(ctimer), len(ctimer)))
            CTIMEOUT = min(max(3, max(ctimer) * 5), 15)
            logging.info('conn timeout set to: %s' % CTIMEOUT)
            ctimer = []


def update(auto=False):
    conf.version.set('Update', 'LastUpdate', str(time.time()))
    filelist = [('https://autoproxy-gfwlist.googlecode.com/svn/trunk/gfwlist.txt', './fgfw-lite/gfwlist.txt'), ]
    for url, path in filelist:
        etag = conf.version.dget('Update', path.replace('./', '').replace('/', '-'), '')
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
    import json
    try:
        r = json.loads(urllib2.urlopen('https://github.com/v3aqb/fgfw-lite/raw/0.4/fgfw-lite/update.json').read())
    except Exception as e:
        logging.info('read update.json failed. Reason: %r' % e)
    else:
        import hashlib
        for path, v, in r.items():
            if v == conf.version.dget('Update', path.replace('./', '').replace('/', '-'), ''):
                logging.info('{} NOT updated. Reason: Not Modified'.format(path))
                continue
            fdata = urllib2.urlopen('https://github.com/v3aqb/fgfw-lite/raw/0.4%s' % path[1:]).read()
            h = hashlib.new("sha256", fdata).hexdigest()
            if h != v:
                logging.info('{} NOT updated. hash mismatch.'.format(path))
                continue
            with open(path, 'wb') as localfile:
                localfile.write(fdata)
            logging.info('%s Updated.' % path)
            conf.version.set('Update', path.replace('./', '').replace('/', '-'), h)
            conf.confsave()
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
        self.start()

    def config(self):
        pass

    def start(self):
        self.config()
        if self.enable:
            logging.info('starting %s' % self.cmd)
            self.subpobj = subprocess.Popen(shlex.split(self.cmd), cwd=self.cwd, stdin=subprocess.PIPE)

    def restart(self):
        self.stop()
        self.start()

    def stop(self):
        try:
            self.subpobj.terminate()
        except:
            pass
        finally:
            self.subpobj = None


class goagentHandler(FGFWProxyHandler):
    """docstring for ClassName"""
    def __init__(self):
        FGFWProxyHandler.__init__(self)

    def config(self):
        self.cwd = '%s/goagent' % WORKINGDIR
        self.cmd = '{} {}/goagent/proxy.py'.format(PYTHON2, WORKINGDIR)
        self.enable = conf.userconf.dgetbool('goagent', 'enable', True)
        with open('%s/goagent/proxy.py' % WORKINGDIR, 'rb') as f:
            t = f.read()
        with open('%s/goagent/proxy.py' % WORKINGDIR, 'wb') as f:
            t = t.replace(b'sys.stdout.write', b'sys.stderr.write')
            t = t.replace(b"ctypes.windll.kernel32.SetConsoleTitleW(u'GoAgent v%s' % __version__)", b'pass')
            f.write(t)
        if self.enable:
            self._config()

    def _config(self):
        goagent = SConfigParser()
        goagent.read('./goagent/proxy.sample.ini')

        if conf.userconf.dget('goagent', 'GAEAppid', 'goagent') != 'goagent':
            goagent.set('gae', 'appid', conf.userconf.dget('goagent', 'GAEAppid', 'goagent'))
            goagent.set("gae", "password", conf.userconf.dget('goagent', 'GAEpassword', ''))
            goagent.set('gae', 'obfuscate', conf.userconf.dget('goagent', 'obfuscate', '0'))
            goagent.set('gae', 'validate', conf.userconf.dget('goagent', 'validate', '0'))
            goagent.set('gae', 'options', conf.userconf.dget('goagent', 'options', ''))
        else:
            logging.warning('GoAgent APPID is NOT set! Fake APPID is used.')
            goagent.set('gae', 'appid', 'dummy')
        goagent.set('gae', 'profile', conf.userconf.dget('goagent', 'profile', 'auto'))
        goagent.set('gae', 'mode', conf.userconf.dget('goagent', 'mode', 'https'))
        conf.addparentproxy('goagent', 'http://127.0.0.1:8087 20')

        if conf.userconf.dget('goagent', 'phpfetchserver'):
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
            conf.addparentproxy('snova-c4', 'http://127.0.0.1:48102')
        else:
            proxy.set('C4', 'Enable', '0')

        proxy.set('SPAC', 'Enable', '0')
        proxy.set('Misc', 'RC4Key', conf.userconf.dget('snova', 'RC4Key', '8976501f8451f03c5c4067b47882f2e5'))
        with open('./snova/conf/snova.conf', 'w') as configfile:
            proxy.write(configfile)


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
            return self.getfloat(section, option)
        except Exception:
            return float(default)

    def dgetint(self, section, option, default=0):
        try:
            return self.getint(section, option)
        except Exception:
            return int(default)

    def dgetbool(self, section, option, default=False):
        try:
            return self.getboolean(section, option)
        except Exception:
            return bool(default)

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
            return configparser.ConfigParser.items(self, section)
        except Exception:
            return []

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
        self.parentdict = {}
        listen = self.userconf.dget('fgfwproxy', 'listen', '8118')
        if listen.isdigit():
            self.listen = ('127.0.0.1', int(listen))
        else:
            self.listen = (listen.rsplit(':', 1)[0], int(listen.rsplit(':', 1)[1]))

        self.region = set(x.upper() for x in self.userconf.dget('fgfwproxy', 'region', 'cn').split('|') if x.strip())

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
        with open('version.ini', 'w') as f:
            self.version.write(f)
        self.userconf.read('userconf.ini')

    def addparentproxy(self, name, proxy):
        '''
        {
            'direct': ('', 0),
            'goagent': ('http://127.0.0.1:8087', 20)
        }
        '''
        proxy, _, priority = proxy.partition(' ')
        self.parentdict[name] = (proxy if proxy != 'direct' else '', int(priority) if priority else 99)

REDIRECTOR = redirector()
PARENT_PROXY = parent_proxy()
conf = Config()


@atexit.register
def atexit_do():
    for item in FGFWProxyHandler.ITEMS:
        item.stop()


def main():
    if os.name == 'nt':
        import ctypes
        ctypes.windll.kernel32.SetConsoleTitleW(u'FGFW-Lite v%s' % __version__)
    goagentHandler()
    snovaHandler()
    for k, v in conf.userconf.items('parents'):
        conf.addparentproxy(k, v)
    conf.addparentproxy('direct', 'direct 0')
    PARENT_PROXY.config()
    updatedaemon = Thread(target=updater)
    updatedaemon.daemon = True
    updatedaemon.start()
    server = ThreadingHTTPServer(conf.listen, ProxyHandler)
    server.serve_forever()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)

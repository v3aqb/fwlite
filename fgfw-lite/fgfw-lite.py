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

from __future__ import print_function, unicode_literals

__version__ = '0.3.4.0'

import sys
import os
import subprocess
import shlex
import time
import re
from threading import Thread
import atexit
import platform
import base64
import hashlib
import socket
import struct
import random
import urllib2
import tornado.ioloop
import tornado.iostream
import tornado.web
from tornado.httputil import HTTPHeaders
from tornado.httpserver import HTTPConnection, HTTPServer, _BadRequestException, HTTPRequest
from tornado.escape import native_str
try:
    import configparser
except ImportError:
    import ConfigParser as configparser
configparser.RawConfigParser.OPTCRE = re.compile(r'(?P<option>[^=\s][^=]*)\s*(?P<vi>[=])\s*(?P<value>.*)$')
try:
    import ipaddress
    ip_address = ipaddress.ip_address
    ip_network = ipaddress.ip_network
except ImportError:
    import ipaddr
    ip_address = ipaddr.IPAddress
    ip_network = ipaddr.IPNetwork

import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('FGFW-Lite')

WORKINGDIR = '/'.join(os.path.dirname(os.path.abspath(__file__).replace('\\', '/')).split('/')[:-1])
if ' ' in WORKINGDIR:
    print('no spacebar allowed in path')
    sys.exit()
os.chdir(WORKINGDIR)

if sys.platform.startswith('win'):
    PYTHON2 = '%s/Python27/python27.exe' % WORKINGDIR
else:
    for cmd in ('python2.7', 'python27', 'python2'):
        if subprocess.call(shlex.split('which %s' % cmd)) == 0:
            PYTHON2 = cmd
            break

if not os.path.isfile('./userconf.ini'):
    with open('./userconf.ini', 'w') as f:
        f.write(open('./userconf.sample.ini').read())

if not os.path.isfile('./fgfw-lite/redirector.txt'):
    with open('./fgfw-lite/redirector.txt', 'w') as f:
        f.write('''\
|http://www.google.com/search forcehttps
|http://www.google.com/url forcehttps
|http://news.google.com forcehttps
|http://appengine.google.com forcehttps
|http://www.google.com.hk/url forcehttps
|http://www.google.com.hk/search forcehttps
/^http://www\.google\.com/?$/ forcehttps
|http://*.googlecode.com forcehttps
|http://*.wikipedia.org forcehttps
''')
if not os.path.isfile('./fgfw-lite/local.txt'):
    with open('./fgfw-lite/local.txt', 'w') as f:
        f.write('! local gfwlist config\n! rules: https://adblockplus.org/zh_CN/filters\n')

for item in ['./fgfw-lite/redirector.txt', './userconf.ini', './fgfw-lite/local.txt']:
    with open(item) as f:
        data = open(item).read()
    with open(item, 'w') as f:
        f.write(data)

UPSTREAM_POOL = {}


class HTTPProxyConnection(HTTPConnection):
    def _on_headers(self, data):
        try:
            data = native_str(data.decode('latin1'))
            eol = data.find("\r\n")
            start_line = data[:eol]
            try:
                method, uri, version = start_line.split(" ")
            except ValueError:
                raise _BadRequestException("Malformed HTTP request line")
            if not version.startswith("HTTP/"):
                raise _BadRequestException("Malformed HTTP version in HTTP Request-Line")
            try:
                headers = HTTPHeaders.parse(data[eol:])
            except ValueError:
                # Probably from split() if there was no ':' in the line
                raise _BadRequestException("Malformed HTTP headers")

            # HTTPRequest wants an IP, not a full socket address
            if self.address_family in (socket.AF_INET, socket.AF_INET6):
                remote_ip = self.address[0]
            else:
                # Unix (or other) socket; fake the remote address
                remote_ip = '0.0.0.0'

            self._request = HTTPRequest(
                connection=self, method=method, uri=uri, version=version,
                headers=headers, remote_ip=remote_ip, protocol=self.protocol)

            content_length = headers.get("Content-Length")
            if content_length:
                content_length = int(content_length)
                if content_length > self.stream.max_buffer_size:
                    raise _BadRequestException("Content-Length too long")
                if headers.get("Expect") == "100-continue":
                    self.stream.write(b"HTTP/1.1 100 (Continue)\r\n\r\n")

            self.request_callback(self._request)
        except _BadRequestException as e:
            logger.info("Malformed HTTP request from %s: %s",
                        self.address[0], e)
            self.close()
            return


class HTTPProxyServer(HTTPServer):
    def handle_stream(self, stream, address):
        HTTPProxyConnection(stream, address, self.request_callback,
                            self.no_keep_alive, self.xheaders, self.protocol)


class ProxyHandler(tornado.web.RequestHandler):
    SUPPORTED_METHODS = ('GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'TRACE', 'CONNECT', 'OPTIONS')

    def getparent(self, uri, forceproxy=False):
        self.ppname, pp = PARENT_PROXY.parentproxy(uri, forceproxy)
        self.pptype, self.pphost, self.ppport, self.ppusername, self.pppassword = pp
        if self.pptype == 'socks5':
            self.upstream_name = '{}-{}-{}'.format(self.ppname, self.request.host, str(self.requestport))
        else:
            self.upstream_name = self.ppname if self.pphost else '{}-{}'.format(self.request.host, str(self.requestport))

        logger.info('{} {} via {}'.format(self.request.method, self.request.uri.split('?')[0], self.ppname))

    def prepare(self):
        uri = self.request.uri
        self._close_flag = True
        self._proxy_retry = 0
        if '//' not in uri:
            uri = 'https://{}'.format(uri)
        # redirector
        new_url = REDIRECTOR.get(uri)
        if new_url:
            logger.debug('redirecting to %s' % new_url)
            if new_url.startswith('403'):
                self.send_error(status_code=403)
            else:
                self.redirect(new_url)
            return
        # self.request.headers['X-Forwarded-For'] = self.request.remote_ip

        urisplit = uri.split('/')
        self.requestpath = '/'.join(urisplit[3:])

        self.requestport = int(urisplit[2].split(':')[1]) if ':' in urisplit[2] else 80

        self.getparent(uri)

    @tornado.web.asynchronous
    def get(self):
        if self.request.method == 'CONNECT':
            return self.connect()
        client = self.request.connection.stream

        def _get_upstream():

            def socks5_handshake(data=None):
                def socks5_auth(data=None):
                    if data == b'\x05\x00':  # no auth needed
                        conn_upstream()
                    elif data == b'\x05\x02':  # basic auth
                        self.upstream.write(b''.join([b"\x01",
                                            chr(len(self.ppusername)).encode(),
                                            self.ppusername.encode(),
                                            chr(len(self.pppassword)).encode(),
                                            self.pppassword.encode()]))
                        self.upstream.read_bytes(2, socks5_auth_finish)
                    else:  # bad day, something is wrong
                        fail()

                def socks5_auth_finish(data=None):
                    if data == b'\x01\x00':  # auth passed
                        conn_upstream()
                    else:
                        fail()

                def conn_upstream(data=None):
                    req = b''.join([b"\x05\x01\x00\x03",
                                   chr(len(self.request.host)).encode(),
                                   self.request.host.encode(),
                                   struct.pack(b">H", self.requestport)])
                    self.upstream.write(req)
                    self.upstream.read_bytes(4, read_upstream_data)

                def read_upstream_data(data=None):
                    if data.startswith(b'\x05\x00\x00\x01'):
                        self.upstream.read_bytes(6, conn)
                    elif data.startswith(b'\x05\x00\x00\x03'):
                        self.upstream.read_bytes(3, readhost)
                    elif data.startswith(b'\x05\x00\x00\x04'):
                        self.upstream.read_bytes(18, conn)
                    else:
                        fail()

                def readhost(data=None):
                    self.upstream.read_bytes(ord(data[0]), conn)

                def conn(data=None):
                    self.upstream.set_nodelay(False)
                    logger.debug('socks5 remote server connected')
                    _sent_request()

                def fail():
                    self.send_error(500)
                    self.upstream.close()

                self.upstream.set_nodelay(True)
                self.upstream.write(b"\x05\x02\x00\x02" if self.ppusername else b"\x05\x01\x00")
                self.upstream.read_bytes(2, socks5_auth)

            def _create_upstream():
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
                self.upstream = tornado.iostream.IOStream(s)
                self.upstream.set_close_callback(self.on_upstream_close)
                if self.pptype == 'http':
                    self.upstream.connect((self.pphost, int(self.ppport)), _sent_request)
                elif self.pptype == 'https':
                    self.upstream = tornado.iostream.SSLIOStream(s)
                    self.upstream.connect((self.pphost, int(self.ppport)), _sent_request)
                elif self.pptype is None:
                    self.upstream.connect((self.request.host.split(':')[0], self.requestport), _sent_request)
                elif self.pptype == 'socks5':
                    self.upstream.connect((self.pphost, int(self.ppport)), socks5_handshake)
                else:
                    self.send_error(501)

            lst = UPSTREAM_POOL.get(self.upstream_name, [])
            self.upstream = None
            for item in lst:
                lst.remove(item)
                if not item.closed():
                    if time.time() - item._last_active < 60:
                        logger.debug('reuse connection')
                        self.upstream = item
                        self.upstream.set_close_callback(self.on_upstream_close)
                        break
                    item.close()
            if self.upstream is None:
                _create_upstream()
            else:
                _sent_request()

        def _client_write(data):
            if not client.closed():
                client.write(data)

        def _sent_request():
            logger.debug('remote server connected, sending http request')
            if self.pptype == 'http' or self.pptype == 'https':
                s = u'%s %s %s\r\n' % (self.request.method, self.request.uri, self.request.version)
                if self.ppusername and 'Proxy-Authorization' not in self.request.headers:
                    a = '%s:%s' % (self.ppusername, self.pppassword)
                    self.request.headers['Proxy-Authorization'] = 'Basic %s\r\n' % base64.b64encode(a.encode())
            else:
                s = u'%s /%s %s\r\n' % (self.request.method, self.requestpath, self.request.version)
            s = [s, ]
            s.append(u'\r\n'.join([u'%s: %s' % (key, unicode(value, 'utf8')) for key, value in self.request.headers.items() if key not in ["Expect", ]]))
            s.append(u'\r\n\r\n')
            self.upstream.write(u''.join(s).encode('latin1'))
            content_length = self.request.headers.get("Content-Length")
            if content_length:
                logger.debug('sending request body')
                client.read_bytes(int(content_length), end_body, streaming_callback=self.upstream.write)
            else:
                self.upstream.read_until_regex(r"\r?\n\r?\n", _on_headers)

        def end_body(data=None):
            # self.upstream.write(b'\r\n\r\n')
            logger.debug('reading response header')
            self.upstream.read_until_regex(r"\r?\n\r?\n", _on_headers)

        def _on_headers(data=None):
            _client_write(data)
            self._headers_written = True
            data = unicode(data, 'latin1')
            first_line, _, header_data = data.partition("\n")
            status_code = int(first_line.split()[1])
            try:
                self.set_status(status_code)
            except ValueError:
                self.set_status(500)

            self._headers = HTTPHeaders.parse(header_data)
            conn_header = self._headers.get("Connection")
            if conn_header and (conn_header.lower() == "keep-alive"):
                self._close_flag = False
            logger.debug('_close_flag: %s' % self._close_flag)
            if "Content-Length" in self._headers:
                if "," in self._headers["Content-Length"]:
                    # Proxies sometimes cause Content-Length headers to get
                    # duplicated.  If all the values are identical then we can
                    # use them but if they differ it's an error.
                    pieces = re.split(r',\s*', self._headers["Content-Length"])
                    if any(i != pieces[0] for i in pieces):
                        raise ValueError("Multiple unequal Content-Lengths: %r" %
                                         self._headers["Content-Length"])
                    self._headers["Content-Length"] = pieces[0]
                content_length = int(self._headers["Content-Length"])
            else:
                content_length = None

            if self.request.method == "HEAD" or status_code == 304:
                _finish()
            elif self._headers.get("Transfer-Encoding") == "chunked":
                self.upstream.read_until(b"\r\n", _on_chunk_lenth)
            elif content_length is not None:
                logger.debug('reading response body')
                self.upstream.read_bytes(content_length, _finish, streaming_callback=_client_write)
            elif self._headers.get("Connection") == "close":
                logger.debug('reading response body')
                self.upstream.read_until_close(_finish)
            else:
                _finish()

        def _on_chunk_lenth(data):
            _client_write(data)
            logger.debug('reading chunk data')
            length = int(data.strip(), 16)
            self.upstream.read_bytes(length + 2,  # chunk ends with \r\n
                                     _on_chunk_data)

        def _on_chunk_data(data):
            _client_write(data)
            if len(data) != 2:
                logger.debug('reading chunk lenth')
                self.upstream.read_until(b"\r\n", _on_chunk_lenth)
            else:
                _finish()

        def _finish(data=None):
            if data:
                _client_write(data)
            self.finish()

        _get_upstream()

    options = post = delete = trace = put = head = get

    def on_finish(self):
        if hasattr(self, 'upstream'):
            if self.upstream.closed() or self._close_flag:
                self.upstream.close()
                self.request.connection.stream.close()
            else:
                if self.upstream_name not in UPSTREAM_POOL:
                    UPSTREAM_POOL[self.upstream_name] = []
                self.upstream._last_active = time.time()
                self.upstream.set_close_callback(None)
                UPSTREAM_POOL.get(self.upstream_name).append(self.upstream)

    def on_connection_close(self):
        if hasattr(self, 'upstream'):
            self.upstream.close()
        logger.debug('client connection closed')
        self.finish()

    def on_upstream_close(self):
        if not self._headers_written:
            if self._proxy_retry < 3:
                self._proxy_retry += 1
                self.clear()
                self.getparent(self.request.uri, forceproxy=True)
                self.get()
            else:
                self.send_error(504)

    @tornado.web.asynchronous
    def connect(self):
        client = self.request.connection.stream

        def read_from_client(data):
            if not upstream.closed():
                upstream.write(data)

        def read_from_upstream(data):
            if not client.closed():
                client.write(data)

        def client_close(data=None):
            if not upstream.closed():
                if data:
                    upstream.write(data)
                upstream.close()

        def upstream_close(data=None):
            if not client.closed():
                if data:
                    client.write(data)
                client.close()

        def start_tunnel(data=None):
            self._headers_written = True
            client.read_until_close(client_close, read_from_client)
            upstream.read_until_close(upstream_close, read_from_upstream)
            if data:
                read_from_client(data.encode())

        def start_ssltunnel(data=None):
            self._headers_written = True
            client.read_until_close(client_close, read_from_client)
            upstream.read_until_close(upstream_close, read_from_upstream)
            read_from_upstream(b'HTTP/1.1 200 Connection established\r\n\r\n')

        def http_conntgt(data=None):
            if self.pptype == 'http' or self.pptype == 'https':
                s = b'%s %s %s\r\n' % (self.request.method, self.request.uri, self.request.version)
                if 'Proxy-Authorization' not in self.request.headers and self.ppusername:
                    a = '%s:%s' % (self.ppusername, self.pppassword)
                    self.request.headers['Proxy-Authorization'] = 'Basic %s\r\n' % base64.b64encode(a.encode())
            else:
                s = '%s /%s %s\r\n' % (self.request.method, self.requestpath, self.request.version)
            if self.request.method != 'CONNECT':
                self.request.headers['Connection'] = 'close'
            s = [s, ]
            s.append(b'\r\n'.join(['%s: %s' % (key, value) for key, value in self.request.headers.items()]).encode('utf8'))
            s.append(b'\r\n\r\n')
            if self.request.body:
                s.extend([self.request.body, b'\r\n\r\n'])
            start_tunnel(b''.join(s))

        def socks5_handshake(data=None):
            def socks5_auth(data=None):
                if data == b'\x05\x00':  # no auth needed
                    conn_upstream()
                elif data == b'\x05\x02':  # basic auth
                    upstream.write(b''.join([b"\x01",
                                   chr(len(self.ppusername)).encode(),
                                   self.ppusername.encode(),
                                   chr(len(self.pppassword)).encode(),
                                   self.pppassword.encode()]))
                    upstream.read_bytes(2, socks5_auth_finish)
                else:  # bad day, something is wrong
                    fail()

            def socks5_auth_finish(data=None):
                if data == b'\x01\x00':  # auth passed
                    conn_upstream()
                else:
                    fail()

            def conn_upstream(data=None):
                req = b''.join([b"\x05\x01\x00\x03",
                               chr(len(self.request.host)).encode(),
                               self.request.host.encode(),
                               struct.pack(b">H", self.requestport)])
                upstream.write(req)
                upstream.read_bytes(4, read_upstream_data)

            def read_upstream_data(data=None):
                if data.startswith(b'\x05\x00\x00\x01'):
                    upstream.read_bytes(6, conn)
                elif data.startswith(b'\x05\x00\x00\x03'):
                    upstream.read_bytes(3, readhost)
                elif data.startswith(b'\x05\x00\x00\x04'):
                    self.upstream.read_bytes(18, conn)
                else:
                    fail()

            def readhost(data=None):
                upstream.read_bytes(ord(data[0]), conn)

            def conn(data=None):
                upstream.set_nodelay(False)
                if self.request.method == 'CONNECT':
                    start_ssltunnel()
                else:
                    http_conntgt()

            def fail():
                self.send_error(500)
                upstream.close()

            upstream.set_nodelay(True)
            upstream.write(b"\x05\x02\x00\x02" if self.ppusername else b"\x05\x01\x00")
            upstream.read_bytes(2, socks5_auth)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        self.upstream = tornado.iostream.IOStream(s)
        self.upstream.set_close_callback(self.on_upstream_close)
        upstream = self.upstream
        if self.pphost is None:
            if self.request.method == 'CONNECT':
                self.upstream.connect((self.request.host.split(':')[0], self.requestport), start_ssltunnel)
            else:
                self.upstream.connect((self.request.host.split(':')[0], self.requestport), http_conntgt)
        elif self.pptype == 'http':
            self.upstream.connect((self.pphost, int(self.ppport)), http_conntgt)
        elif self.pptype == 'https':
            self.upstream = tornado.iostream.SSLIOStream(s)
            self.upstream.connect((self.pphost, int(self.ppport)), http_conntgt)
        elif self.pptype == 'socks5':
            self.upstream.connect((self.pphost, int(self.ppport)), socks5_handshake)
        else:
            self.send_error(501)


class ForceProxyHandler(ProxyHandler):
    def getparent(self, uri, forceproxy=True):
        self.ppname, pp = PARENT_PROXY.parentproxy(uri, forceproxy)
        self.pptype, self.pphost, self.ppport, self.ppusername, self.pppassword = pp
        if self.pptype == 'socks5':
            self.upstream_name = '{}-{}-{}'.format(self.ppname, self.request.host, str(self.requestport))
        else:
            self.upstream_name = self.ppname if self.pphost else '{}-{}'.format(self.request.host, str(self.requestport))
        logger.info('{} {} via {}'.format(self.request.method, self.request.uri.split('?')[0], self.ppname))


class autoproxy_rule(object):
    def __init__(self, arg):
        super(autoproxy_rule, self).__init__()
        if not isinstance(arg, str):
            if isinstance(arg, bytes):
                arg = arg.decode()
            else:
                raise TypeError("invalid type: must be a string(or bytes)")
        self.rule = arg.strip()
        if len(self.rule) < 3 or self.rule.startswith('!') or self.rule.startswith('[') or '#' in self.rule:
            raise TypeError("invalid autoproxy_rule: %s" % self.rule)
        self._ptrn = self._autopxy_rule_parse(self.rule)

    def _autopxy_rule_parse(self, rule):
        def parse(rule):
            if rule.startswith('||'):
                return re.compile(rule.replace('.', r'\.').replace('?', r'\?').replace('*', '.*').replace('^', r'[^\w%._-]').replace('||', '^(?:https?://)?(?:[^/]+\.)?'))
            elif rule.startswith('/') and rule.endswith('/'):
                return re.compile(rule[1:-1])
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
        # url must be something like https://www.google.com
        if self._ptrn.search(uri):
            return True
        return False


class redirector(object):
    """docstring for redirector"""
    def config(self):
        self.lst = []

        for line in open('./fgfw-lite/redirector.txt'):
            line = line.strip()
            if len(line.split()) == 2:  # |http://www.google.com/url forcehttps
                try:
                    o = autoproxy_rule(line.split()[0])
                except TypeError:
                    pass
                else:
                    self.lst.append((o, line.split()[1]))

    def get(self, uri, host=None):
        searchword = re.match(r'^http://([\w-]+)/$', uri)
        if searchword:
            q = searchword.group(1)
            if 'xn--' in q:
                q = q.decode('idna')
            result = 'https://www.google.com/search?q=%s&ie=utf-8&oe=utf-8&aq=t&rls=org.mozilla:zh-CN:official' % urllib2.quote(q.encode('utf-8'))
            logger.info('Match redirect rule addressbar-search')
            return result
        for rule, result in self.lst:
            if rule.match(uri):
                logger.info('Match redirect rule {}, {}'.format(rule.rule, result))
                if rule.override:
                    return None
                if result == 'forcehttps':
                    return uri.replace('http://', 'https://', 1)
                return result

REDIRECTOR = redirector()
REDIRECTOR.config()


class parent_proxy(object):
    """docstring for parent_proxy"""
    def config(self):
        self.gfwlist = []
        self.gfwlist_force = []
        self.hostinchina = {}

        def add_rule(line, force=False):
            try:
                o = autoproxy_rule(line)
            except TypeError as e:
                logger.debug('create autoproxy rule failed: %s' % e)
            else:
                if force:
                    if o.override:
                        self.gfwlist_force.insert(0, o)
                    else:
                        self.gfwlist_force.append(o)
                else:
                    if o.override:
                        self.gfwlist.insert(0, o)
                    else:
                        self.gfwlist.append(o)

        for line in open('./fgfw-lite/local.txt'):
            add_rule(line)

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
                f.seek(0)
                if f.readline().startswith('[AutoProxy'):
                    for line in f:
                        add_rule(line)
                else:
                    logger.warning('./fgfw-lite/gfwlist.txt is corrupted!')

        self.chinanet = []
        self.chinanet.append(ip_network('192.168.0.0/16'))
        self.chinanet.append(ip_network('172.16.0.0/12'))
        self.chinanet.append(ip_network('10.0.0.0/8'))
        self.chinanet.append(ip_network('127.0.0.0/8'))
        # ripped from https://github.com/fivesheep/chnroutes
        import math
        data = open('./fgfw-lite/delegated-apnic-latest').read()

        cnregex = re.compile(r'apnic\|cn\|ipv4\|[0-9\.]+\|[0-9]+\|[0-9]+\|a.*', re.IGNORECASE)
        cndata = cnregex.findall(data)

        for item in cndata:
            unit_items = item.split('|')
            starting_ip = unit_items[3]
            num_ip = int(unit_items[4])

            #mask in *nix format
            mask2 = 32 - int(math.log(num_ip, 2))

            self.chinanet.append(ip_network('{}/{}'.format(starting_ip, mask2)))

    def parentproxy(self, uri, forceproxy=False):
        '''
            decide which parentproxy to use.
            url:  'https://www.google.com'
            domain: 'www.google.com'
        '''
        domain = uri.split('/')[2].split(':')[0]
        # return ('direct', conf.parentdict.get('direct'))

        def ifgfwlist_force():
            for rule in self.gfwlist_force:
                if rule.match(uri):
                    logger.info('Autoproxy Rule match {}'.format(rule.rule))
                    return not rule.override
            return None

        def ifhost_in_china():
            if not domain:
                return None
            if domain in self.hostinchina:
                return self.hostinchina.get(domain)
            try:
                ipo = ip_address(socket.gethostbyname(domain))
            except Exception:
                return None
            for net in self.chinanet:
                if ipo in net:
                    self.hostinchina[domain] = True
                    return True
            self.hostinchina[domain] = False
            return False

        def ifgfwlist():
            for rule in self.gfwlist:
                if rule.match(uri):
                    logger.info('Autoproxy Rule match {}'.format(rule.rule))
                    return not rule.override
            return None

        parentlist = conf.parentdict.keys()
        if uri.startswith('ftp://'):
            if 'GoAgent' in parentlist:
                parentlist.remove('GoAgent')
        if 'cow' in parentlist:
            parentlist.remove('cow')
        parentlist.remove('direct')

        # select parent via uri

        a = ifgfwlist_force()

        if a is False or ifhost_in_china():
            return ('direct', conf.parentdict.get('direct'))

        if a or forceproxy or ifgfwlist():
            if parentlist:
                if len(parentlist) == 1:
                    return (parentlist[0], conf.parentdict.get(parentlist[0]))
                else:
                    hosthash = hashlib.md5(domain).hexdigest()
                    ppname = parentlist[int(hosthash, 16) % len(parentlist)]
                    return (ppname, conf.parentdict.get(ppname))
            else:
                logger.warning('No parent proxy available, direct connection is used')
        if 'cow' in conf.parentdict.keys() and not uri.startswith('ftp://'):
            return ('cow', conf.parentdict.get('cow'))
        return ('direct', conf.parentdict.get('direct'))

PARENT_PROXY = parent_proxy()
PARENT_PROXY.config()


def updateNbackup():
    while 1:
        time.sleep(90)
        ifupdate()
        if conf.userconf.dgetbool('AutoBackupConf', 'enable', False):
            ifbackup()


def ifupdate():
    if conf.userconf.dgetbool('FGFW_Lite', 'autoupdate'):
        lastupdate = conf.version.dgetfloat('Update', 'LastUpdate', 0)
        if time.time() - lastupdate > conf.UPDATE_INTV * 60 * 60:
            update(auto=True)


def ifbackup():
    lastbackup = conf.userconf.dgetfloat('AutoBackupConf', 'LastBackup', 0)
    if time.time() - lastbackup > conf.BACKUP_INTV * 60 * 60:
        Thread(target=backup).start()


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
    REDIRECTOR.config()


def backup():
    import tarfile
    conf.userconf.set('AutoBackupConf', 'LastBackup', str(time.time()))
    conf.confsave()
    try:
        backuplist = conf.userconf.items('AutoBackup', raw=True)
        backupPath = conf.userconf.get('AutoBackupConf', 'BackupPath', raw=True)
    except:
        logger.error("read userconf.ini failed!")
    else:
        if not os.path.isdir(backupPath):
            os.makedirs(backupPath)
        if len(backuplist) > 0:
            logger.info("start packing")
            for i in range(len(backuplist)):
                if os.path.exists(backuplist[i][1]):
                    filepath = '%s/%s-%s.tar.bz2' % (backupPath, backuplist[i][0], time.strftime('%Y%m%d%H%M%S'))
                    logger.info('packing %s to %s' % (backuplist[i][1], filepath))
                    pack = tarfile.open(filepath, "w:bz2")
                    try:
                        pack.add(backuplist[i][1])
                    except Exception:
                        pack.close()
                        os.remove(filepath)
                        logger.info('Packing %s failed.' % filepath)
                    else:
                        pack.close()
                        logger.info('Done Packing %s.' % filepath)
        #remove old backup file
        rotation = conf.userconf.dgetint('AutoBackupConf', 'rotation', 10)
        filelist = os.listdir(str(backupPath))
        filelist.sort()
        surname = ''
        group = []
        for filename in filelist:
            if re.search(r'\d{14}\.tar\.bz2$', filename):
                if filename.split('-')[0] == surname:
                    group.append(filename)
                    if len(group) > rotation:
                        os.remove('%s/%s' % (backupPath, group.pop(0)))
                else:
                    group = []
                    group.append(filename)
                    surname = filename.split('-')[0]


class FGFWProxyHandler(object):
    """docstring for FGFWProxyHandler"""
    ITEMS = []

    def __init__(self):
        FGFWProxyHandler.ITEMS.append(self)
        self.subpobj = None
        self.config()
        self.daemon = Thread(target=self.start)
        self.daemon.daemon = True
        self.daemon.start()

    def config(self):
        self._config()

    def _config(self):
        self.cmd = ''
        self.cwd = ''
        self.filelist = []
        self.enable = True
        self.enableupdate = True

    def start(self):
        while 1:
            if self.enable:
                if self.cwd:
                    os.chdir(self.cwd)
                self.subpobj = subprocess.Popen(shlex.split(self.cmd))
                os.chdir(WORKINGDIR)
                self.subpobj.wait()
            time.sleep(3)

    def restart(self):
        try:
            self.subpobj.terminate()
        except Exception:
            pass

    def _update(self):
        self._listfileupdate()

    def update(self):
        if self.enable and self.enableupdate:
            self._update()

    def _listfileupdate(self):
        if len(self.filelist) > 0:
            for i in range(len(self.filelist)):
                url, path = self.filelist[i]
                etag = conf.version.dget('Update', path.replace('./', '').replace('/', '-'), '')
                self.updateViaHTTP(url, etag, path)

    def updateViaHTTP(self, url, etag, path):
        req = urllib2.Request(url)
        req.add_header('If-None-Match', etag)
        try:
            r = urllib2.urlopen(req)
        except Exception as e:
            logger.info('{} NOT updated. Reason: {}'.format(path, e))
        else:
            if r.getcode() == 200:
                with open(path, 'wb') as localfile:
                    localfile.write(r.read())
                conf.version.set('Update', path.replace('./', '').replace('/', '-'), r.info().getheader('ETag'))
                logger.info('%s Updated.' % path)
            else:
                logger.info('{} NOT updated. Reason: {}'.format(path, str(r.getcode())))


class goagentHandler(FGFWProxyHandler):
    """docstring for ClassName"""
    def __init__(self):
        FGFWProxyHandler.__init__(self)

    def _config(self):
        self.filelist = [['https://github.com/goagent/goagent/raw/3.0/local/proxy.py', './goagent/proxy.py'],
                         ['https://github.com/goagent/goagent/raw/3.0/local/proxy.ini', './goagent/proxy.ini'],
                         ['https://github.com/goagent/goagent/raw/3.0/local/cacert.pem', './goagent/cacert.pem'],
                         ]
        self.cwd = '%s/goagent' % WORKINGDIR
        self.cmd = '{} {}/goagent/proxy.py'.format(PYTHON2, WORKINGDIR)
        self.enable = conf.userconf.dgetbool('goagent', 'enable', True)
        self.enableupdate = conf.userconf.dgetbool('goagent', 'update', True)

        listen = conf.userconf.dget('goagent', 'listen', '127.0.0.1:8087')
        if ':' in listen:
            listen_ip, listen_port = listen.split(':')
        else:
            listen_ip = '127.0.0.1'
            listen_port = listen

        proxy = SConfigParser()
        proxy.read('./goagent/proxy.ini')
        proxy.set('listen', 'ip', listen_ip)
        proxy.set('listen', 'port', listen_port)

        if self.enable:
            conf.addparentproxy('GoAgent', ('http', '127.0.0.1', int(listen_port), None, None))

        proxy.set('gae', 'profile', conf.userconf.dget('goagent', 'profile', 'google_cn'))
        proxy.set('gae', 'appid', conf.userconf.dget('goagent', 'goagentGAEAppid', ''))
        proxy.set("gae", "password", conf.userconf.dget('goagent', 'goagentGAEpassword', ''))
        proxy.set('gae', 'obfuscate', conf.userconf.dget('goagent', 'obfuscate', '0'))
        proxy.set('gae', 'validate', conf.userconf.dget('goagent', 'validate', '0'))
        proxy.set('gae', 'options', conf.userconf.dget('goagent', 'options', ''))
        proxy.set('pac', 'enable', '0')
        proxy.set('paas', 'fetchserver', conf.userconf.dget('goagent', 'paasfetchserver', ''))
        if conf.userconf.dget('goagent', 'paasfetchserver'):
            proxy.set('paas', 'enable', '1')
            if self.enable:
                conf.addparentproxy('GoAgent-PAAS', ('http', '127.0.0.1', 8088, None, None))

        if '-hide' in sys.argv[1:]:
            proxy.set('listen', 'visible', '0')
        else:
            proxy.set('listen', 'visible', '1')

        with open('./goagent/proxy.ini', 'w') as configfile:
            proxy.write(configfile)

        if not os.path.isfile('./goagent/CA.crt'):
            self.createCA()

    def createCA(self):
        '''
        ripped from goagent 2.1.14
        '''
        import OpenSSL
        ca_vendor = 'FGFW_Lite'
        keyfile = './goagent/CA.crt'
        key = OpenSSL.crypto.PKey()
        key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
        ca = OpenSSL.crypto.X509()
        ca.set_serial_number(0)
        ca.set_version(2)
        subj = ca.get_subject()
        subj.countryName = 'CN'
        subj.stateOrProvinceName = 'Internet'
        subj.localityName = 'Cernet'
        subj.organizationName = ca_vendor
        subj.organizationalUnitName = '%s Root' % ca_vendor
        subj.commonName = '%s Root CA' % ca_vendor
        ca.gmtime_adj_notBefore(0)
        ca.gmtime_adj_notAfter(24 * 60 * 60 * 3652)
        ca.set_issuer(ca.get_subject())
        ca.set_pubkey(key)
        ca.add_extensions([
            OpenSSL.crypto.X509Extension(b'basicConstraints', True, b'CA:TRUE'),
            OpenSSL.crypto.X509Extension(b'keyUsage', False, b'keyCertSign, cRLSign'),
            OpenSSL.crypto.X509Extension(b'subjectKeyIdentifier', False, b'hash', subject=ca), ])
        ca.sign(key, 'sha1')
        with open(keyfile, 'wb') as fp:
            fp.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, ca))
            fp.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key))
        import shutil
        if os.path.isdir('./goagent/certs'):
            shutil.rmtree('./goagent/certs')
        self.import_ca()

    def import_ca(self):
        '''
        ripped from goagent 3.0.0
        '''
        certfile = os.path.abspath('./goagent/CA.crt')
        dirname, basename = os.path.split(certfile)
        commonname = 'FGFW_Lite CA'
        if sys.platform.startswith('win'):
            with open(certfile, 'rb') as fp:
                certdata = fp.read()
                if certdata.startswith(b'-----'):
                    begin = b'-----BEGIN CERTIFICATE-----'
                    end = b'-----END CERTIFICATE-----'
                    certdata = base64.b64decode(b''.join(certdata[certdata.find(begin) + len(begin):certdata.find(end)].strip().splitlines()))
                import ctypes
                crypt32_handle = ctypes.windll.kernel32.LoadLibraryW('crypt32.dll')
                crypt32 = ctypes.WinDLL(None, handle=crypt32_handle)
                store_handle = crypt32.CertOpenStore(10, 0, 0, 0x4000 | 0x10000, 'ROOT')
                if not store_handle:
                    return -1
                ret = crypt32.CertAddEncodedCertificateToStore(store_handle, 0x1, certdata, len(certdata), 4, None)
                crypt32.CertCloseStore(store_handle, 0)
                del crypt32
                ctypes.windll.kernel32.FreeLibrary(crypt32_handle)
                return 0 if ret else -1
        elif sys.platform == 'darwin':
            return subprocess.call(shlex.split('security find-certificate -a -c "%s" | grep "%s" >/dev/null || security add-trusted-cert -d -r trustRoot -k "/Library/Keychains/System.keychain" "%s"' % (commonname, commonname, certfile)))
        elif sys.platform.startswith('linux'):
            platform_distname = platform.dist()[0]
            if platform_distname == 'Ubuntu':
                pemfile = "/etc/ssl/certs/%s.pem" % commonname
                new_certfile = "/usr/local/share/ca-certificates/%s.crt" % commonname
                if not os.path.exists(pemfile):
                    return subprocess.call(shlex.split('cp "%s" "%s" && update-ca-certificates' % (certfile, new_certfile)))
            elif any(os.path.isfile('%s/certutil' % x) for x in os.environ['PATH'].split(os.pathsep)):
                return subprocess.call(shlex.split('certutil -L -d sql:$HOME/.pki/nssdb | grep "%s" || certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "%s" -i "%s"' % (commonname, commonname, certfile)))
            else:
                logging.warning('please install *libnss3-tools* package to import GoAgent root ca')
        return 0


class shadowsocksHandler(FGFWProxyHandler):
    """docstring for ClassName"""
    def __init__(self):
        FGFWProxyHandler.__init__(self)

    def _config(self):
        self.filelist = [['https://github.com/clowwindy/shadowsocks/raw/master/shadowsocks/local.py', './shadowsocks/local.py'],
                         ['https://github.com/clowwindy/shadowsocks/raw/master/shadowsocks/encrypt.py', './shadowsocks/encrypt.py'],
                         ['https://github.com/clowwindy/shadowsocks/raw/master/shadowsocks/utils.py', './shadowsocks/utils.py']]
        self.cmd = '{} -B {}/shadowsocks/local.py'.format(PYTHON2, WORKINGDIR)
        self.cwd = '%s/shadowsocks' % WORKINGDIR
        self.enable = conf.userconf.dgetbool('shadowsocks', 'enable', False)
        self.enableupdate = conf.userconf.dgetbool('shadowsocks', 'update', False)
        if self.enable:
            lst = []
            if sys.platform.startswith('win'):
                self.cmd = 'c:/python27/python.exe -B %s/shadowsocks/local.py' % WORKINGDIR
                for cmd in ('ss-local', 'sslocal'):
                    if 'XP' in platform.platform():
                        continue
                    if subprocess.call(shlex.split('where %s' % cmd)) == 0:
                        self.cmd = cmd
                        break
                else:
                    lst = ['./shadowsocks/ss-local.exe',
                           './shadowsocks/shadowsocks-local.exe',
                           './shadowsocks/shadowsocks.exe']
            elif sys.platform.startswith('linux'):
                for cmd in ('ss-local', 'sslocal'):
                    if subprocess.call(shlex.split('which %s' % cmd)) == 0:
                        self.cmd = cmd
                        break
                else:
                    lst = ['./shadowsocks/ss-local',
                           './shadowsocks/shadowsocks-local']
            for f in lst:
                if os.path.isfile(f):
                    self.cmd = ''.join([WORKINGDIR, f[1:]])
                    break

            if not self.cmd.endswith('shadowsocks.exe'):
                server = conf.userconf.dget('shadowsocks', 'server', '127.0.0.1')
                server_port = conf.userconf.dget('shadowsocks', 'server_port', '8388')
                if not server_port.isdigit():
                    portlst = []
                    for item in server_port.split(','):
                        if item.strip().isdigit():
                            portlst.append(item.strip())
                        else:
                            a, b = item.strip().split('-')
                            for i in range(int(a), int(b) + 1):
                                portlst.append(str(i))
                    server_port = random.choice(portlst)

                password = conf.userconf.dget('shadowsocks', 'password', 'barfoo!')
                method = conf.userconf.dget('shadowsocks', 'method', 'aes-256-cfb')
                self.cmd = '{} -s {} -p {} -l 1080 -k {} -m {}'.format(self.cmd, server, server_port, password, method.strip('"'))
            conf.addparentproxy('shadowsocks', ('socks5', '127.0.0.1', 1080, None, None))


class cowHandler(FGFWProxyHandler):
    """docstring for cow_abs"""
    def __init__(self):
        FGFWProxyHandler.__init__(self)

    def _config(self):
        self.filelist = []
        self.cwd = '%s/cow' % WORKINGDIR

        self.enable = conf.userconf.dgetbool('cow', 'enable', True)
        if sys.platform.startswith('win'):
            self.cmd = '%s/cow/cow.exe' % WORKINGDIR
        else:
            self.cmd = '%s/cow/cow' % WORKINGDIR
        self.enableupdate = conf.userconf.dgetbool('cow', 'update', False)
        if not os.path.isfile(self.cmd):
            self.enable = False
            return
        configfile = []
        configfile.append('listen = %s' % conf.userconf.dget('cow', 'listen', '127.0.0.1:8117'))
        for key, item in conf.parentdict.items():
            pptype, pphost, ppport, ppusername, pppassword = item
            if key == 'direct' or key == 'cow':
                continue
            if pptype == 'http':
                configfile.append('httpParent = %s:%s' % (pphost, ppport))
            if pptype == 'socks5':
                configfile.append('socksParent = %s:%s' % (pphost, ppport))
        if sys.platform.startswith('win'):
            filepath = '%s/cow/rc.txt' % WORKINGDIR
        else:
            filepath = ''.join([os.path.expanduser('~'), '/.cow/rc'])
        with open(filepath, 'w') as f:
            f.write('\n'.join(configfile))
        if self.enable:
            conf.addparentproxy('cow', ('http', '127.0.0.1', 8117, None, None))


class fgfwproxy(FGFWProxyHandler):
    """docstring for ClassName"""
    def __init__(self, arg=''):
        FGFWProxyHandler.__init__(self)
        self.arg = arg

    def _config(self):
        self.filelist = [['https://autoproxy-gfwlist.googlecode.com/svn/trunk/gfwlist.txt', './fgfw-lite/gfwlist.txt'],
                         ['http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest', './fgfw-lite/delegated-apnic-latest'],
                         ['https://fgfw-lite.googlecode.com/git-history/master/fgfw-lite/fgfw-lite.py', './fgfw-lite/fgfw-lite.py'],
                         ['https://fgfw-lite.googlecode.com/git-history/master/fgfw-lite/cloud.txt', './fgfw-lite/cloud.txt'],
                         ['https://fgfw-lite.googlecode.com/git-history/master/userconf.sample.ini', './userconf.sample.ini'],
                         ['https://fgfw-lite.googlecode.com/git-history/master/README.md', './README.md'],
                         ['https://fgfw-lite.googlecode.com/git-history/master/Python27/python27.zip', './Python27/python27.zip'],
                         # ['https://github.com/v3aqb/fgfw-lite/raw/master/fgfw-lite/FGFW_Lite.py', './fgfw-lite/FGFW_Lite.py'],
                         # ['https://github.com/v3aqb/fgfw-lite/raw/master/fgfw-lite/cloud.txt', './fgfw-lite/cloud.txt'],
                         # ['https://github.com/v3aqb/fgfw-lite/raw/master/userconf.sample.ini', './userconf.sample.ini'],
                         # ['https://github.com/v3aqb/fgfw-lite/raw/master/README.md', './README.md'],
                         ]
        self.enable = conf.userconf.dgetbool('fgfwproxy', 'enable', True)
        self.enableupdate = conf.userconf.dgetbool('fgfwproxy', 'update', True)
        self.listen = conf.userconf.dget('fgfwproxy', 'listen', '8118')

    def start(self):
        if self.enable:
            if ':' in self.listen:
                self.run_proxy(self.listen.split(':')[1], address=self.listen.split(':')[0])
            else:
                self.run_proxy(self.listen)

    def run_proxy(self, port, start_ioloop=True):
        """
        Run proxy on the specified port. If start_ioloop is True (default),
        the tornado IOLoop will be started immediately.
        """
        print("Starting HTTP proxy on port {} and {}".format(port, str(int(port) + 1)))
        app = tornado.web.Application([(r'.*', ProxyHandler), ])
        http_server = HTTPProxyServer(app)
        http_server.listen(8118)
        app2 = tornado.web.Application([(r'.*', ForceProxyHandler), ])
        http_server2 = HTTPProxyServer(app2)
        http_server2.listen(8119)
        ioloop = tornado.ioloop.IOLoop.instance()
        if start_ioloop:
            ioloop.start()


class SConfigParser(configparser.ConfigParser):
    """docstring for SSafeConfigParser"""
    def __init__(self):
        configparser.ConfigParser.__init__(self)

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

    def reload(self):
        self.version.read('version.ini')
        self.userconf.read('userconf.ini')

    def confsave(self):
        self.version.write(open('version.ini', 'w'))
        self.userconf.write(open('userconf.ini', 'w'))

    def addparentproxy(self, name, proxy):
        '''
        {
            'direct': (None, None, None, None, None),
            'goagent': ('http', '127.0.0.1', 8087, None, None)
        }  # type, host, port, username, password
        '''
        self.parentdict[name] = proxy

conf = Config()
conf.addparentproxy('direct', (None, None, None, None, None))


@atexit.register
def atexit_do():
    for item in FGFWProxyHandler.ITEMS:
        item.enable = False
        item.restart()
    conf.confsave()


def main():
    if conf.userconf.dgetbool('fgfwproxy', 'enable', True):
        fgfwproxy()
    if conf.userconf.dgetbool('goagent', 'enable', True):
        goagentHandler()
    if conf.userconf.dgetbool('shadowsocks', 'enable', False):
        shadowsocksHandler()
    if conf.userconf.dgetbool('https', 'enable', False):
        host = conf.userconf.dget('https', 'host', '')
        port = conf.userconf.dget('https', 'port', '443')
        user = conf.userconf.dget('https', 'user', None)
        passwd = conf.userconf.dget('https', 'passwd', None)
        conf.addparentproxy('https', ('https', host, int(port), user, passwd))
    if conf.userconf.dgetbool('cow', 'enable', True):
        cowHandler()
    updatedaemon = Thread(target=updateNbackup)
    updatedaemon.daemon = True
    updatedaemon.start()
    while 1:
        try:
            exec(raw_input().strip())
        except Exception as e:
            print(repr(e))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)

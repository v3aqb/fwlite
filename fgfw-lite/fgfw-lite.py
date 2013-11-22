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

__version__ = '0.3.5.1'

import sys
import os
import subprocess
import shlex
import time
import re
import errno
from threading import Thread
import atexit
import platform
import base64
import hashlib
import socket
import struct
import urllib2
import urlparse
import tornado.ioloop
import tornado.iostream
import tornado.web
from tornado import gen, stack_context
from tornado.httputil import HTTPHeaders
from tornado.httpserver import HTTPConnection, HTTPServer, _BadRequestException, HTTPRequest
try:
    import configparser
except ImportError:
    import ConfigParser as configparser
configparser.RawConfigParser.OPTCRE = re.compile(r'(?P<option>[^=\s][^=]*)\s*(?P<vi>[=])\s*(?P<value>.*)$')
try:
    import ipaddress
except ImportError:
    import ipaddr as ipaddress
    ipaddress.ip_address = ipaddress.IPAddress
    ipaddress.ip_network = ipaddress.IPNetwork

import logging
logging.basicConfig(level=logging.INFO)

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
ctimer = []
rtimer = []
CTIMEOUT = 5
RTIMEOUT = 5


class Application(tornado.web.Application):
    def log_request(self, handler):
        if "log_function" in self.settings:
            self.settings["log_function"](handler)
            return
        if handler.request.method == 'CONNECT':
            return
        if handler.get_status() < 400:
            log_method = logging.info
        elif handler.get_status() < 500:
            log_method = logging.warning
        else:
            log_method = logging.error
        request_time = 1000.0 * handler.request.request_time()
        log_method("%d %s %.2fms", handler.get_status(),
                   handler._request_summary(), request_time)


class HTTPProxyConnection(HTTPConnection):
    def _handle_events(self, fd, events):
        if self.stream.closed():
            gen_log.warning("Got events for closed stream %d", fd)
            return
        try:
            if events & self.stream.io_loop.READ:
                self.stream._handle_read()
            if self.stream.closed():
                return
            if events & self.stream.io_loop.WRITE:
                if self.stream._connecting:
                    self.stream._handle_connect()
                self.stream._handle_write()
            if self.stream.closed():
                return
            if events & self.stream.io_loop.ERROR:
                self.stream.error = self.stream.get_fd_error()
                # We may have queued up a user callback in _handle_read or
                # _handle_write, so don't close the IOStream until those
                # callbacks have had a chance to run.
                self.stream.io_loop.add_callback(self.stream.close)
                return
            state = self.stream.io_loop.ERROR
            if self.stream.reading():
                state |= self.stream.io_loop.READ
            if self.stream.writing():
                state |= self.stream.io_loop.WRITE
            # if state == self.stream.io_loop.ERROR:
            #     state |= self.stream.io_loop.READ
            if state != self.stream._state:
                assert self.stream._state is not None, \
                    "shouldn't happen: _handle_events without self._state"
                self.stream._state = state
                self.stream.io_loop.update_handler(self.stream.fileno(), self.stream._state)
        except Exception:
            gen_log.error("Uncaught exception, closing connection.",
                          exc_info=True)
            self.stream.close(exc_info=True)
            raise

    def read_from_fd(self):
        if self.stream._read_buffer_size >= 327680:
            if sys.platform.startswith('win'):
                time.sleep(0.003)
            return None
        try:
            chunk = self.stream.socket.recv(self.stream.read_chunk_size)
        except socket.error as e:
            if e.args[0] in (errno.EWOULDBLOCK, errno.EAGAIN):
                return None
            else:
                raise
        if not chunk:
            self.stream.close()
            return None
        return chunk

    def _on_headers(self, data):
        try:
            data = unicode(data.decode('latin1'))
            eol = data.find("\r\n")
            start_line = data[:eol]
            try:
                method, uri, version = start_line.split(" ")
            except ValueError:
                raise _BadRequestException("Malformed HTTP request line")
            if not version.startswith("HTTP/"):
                raise _BadRequestException("Malformed HTTP version in HTTP Request-Line")

            if method == 'POST':
                # overwrite self.stream.read_from_fd, force a block
                setattr(self.stream, 'read_from_fd', self.read_from_fd)
                setattr(self.stream, '_handle_events', self._handle_events)
                self.stream.io_loop.remove_handler(self.stream.fileno())
                self.stream._state = None
            try:
                headers = HTTPHeaders.parse(data[eol:])
            except ValueError:
                # Probably from split() if there was no ':' in the line
                raise _BadRequestException("Malformed HTTP headers")
            if method == 'POST':
                headers["Connection"] = "close"

            # HTTPRequest wants an IP, not a full socket address
            if self.address_family in (socket.AF_INET, socket.AF_INET6):
                remote_ip = self.address[0]
            else:
                # Unix (or other) socket; fake the remote address
                remote_ip = '0.0.0.0'

            self._request = HTTPRequest(
                connection=self, method=method, uri=uri, version=version,
                headers=headers, remote_ip=remote_ip, protocol=self.protocol)

            self.request_callback(self._request)
        except _BadRequestException as e:
            logging.info("Malformed HTTP request from %s: %s",
                         self.address[0], e)
            self.close()
            return


class HTTPProxyServer(HTTPServer):
    def handle_stream(self, stream, address):
        HTTPProxyConnection(stream, address, self.request_callback,
                            self.no_keep_alive, self.xheaders, self.protocol)


class ProxyHandler(tornado.web.RequestHandler):
    SUPPORTED_METHODS = ('GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'TRACE', 'CONNECT', 'OPTIONS')

    def _getparent(self, level=1):
        self.ppname, pp = PARENT_PROXY.parentproxy(self.request.uri, self.request.host.rsplit(':', 1)[0], level)
        p = urlparse.urlparse(pp)
        self.pptype, self.pphost, self.ppport, self.ppusername, self.pppassword = (p.scheme or None, p.hostname or p.path or None, p.port, p.username, p.password)
        if self.pphost:
            if self.pptype is None:
                self.pptype = 'http'
            r = re.match(r'^(.*)\:(\d+)$', self.pphost)
            if r:
                self.pphost, self.ppport = r.group(1), int(r.group(2))
        if self.pptype == 'socks5':
            self.upstream_name = '{}-{}-{}'.format(self.ppname, self.request.host, str(self.requestport))
        else:
            self.upstream_name = self.ppname if self.pphost else '{}-{}'.format(self.request.host, str(self.requestport))

        logging.info('{} {} via {}'.format(self.request.method, self.request.uri.split('?')[0], self.ppname))

    def getparent(self, level=1):
        self._getparent(level)

    @gen.coroutine
    def prepare(self):
        self._close_flag = True
        self._proxy_retry = 0
        self._timeout = None
        self._success = False
        # transparent proxy
        if self.request.method != 'CONNECT' and self.request.uri.startswith('/') and self.request.host != "127.0.0.1":
            self.request.uri = 'http://%s%s' % (self.request.host, self.request.uri)
        # redirector
        new_url = REDIRECTOR.get(self.request.uri)
        if new_url:
            logging.info('redirecting to %s' % new_url)
            if new_url.startswith('403'):
                self.send_error(status_code=403)
            else:
                self.redirect(new_url)
            return

        # try to get host from uri
        if self.request.host == "127.0.0.1":
            if not self.request.uri.startswith('/'):
                self.request.headers['Host'] = self.request.host = self.request.uri.split('/')[2] if '//' in self.request.uri else self.request.uri
            else:
                self.send_error(status_code=403)
                return

        self.requestpath = '/'.join(self.request.uri.split('/')[3:]) if '//' in self.request.uri else ''
        if self.request.method == 'CONNECT':
            self.requestport = int(self.request.uri.rsplit(':', 1)[1])
        else:
            self.requestport = int(self.request.host.rsplit(':', 1)[1]) if ':' in self.request.host else 80

        self.getparent()
        yield self.get_remote_conn()

    @gen.coroutine
    def get_remote_conn(self):
        if hasattr(self, 'upstream'):
            del self.upstream
        if self.request.method != 'CONNECT':
            lst = UPSTREAM_POOL.get(self.upstream_name, [])
            for item in lst:
                lst.remove(item)
                if not item.closed():
                    if time.time() - item._last_active < 60:
                        logging.debug('reuse connection')
                        self.upstream = item
                        self.upstream.set_close_callback(self.on_upstream_close)
                        break
                    item.close()
        if not hasattr(self, 'upstream'):
            logging.debug('connecting to server')
            if self.ppname == 'none':
                self._timeout = tornado.ioloop.IOLoop.current().add_timeout(time.time() + CTIMEOUT, stack_context.wrap(self.on_upstream_close))
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
            self.upstream = tornado.iostream.IOStream(s)
            self.upstream.set_close_callback(self.on_upstream_close)
            if self.pptype is None:
                t = time.time()
                yield gen.Task(self.upstream.connect, (self.request.host.rsplit(':', 1)[0], self.requestport))
                ctimer.append(time.time() - t)
            elif self.pptype == 'http':
                yield gen.Task(self.upstream.connect, (self.pphost, int(self.ppport)))
            elif self.pptype == 'https':
                self.upstream = tornado.iostream.SSLIOStream(s)
                self.upstream.set_close_callback(self.on_upstream_close)
                yield gen.Task(self.upstream.connect, (self.pphost, int(self.ppport)))
            elif self.pptype == 'socks5':
                logging.debug('connecting to socks5 server')
                yield gen.Task(self.upstream.connect, (self.pphost, int(self.ppport)))
                try:
                    self.upstream.set_nodelay(True)
                    self.upstream.write(b"\x05\x02\x00\x02" if self.ppusername else b"\x05\x01\x00")
                    data = yield gen.Task(self.upstream.read_bytes, 2)
                    if data == b'\x05\x02':  # basic auth
                        self.upstream.write(b''.join([b"\x01",
                                                     chr(len(self.ppusername)).encode(),
                                                     self.ppusername.encode(),
                                                     chr(len(self.pppassword)).encode(),
                                                     self.pppassword.encode()]))
                        data = yield gen.Task(self.upstream.read_bytes, 2)

                    assert data[1] == b'\x00'  # no auth needed or auth passed
                    req = b''.join([b"\x05\x01\x00\x03",
                                     chr(len(self.request.host.rsplit(':', 1)[0])).encode(),
                                     self.request.host.rsplit(':', 1)[0].encode(),
                                     struct.pack(b">H", self.requestport)])
                    self.upstream.write(req)
                    data = yield gen.Task(self.upstream.read_bytes, 4)
                    assert data[1] == b'\x00'
                    if data[3] == b'\x01':  # read ipv4 addr
                        yield gen.Task(self.upstream.read_bytes, 4)
                    elif data[3] == b'\x03':  # read host addr
                        data = yield gen.Task(self.upstream.read_bytes, 1)
                        yield gen.Task(self.upstream.read_bytes, ord(data))
                    elif data[3] == b'\x04':  # read ipv6 addr
                        yield gen.Task(self.upstream.read_bytes, 16)
                    yield gen.Task(self.upstream.read_bytes, 2)  # read port
                    self.upstream.set_nodelay(False)
                except Exception:
                    self.send_error(504, 'connect to socks5 proxy server failed')
            else:
                self.send_error(501)
            logging.debug('remote server connected')
            self.remove_timeout()

    @tornado.web.asynchronous
    def get(self):
        logging.debug('GET')
        client = self.request.connection.stream
        self._client_write_buffer = []
        self._close_flag = True

        def _do_client_write(data):
            if not client.closed():
                client.write(data)

        def _client_write(data):
            if self._headers_written:
                _do_client_write(data)
            else:
                self._client_write_buffer.append(data)
                if len(b''.join(self._client_write_buffer)) > 512000:
                    while self._client_write_buffer:
                        _do_client_write(self._client_write_buffer.pop(0))
                    self._headers_written = True

        def body_transfer(s, d, callback):
            def read_from():
                if self.__content_length > 0:
                    self.__content_length -= min(self.__content_length, 65536)
                    s.read_bytes(min(self.__content_length, 65536), write_to)
                else:
                    callback()

            def write_to(data=None):
                if not d.closed():
                    d.write(data, read_from)

            read_from()

        def _sent_request():
            logging.debug('remote server connected, sending http request')
            if self.pptype == 'http' or self.pptype == 'https':
                s = u'%s %s %s\r\n' % (self.request.method, self.request.uri, self.request.version)
                if self.ppusername and 'Proxy-Authorization' not in self.request.headers:
                    a = '%s:%s' % (self.ppusername, self.pppassword)
                    self.request.headers['Proxy-Authorization'] = 'Basic %s\r\n' % base64.b64encode(a.encode())
            else:
                s = u'%s /%s %s\r\n' % (self.request.method, self.requestpath, self.request.version)
            s = [s, ]
            s.append(u'\r\n'.join([u'%s: %s' % (key, value) for key, value in self.request.headers.items()]))
            s.append(u'\r\n\r\n')
            self.upstream.write(u''.join(s).encode('latin1'))
            content_length = self.request.headers.get("Content-Length")
            if content_length:
                logging.debug('sending request body')
                self.__content_length = int(content_length)
                body_transfer(client, self.upstream, read_headers)
            else:
                read_headers()

        def read_headers(data=None):
            logging.debug('reading response header')
            self.__t = time.time()
            if self.ppname == 'none':
                self._timeout = tornado.ioloop.IOLoop.current().add_timeout(time.time() + RTIMEOUT, stack_context.wrap(self.on_upstream_close))
            self.upstream.read_until_regex(r"\r?\n\r?\n", _on_headers)

        def _on_headers(data=None):
            self.remove_timeout()
            rtimer.append(time.time() - self.__t)
            _client_write(data)
            data = unicode(data, 'latin1')
            first_line, _, header_data = data.partition("\n")
            first_line = first_line.split()
            try:
                if len(first_line) >= 3:
                    self.set_status(int(first_line[1]), ' '.join(first_line[2:]))
                else:
                    self.set_status(int(first_line[1]))
                if self.request.supports_http_1_1():
                    self.request.version = first_line[0]
            except ValueError:
                self.set_status(500)

            self._headers = HTTPHeaders.parse(header_data)
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

            if self.request.method == "HEAD" or self._status_code == 304 or \
                    100 <= self._status_code < 200 or self._status_code == 204:
                _finish()
            elif self._headers.get("Transfer-Encoding") == "chunked":
                self.upstream.read_until(b"\r\n", _on_chunk_lenth)
            elif content_length is not None:
                logging.debug('reading response body')
                self.upstream.read_bytes(content_length, _finish, streaming_callback=_client_write)
            else:
                logging.debug('reading response body')
                self._headers["Connection"] = "close"
                self.upstream.read_until_close(_finish, _client_write)

        def _on_chunk_lenth(data):
            _client_write(data)
            logging.debug('reading chunk data')
            length = int(data.strip(), 16)
            self.upstream.read_bytes(length + 2,  # chunk ends with \r\n
                                     _on_chunk_data)

        def _on_chunk_data(data):
            _client_write(data)
            if len(data) != 2:
                logging.debug('reading chunk lenth')
                self.upstream.read_until(b"\r\n", _on_chunk_lenth)
            else:
                _finish()

        def _finish(data=None):
            if self._client_write_buffer:
                while self._client_write_buffer:
                    _do_client_write(self._client_write_buffer.pop(0))
                self._headers_written = True
            self._success = True
            conn_header = self._headers.get("Connection")
            if conn_header:
                conn_header = conn_header.lower()
            if self.request.supports_http_1_1():
                self._close_flag = conn_header == 'close'
            else:
                self._close_flag = conn_header != 'keep_alive'
            self.upstream.set_close_callback(None)
            self.finish()

        _sent_request()

    options = post = delete = trace = put = head = get

    def remove_timeout(self):
        if self._timeout is not None:
            tornado.ioloop.IOLoop.current().remove_timeout(self._timeout)
            self._timeout = None

    def on_finish(self):
        logging.debug('on finish')
        logging.debug('self._success? %s' % self._success)
        logging.debug('retry? %s' % self._proxy_retry)
        self.remove_timeout()
        if hasattr(self, 'upstream'):
            if self.upstream.closed() or self._close_flag:
                logging.debug('close remote connection, closed: %s flag: %s' % (self.upstream.closed(), self._close_flag))
                self.upstream.set_close_callback(None)
                self.upstream.close()
                self.request.connection.stream.close()
            elif self._success:
                if self.upstream_name not in UPSTREAM_POOL:
                    UPSTREAM_POOL[self.upstream_name] = []
                self.upstream._last_active = time.time()
                self.upstream.set_close_callback(None)
                UPSTREAM_POOL.get(self.upstream_name).append(self.upstream)
                logging.debug('pooling remote connection')
        if (self._success and self._proxy_retry > 0 and self.ppname != 'direct') or (not self._success and self.request.method == 'CONNECT' and self.ppname == 'direct'):
            logging.info('add autoproxy rule: ||%s' % self.request.host.split(':')[0])
            o = autoproxy_rule('||%s' % self.request.host.split(':')[0])
            o.expire = time.time() + 60 * 2
            PARENT_PROXY.gfwlist_force.append(o)

    def on_connection_close(self):
        logging.debug('client connection closed')
        self._close_flag = True
        if hasattr(self, 'upstream'):
            self.upstream.set_close_callback(None)
            self.upstream.close()
        if not self._finished:
            self.finish()

    @gen.coroutine
    def on_upstream_close(self):
        logging.debug('on_upstream_close upstream closed? %s' % self.upstream.closed())
        self.remove_timeout()
        if not self.upstream.closed():
            self.upstream.set_close_callback(None)
            self.upstream.close()
        logging.debug('request finished? %s' % self._finished)
        logging.debug('headers_written? %s' % self._headers_written)
        if not self._finished:
            if not self._headers_written:
                if self._proxy_retry < 4:
                    logging.warning('%s %s Failed, retry...' % (self.request.method, self.request.uri))
                    self.clear()
                    self.getparent(level=3 if self.ppname in ('none', 'direct') else 0)
                    self._proxy_retry += 1
                    yield self.get_remote_conn()
                    if self.request.method == 'CONNECT':
                        self.connect()
                    else:
                        self.get()
                else:
                    logging.warning('%s %s FAILED!' % (self.request.method, self.request.uri))
                    self.send_error(504)
            else:
                if self.request.method != 'CONNECT':
                    logging.warning('%s %s FAILED!' % (self.request.method, self.request.uri))

    @tornado.web.asynchronous
    def connect(self):
        def upstream_write(data):
            if not upstream.closed():
                upstream.write(data)

        def client_write(data):
            self._headers_written = True
            if len(data) > 128:
                self._success = True
                self.remove_timeout()
                rtimer.append(time.time() - self.__t)
            if not client.closed():
                client.write(data)
        logging.debug('CONNECT')
        client = self.request.connection.stream
        upstream = self.upstream
        self.__t = time.time()
        if self.ppname == 'none':
            self._timeout = tornado.ioloop.IOLoop.current().add_timeout(time.time() + RTIMEOUT, stack_context.wrap(self.on_upstream_close))
        if self.pptype and 'http' in self.pptype:
            s = [b'%s %s %s\r\n' % (self.request.method, self.request.uri, self.request.version), ]
            if 'Proxy-Authorization' not in self.request.headers and self.ppusername:
                a = '%s:%s' % (self.ppusername, self.pppassword)
                self.request.headers['Proxy-Authorization'] = 'Basic %s\r\n' % base64.b64encode(a.encode())
            s.append(b'\r\n'.join(['%s: %s' % (key, value) for key, value in self.request.headers.items()]).encode('utf8'))
            s.append(b'\r\n\r\n')
            upstream_write(b''.join(s).encode())
            client.read_until_close(upstream.close, upstream_write)
            upstream.read_until_close(client.close, client_write)
        else:
            client_write(b'HTTP/1.1 200 Connection established\r\n\r\n')
            client.read_until_close(upstream.close, upstream_write)
            upstream.read_until_close(client.close, client_write)


class ForceProxyHandler(ProxyHandler):
    def getparent(self, level=3):
        self._getparent(level)


class autoproxy_rule(object):
    def __init__(self, arg):
        super(autoproxy_rule, self).__init__()
        if not isinstance(arg, str):
            arg = str(arg)
        self.rule = arg.strip()
        if len(self.rule) < 3 or self.rule.startswith('!') or self.rule.startswith('[') or '#' in self.rule:
            raise TypeError("invalid autoproxy_rule: %s" % self.rule)
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
                regex = r'^(?:https://)?%s(?:[:/]|$)' % regex.replace('.', r'\.').replace('*', '[^/]*')
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
        # url must be something like https://www.google.com
        if self._ptrn.search(uri):
            logging.debug('Autoproxy Rule match {}'.format(self.rule))
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
            logging.debug('Match redirect rule addressbar-search')
            return result
        for rule, result in self.lst:
            if rule.match(uri):
                logging.debug('Match redirect rule {}, {}'.format(rule.rule, result))
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
        self.override = []
        self.gfwlist_force = []
        self.hostinchina = {}

        def add_rule(line, force=False):
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
                f.seek(0)
                if f.readline().startswith('[AutoProxy'):
                    for line in f:
                        add_rule(line)
                else:
                    logging.warning('./fgfw-lite/gfwlist.txt is corrupted!')

        self.chinanet = []
        self.chinanet.append(ipaddress.ip_network('192.168.0.0/16'))
        self.chinanet.append(ipaddress.ip_network('172.16.0.0/12'))
        self.chinanet.append(ipaddress.ip_network('10.0.0.0/8'))
        self.chinanet.append(ipaddress.ip_network('127.0.0.0/8'))
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

            self.chinanet.append(ipaddress.ip_network('{}/{}'.format(starting_ip, mask2)))

    def ifgfwed(self, uri, host, level=1):
        def ifhost_in_china():
            if not host:
                return None
            if host in self.hostinchina:
                return self.hostinchina.get(host)
            try:
                ipo = ipaddress.ip_address(socket.gethostbyname(host))
            except Exception:
                return None
            if any(ipo in net for net in self.chinanet):
                logging.info('%s in china' % host)
                self.hostinchina[host] = True
                return True
            self.hostinchina[host] = False
            return False

        def if_gfwlist_force():
            for rule in self.gfwlist_force:
                if hasattr(rule, 'expire') and time.time() > rule.expire:
                    self.gfwlist_force.remove(rule)
                    logging.debug('%s expired' % rule.rule)
                elif rule.match(uri):
                    return True

        forceproxy = False

        if level == 0:
            return False
        elif level == 1:
            pass
        elif level == 2:
            forceproxy = True
        if level == 3:
            a = True
        else:
            a = if_gfwlist_force()

        if not a and ifhost_in_china():
            return None

        if a or forceproxy or any(rule.match(uri) for rule in self.gfwlist):
            if any(rule.match(uri) for rule in self.override):
                return False
            return True

    def parentproxy(self, uri, host, level=1):
    # 0 -- direct
    # 1 -- proxy if force, direct if ip in china or override, proxy if gfwlist
    # 2 -- proxy if force, direct if ip in china or override, proxy if all
    # 3 -- proxy if not override
        '''
            decide which parentproxy to use.
            url:  'https://www.google.com'
            domain: 'www.google.com'
        '''
        # return ('direct', conf.parentdict.get('direct'))

        f = self.ifgfwed(uri, host, level)
        parentlist = conf.parentdict.keys()
        if 'cow' in parentlist:
            parentlist.remove('cow')
        parentlist.remove('direct')

        if f is False:
            return ('direct', conf.parentdict.get('direct'))
        if f is True:
            if parentlist:
                if len(parentlist) == 1:
                    return (parentlist[0], conf.parentdict.get(parentlist[0]))
                else:
                    hosthash = hashlib.md5(host).hexdigest()
                    ppname = parentlist[int(hosthash, 16) % len(parentlist)]
                    return (ppname, conf.parentdict.get(ppname))
            else:
                logging.warning('No parent proxy available, direct connection is used')
        if 'cow' in conf.parentdict.keys() and not uri.startswith('ftp://'):
            return ('cow', conf.parentdict.get('cow'))
        return ('none', conf.parentdict.get('direct'))

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
            CTIMEOUT = min(max(3, max(ctimer) * 5), 15)
            logging.info('conn timeout set to: %s' % CTIMEOUT)
            ctimer = []
        else:
            CTIMEOUT = min(CTIMEOUT + 2, 15)
        if rtimer:
            logging.info('max read time: %ss in %s' % (max(rtimer), len(rtimer)))
            RTIMEOUT = min(max(4, max(rtimer) * 10), 15)
            logging.info('read timeout set to: %s' % RTIMEOUT)
            rtimer = []
        else:
            RTIMEOUT = min(RTIMEOUT + 2, 15)


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
            logging.info('{} NOT updated. Reason: {}'.format(path, e))
        else:
            if r.getcode() == 200:
                with open(path, 'wb') as localfile:
                    localfile.write(r.read())
                conf.version.set('Update', path.replace('./', '').replace('/', '-'), r.info().getheader('ETag'))
                logging.info('%s Updated.' % path)
            else:
                logging.info('{} NOT updated. Reason: {}'.format(path, str(r.getcode())))


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
            listen_ip, listen_port = listen.rsplit(':', 1)
        else:
            listen_ip = '127.0.0.1'
            listen_port = listen

        goagent = SConfigParser()
        goagent.read('./goagent/proxy.ini')
        goagent.set('listen', 'ip', listen_ip)
        goagent.set('listen', 'port', listen_port)

        if self.enable:
            conf.addparentproxy('GoAgent', 'http://127.0.0.1:%s' % listen_port)

        goagent.set('gae', 'profile', conf.userconf.dget('goagent', 'profile', 'google_cn'))
        goagent.set('gae', 'appid', conf.userconf.dget('goagent', 'goagentGAEAppid', 'goagent'))
        goagent.set("gae", "password", conf.userconf.dget('goagent', 'goagentGAEpassword', ''))
        goagent.set('gae', 'obfuscate', conf.userconf.dget('goagent', 'obfuscate', '0'))
        goagent.set('gae', 'validate', conf.userconf.dget('goagent', 'validate', '0'))
        goagent.set('gae', 'options', conf.userconf.dget('goagent', 'options', ''))
        goagent.set('pac', 'enable', '0')
        goagent.set('paas', 'fetchserver', conf.userconf.dget('goagent', 'paasfetchserver', ''))
        if conf.userconf.dget('goagent', 'paasfetchserver'):
            goagent.set('paas', 'enable', '1')
            if self.enable:
                conf.addparentproxy('GoAgent-PAAS', 'http://127.0.0.1:8088')
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
        self.filelist = [['https://github.com/v3aqb/fgfw-lite/raw/master/shadowsocks/local.py', './shadowsocks/local.py'],
                         ['https://github.com/v3aqb/fgfw-lite/raw/master/shadowsocks/encrypt.py', './shadowsocks/encrypt.py'],
                         ['https://github.com/v3aqb/fgfw-lite/raw/master/shadowsocks/utils.py', './shadowsocks/utils.py']]
        self.cmd = '{} -B {}/shadowsocks/local.py'.format(PYTHON2, WORKINGDIR)
        self.cwd = '%s/shadowsocks' % WORKINGDIR
        self.enable = conf.userconf.dgetbool('shadowsocks', 'enable', False)
        self.enableupdate = conf.userconf.dgetbool('shadowsocks', 'update', True)
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
                import random
                import json
                config = {}
                config['server'] = conf.userconf.dget('shadowsocks', 'server', '127.0.0.1').strip('"')
                config['server_port'] = conf.userconf.dget('shadowsocks', 'server_port', '8388')
                config['password'] = conf.userconf.dget('shadowsocks', 'password', 'barfoo!').strip('"')
                config['method'] = conf.userconf.dget('shadowsocks', 'method', 'aes-256-cfb').strip('"')
                config['local_port'] = 1080
                portlst = []
                if not config['server_port'].isdigit():
                    for item in config['server_port'].split(','):
                        if item.strip().isdigit():
                            portlst.append(int(item.strip()))
                        else:
                            a, b = item.strip().split('-')
                            for i in range(int(a), int(b) + 1):
                                portlst.append(i)
                    config['server_port'] = portlst
                else:
                    config['server_port'] = int(config['server_port'])
                if config['server'].startswith('['):
                    config['server'] = json.loads(config['server'])
                with open('./shadowsocks/config.json', 'wb') as f:
                    f.write(json.dumps(config, indent=4, separators=(',', ': ')))
                self.cmd = '{} -c {}'.format(self.cmd, '%s/shadowsocks/config.json' % WORKINGDIR)
            conf.addparentproxy('shadowsocks', 'socks5://127.0.0.1:1080')


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
            p = urlparse.urlparse(item)
            pptype, pphost, ppport, ppusername, pppassword = (p.scheme or None, p.hostname or p.path or None, p.port, p.username, p.password)
            if pphost:
                if pptype is None:
                    pptype = 'http'
                r = re.match(r'^(.*)\:(\d+)$', pphost)
                if r:
                    pphost, ppport = r.group(1), int(r.group(2))
            if pptype is None or key == 'cow':
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
            conf.addparentproxy('cow', 'http://127.0.0.1:8117')


class fgfwproxy(FGFWProxyHandler):
    """docstring for ClassName"""
    def __init__(self, arg=''):
        FGFWProxyHandler.__init__(self)
        self.arg = arg

    def _config(self):
        self.filelist = [['https://autoproxy-gfwlist.googlecode.com/svn/trunk/gfwlist.txt', './fgfw-lite/gfwlist.txt'],
                         ['http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest', './fgfw-lite/delegated-apnic-latest'],
                         ['https://github.com/v3aqb/fgfw-lite/raw/master/fgfw-lite/fgfw-lite.py', './fgfw-lite/fgfw-lite.py'],
                         ['https://github.com/v3aqb/fgfw-lite/raw/master/fgfw-lite/cloud.txt', './fgfw-lite/cloud.txt'],
                         ['https://github.com/v3aqb/fgfw-lite/raw/master/userconf.sample.ini', './userconf.sample.ini'],
                         ['https://github.com/v3aqb/fgfw-lite/raw/master/README.md', './README.md'],
                         ['https://github.com/v3aqb/fgfw-lite/raw/master/Python27/python27.zip', './Python27/python27.zip'],
                         ]
        self.enable = conf.userconf.dgetbool('fgfwproxy', 'enable', True)
        self.enableupdate = conf.userconf.dgetbool('fgfwproxy', 'update', True)
        self.listen = conf.userconf.dget('fgfwproxy', 'listen', '8118')
        if conf.userconf.dgetbool('FGFW_Lite', 'debuginfo', False):
            logging.basicConfig(level=logging.DEBUG)

    def start(self):
        if self.enable:
            if ':' in self.listen:
                self.run_proxy(self.listen.rsplit(':', 1)[1], address=self.listen.rsplit(':', 1)[0])
            else:
                self.run_proxy(self.listen)

    def run_proxy(self, port, start_ioloop=True):
        """
        Run proxy on the specified port. If start_ioloop is True (default),
        the tornado IOLoop will be started immediately.
        """
        print("Starting HTTP proxy on port {} and {}".format(port, str(int(port) + 1)))
        app = Application([(r'.*', ProxyHandler), ])
        http_server = HTTPProxyServer(app)
        http_server.listen(8118)
        app2 = Application([(r'.*', ForceProxyHandler), ])
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
        self.userconf.read('userconf.ini')

    def addparentproxy(self, name, proxy):
        '''
        {
            'direct': (None, None, None, None, None),
            'goagent': ('http', '127.0.0.1', 8087, None, None)
        }  # type, host, port, username, password
        '''
        self.parentdict[name] = proxy

conf = Config()
conf.addparentproxy('direct', '')


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
        conf.addparentproxy('https', 'https://%s%s:%s' % ('%s:%s@' % (user, passwd) if user else '', host, port))
    if conf.userconf.dgetbool('cow', 'enable', True):
        cowHandler()
    updatedaemon = Thread(target=updater)
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

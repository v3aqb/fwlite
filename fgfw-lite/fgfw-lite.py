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

__version__ = '0.3.6.2'

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
import encrypt
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
import tornado.ioloop
import tornado.iostream
import tornado.web
from tornado import gen, stack_context
from tornado.concurrent import run_on_executor
from tornado.httputil import HTTPHeaders
from tornado.httpserver import HTTPConnection, HTTPServer, _BadRequestException, HTTPRequest
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


class Application(tornado.web.Application):
    def log_request(self, handler):
        if "log_function" in self.settings:
            self.settings["log_function"](handler)
            return
        if handler.request.method == 'CONNECT':
            return
        request_time = 1000.0 * handler.request.request_time()
        if handler.get_status() < 400:
            log_method = logging.info
            if request_time < 500:
                log_method = logging.debug

        elif handler.get_status() < 500:
            log_method = logging.warning
        else:
            log_method = logging.error
        log_method("%d %s %.2fms", handler.get_status(), handler._request_summary(), request_time)


class HTTPProxyConnection(HTTPConnection):
    def __init__(self, stream, address, request_callback, no_keep_alive=False,
                 xheaders=False, protocol=None):
        super(HTTPProxyConnection, self).__init__(stream, address, request_callback, no_keep_alive=False,
                                                  xheaders=False, protocol=None)
        self._timeout = tornado.ioloop.IOLoop.current().add_timeout(time.time() + 10, stack_context.wrap(self.close))

    def _handle_events(self, fd, events):
        if self.stream.closed():
            logging.warning("Got events for closed stream %d", fd)
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
            logging.error("Uncaught exception, closing connection.",
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
        self._timeout.callback = None
        try:
            raw_data = data
            data = unicode(data.decode('latin1'))
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

            if method == 'POST' and int(headers.get("Content-Length", 0)) > 65535:
                # overwrite self.stream.read_from_fd, force a block
                setattr(self.stream, 'read_from_fd', self.read_from_fd)
                setattr(self.stream, '_handle_events', self._handle_events)
                self.stream.io_loop.remove_handler(self.stream.fileno())
                self.stream._state = None
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
            self._request.raw_data = raw_data
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


class ssClientStream(tornado.iostream.IOStream):

    def connect(self, address, ssServer, callback=None, server_hostname=None):
        '''
        connect address via ssServer
        ssServer: 'ss://method:password@hostname:port'
        '''
        p = urlparse.urlparse(ssServer)
        self._ssr = address
        self._sscb = callback
        _, sshost, ssport, ssmethod, sspassword = (p.scheme, p.hostname, p.port, p.username, p.password)
        self.crypto = encrypt.Encryptor(sspassword, ssmethod)
        super(ssClientStream, self).connect((sshost, ssport), self.ss_conn)

    def ss_conn(self):
        host, port = self._ssr
        data = b''.join([b'\x03',
                        chr(len(host)).encode(),
                        host.encode(),
                        struct.pack(b">H", port)])
        self.write(data, self._sscb)

    def read_from_fd(self):
        chunk = super(ssClientStream, self).read_from_fd()
        if chunk:
            return self.crypto.decrypt(chunk)
        return chunk

    def write(self, data, callback=None):
        super(ssClientStream, self).write(self.crypto.encrypt(data), callback)


class ProxyHandler(tornado.web.RequestHandler):
    SUPPORTED_METHODS = ('GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'TRACE', 'CONNECT', 'OPTIONS')
    LOCALHOST = ('127.0.0.1', '::1', 'localhost')
    DEFAULT_PORT = {'http': 80, 'https': 443, 'socks5': 1080, }
    executor = ThreadPoolExecutor(10)

    def _getparent(self, level=1):
        if not self._proxylist:
            self._proxylist = PARENT_PROXY.parentproxy(self.request.uri, self.request.host.rsplit(':', 1)[0], level)
        self.ppname = self._proxylist.pop(0)
        p = urlparse.urlparse(conf.parentdict.get(self.ppname))
        self.pptype, self.pphost, self.ppport, self.ppusername, self.pppassword = (p.scheme or None, p.hostname or p.path or None, p.port, p.username, p.password)
        if self.pphost:
            self.pptype = self.pptype or 'http'
            r = re.match(r'^(.*)\:(\d+)$', self.pphost)
            if r:
                self.pphost, self.ppport = r.groups()
        self.ppport = self.ppport or self.DEFAULT_PORT.get(self.pptype)
        if self.pptype in ('socks5', 'ss'):
            self.upstream_name = '{}-{}-{}'.format(self.ppname, self.request.host, str(self.requestport))
        else:
            self.upstream_name = self.ppname if self.pphost else '{}-{}'.format(self.request.host, str(self.requestport))

        logging.info('{} {} via {}'.format(self.request.method, self.uris, self.ppname))

    def getparent(self, level=1):
        self._getparent(level)

    def prepare(self):
        self._proxy_retry = 0
        self._no_retry = False
        self._timeout = None
        self._success = False
        self.ppname, self.pptype, self.pphost, self.ppport, self.ppusername, self.pppassword = 'direct', None, None, None, None, None
        self._proxylist = []
        self._crbuffer = []
        self._state = 'prepare'
        # transparent proxy
        if self.request.uri.startswith('/') and self.request.host != "127.0.0.1":
            self.request.uri = 'http://%s%s' % (self.request.host, self.request.uri)

        self.uris = '%s%s' % (self.request.uri.split('?')[0], '?' if len(self.request.uri.split('?')) > 1 else '')

        # redirector
        new_url = REDIRECTOR.get(self.request.uri)
        if new_url:
            logging.info('redirecting %s to %s' % (self.uris, new_url))
            if new_url.startswith('403'):
                self.send_error(status_code=403)
            if new_url.startswith('adblock'):
                self.set_header('Content-type', 'image/gif')
                self._write_buffer.append(b'GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x01D\x00;')
                self.finish()
            else:
                self.redirect(new_url)
            return

        # try to get host from uri
        if self.request.host == "127.0.0.1":  # no host section in headers
            if not self.request.uri.startswith('/'):
                self.request.headers['Host'] = self.request.host = self.request.uri.split('/')[2] if '//' in self.request.uri else self.request.uri
            else:
                self.send_error(status_code=501)
                return

        if any(host == self.request.host.rsplit(':', 1)[0] for host in self.LOCALHOST):
            self.send_error(status_code=403)
            return

        if self.request.method == 'CONNECT':
            self.requestport = int(self.request.uri.rsplit(':', 1)[1])
        else:
            self.requestport = int(self.request.host.rsplit(':', 1)[1]) if ':' in self.request.host else 80

        if self.request.method == 'CONNECT':
            self.request.connection.stream.write(b'HTTP/1.1 200 Connection established\r\n\r\n')
            self._headers_written = True

    @run_on_executor
    def create_connection(self, host, port, family=socket.AF_UNSPEC):
        hosts = HOSTS.get(host, [])
        for ipaddr in hosts:
            try:
                s = socket.create_connection((ipaddr, port), timeout=2)
                return s
            except socket.error:
                pass
        try:
            s = socket.create_connection((host, port), timeout=5)
            return s
        except socket.error:
            pass
        return None

    @run_on_executor
    def resolve(self, host, port, family=socket.AF_UNSPEC):
        addrinfo = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)
        results = []
        for family, socktype, proto, canonname, address in addrinfo:
            results.append((family, address))
        return results

    @gen.coroutine
    def connect_remote_with_proxy(self):
        logging.debug('connecting to server')
        self._state = 'connecting'

        if self.pptype is None:
            s = yield self.create_connection(self.request.host.rsplit(':', 1)[0], self.requestport)
            if s:
                self.upstream = tornado.iostream.IOStream(s)
                self.upstream.set_close_callback(self.on_upstream_close)
            elif self._proxylist:
                yield self.get_remote_conn()
            else:
                self.send_error(status_code=504)
        elif self.pptype == 'http':
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
            self.upstream = tornado.iostream.IOStream(s)
            self.upstream.set_close_callback(self.on_upstream_close)
            yield gen.Task(self.upstream.connect, (self.pphost, int(self.ppport)))
        elif self.pptype == 'https':
            if self._proxylist:  # on connection timeout
                self._timeout = tornado.ioloop.IOLoop.current().add_timeout(time.time() + CTIMEOUT, stack_context.wrap(self.on_upstream_close))
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
            self.upstream = tornado.iostream.SSLIOStream(s)
            self.upstream.set_close_callback(self.on_upstream_close)
            yield gen.Task(self.upstream.connect, (self.pphost, int(self.ppport)))
        elif self.pptype == 'ss':
            if self._proxylist:  # on connection timeout
                self._timeout = tornado.ioloop.IOLoop.current().add_timeout(time.time() + CTIMEOUT, stack_context.wrap(self.on_upstream_close))
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
            self.upstream = ssClientStream(s)
            self.upstream.set_close_callback(self.on_upstream_close)
            yield gen.Task(self.upstream.connect, (self.request.host.rsplit(':', 1)[0], self.requestport), conf.parentdict.get(self.ppname))
        elif self.pptype == 'socks5':
            logging.debug('connecting to socks5 server')
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
            self.upstream = tornado.iostream.IOStream(s)
            self.upstream.set_close_callback(self.on_upstream_close)
            yield gen.Task(self.upstream.connect, (self.pphost, int(self.ppport)))
            try:
                self.upstream.set_nodelay(True)
                yield gen.Task(self.upstream.write, b"\x05\x02\x00\x02" if self.ppusername else b"\x05\x01\x00")
                data = yield gen.Task(self.upstream.read_bytes, 2)
                if data == b'\x05\x02':  # basic auth
                    self.upstream.write(b''.join([b"\x01",
                                                 chr(len(self.ppusername)).encode(),
                                                 self.ppusername.encode(),
                                                 chr(len(self.pppassword)).encode(),
                                                 self.pppassword.encode()]))
                    data = yield gen.Task(self.upstream.read_bytes, 2)

                assert data[1] == b'\x00'  # no auth needed or auth passed
                self.upstream.write(b''.join([b"\x05\x01\x00\x03",
                                    chr(len(self.request.host.rsplit(':', 1)[0])).encode(),
                                    self.request.host.rsplit(':', 1)[0].encode(),
                                    struct.pack(b">H", self.requestport)]))
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
                if self._proxylist:
                    yield self.get_remote_conn()
                else:
                    self.send_error(status_code=504)
        logging.debug('remote server connected')
        self.remove_timeout()

    @gen.coroutine
    def get_remote_conn(self):
        self.getparent()
        self.upstream = None
        if self.request.method != 'CONNECT' and self._proxy_retry == 0:
            lst = UPSTREAM_POOL.get(self.upstream_name, [])
            for item in lst:
                lst.remove(item)
                if item.last_active < time.time() - 5:  # keep-alive for 5s
                    if not item.closed():
                        item.close()
                elif not item.closed():
                    logging.debug('reuse connection')
                    self.upstream = item
                    self.upstream.set_close_callback(self.on_upstream_close)
                    break
        if self.upstream is None:
            yield self.connect_remote_with_proxy()

    @gen.coroutine
    @tornado.web.asynchronous
    def get(self):
        yield self.get_remote_conn()

        if self._finished:
            return
        logging.debug('GET')
        self._state = 'get'
        client = self.request.connection.stream
        self._client_write_buffer = []

        def _do_client_write(data):
            self.remove_timeout()
            if not client.closed():
                client.write(data)
                self._headers_written = True
                self._no_retry = True

        def _client_write(data):
            if self._headers_written:
                _do_client_write(data)
            else:
                self._client_write_buffer.append(data)
                if len(b''.join(self._client_write_buffer)) > 65536:
                    while self._client_write_buffer:
                        _do_client_write(self._client_write_buffer.pop(0))

        def body_transfer(s, d, callback):
            def read_from():
                if self.__content_length > 0:
                    s.read_bytes(min(self.__content_length, 65536), write_to)
                    self.__content_length -= min(self.__content_length, 65536)
                else:
                    callback()

            def write_to(data=None):
                if int(self.request.headers.get("Content-Length")) < 65536:
                    self._crbuffer.append(data)
                else:
                    self._no_retry = True
                if not d.closed():
                    d.write(data, read_from)

            read_from()

        def _sent_request():
            logging.debug('remote server connected, sending http request')
            self._state = 'sent Request'
            if self.pptype in ('http', 'https'):
                s = u'%s %s %s\r\n' % (self.request.method, self.request.uri, self.request.version)
                if self.ppusername and 'Proxy-Authorization' not in self.request.headers:
                    a = '%s:%s' % (self.ppusername, self.pppassword)
                    self.request.headers['Proxy-Authorization'] = 'Basic %s\r\n' % base64.b64encode(a.encode())
            else:
                s = u'%s /%s %s\r\n' % (self.request.method, '/'.join(self.request.uri.split('/')[3:]), self.request.version)
            s = [s, ]
            s.append(u'\r\n'.join([u'%s: %s' % (key, value) for key, value in self.request.headers.items()]))
            s.append(u'\r\n\r\n')
            self.upstream.write(u''.join(s).encode('latin1'), _sent_body)

        def _sent_body():
            self._state = 'sent request body'
            content_length = self.request.headers.get("Content-Length")
            if content_length:
                logging.debug('sending request body')
                if not hasattr(self, '__content_length'):
                    self.__content_length = int(content_length)
                if self._crbuffer:
                    self.upstream.write(b''.join(self._crbuffer))
                body_transfer(client, self.upstream, read_headers)
            else:
                read_headers()

        def read_headers(data=None):
            self._state = 'read headers'
            logging.debug('reading response header')
            self.__t = time.time()
            if self._proxylist:
                self._timeout = tornado.ioloop.IOLoop.current().add_timeout(time.time() + RTIMEOUT, stack_context.wrap(self.on_upstream_close))
            self.upstream.read_until_regex(r"\r?\n\r?\n", _on_headers)

        def _on_headers(data=None):
            self._state = 'resolve headers'
            rtimer.append(time.time() - self.__t)
            _data = unicode(data, 'latin1')
            first_line, _, header_data = _data.partition("\n")
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
            try:
                self._headers = HTTPHeaders.parse(header_data)
            except Exception:
                self._headers = HTTPHeaders.parse(str('Connection: close'))

            _client_write(data)

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
            self._state = '_on_body'
            if self.request.method == "HEAD" or 100 <= self.get_status() < 200 or\
                    self.get_status() in (204, 304):
                _finish()
            elif self._headers.get("Transfer-Encoding") and self._headers.get("Transfer-Encoding") != "identity":
                self.upstream.read_until(b"\r\n", _on_chunk_lenth)
            elif content_length is not None:
                logging.debug('reading response body')
                self.upstream.read_bytes(content_length, _finish, streaming_callback=_client_write)
            else:
                logging.debug('reading response body')
                self._headers["Connection"] = "close"
                self.upstream.set_close_callback(None)
                self.upstream.read_until_close(_finish, _client_write)

        def _on_chunk_lenth(data):
            _client_write(data)
            logging.debug('reading chunk data')
            self._state = '_on_chunk_lenth'
            length = int(data.strip(), 16)
            self.upstream.read_bytes(length + 2,  # chunk ends with \r\n
                                     _on_chunk_data)

        def _on_chunk_data(data):
            self._state = '_on_chunk_data'
            _client_write(data)
            if len(data) != 2:
                logging.debug('reading chunk lenth')
                self.upstream.read_until(b"\r\n", _on_chunk_lenth)
            else:
                _finish()

        def _finish(data=None):
            if self._client_write_buffer:
                _do_client_write(b''.join(self._client_write_buffer))
            self._success = True
            conn_header = self._headers.get("Connection", '').lower()
            if self.request.supports_http_1_1():
                _close_flag = conn_header == 'close'
            else:
                _close_flag = conn_header != 'keep_alive'
            self.upstream.set_close_callback(None)
            if _close_flag:
                self.upstream.close()
                client.close()
            elif not self.upstream.closed():
                self.upstream.last_active = time.time()
                UPSTREAM_POOL[self.upstream_name].append(self.upstream)
                logging.debug('pooling remote connection')
            if not self._finished:
                self.finish()

        _sent_request()

    options = post = delete = trace = put = head = get

    def remove_timeout(self):
        if self._timeout is not None:
            self._timeout.callback = None

    def on_finish(self):
        logging.debug('on finish')
        logging.debug('self._success? %s' % self._success)
        logging.debug('retry? %s' % self._proxy_retry)
        self.remove_timeout()
        if all((self._success, self.get_status() < 400, self._proxy_retry)) or\
                all((self.request.method == 'CONNECT', not self._success, self.ppname == 'direct', self._proxylist)):
            rule = '%s%s' % ('|https://' if self.request.method == 'CONNECT' else '|http://', self.request.host.split(':')[0])
            PARENT_PROXY.add_temp_rule(rule)

    def on_connection_close(self):
        logging.debug('client connection closed')
        try:
            self.upstream.set_close_callback(None)
            self.upstream.close()
        except Exception:
            pass
        if not self._finished:
            self.finish()

    @gen.coroutine
    def on_upstream_close(self):
        # possible GFW reset or timeout
        logging.debug('on_upstream_close upstream closed? %s' % self.upstream.closed())
        self.remove_timeout()
        if not self.upstream.closed():
            self.upstream.set_close_callback(None)
            self.upstream.close()
        logging.debug('request finished? %s headers_written? %s' % (self._finished, self._headers_written))
        if not self._finished:
            if not self._no_retry:
                if self._proxylist:
                    logging.warning('%s %s Failed, info: %s, retry...' % (self.request.method, self.uris, self._state))
                    self.clear()
                    self._proxy_retry += 1
                    yield self.get_remote_conn()
                    if self.request.method == 'CONNECT':
                        self.connect()
                    else:
                        self.get()
                else:
                    logging.warning('%s %s FAILED! info: %s' % (self.request.method, self.uris, self._state))
                    if not self._headers_written:
                        self.send_error(504)
            else:
                if self.request.method != 'CONNECT':
                    logging.warning('%s %s FAILED! info: %s' % (self.request.method, self.uris, self._state))
                if not self.request.connection.stream.closed():
                    self.request.connection.stream.close()

    @gen.coroutine
    @tornado.web.asynchronous
    def connect(self):
        yield self.get_remote_conn()

        def upstream_write(data=None):
            if data is None:
                data = b''.join(self._crbuffer)
            elif data and self._no_retry is False:
                self._crbuffer.append(data)
            if data and not upstream.closed():
                upstream.write(data)

        def client_write(data):
            self._no_retry = True
            if len(data) > 128:
                self._success = True
                self.remove_timeout()
            if not client.closed():
                client.write(data)

        def forward(data=None):
            if data:
                assert b' 200 ' in data
            upstream_write()
            client.read_until_close(upstream.close, upstream_write)
            upstream.read_until_close(client.close, client_write)

        logging.debug('CONNECT')
        self._state = 'connect method'
        client = self.request.connection.stream
        upstream = self.upstream

        if self.ppname not in ('direct', 'goagent'):  # detect bad shadowsocks server
            self._timeout = tornado.ioloop.IOLoop.current().add_timeout(time.time() + RTIMEOUT, stack_context.wrap(self.on_upstream_close))
        if self.pptype and 'http' in self.pptype:
            s = [b'%s %s %s\r\n' % (self.request.method, self.request.uri, self.request.version), ]
            if 'Proxy-Authorization' not in self.request.headers and self.ppusername:
                a = '%s:%s' % (self.ppusername, self.pppassword)
                self.request.headers['Proxy-Authorization'] = 'Basic %s\r\n' % base64.b64encode(a.encode())
            s.append(b'\r\n'.join(['%s: %s' % (key, value) for key, value in self.request.headers.items()]).encode('utf8'))
            s.append(b'\r\n\r\n')
            upstream.write(b''.join(s).encode(), upstream.read_until_regex(r"\r?\n\r?\n", forward))
        else:
            forward()

    def _request_summary(self):
        return '%s %s (%s)' % (self.request.method, self.uris, self.request.remote_ip)


class ForceProxyHandler(ProxyHandler):
    def getparent(self, level=3):
        self._getparent(level)


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
                         ('https://github.com/v3aqb/fgfw-lite/raw/master/fgfw-lite/fgfw-lite.py', './fgfw-lite/fgfw-lite.py'),
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
        if self.enable:
            if self.listen.isdigit():
                port = self.listen
                addr = '127.0.0.1'
            else:
                addr, port = self.listen.rsplit(':', 1)
            self.run_proxy(int(port), address=addr)

    def run_proxy(self, port=8118, address='', start_ioloop=True):
        """
        Run proxy on the specified port. If start_ioloop is True (default),
        the tornado IOLoop will be started immediately.
        """
        logging.info("Starting HTTP proxy on port {} and {}".format(port, str(int(port) + 1)))
        app = Application([(r'.*', ProxyHandler), ], transforms=[])
        http_server = HTTPProxyServer(app)
        http_server.listen(port, address=address)
        app2 = Application([(r'.*', ForceProxyHandler), ], transforms=[])
        http_server2 = HTTPProxyServer(app2)
        http_server2.listen(port + 1, address=address)
        ioloop = tornado.ioloop.IOLoop.instance()
        pcallback = tornado.ioloop.PeriodicCallback(self.purge, 90000, io_loop=ioloop)
        pcallback.start()
        if start_ioloop:
            ioloop.start()

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

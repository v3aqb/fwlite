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

__version__ = '0.3.5.4'

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
import bisect
import hashlib
import socket
import struct
import urllib2
import urlparse
from repoze.lru import lru_cache
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

UPSTREAM_POOL = {}
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
            f.write('! local gfwlist config\n! rules: https://adblockplus.org/zh_CN/filters\n')

    for item in ['./userconf.ini', './fgfw-lite/local.txt']:
        with open(item) as f:
            data = open(item).read()
        with open(item, 'w') as f:
            f.write(data)


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
        default_port = {'http': 80, 'https': 443, 'socks5': 1080, }
        self.ppname, pp = PARENT_PROXY.parentproxy(self.request.uri, self.request.host.rsplit(':', 1)[0], level)
        p = urlparse.urlparse(pp)
        self.pptype, self.pphost, self.ppport, self.ppusername, self.pppassword = (p.scheme or None, p.hostname or p.path or None, p.port, p.username, p.password)
        if self.pphost:
            if self.pptype is None:
                self.pptype = 'http'
            r = re.match(r'^(.*)\:(\d+)$', self.pphost)
            if r:
                self.pphost, self.ppport = r.group(1), int(r.group(2))
        self.ppport = self.ppport or default_port.get(self.pptype)
        if self.pptype == 'socks5':
            self.upstream_name = '{}-{}-{}'.format(self.ppname, self.request.host, str(self.requestport))
        else:
            self.upstream_name = self.ppname if self.pphost else '{}-{}'.format(self.request.host, str(self.requestport))

        logging.info('{} {} via {}'.format(self.request.method, self.uris, self.ppname))

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

        self.uris = '%s%s' % (self.request.uri.split('?')[0], '?' if len(self.request.uri.split('?')) > 1 else '')

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
                    logging.debug('reuse connection')
                    self.upstream = item
                    self.upstream.set_close_callback(self.on_upstream_close)
                    break
        if not hasattr(self, 'upstream'):
            logging.debug('connecting to server')
            if self.ppname == 'none':
                self._timeout = tornado.ioloop.IOLoop.current().add_timeout(time.time() + CTIMEOUT, stack_context.wrap(self.on_upstream_close))
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
            self.upstream = tornado.iostream.IOStream(s)
            self.upstream.set_close_callback(self.on_upstream_close)
            if self.pptype is None:
                t = time.time()
                yield gen.Task(self.upstream.connect, (conf.hosts.get(self.request.host.rsplit(':', 1)[0]) or self.request.host.rsplit(':', 1)[0], self.requestport))
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
                self._headers_written = True

        def _client_write(data):
            if self._headers_written:
                _do_client_write(data)
            else:
                self._client_write_buffer.append(data)
                if len(b''.join(self._client_write_buffer)) > 512000:
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
                if not d.closed():
                    d.write(data, read_from)

            read_from()

        def _sent_request():
            logging.debug('remote server connected, sending http request')
            if self.pptype in ('http', 'https'):
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
            if self.ppname != 'direct':
                self._timeout = tornado.ioloop.IOLoop.current().add_timeout(time.time() + RTIMEOUT, stack_context.wrap(self.on_upstream_close))
            self.upstream.read_until_regex(r"\r?\n\r?\n", _on_headers)

        def _on_headers(data=None):
            self.remove_timeout()
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

            if self.request.method == "HEAD" or 100 <= self.get_status() < 200 or\
                    self.get_status() in (204, 304):
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
            self._timeout.callback = None

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
        if (self._success and self._proxy_retry and self.ppname != 'direct') or\
                (not self._success and self.request.method == 'CONNECT' and self.ppname == 'none'):
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
        # possible GFW reset
        logging.debug('on_upstream_close upstream closed? %s' % self.upstream.closed())
        self.remove_timeout()
        if not self.upstream.closed():
            self.upstream.set_close_callback(None)
            self.upstream.close()
            global CTIMEOUT, RTIMEOUT
            CTIMEOUT = min(CTIMEOUT + 1, 15)
            RTIMEOUT = min(RTIMEOUT + 2, 15)
        logging.debug('request finished? %s' % self._finished)
        logging.debug('headers_written? %s' % self._headers_written)
        if not self._finished:
            if not self._headers_written:
                if self._proxy_retry < 4 and self.ppname != 'direct':
                    logging.warning('%s %s Failed, retry...' % (self.request.method, self.uris))
                    self.clear()
                    self.getparent(level=3)
                    self._proxy_retry += 1
                    yield self.get_remote_conn()
                    if self.request.method == 'CONNECT':
                        self.connect()
                    else:
                        self.get()
                else:
                    logging.warning('%s %s FAILED!' % (self.request.method, self.uris))
                    self.send_error(504)
            else:
                if self.request.method != 'CONNECT':
                    logging.warning('%s %s FAILED!' % (self.request.method, self.uris))

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
            if not client.closed():
                client.write(data)
        logging.debug('CONNECT')
        client = self.request.connection.stream
        upstream = self.upstream
        if self.ppname != 'direct':  # detect bad shadowsocks server
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

    def _request_summary(self):
        return '%s %s (%s)' % (self.request.method, self.uris, self.request.remote_ip)


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
        if self._ptrn.search(uri):
            logging.debug('Autoproxy Rule match {}'.format(self.rule))
            return True
        return False


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
                if result.startswith('/') and result.endswith('/'):
                    return rule._ptrn.sub(result[1:-1], uri)
                return result

REDIRECTOR = redirector()


def ip_from_string(ip):
    # https://gist.github.com/cslarsen/1595135
    return reduce(lambda a, b: a << 8 | b, map(int, ip.split(".")))


class parent_proxy(object):
    """docstring for parent_proxy"""
    def config(self):
        self.gfwlist = []
        self.override = []
        self.gfwlist_force = []
        REDIRECTOR.lst = []

        def add_rule(line, force=False):
            line = line.strip()
            if len(line.split()) == 2:  # |http://www.google.com/url forcehttps
                try:
                    o = autoproxy_rule(line.split()[0])
                except TypeError as e:
                    logging.debug('create autoproxy rule failed: %s' % e)
                else:
                    REDIRECTOR.lst.append((o, line.split()[1]))
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
                f.seek(0)
                if f.readline().startswith('[AutoProxy'):
                    for line in f:
                        add_rule(line)
                else:
                    logging.warning('./fgfw-lite/gfwlist.txt is corrupted!')

        self.chinanet = []
        self.chinanet.append((ip_from_string('192.168.0.0'), 2 ** (32 - 16)))
        self.chinanet.append((ip_from_string('172.16.0.0'), 2 ** (32 - 12)))
        self.chinanet.append((ip_from_string('10.0.0.0'), 2 ** (32 - 8)))
        self.chinanet.append((ip_from_string('127.0.0.0'), 2 ** (32 - 8)))

        cnregex = re.compile(r'apnic\|cn\|ipv4\|[0-9\.]+\|[0-9]+\|[0-9]+\|a.*', re.IGNORECASE)

        for item in cnregex.findall(open('./fgfw-lite/delegated-apnic-latest').read()):
            unit_items = item.split('|')
            starting_ip = ip_from_string(unit_items[3])
            num_ip = int(unit_items[4])
            self.chinanet.append((starting_ip, num_ip))

        self.chinanet.sort(key=lambda r: r[0])
        self.iplist = [r[0] for r in self.chinanet]

    @lru_cache(128)
    def ifhost_in_china(self, host):
        try:
            i = ip_from_string(socket.gethostbyname(host))
            a = self.chinanet[bisect.bisect_right(self.iplist, i) - 1]
            if a[0] <= i < a[0] + a[1]:
                logging.info('%s in china' % host)
                return True
            return False
        except Exception:
            return None

    def ifgfwed(self, uri, host, level=1):

        def if_gfwlist_force():
            for rule in self.gfwlist_force:
                if hasattr(rule, 'expire') and time.time() > rule.expire:
                    self.gfwlist_force.remove(rule)
                    logging.debug('%s expired' % rule.rule)
                elif rule.match(uri):
                    return True

        if level == 0:
            return False
        elif level == 2:
            forceproxy = True
        else:
            forceproxy = False

        if level == 3:
            a = True
        else:
            a = if_gfwlist_force()

        if any(rule.match(uri) for rule in self.override):
            return False

        if not a and self.ifhost_in_china(host):
            return None

        if a or forceproxy or any(rule.match(uri) for rule in self.gfwlist):
            return True

    def parentproxy(self, uri, host, level=1):
        # 0 -- direct
        # 1 -- proxy if force, direct if ip in china or override, proxy if gfwlist
        # 2 -- proxy if force, direct if ip in china or override, proxy if all
        # 3 -- proxy if not override
        '''
            decide which parentproxy to use.
            url:  'https://www.google.com'
            host: 'www.google.com'
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

    def config(self):
        self.filelist = [('https://github.com/goagent/goagent/raw/3.0/local/proxy.py', './goagent/proxy.py'),
                         ('https://github.com/goagent/goagent/raw/3.0/local/proxy.ini', './goagent/proxy.ini'),
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
        goagent.read('./goagent/proxy.ini')

        if conf.userconf.dget('goagent', 'GAEAppid', ''):
            conf.addparentproxy('GoAgent', 'http://127.0.0.1:8087')

        goagent.set('gae', 'profile', conf.userconf.dget('goagent', 'profile', 'ipv4'))
        goagent.set('gae', 'mode', conf.userconf.dget('goagent', 'mode', 'https'))
        goagent.set('gae', 'appid', conf.userconf.dget('goagent', 'GAEAppid', 'goagent'))
        goagent.set("gae", "password", conf.userconf.dget('goagent', 'GAEpassword', ''))
        goagent.set('gae', 'obfuscate', conf.userconf.dget('goagent', 'obfuscate', '0'))
        goagent.set('gae', 'validate', conf.userconf.dget('goagent', 'validate', '0'))
        goagent.set('gae', 'options', conf.userconf.dget('goagent', 'options', ''))
        goagent.set('pac', 'enable', '0')

        if conf.userconf.dget('goagent', 'paasfetchserver'):
            goagent.set('php', 'enable', '1')
            goagent.set('php', 'password', conf.userconf.dget('goagent', 'phppassword', '123456'))
            goagent.set('php', 'fetchserver', conf.userconf.dget('goagent', 'phpfetchserver', 'http://.com/'))
            conf.addparentproxy('GoAgent-PAAS', 'http://127.0.0.1:8088')
        else:
            goagent.set('php', 'enable', '0')
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
        subj.commonName = 'GoAgent Root CA'
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
        commonname = 'FGFW_Lite CA'
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

        worknodes = conf.userconf.get('snova', 'GAEworknodes')
        if worknodes:
            worknodes = worknodes.split('|')
            for i in range(len(worknodes)):
                proxy.set('GAE', 'WorkerNode[%s]' % i, worknodes[i])
            proxy.set('GAE', 'Enable', '1')
            conf.userconf.addparentproxy('snova-gae', 'http://127.0.0.1:48101')
        else:
            proxy.set('GAE', 'Enable', '0')

        worknodes = conf.userconf.get('snova', 'C4worknodes')
        if worknodes:
            worknodes = worknodes.split('|')
            for i in range(len(worknodes)):
                proxy.set('C4', 'WorkerNode[%s]' % i, worknodes[i])
            proxy.set('C4', 'Enable', '1')
            fgfwproxy.addparentproxy('snova-c4', 'http://127.0.0.1:48102')
        else:
            proxy.set('C4', 'Enable', '0')

        proxy.set('SPAC', 'Enable', '0')
        proxy.set('Misc', 'RC4Key', conf.userconf.dget('snova', 'RC4Key', '8976501f8451f03c5c4067b47882f2e5'))
        with open('./snova/conf/snova.conf', 'w') as configfile:
            proxy.write(configfile)


class shadowsocksHandler(FGFWProxyHandler):
    """docstring for ClassName"""
    def __init__(self):
        FGFWProxyHandler.__init__(self)

    def config(self):
        self.filelist = [('https://github.com/v3aqb/fgfw-lite/raw/master/shadowsocks/local.py', './shadowsocks/local.py'),
                         ('https://github.com/v3aqb/fgfw-lite/raw/master/shadowsocks/encrypt.py', './shadowsocks/encrypt.py'),
                         ('https://github.com/v3aqb/fgfw-lite/raw/master/shadowsocks/utils.py', './shadowsocks/utils.py'),
                         ]
        self.cmd = '{} -B {}/shadowsocks/local.py'.format(PYTHON2, WORKINGDIR)
        self.cwd = '%s/shadowsocks' % WORKINGDIR
        self.enable = conf.userconf.dgetbool('shadowsocks', 'enable', False)
        self.enableupdate = conf.userconf.dgetbool('shadowsocks', 'update', True)
        if self.enable:
            self._config()

    def _config(self):
        lst = []
        if sys.platform.startswith('win'):
            self.cmd = 'c:/python27/python.exe -B %s/shadowsocks/local.py' % WORKINGDIR
            for cmd in ('ss-local', 'sslocal'):
                if 'XP' in platform.platform():
                    continue
                if subprocess.call(shlex.split('where %s' % cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0:
                    self.cmd = cmd
                    break
            else:
                lst = ['./shadowsocks/ss-local.exe',
                       './shadowsocks/shadowsocks-local.exe',
                       './shadowsocks/shadowsocks.exe']
        elif sys.platform.startswith('linux'):
            for cmd in ('ss-local', 'sslocal'):
                if subprocess.call(shlex.split('which %s' % cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0:
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

    def config(self):
        self.filelist = []
        self.cwd = '%s/cow' % WORKINGDIR

        self.enable = conf.userconf.dgetbool('cow', 'enable', True)
        self.enableupdate = False
        if self.enable:
            self._config()

    def _config(self):
        self.cmd = '%s/cow/cow%s' % (WORKINGDIR, '.exe' if sys.platform.startswith('win') else '')
        self.enableupdate = conf.userconf.dgetbool('cow', 'update', False)
        if not os.path.isfile(self.cmd):
            self.enable = False
            return
        configfile = ['listen = %s' % conf.userconf.dget('cow', 'listen', '127.0.0.1:8117'), ]
        for key, item in conf.parentdict.items():
            if not item or key == 'cow':
                continue
            configfile.append('proxy = %s' % item)

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

    def config(self):
        self.filelist = [('https://autoproxy-gfwlist.googlecode.com/svn/trunk/gfwlist.txt', './fgfw-lite/gfwlist.txt'),
                         ('http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest', './fgfw-lite/delegated-apnic-latest'),
                         ('https://github.com/v3aqb/fgfw-lite/raw/master/fgfw-lite/fgfw-lite.py', './fgfw-lite/fgfw-lite.py'),
                         ('https://github.com/v3aqb/fgfw-lite/raw/master/fgfw-lite/cloud.txt', './fgfw-lite/cloud.txt'),
                         ('https://github.com/v3aqb/fgfw-lite/raw/master/userconf.sample.ini', './userconf.sample.ini'),
                         ('https://github.com/v3aqb/fgfw-lite/raw/master/README.md', './README.md'),
                         ('https://github.com/v3aqb/fgfw-lite/raw/master/Python27/python27.zip', './Python27/python27.zip'),
                         ]
        self.enable = conf.userconf.dgetbool('fgfwproxy', 'enable', True)
        self.enableupdate = conf.userconf.dgetbool('fgfwproxy', 'update', True)
        self.listen = conf.userconf.dget('fgfwproxy', 'listen', '8118')
        if conf.userconf.dgetbool('FGFW_Lite', 'debuginfo', False):
            logging.basicConfig(level=logging.DEBUG)

    def start(self):
        if self.enable:
            self.run_proxy(8118)

    def run_proxy(self, port, start_ioloop=True):
        """
        Run proxy on the specified port. If start_ioloop is True (default),
        the tornado IOLoop will be started immediately.
        """
        logging.info("Starting HTTP proxy on port {} and {}".format(port, str(int(port) + 1)))
        app = Application([(r'.*', ProxyHandler), ], transforms=[])
        http_server = HTTPProxyServer(app)
        http_server.listen(8118)
        app2 = Application([(r'.*', ForceProxyHandler), ], transforms=[])
        http_server2 = HTTPProxyServer(app2)
        http_server2.listen(8119)
        ioloop = tornado.ioloop.IOLoop.instance()
        if start_ioloop:
            ioloop.start()


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
        self.hosts = {}
        if 'hosts' not in self.userconf.sections():
            self.userconf.add_section('hosts')
        for host, ip in self.userconf.items('hosts'):
            self.hosts[host] = ip

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

conf = Config()
conf.addparentproxy('direct', '')


@atexit.register
def atexit_do():
    for item in FGFWProxyHandler.ITEMS:
        item.stop()
    conf.confsave()


def main():
    prestart()
    fgfwproxy()
    goagentHandler()
    snovaHandler()
    shadowsocksHandler()
    for k, v in conf.userconf.items('parents'):
        conf.addparentproxy(k, v)
    cowHandler()
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

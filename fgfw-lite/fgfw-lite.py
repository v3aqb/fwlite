#!/usr/bin/env python
#-*- coding: UTF-8 -*-
#
# FGFW_Lite.py A Proxy Server help go around the Great Firewall
#
# Copyright (C) 2012-2014 Jiang Chao <sgzz.cj@gmail.com>
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
reload(sys).setdefaultencoding('UTF-8')
sys.dont_write_bytecode = True
WORKINGDIR = '/'.join(os.path.dirname(os.path.abspath(__file__).replace('\\', '/')).split('/')[:-1])
if ' ' in WORKINGDIR:
    sys.stderr.write('no spacebar allowed in path\n')
    sys.exit(-1)
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
    sys.stderr.write('Warning: Please update gevent to the latest 1.0 version!\n')
from collections import defaultdict, deque
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
import logging
import random
import select
import shutil
import socket
import struct
import ssl
from threading import Thread
import pygeoip
try:
    import markdown
except ImportError:
    markdown = None
    sys.stderr.write('Warning: python-Markdown is NOT installed!\n')
try:
    from repoze.lru import lru_cache
except ImportError:
    def lru_cache(size=0, timeout=0):
        def decorator(func):
            return func
        return decorator
try:
    import configparser
    import urllib.request as urllib2
    import urllib.parse as urlparse
    urlquote = urlparse.quote
    from socketserver import ThreadingMixIn
    from http.server import BaseHTTPRequestHandler, HTTPServer
except ImportError:
    import urllib2
    import urlparse
    urlquote = urllib2.quote
    import ConfigParser as configparser
    from SocketServer import ThreadingMixIn
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
configparser.RawConfigParser.OPTCRE = re.compile(r'(?P<option>[^=\s][^=]*)\s*(?P<vi>[=])\s*(?P<value>.*)$')

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
PYTHON = sys.executable.replace('\\', '/')

UPSTREAM_POOL = defaultdict(deque)
HOSTS = defaultdict(list)
ctimer = []
CTIMEOUT = 5
NetWorkIOError = (socket.error, ssl.SSLError, OSError)


def prestart():
    s = 'FGFW_Lite ' + __version__
    s += ' with gevent' if gevent else ''
    logging.info(s)

    if not os.path.isfile('./userconf.ini'):
        shutil.copyfile('./userconf.sample.ini', './userconf.ini')

    if not os.path.isfile('./fgfw-lite/local.txt'):
        with open('./fgfw-lite/local.txt', 'w') as f:
            f.write('''
! local gfwlist config
! rules: https://autoproxy.org/zh-CN/Rules
! /^http://www.baidu.com/.*wd=([^&]*).*$/ /https://www.google.com/search?q=\1/
''')

prestart()


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    pass


class HTTPRequestHandler(BaseHTTPRequestHandler):
    def _quote_html(self, html):
        return html.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def redirect(self, url):
        self.send_response(302)
        self.send_header("Location", url)
        self.send_header('Connection', 'keep_alive')
        self.send_header("Content-Length", '0')
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

    def send_error(self, code, message=None):
        """Send and log an error reply. """
        try:
            short, long = self.responses[code]
        except KeyError:
            short, long = '???', '???'
        if message is None:
            message = short
        explain = long
        # using _quote_html to prevent Cross Site Scripting attacks (see bug #1100201)
        content = (self.error_message_format %
                   {'code': code, 'message': self._quote_html(message), 'explain': explain})
        self.send_response(code, message)
        self.send_header("Content-Type", self.error_content_type)
        self.send_header('Content-Length', str(len(content)))
        self.send_header('Connection', 'keep_alive')
        self.end_headers()
        if self.command != 'HEAD' and code >= 200 and code not in (204, 304):
            self.wfile.write(content)

    def send_response(self, code, message=None):
        if message is None:
            if code in self.responses:
                message = self.responses[code][0]
            else:
                message = ''
        if self.request_version != 'HTTP/0.9':
            s = "%s %d %s\r\n" % (self.protocol_version, code, message)
            self.wfile.write(s.encode())
        self.send_header('ProxyServer', self.version_string())
        self.send_header('Date', self.date_time_string())

    def send_trunk(self, data):
        self.wfile.write(b"%x\r\n" % len(data))
        self.wfile.write(data)
        self.wfile.write(b'\r\n')

    def end_trunk(self):
        self.wfile.write(b'0\r\n\r\n')


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
        self.request_body_read = False
        self.rbuffer = deque()  # client read buffer: store request body, ssl handshake package for retry. no pop method.
        self.wbuffer = deque()  # client write buffer: read only once, not used in connect method
        self.wbuffer_size = 0
        self.retrycount = 0
        try:
            HTTPRequestHandler.handle_one_request(self)
        except socket.error as e:
            if e.errno in (errno.ECONNABORTED, errno.ECONNRESET, errno.EPIPE):
                self.close_connection = 1
            else:
                raise

    def send_response(self, code, message=None):
        if not self.request_body_read:
            raise ValueError('request body not read, should close connection')
        HTTPRequestHandler.send_response(self, code, message=None)

    def handle(self):
        ip, port = self.client_address
        logging.debug("Request from %s" % ip)
        if self.allowed_clients and ip not in self.allowed_clients:
            self.raw_requestline = self.rfile.readline()
            if self.parse_request():
                self.send_error(403)
        else:
            HTTPRequestHandler.handle(self)

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
        if isinstance(self.path, bytes):
            self.path = self.path.decode('latin1')
        if self.path.lower().startswith('ftp://'):
            return self.do_FTP()
        # transparent proxy
        if int(self.headers.get('Content-Length', 0)) == 0:
            self.request_body_read = True
        if self.path.startswith('/') and 'Host' in self.headers:
            self.path = 'http://%s%s' % (self.headers['Host'], self.path)
        if self.path.startswith('/'):
            return self.send_error(403)
        # redirector
        new_url = REDIRECTOR.get(self.path)
        if new_url:
            logging.info('redirecting to %s' % new_url)
            if new_url.isdigit() and 400 <= int(new_url) < 600:
                return self.send_error(int(new_url))
            elif new_url in conf.parentdict.keys():
                self._proxylist = [new_url]
            else:
                return self.redirect(new_url)

        if 'Host' not in self.headers:
            self.headers['Host'] = urlparse.urlparse(self.path).netloc

        if self.headers['Host'].rsplit(':', 1)[0].lower() in self.LOCALHOST:
            self.send_response(200)
            msg = 'Hello World !'
            self.send_header('Content-type', 'text/html')
            self.send_header('Content-Length', str(len(msg)))
            self.send_header('Connection', 'keep_alive')
            self.end_headers()
            # Send the html message
            self.wfile.write(msg)
            return

        host, _, port = self.headers['Host'].partition(':')
        port = port or 80
        self.requesthost = '%s:%s' % (host, port)
        self._do_GET()

    def _do_GET(self, retry=False):
        if self.getparent():
            return self.send_error(504)
        if not self.retryable:
            self.close_connection = 1
            return
        if retry:
            self.retrycount += 1
        if self.pproxyparse.scheme in ('socks5', 'ss'):
            self.upstream_name = '{}-{}'.format(self.ppname, self.requesthost)
        else:
            self.upstream_name = self.ppname if self.pproxy else self.requesthost
        try:
            remotesoc = self._http_connect_via_proxy(self.requesthost)
        except NetWorkIOError as e:
            return self.on_GET_Error(e)
        self.wbuffer = deque()
        self.wbuffer_size = 0
        # send request header
        logging.debug('sending request header')
        s = []
        if self.pproxy.startswith('http'):
            s.append('%s %s %s\r\n' % (self.command, self.path, self.request_version))
        else:
            s.append('%s /%s %s\r\n' % (self.command, '/'.join(self.path.split('/')[3:]), self.request_version))
        del self.headers['Proxy-Connection']
        for k, v in self.headers.items():
            if isinstance(v, bytes):
                v = v.decode('latin1')
            s.append("%s: %s\r\n" % (k, v))
        s.append("\r\n")
        try:
            remotesoc.sendall(''.join(s).encode('latin1'))
        except NetWorkIOError as e:
            return self.on_GET_Error(e)
        logging.debug('sending request body')
        # send request body
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length:
            if content_length > 102400:
                self.retryable = False
            if self.rbuffer:
                for s in self.rbuffer:
                    content_length -= len(s)
                    try:
                        remotesoc.sendall(s)
                    except NetWorkIOError as e:
                        return self.on_GET_Error(e)
            while content_length:
                data = self.rfile.read(min(8192, content_length))
                if not data:
                    break
                content_length -= len(data)
                if self.retryable:
                    self.rbuffer.append(data)
                try:
                    remotesoc.sendall(data)
                except NetWorkIOError as e:
                    return self.on_GET_Error(e)
            self.request_body_read = True
        # read response line
        logging.debug('reading response_line')
        remoterfile = remotesoc if isinstance(remotesoc, sssocket) else remotesoc.makefile('rb', 0)
        try:
            s = response_line = remoterfile.readline()
            if not s:
                raise ValueError('empty response line')
        except (socket.error, ssl.SSLError, OSError, ValueError) as e:
            return self.on_GET_Error(e)
        protocol_version, _, response_status = response_line.rstrip(b'\r\n').partition(b' ')
        response_status, _, response_reason = response_status.partition(b' ')
        response_status = int(response_status)
        # read response headers
        logging.debug('reading response header')
        header_data = []
        try:
            while True:
                line = remoterfile.readline()
                header_data.append(line)
                if line in (b'\r\n', b'\n', b''):
                    break
        except NetWorkIOError as e:
            return self.on_GET_Error(e)
        header_data = b''.join(header_data)
        response_header = email.message_from_string(header_data.decode('latin1'))
        conntype = response_header.get('Connection', "")
        if protocol_version >= b"HTTP/1.1":
            self.close_connection = conntype.lower() == 'close'
        else:
            self.close_connection = conntype.lower() != 'keep_alive'
        logging.debug('reading response body')
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
        self.wfile_write(s)
        self.wfile_write(header_data)
        # read response body
        if self.command == 'HEAD' or 100 <= response_status < 200 or response_status in (204, 304):
            pass
        elif response_header.get("Transfer-Encoding") and response_header.get("Transfer-Encoding") != "identity":
            flag = 1
            while flag:
                try:
                    trunk_lenth = remoterfile.readline()
                except NetWorkIOError as e:
                    return self.on_GET_Error(e)
                self.wfile_write(trunk_lenth)
                trunk_lenth = int(trunk_lenth.strip(), 16) + 2
                flag = trunk_lenth != 2
                while trunk_lenth:
                    try:
                        data = remotesoc.recv(min(4096, trunk_lenth))
                    except NetWorkIOError as e:
                        return self.on_GET_Error(e)
                    trunk_lenth -= len(data)
                    self.wfile_write(data)
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
        self.wfile_write()
        logging.debug('request finish')
        if self.retrycount and response_status < 400:
            PARENT_PROXY.add_temp_rule('|http://%s' % self.headers['Host'].split(':')[0])
        if not self.close_connection and not self.is_connection_dropped(remotesoc):
            UPSTREAM_POOL[self.upstream_name].append(remotesoc)
        else:
            remotesoc.close()

    def on_GET_Error(self, e):
        logging.warning('{} {} via {} failed! {}'.format(self.command, self.path, self.ppname, repr(e)))
        return self._do_GET(True)

    do_OPTIONS = do_POST = do_DELETE = do_TRACE = do_HEAD = do_PUT = do_GET

    def do_CONNECT(self):
        self.close_connection = 1
        self.request_body_read = True  # no request body should to be there in CONNECT method
        if isinstance(self.path, bytes):
            self.path = self.path.decode('latin1')
        if self.path.rsplit(':', 1)[0].lower() in self.LOCALHOST:
            return self.send_error(403)
        if 'Host' not in self.headers:
            self.headers['Host'] = self.path
        self.wfile.write(self.protocol_version.encode())
        self.wfile.write(b" 200 Connection established\r\n\r\n")
        self._do_CONNECT()

    def _do_CONNECT(self, retry=False):
        if not self.retryable or self.getparent():
            return
        if retry:
            self.retrycount += 1
        try:
            remotesoc = self._connect_via_proxy(self.path)
        except NetWorkIOError as e:
            logging.warning('%s %s failed! %r' % (self.command, self.path, e))
            return self._do_CONNECT()

        if self.pproxy.startswith('http'):
            s = ['%s %s %s\r\n' % (self.command, self.path, self.request_version), ]
            s.append('\r\n'.join(['%s: %s' % (key, value) for key, value in self.headers.items()]))
            s.append('\r\n\r\n')
            remotesoc.sendall(''.join(s).encode())
            remoterfile = remotesoc.makefile('rb', 0)
            data = remoterfile.readline()
            if b'200' not in data:
                logging.warning('{} {} failed! 200 not in response'.format(self.command, self.path))
                return self._do_CONNECT(True)
            while not data in (b'\r\n', b'\n', b''):
                data = remoterfile.readline()
        if self.rbuffer:
            for s in self.rbuffer:
                remotesoc.sendall(s)
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
                                    self.rbuffer.append(data)
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

    def wfile_write(self, data=None):
        if self.retryable and data:
            self.wbuffer.append(data)
            self.wbuffer_size += len(data)
            if self.wbuffer_size > 102400:
                self.retryable = False
        else:
            while self.wbuffer:
                self.wfile.write(self.wbuffer.popleft())
            if data:
                self.wfile.write(data)

    def is_connection_dropped(self, sock):  # from urllib3
        """
        Returns True if the connection is dropped and should be closed.

        """
        if not hasattr(select, 'poll'):
            try:
                return select.select([sock], [], [], 0.0)[0]
            except socket.error:
                return True
        # This version is better on platforms that support it.
        p = select.poll()
        p.register(sock, select.POLLIN)
        for (fno, ev) in p.poll(0.0):
            if fno == sock.fileno():
                # Either data is buffered (bad), or the connection is dropped.
                return True

    def _http_connect_via_proxy(self, netloc):
        if self.retrycount == 0:
            pool = UPSTREAM_POOL.get(self.upstream_name)
            while pool:
                sock = pool.popleft()
                if not self.is_connection_dropped(sock):
                    logging.debug('reuse connection')
                    self._proxylist.insert(0, self.ppname)
                    return sock
                else:
                    sock.close()
        return self._connect_via_proxy(netloc)

    def _connect_via_proxy(self, netloc):
        timeout = None if self._proxylist else 20

        host, _, port = netloc.partition(':')
        port = int(port)
        logging.debug("Connect to %s:%s" % (host, port))
        if not self.pproxy:
            return socket.create_connection((host, port), timeout or 5)
        elif self.pproxy.startswith('http://'):
            return socket.create_connection((self.pproxyparse.hostname, self.pproxyparse.port or 80), timeout or 10)
        elif self.pproxy.startswith('https://'):
            s = socket.create_connection((self.pproxyparse.hostname, self.pproxyparse.port or 443), timeout or 10)
            s = ssl.wrap_socket(s)
            s.do_handshake()
            return s
        elif self.pproxy.startswith('ss://'):
            s = sssocket(self.pproxy, timeout)
            s.connect((host, port))
            return s
        elif self.pproxy.startswith('socks5://'):
            s = socket.create_connection((self.pproxyparse.hostname, self.pproxyparse.port or 1080), timeout or 10)
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
                                struct.pack(b">H", port)]))
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
        self.request_body_read = True  # no request body should to be there in FTP method
        logging.info('{} {}'.format(self.command, self.path))
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
        if self.command == "GET":
            if path.endswith('/'):
                return self.do_FTP_LIST(netloc, path, user, passwd)
            else:
                try:
                    ftp = ftplib.FTP(netloc)
                    ftp.login(user, passwd)
                    lst = []
                    response = ftp.retrlines("LIST %s" % path, lst.append)
                    if len(lst) > 1 or lst[0].split()[8] != path:
                        return self.do_FTP_LIST(netloc, path, user, passwd)
                    if not lst:
                        return self.send_error(504, response)
                    self.send_response(200)
                    self.send_header('Content-Length', lst[0].split()[4])
                    self.send_header('Connection', 'keep_alive')
                    self.end_headers()
                    ftp.retrbinary("RETR %s" % path, self.wfile.write, 8192)
                    ftp.quit()
                except Exception as e:  # Possibly no such file
                    logging.warning("FTP Exception: %s" % e)
                    self.send_error(504, repr(e))
        else:
            self.send_error(501)

    def do_FTP_LIST(self, netloc, path, user, passwd):
        if not path.endswith('/'):
            self.path += '/'
        lst = []
        md = '|Content|Size|Modify|\r\n|:----|----:|----:|\r\n'
        try:
            ftp = ftplib.FTP(netloc)
            ftp.login(user, passwd)
            response = ftp.retrlines("LIST %s" % path, lst.append)
            ftp.quit()
            for line in lst:
                line_split = line.split()
                if line.startswith('d'):
                    line_split[8] += '/'
                md += '|[%s](%s%s)|%s|%s %s %s|\r\n' % (line_split[8], self.path, line_split[8], line_split[4], line_split[5], line_split[6], line_split[7])
            md += '|================|==========|=============|\r\n'
            md += '\r\n%s\r\n' % response
        except Exception as e:
            logging.warning("FTP Exception: %r" % e)
            self.send_error(504, repr(e))
        else:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.send_header('Transfer-Encoding', 'chunked')
            self.send_header('Connection', 'keep_alive')
            self.end_headers()
            self.send_trunk('<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">')
            self.send_trunk("<html>\n<title>Directory listing for %s</title>\n" % path)
            self.send_trunk("<body>\n<h2>Directory listing for %s</h2>\n" % path)
            self.send_trunk("<hr>\n")
            self.send_trunk(markdown.markdown(md, extensions=['tables', ]))
            self.send_trunk("<hr>\n</body>\n</html>\n")
            self.end_trunk()


class ForceProxyHandler(ProxyHandler):
    def getparent(self, level=3):
        return self._getparent(level)


class sssocket(object):
    def __init__(self, ssServer, timeout=10, parentproxy=''):
        self.ssServer = ssServer
        self.timeout = timeout
        self.parentproxy = parentproxy
        self._sock = None
        self.crypto = None
        self.__rbuffer = b''

    def connect(self, address):
        p = urlparse.urlparse(self.ssServer)
        _, sshost, ssport, ssmethod, sspassword = (p.scheme, p.hostname, p.port, p.username, p.password)
        self._sock = socket.create_connection((sshost, ssport), self.timeout)
        self.crypto = encrypt.Encryptor(sspassword, ssmethod)
        host, port = address
        data = b''.join([b'\x03',
                        chr(len(host)).encode(),
                        host.encode(),
                        struct.pack(b">H", port)])
        self.sendall(data)

    def recv(self, size):
        if len(self.__rbuffer) < size:
            data = self.crypto.decrypt(self._sock.recv(max(size, 4096)))
            self.__rbuffer = b''.join([self.__rbuffer, data])
        result, self.__rbuffer = self.__rbuffer[:size], self.__rbuffer[size:]
        return result

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

        self.override = rule.startswith('@@')
        return parse(rule[2:]) if self.override else parse(rule)

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
                q = q.encode().decode('idna')
            logging.debug('Match redirect rule addressbar-search')
            return 'https://www.google.com/search?q=%s&ie=utf-8&oe=utf-8&aq=t&rls=org.mozilla:zh-CN:official' % urlquote(q.encode('utf-8'))
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
        REDIRECTOR.lst = []

        for line in open('./fgfw-lite/local.txt'):
            self.add_rule(line, force=True)

        for line in open('./fgfw-lite/cloud.txt'):
            self.add_rule(line, force=True)

        if conf.userconf.dgetbool('fgfwproxy', 'enable_gfwlist', True):
            try:
                with open('./fgfw-lite/gfwlist.txt') as f:
                    data = f.read()
                    if '!' not in data:
                        data = ''.join(data.split())
                        if len(data) % 4:
                            data += '=' * (4 - len(data) % 4)
                        data = base64.b64decode(data).decode()
                    for line in data.splitlines():
                        self.add_rule(line)
            except TypeError:
                logging.warning('./fgfw-lite/gfwlist.txt is corrupted!')

        self.localnet.append((ip_from_string('192.168.0.0'), ip_from_string('192.168.0.0') + 2 ** (32 - 16)))
        self.localnet.append((ip_from_string('172.16.0.0'), ip_from_string('172.16.0.0') + 2 ** (32 - 12)))
        self.localnet.append((ip_from_string('10.0.0.0'), ip_from_string('10.0.0.0') + 2 ** (32 - 8)))
        self.localnet.append((ip_from_string('127.0.0.0'), ip_from_string('127.0.0.0') + 2 ** (32 - 8)))

        self.geoip = pygeoip.GeoIP('./goagent/GeoIP.dat')

    def add_rule(self, line, force=False):
        rule = line.strip().split()
        if len(rule) == 2:  # |http://www.google.com/url forcehttps
            try:
                rule, result = rule
                REDIRECTOR.lst.append((autoproxy_rule(rule), result))
            except TypeError as e:
                logging.debug('create autoproxy rule failed: %s' % e)
        elif len(rule) == 1:
            try:
                o = autoproxy_rule(rule[0])
                if o.override:
                    self.override.append(o)
                elif force:
                    self.gfwlist_force.append(o)
                else:
                    self.gfwlist.append(o)
            except TypeError as e:
                logging.debug('create autoproxy rule failed: %s' % e)
        elif rule and '!' not in line:
            logging.warning('Bad autoproxy rule: %r' % line)

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
        a = conf.userconf.dget('goagent', 'gaeappid', 'goagent') == 'goagent'
        if s or a:  # two reasons not to use goagent
            if re.match(r'^([^/]+):\d+$', uri):  # connect method
                if host in conf.FAKEHTTPS:
                    return True
                if host in conf.WITHGAE:
                    return True
                if host in conf.HOST:
                    return False
                if host.endswith(conf.HOST_POSTFIX):
                    return False
                if host.endswith(conf.CONN_POSTFIX):
                    return False
                return True
            else:  # get method
                if host in conf.WITHGAE:
                    return a
                if host in conf.HOST:
                    return False
                if host.endswith(conf.HOST_POSTFIX):
                    return False
                return a

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

        f = self.ifgfwed(uri, host, level)

        if f is False:
            return ['direct']

        parentlist = list(conf.parentdict.keys())
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
            logging.info('%s NOT updated. Reason: %r' % (path, e))
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
    branch = conf.userconf.dget('FGFW_Lite', 'branch', 'master')
    try:
        r = json.loads(urllib2.urlopen('https://github.com/v3aqb/fgfw-lite/raw/%s/fgfw-lite/update.json' % branch).read())
    except Exception as e:
        logging.info('read update.json failed. Reason: %r' % e)
    else:
        import hashlib
        for path, v, in r.items():
            if v == conf.version.dget('Update', path.replace('./', '').replace('/', '-'), ''):
                logging.info('{} NOT updated. Reason: Not Modified'.format(path))
                continue
            fdata = urllib2.urlopen('https://github.com/v3aqb/fgfw-lite/raw/%s%s' % (branch, path[1:])).read()
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

        if conf.userconf.dget('goagent', 'gaeappid', 'goagent') != 'goagent':
            goagent.set('gae', 'appid', conf.userconf.dget('goagent', 'gaeappid', 'goagent'))
            goagent.set("gae", "password", conf.userconf.dget('goagent', 'gaepassword', ''))
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

        goagent.set('proxy', 'autodetect', '0')
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

        conf.FAKEHTTPS = set(goagent.dget('ipv4/http', 'fakehttps').split('|'))
        conf.WITHGAE = set(goagent.dget('ipv4/http', 'withgae').split('|'))
        conf.HOST = ('upload.youtube.com', )
        conf.HOST_POSTFIX = tuple([k for k, v in goagent.items('ipv4/hosts') if '\\' not in k and ':' not in k and k.startswith('.')])
        conf.CONN_POSTFIX = ('.box.com', '.copy.com')
        for s in goagent.dget('ipv4/http', 'forcehttps').split('|'):
            PARENT_PROXY.add_rule('|http://%s forcehttps' % s)

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

        worknodes = conf.userconf.dget('snova', 'C4worknodes')
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
    optionxform = str

    def dget(self, section, option, default=''):
        try:
            value = self.get(section, option)
            if not value:
                value = default
        except Exception:
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
        self.parentdict = {'direct': ('', 0), }
        self.FAKEHTTPS = set()
        self.WITHGAE = set()
        self.HOST = tuple()
        self.HOST_POSTFIX = tuple()
        self.CONN_POSTFIX = tuple()
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
        if proxy == 'direct':
            proxy = ''
        if proxy and not '//' in proxy:
            proxy = 'http://%s' % proxy
        logging.info('adding parent proxy: %s: %s' % (name, proxy))
        self.parentdict[name] = (proxy, int(priority) if priority else 99)

REDIRECTOR = redirector()
PARENT_PROXY = parent_proxy()
conf = Config()
PARENT_PROXY.config()


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
    updatedaemon = Thread(target=updater)
    updatedaemon.daemon = True
    updatedaemon.start()
    server = ThreadingHTTPServer(conf.listen, ProxyHandler)
    Thread(target=server.serve_forever).start()
    server2 = ThreadingHTTPServer((conf.listen[0], conf.listen[1] + 1), ForceProxyHandler)
    server2.serve_forever()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)

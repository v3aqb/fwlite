
# Copyright (C) 2014-2019 v3aqb

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
import re
import io
import base64
import json
import time
import traceback

import urllib.parse as urlparse
from ipaddress import ip_address

import asyncio
import asyncio.streams

from .connection import open_connection
from .base_handler import BaseHandler, read_header_data, read_headers
from .httputil import ConnectionPool
from .util import extract_server_name, parse_hostport

MAX_TIMEOUT = 16
WELCOME = '''<!DOCTYPE html>
<html>
<body>
<p>fwlite running...</p>
<p><a href="http://{host}:{port}/api/log">Check Log</a></p>
<p><a href="http://{host}:{port}/api/localrule">Local Rule</a></p>
<p><a href="http://{host}:{port}/api/proxy">Proxy</a></p>
</body>
</html>'''


class ClientError(Exception):
    def __init__(self, err):
        self.err = err
        super().__init__()


class ForwardContext:
    def __init__(self):
        self.last_active = time.monotonic()
        self.first_send = 0
        # eof recieved
        self.remote_eof = False
        self.local_eof = False
        # link status
        self.writeable = True
        self.readable = True
        # result
        self.timeout = None
        self.retryable = True
        self.err = None


class handler_factory:

    def __init__(self, addr, port, _class, profile, conf):
        self._class = _class
        self.profile = profile
        self.addr = addr
        self.port = port
        self.conf = conf

        self.logger = logging.getLogger('fwlite_%d' % port)
        self.logger.setLevel(logging.INFO)
        hdr = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                                      datefmt='%H:%M:%S')
        hdr.setFormatter(formatter)
        self.logger.addHandler(hdr)

        self.logger.warning('starting server: %s %s', port, profile)

    async def handle(self, reader, writer):
        _handler = self._class(self)
        await _handler.handle(reader, writer)


class BaseProxyHandler(BaseHandler):
    def __init__(self, server):
        self.conf = server.conf

        self.shortpath = ''
        self._proxylist = None
        self.ppname = ''
        self.pproxy = None
        self.rbuffer = []
        self.wbuffer = []
        self.wbuffer_size = 0
        self.retryable = True
        self.request_host = None
        self.remote_reader = None
        self.remote_writer = None
        self.request_ip = None
        self.retry_count = 0
        self.failed_parents = []
        super().__init__(server)

    def pre_request_init(self):
        super().pre_request_init()

        self.shortpath = ''
        self._proxylist = None
        self.ppname = ''
        self.pproxy = None
        self.rbuffer = []
        self.wbuffer = []
        self.wbuffer_size = 0
        self.retryable = True
        self.request_host = None
        self.remote_reader = None
        self.remote_writer = None
        self.request_ip = None
        self.retry_count = 0
        self.failed_parents = []

    def write(self, code=200, msg=None, ctype=None, data=b''):
        '''
        Write http response to client.

        For PAC and rpc-api only.
        '''
        if msg and not isinstance(msg, bytes):
            msg = msg.encode('UTF-8')
        if not isinstance(data, bytes):
            data = data.encode('UTF-8')
        self.send_response(code, msg)
        if ctype:
            self.send_header('Content-type', ctype)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Connection', 'close')
        self.end_headers()
        if self.command != 'HEAD' and code >= 200 and code not in (204, 304):
            self.wfile.write(data)

    def redirect(self, url):
        self.send_response(302)
        self.send_header("Location", url)
        self.send_header('Connection', 'keep_alive')
        self.send_header("Content-Length", '0')
        self.end_headers()

    async def client_reader_read(self, size, timeout=1):
        fut = self.client_reader.read(size)
        err = None
        try:
            data = await asyncio.wait_for(fut, timeout=timeout)
            return data
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            err = exc
        raise ClientError(err)

    async def client_reader_readexactly(self, size, timeout=1):
        fut = self.client_reader.readexactly(size)
        err = None
        try:
            data = await asyncio.wait_for(fut, timeout=timeout)
            return data
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            err = exc
        raise ClientError(err)

    async def client_reader_readline(self, timeout=1):
        fut = self.client_reader.readline()
        err = None
        try:
            data = await asyncio.wait_for(fut, timeout=timeout)
            return data
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            err = exc
        raise ClientError(err)

    async def client_reader_readuntil(self, sep, timeout=1):
        fut = self.client_reader.readuntil(sep)
        err = None
        try:
            data = await asyncio.wait_for(fut, timeout=timeout)
            return data
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            err = exc
        raise ClientError(err)

    def _wfile_write(self, data):
        # write to self.client_writer
        self.retryable = False
        # self.traffic_count[1] += len(data)
        self.client_writer.write(data)

    def wfile_write(self, data=None):
        if data is None:
            self.retryable = False
        if self.retryable and data:
            self.wbuffer.append(data)
            self.wbuffer_size += len(data)
            if self.wbuffer_size > 102400:
                self.retryable = False
        else:
            if self.wbuffer:
                self._wfile_write(b''.join(self.wbuffer))
                self.wbuffer = []
            if data:
                self._wfile_write(data)

    async def read_resp_line(self):
        fut = self.remote_reader.readline()
        response_line = await asyncio.wait_for(fut, self.timeout)
        split = response_line.split()
        if len(split) < 2:
            self.logger.error('incomplete response line: %r' % response_line)
            raise ValueError('incomplete response line')
        protocol_version = split[0]
        response_status = split[1]
        response_reason = b' '.join(split[2:])
        response_status = int(response_status)
        return response_line, protocol_version, response_status, response_reason


class http_handler(BaseProxyHandler):
    HTTPCONN_POOL = ConnectionPool()

    async def do_GET(self):
        # self.logger.info('req_count %s' % self.req_count)
        if isinstance(self.path, bytes):
            self.path = self.path.decode('latin1')
        if self.path.lower().startswith('ftp://'):
            self.send_error(400, explain='GET ftp:// not supported')
            return

        if self.path == '/pac':
            if self.headers['Host'].startswith(self.conf.local_ip):
                self.write(msg=self.conf.PAC, ctype='application/x-ns-proxy-autoconfig')
                return

        # transparent proxy
        if self.path.startswith('/'):
            if 'Host' not in self.headers:
                self.send_error(400, explain='Host not in headers')
                return
            self.path = 'http://%s%s' % (self.headers['Host'], self.path)

        # fix request
        if self.path.startswith('http://http://'):
            self.path = self.path[7:]

        parse = urlparse.urlparse(self.path)

        self.shortpath = '%s://%s%s%s' % (parse.scheme,
                                          parse.netloc,
                                          parse.path.split(':')[0],
                                          '?' if parse.query else '')

        if 'Host' not in self.headers:
            request_host = parse_hostport(parse.netloc, 80)
        else:
            host = parse_hostport(self.headers['Host'], 80)
            netloc = parse_hostport(parse.netloc, 80)
            if host != netloc:
                self.logger.warning('Host and URI mismatch! %s %s', self.path, self.headers['Host'])
                self.send_error(400, explain='Host and URI mismatch!')
                return
            request_host = parse_hostport(self.headers['Host'], 80)

        self.request_host = request_host

        # redirector
        new_url = self.conf.GET_PROXY.redirect(self)
        if new_url:
            self.logger.debug('redirect %s, %s %s', new_url, self.command, self.shortpath)
            if new_url.isdigit() and 400 <= int(new_url) < 600:
                self.send_error(int(new_url))
                return
            if new_url.lower() == 'return':
                # request handled by redirector, return
                self.logger.info('%s %s return', self.command, self.shortpath)
                return
            if new_url.lower() == 'reset':
                self.close_connection = 1
                self.logger.info('%s %s reset', self.command, self.shortpath)
                return
            if new_url.lower() == 'adblock':
                self.close_connection = 1
                self.logger.debug('%s %s adblock', self.command, self.shortpath)
                return
            if all(u in self.conf.parentlist.dict.keys() for u in new_url.split()):
                self._proxylist = [self.conf.parentlist.get(u) for u in new_url.split()]
                # sort by priority?
                # random.shuffle(self._proxylist)
            else:
                self.logger.info('redirect %s %s', self.shortpath, new_url)
                self.redirect(new_url)
                return

        parse = urlparse.urlparse(self.path)

        # gather info (redirector may change this)
        if 'Host' not in self.headers:
            self.logger.warning('"Host" not in self.headers')
            request_host = parse_hostport(parse.netloc, 80)
        else:
            host = parse_hostport(self.headers['Host'], 80)
            netloc = parse_hostport(parse.netloc, 80)
            if host != netloc:
                self.logger.warning('Host and URI mismatch! %s %s', self.path, self.headers['Host'])
                self.send_error(400, explain='Host and URI mismatch! (post redirect)')
                return
            request_host = parse_hostport(self.headers['Host'], 80)

        self.request_host = request_host

        self.shortpath = '%s://%s%s%s' % (parse.scheme,
                                          parse.netloc,
                                          parse.path.split(':')[0],
                                          '?' if parse.query else '')
        self.request_ip = await self.conf.resolver.get_ip_address(self.request_host[0])

        if self.request_ip.is_loopback:
            if ip_address(self.client_address[0]).is_loopback:
                if self.request_host[1] == self.conf.listen[1]:
                    if parse.path == '/' and self.command == 'GET':
                        self.write(200, data=WELCOME.format(host=self.request_host[0],
                                                            port=self.request_host[1]),
                                   ctype='text/html; charset=utf-8')
                        return
                    await self.api(parse)
                    return
            else:
                self.send_error(403)
                return

        if str(self.request_ip) == self.client_writer.get_extra_info('sockname')[0]:
            if self.request_host[1] == self.conf.listen[1]:
                if parse.path == '/' and self.command == 'GET':
                    self.write(200, data=WELCOME.format(host=self.request_host[0],
                                                        port=self.request_host[1]),
                               ctype='text/html; charset=utf-8')
                    return
                if not self.conf.remoteapi:
                    self.send_error(403)
                    return
                await self.api(parse)
                await self.client_writer.drain()
                return

        if 'X-Forwarded-For' in self.headers:
            del self.headers['X-Forwarded-For']

        for header in ['Proxy-Connection', 'Proxy-Authenticate']:
            if header in self.headers:
                del self.headers[header]

        await self._do_GET()

    async def _do_GET(self, retry=False):
        try:
            if retry:
                self.failed_parents.append(self.ppname)
                self.retry_count += 1
                if self.retry_count > 10:
                    self.logger.error('retry time exceeded 10, pls check!')
                    return
            if not self.retryable:
                self.close_connection = 1
                self.conf.GET_PROXY.notify(self.command, self.shortpath, self.request_host, False,
                                           self.failed_parents, self.ppname)
                return

            self.set_timeout()

            if self.getparent():
                # if no more proxy available
                self.conf.GET_PROXY.notify(self.command, self.shortpath, self.request_host, False,
                                           self.failed_parents, self.ppname)
                return self.send_error(504, explain='no more proxy available')

            # try get from connection pool
            if not self.failed_parents:
                result = self.HTTPCONN_POOL.get((self.client_address[0], self.request_host))
                if result:
                    self._proxylist.insert(0, self.conf.parentlist.get(self.ppname))
                    sock, self.ppname = result
                    self.remote_reader, self.remote_writer = sock
                    self.logger.info('%s %s via %s.',
                                     self.command, self.shortpath, self.ppname)

            if not self.remote_writer:
                iplist = []
                if self.pproxy.name == '_D1R3CT_' and \
                        self.request_host[0] in self.conf.HOSTS and \
                        not self.failed_parents:
                    iplist = self.conf.HOSTS.get(self.request_host[0])
                    self._proxylist.insert(0, self.pproxy)

                self.logger.info('%s %s via %s',
                                 self.command, self.shortpath, self.pproxy.name)

                addr, port = self.request_host
                # addr, port, proxy=None, timeout=3, iplist=[], tunnel=False
                self.remote_reader, self.remote_writer, self.ppname = \
                    await open_connection(addr, port, self.pproxy, self.timeout, iplist, False)

                if self.ppname != self.pproxy.name:
                    self._proxylist.insert(0, self.pproxy)

            # write buffer for retry
            self.wbuffer = []
            self.wbuffer_size = 0
            # prep request header
            req = []
            if self.pproxy.proxy.startswith('http'):
                req.append('%s %s %s\r\n' % (self.command, self.path, self.request_version))
                if self.pproxy.username:
                    auth = '%s:%s' % (self.pproxy.username, self.pproxy.password)
                    req.append('Proxy-Authorization: Basic %s' % base64.b64encode(auth.encode()).decode())
            else:
                req.append('%s /%s %s\r\n' % (self.command,
                                              '/'.join(self.path.split('/')[3:]),
                                              self.request_version))
            # Does the client want to close connection after this request?
            conntype = self.headers.get('Connection', "")
            if self.request_version >= "HTTP/1.1":
                self.close_connection |= 'close' in conntype.lower()
            else:
                self.close_connection |= 'keep_alive' in conntype.lower()
            if 'Upgrade' in self.headers:
                self.close_connection = True
                self.logger.warning('Upgrade header found! (%s)', self.headers['Upgrade'])
                # del self.headers['Upgrade']

            for key, val in self.headers.items():
                if isinstance(val, bytes):
                    val = val.decode('latin1')
                req.append("%s: %s\r\n" % ("-".join([w.capitalize() for w in key.split("-")]), val))
            req.append("\r\n")
            data = ''.join(req).encode('latin1')

            # send request header
            self.remote_writer.write(data)
            # self.traffic_count[0] += len(data)

            # Expect
            skip = False
            if 'Expect' in self.headers:
                try:
                    response_line, protocol_version, response_status, _ = \
                        await self.read_resp_line()
                except asyncio.CancelledError:
                    raise
                except Exception as err:
                    # TODO: probably the server don't handle Expect well.
                    self.logger.warning('read response line error: %r', err)
                else:
                    if response_status == 100:
                        hdata = await read_header_data(self.remote_reader, timeout=self.timeout)
                        self._wfile_write(response_line + hdata)
                    else:
                        skip = True
            # send request body
            if not skip:
                content_length = int(self.headers.get('Content-Length', 0))
                if self.headers.get("Transfer-Encoding", "identity") != "identity":
                    if self.rbuffer:
                        self.remote_writer.write(b''.join(self.rbuffer))
                    flag = 1
                    req_body_len = 0
                    while flag:
                        trunk_lenth = await self.client_reader_readline()
                        if self.retryable:
                            self.rbuffer.append(trunk_lenth)
                            req_body_len += len(trunk_lenth)
                        self.remote_writer.write(trunk_lenth)
                        trunk_lenth = int(trunk_lenth.strip(), 16) + 2
                        flag = trunk_lenth != 2
                        data = self.client_reader_readexactly(trunk_lenth)
                        if self.retryable:
                            self.rbuffer.append(data)
                            req_body_len += len(data)
                        self.remote_writer.write(data)
                        if req_body_len > 102400:
                            self.retryable = False
                            self.rbuffer = []
                elif content_length > 0:
                    if content_length > 102400:
                        self.retryable = False
                    if self.rbuffer:
                        data = b''.join(self.rbuffer)
                        content_length -= len(data)
                        self.remote_writer.write(data)
                    while content_length:
                        data = await self.client_reader_readexactly(min(self.bufsize,
                                                                        content_length))
                        if not data:
                            break
                        content_length -= len(data)
                        if self.retryable:
                            self.rbuffer.append(data)
                        self.remote_writer.write(data)
                # read response line
                timelog = time.monotonic()
                response_line, protocol_version, response_status, _ = await self.read_resp_line()
                rtime = time.monotonic() - timelog
            # read response headers
            while response_status == 100:
                hdata = await read_header_data(self.remote_reader, timeout=self.timeout)
                self._wfile_write(response_line + hdata)
                response_line, protocol_version, response_status, _ = \
                    await self.read_resp_line()

            header_data, response_header = await read_headers(self.remote_reader, self.timeout)

            # check response headers
            conntype = response_header.get('Connection', "")
            if protocol_version >= b"HTTP/1.1":
                remote_close = 'close' in conntype.lower()
            else:
                remote_close = 'keep_alive' not in conntype.lower()
            if 'Upgrade' in response_header:
                self.close_connection = remote_close = True
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

            if response_status in (301, 302) and \
                    self.conf.GET_PROXY.bad302(response_header.get('Location')):
                raise IOError(0, 'Bad 302!')

            self.wfile_write(response_line)
            self.wfile_write(header_data)
            # read response body
            if self.command == 'HEAD' or response_status in (204, 205, 304):
                pass
            elif response_header.get("Transfer-Encoding", "identity") != "identity":
                flag = 1
                while flag:
                    trunk_lenth = await self.remote_reader.readline()
                    self.wfile_write(trunk_lenth)
                    trunk_lenth = int(trunk_lenth.strip(), 16) + 2
                    flag = trunk_lenth != 2
                    while trunk_lenth:
                        data = await self.remote_reader.read(min(self.bufsize, trunk_lenth))
                        # self.logger.info('chunk data received %d %s', len(data), self.path)
                        trunk_lenth -= len(data)
                        self.wfile_write(data)
            elif content_length is not None:
                while content_length:
                    data = await self.remote_reader.read(min(self.bufsize, content_length))
                    if not data:
                        raise IOError(0, 'remote socket closed')
                    # self.logger.info('content_length data received %d %s', len(data), self.path)
                    content_length -= len(data)
                    self.wfile_write(data)
            elif 'Upgrade' in response_header:
                # if Upgrade in headers, websocket?
                #     forward tcp
                self.logger.info('Upgrade: %s', response_header['Upgrade'])
                self.close_connection = True
                self.retryable = False
                # flush writer buf
                self.wfile_write()

                # start forwarding...
                context = await self.forward()
                if context.timeout:
                    # no response from server
                    pass
            elif content_length is None:
                # http/1.0 response, content_lenth not in header
                #     read response body until connection closed
                while True:
                    data = await self.remote_reader.read(self.bufsize)
                    if not data:
                        break
                    self.wfile_write(data)
            else:
                self.logger.error('forward response body error.')

            self.wfile_write()
            self.conf.GET_PROXY.notify(self.command, self.shortpath, self.request_host, True,
                                       self.failed_parents, self.ppname)
            self.pproxy.log(self.request_host[0], rtime)
            if remote_close or self.close_connection:
                self.remote_writer.write_eof()
                self.remote_writer.close()
                self.remote_writer = None
                self.close_connection = True
            else:
                # keep for next request
                ppn = self.ppname if '(pooled)' in self.ppname else (self.ppname + '(pooled)')
                self.HTTPCONN_POOL.put((self.client_address[0], self.request_host),
                                       (self.remote_reader, self.remote_writer),
                                       ppn)
                self.remote_writer = None
        except ClientError:
            self.logger.error('client error')
            self.close_connection = True
            return
        except (asyncio.TimeoutError, OSError, ValueError, asyncio.IncompleteReadError) as err:
            if self.remote_writer:
                try:
                    self.remote_writer.write_eof()
                except OSError:
                    pass
                self.remote_writer.close()
                self.remote_writer = None
            await self.on_GET_Error(err)
        except asyncio.CancelledError:
            raise
        except Exception as err:
            self.close_connection = True
            self.logger.error('http_handler')
            self.logger.error(repr(err))
            self.logger.error(traceback.format_exc())

    async def on_GET_Error(self, err):
        if self.ppname:
            self.logger.warning('%s %s via %s failed: %r',
                                self.command, self.shortpath, self.ppname, err)
            self.pproxy.log(self.request_host[0], MAX_TIMEOUT)
            await self._do_GET(True)
            return
        self.conf.GET_PROXY.notify(self.command, self.shortpath, self.request_host, False,
                                   self.failed_parents, self.ppname)
        return self.send_error(504)

    do_HEAD = do_POST = do_PUT = do_DELETE = do_OPTIONS = do_PATCH = do_TRACE = do_GET

    async def do_CONNECT(self):
        self.close_connection = True
        if isinstance(self.path, bytes):
            self.path = self.path.decode('latin1')

        if not self.socks5:
            self._wfile_write(self.protocol_version.encode() + b" 200 Connection established\r\n\r\n")

        self.rbuffer = []

        # fix SNI
        try:
            data = await self.client_reader_read(4)

            if data.startswith(b'\x16\x03'):
                # parse SNI
                data += await self.client_reader_read(8196)
                try:
                    server_name = extract_server_name(data)
                    if server_name and server_name not in self.path:
                        self.shortpath = server_name
                except Exception:
                    pass
            elif data in (b'GET ', b'HEAD', b'POST', b'PUT ', b'DELE', b'OPTI', b'PATC', b'TRAC'):
                data += await self.client_reader_read(8196)
                for line in data.splitlines():
                    if line.startswith(b'Host: '):
                        self.shortpath = parse_hostport(line.strip().decode()[6:])[0]
                        break
        except ClientError:
            return

        if data:
            self.rbuffer.append(data)

        self.request_host = parse_hostport(self.path)
        if self.shortpath:
            self.request_host = (self.shortpath, self.request_host[1])
            self.shortpath = '%s:%d' % self.request_host

        # redirector
        new_url = self.conf.GET_PROXY.redirect(self)
        if new_url:
            self.logger.debug('redirect %s, %s %s', new_url, self.command, self.path)
            if new_url.isdigit() and 400 <= int(new_url) < 600:
                self.logger.info('%s %s send error %s', self.command, self.path, new_url)
                return
            if new_url.lower() in ('reset', 'return'):
                self.logger.info('%s %s reset', self.command, self.path)
                return
            if new_url.lower() == 'adblock':
                self.logger.debug('%s %s adblock', self.command, self.path)
                return
            if all(u in self.conf.parentlist.dict.keys() for u in new_url.split()):
                self._proxylist = [self.conf.parentlist.get(u) for u in new_url.split()]
                # random.shuffle(self._proxylist)

        self.request_ip = await self.conf.resolver.get_ip_address(self.request_host[0])

        if int(self.request_ip) == 0 and self.shortpath:
            self.path = self.shortpath

        if self.request_ip.is_loopback:
            if ip_address(self.client_address[0]).is_loopback:
                if self.request_host[1] in range(self.conf.listen[1],
                                                 self.conf.listen[1] + len(self.conf.profile)):
                    # prevent loop
                    return
            else:
                return
        await self._do_CONNECT()

    async def _do_CONNECT(self, retry=False):
        if retry:
            self.failed_parents.append(self.ppname)
            self.pproxy.log(self.request_host[0], MAX_TIMEOUT)
            self.retry_count += 1
            if self.retry_count > 10:
                self.logger.error('retry time exceeded 10, pls check!')
                return

        if self.getparent():
            self.conf.GET_PROXY.notify(self.command, self.shortpath or self.path, self.request_host,
                                       False, self.failed_parents, self.ppname)
            return

        iplist = None
        if self.pproxy.name == '_D1R3CT_' and\
                self.request_host[0] in self.conf.HOSTS and not self.failed_parents:
            iplist = self.conf.HOSTS.get(self.request_host[0])
            self._proxylist.insert(0, self.pproxy)

        self.set_timeout()

        try:
            self.logger.info('%s %s via %s. %s', self.command, self.shortpath or self.path,
                             self.pproxy.name, self.client_address[1])
            addr, port = parse_hostport(self.path, 443)
            self.remote_reader, self.remote_writer, self.ppname = \
                await open_connection(addr, port, self.pproxy, self.timeout, iplist, True)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, OSError) as err:
            self.logger.warning('%s %s via %s failed on connect! %r',
                                self.command, self.shortpath or self.path, self.ppname, err)
            self.conf.GET_PROXY.notify(self.command, self.shortpath or self.path, self.request_host,
                                       False, self.failed_parents, self.ppname)
            await self._do_CONNECT(True)
            return
        self.logger.debug('%s connected', self.path)

        if self.ppname != self.pproxy.name:
            self._proxylist.insert(0, self.pproxy)

        # forward
        context = await self.forward()

        # check, report, retry
        if context.retryable and not context.local_eof:
            self.conf.GET_PROXY.notify(self.command, self.shortpath or self.path, self.request_host,
                                       False, self.failed_parents, self.ppname)
            await self._do_CONNECT(True)
            return

    async def forward(self):
        context = ForwardContext()

        tasks = [self.forward_from_client(self.client_reader, self.remote_writer, context),
                 self.forward_from_remote(self.remote_reader, self.client_writer, context),
                 ]
        try:
            await asyncio.wait(tasks)
        except asyncio.CancelledError:
            raise
        except Exception as err:
            self.logger.error('http_handler.forward')
            self.logger.error(repr(err))
            self.logger.error(traceback.format_exc())
            context.err = err
        self.remote_writer.close()
        return context

    async def forward_from_client(self, read_from, write_to, context, timeout=60):
        if self.command == 'CONNECT':
            # send self.rbuffer
            if self.rbuffer:
                self.remote_writer.write(b''.join(self.rbuffer))
                context.first_send = time.monotonic()
        while True:
            intv = 1 if context.retryable else 5
            try:
                fut = self.client_reader.read(self.bufsize)
                data = await asyncio.wait_for(fut, timeout=intv)
            except asyncio.TimeoutError:
                if time.monotonic() - context.last_active > timeout or context.remote_eof:
                    data = b''
                else:
                    continue
            except (asyncio.IncompleteReadError, ConnectionResetError, ConnectionAbortedError):
                data = b''

            if not data:
                break
            try:
                context.last_active = time.monotonic()
                if context.retryable:
                    self.rbuffer.append(data)
                if not context.first_send:
                    context.first_send = time.monotonic()
                write_to.write(data)
                await write_to.drain()
            except ConnectionResetError:
                context.local_eof = True
                return
        context.local_eof = True
        # client closed, tell remote
        try:
            write_to.write_eof()
        except OSError:
            pass

    async def forward_from_remote(self, read_from, write_to, context, timeout=60):
        count = 0
        while True:
            intv = 1 if context.retryable else 5
            try:
                fut = read_from.read(self.bufsize)
                data = await asyncio.wait_for(fut, intv)
                count += 1
            except (ConnectionResetError, OSError):
                data = b''
            except asyncio.TimeoutError:
                if time.monotonic() - context.last_active > timeout or context.local_eof:
                    data = b''
                elif context.retryable and time.monotonic() - context.last_active > self.timeout:
                    data = b''
                else:
                    continue

            if not data:
                break
            try:
                context.last_active = time.monotonic()
                if count == 1:
                    rtime = time.monotonic() - context.first_send
                    if self.command == 'CONNECT':
                        # log server response time
                        self.pproxy.log(self.request_host[0], rtime)
                        self.conf.GET_PROXY.notify(self.command,
                                                   self.shortpath or self.path,
                                                   self.request_host,
                                                   True,
                                                   self.failed_parents,
                                                   self.ppname)
                context.retryable = False
                write_to.write(data)
                await write_to.drain()
            except (ConnectionResetError, ConnectionAbortedError):
                # client closed
                context.remote_eof = True
                context.retryable = False
                break
        context.remote_eof = True
        context.remote_recv_count = count

        # DO NOT CLOSE Client Connection, for possible retry
        # try:
        #     write_to.write_eof()
        # except OSError:
        #     pass

    def getparent(self):
        if self._proxylist is None:
            self._proxylist = self.conf.GET_PROXY.get_proxy(
                self.shortpath or self.path, self.request_host, self.command,
                self.request_ip, self.server.profile)
        if not self._proxylist:
            self.ppname = ''
            self.pproxy = None
            if self.failed_parents:
                self.logger.error('no more proxy available.')
            return 1
        self.pproxy = self._proxylist.pop(0)
        self.ppname = self.pproxy.name
        return 0

    def set_timeout(self):
        if self._proxylist:
            if self.ppname == '_D1R3CT_':
                self.timeout = self.conf.timeout
            else:
                self.timeout = min(2 ** len(self.failed_parents) + self.conf.timeout - 1,
                                   MAX_TIMEOUT)
        else:
            self.timeout = MAX_TIMEOUT

    async def api(self, parse):
        '''
        path: supported command
        /api/localrule: GET POST DELETE
        '''
        self.logger.debug('api %s %s', self.command, self.path)
        # read request body
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > 102400:
            return
        body = io.BytesIO()
        while content_length:
            data = await self.client_reader_readexactly(min(self.bufsize, content_length))
            if not data:
                return
            content_length -= len(data)
            body.write(data)
        body = body.getvalue()

        # check password
        if self.conf.remotepass:
            if 'Authorization' not in self.headers:
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic')
                self.end_headers()
                return

            auth = self.headers['Authorization'].split()[1]
            _password = base64.b64decode(auth).decode().split(':', 1)[1]
            if _password != self.conf.remotepass:
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic')
                self.end_headers()
                return

        if parse.path == '/api/localrule' and self.command == 'GET':
            data = json.dumps(self.conf.list_localrule(), indent=4)
            self.write(code=200, data=data, ctype='application/json')
            return
        if parse.path == '/api/localrule' and self.command == 'POST':
            # accept a json encoded tuple: (str rule, int exp)
            rule, exp = json.loads(body)
            self.conf.add_localrule(rule, exp)
            self.write(200)
            return
        if parse.path.startswith('/api/localrule/') and self.command == 'DELETE':
            try:
                rule = base64.urlsafe_b64decode(parse.path[15:].encode('latin1')).decode()
                self.conf.del_localrule(rule)
                self.write(200)
                return
            except Exception as err:
                self.logger.error(traceback.format_exc())
                self.send_error(404, repr(err))
                return
        if parse.path == '/api/isgfwed':
            uri = body.decode('utf8')
            host = urlparse.urlparse(uri).netloc
            host = parse_hostport(host, 80)[0]
            result = self.conf.GET_PROXY.isgfwed_resolver(host, uri)
            self.write(200, data=repr(result), ctype='text/plain')
            return
        if parse.path == '/api/redirector' and self.command == 'GET':
            data = json.dumps(self.conf.list_redir(), indent=4)
            self.write(200, data=data, ctype='application/json')
            return
        if parse.path == '/api/redirector' and self.command == 'POST':
            # accept a json encoded tuple: (str rule, str dest)
            rule, dest = json.loads(body)
            self.conf.add_redir(rule, dest)
            self.write(200)
            return
        if parse.path.startswith('/api/redirector/') and self.command == 'DELETE':
            try:
                rule = urlparse.parse_qs(parse.query).get('rule', [''])[0]
                rule = base64.urlsafe_b64decode(rule).decode()
                self.conf.del_redir(rule)
                self.write(200)
                return
            except Exception as err:
                self.send_error(404, repr(err))
                return
        if parse.path == '/api/proxy' and self.command == 'GET':
            data = self.conf.list_proxy()
            data = json.dumps(data, indent=4)
            self.write(200, data=data, ctype='application/json')
            return
        if parse.path == '/api/proxy' and self.command == 'POST':
            # accept a json encoded tuple: (str name, str proxy)
            name, proxy = json.loads(body)
            if 'FWLITE:' in name:
                self.send_error(401)
                return
            if name == '_L0C4L_':
                self.send_error(401)
                return
            try:
                self.conf.add_proxy(name, proxy)
                self.write(200)
            except ValueError:
                self.write(401)
            return
        if parse.path.startswith('/api/proxy/') and self.command == 'DELETE':
            try:
                proxy_name = parse.path[11:]
                proxy_name = base64.urlsafe_b64decode(proxy_name).decode()
                self.conf.del_proxy(proxy_name)
                self.write(200)
                return
            except Exception as err:
                self.send_error(404, repr(err))
                return
        if parse.path.startswith('/api/proxy/') and self.command == 'GET':
            try:
                proxy_name = parse.path[11:]
                proxy_name = base64.urlsafe_b64decode(proxy_name).decode()
                proxy = self.conf.get_proxy(proxy_name)
                self.write(200, data=proxy, ctype='text/plain')
                return
            except Exception as err:
                self.send_error(404, repr(err))
                return
        if parse.path == '/api/forward' and self.command == 'GET':
            data = self.conf.list_forward()
            data = json.dumps(data, indent=4)
            self.write(200, data=data, ctype='application/json')
            return
        if parse.path == '/api/forward' and self.command == 'POST':
            # accept a json encoded tuple: (str target, str proxy, int port)
            target, proxy, port = json.loads(body)
            self.conf.add_forward(target, proxy, port)
            self.write(200, data=data, ctype='application/json')
            return
        if parse.path.startswith('/api/forward/') and self.command == 'DELETE':
            data = parse.path[13:]
            port = int(data)
            self.conf.del_forward(port)
            self.write(200)
            return
        if parse.path == '/api/gfwlist' and self.command == 'GET':
            self.write(200, data=json.dumps(self.conf.gfwlist_enable), ctype='application/json')
            return
        if parse.path == '/api/gfwlist' and self.command == 'POST':
            self.conf.gfwlist_enable = json.loads(body)
            self.write(200, data=data, ctype='application/json')
            return
        if parse.path == '/api/adblock' and self.command == 'GET':
            self.write(200, data=json.dumps(self.conf.adblock_enable), ctype='application/json')
            return
        if parse.path == '/api/adblock' and self.command == 'POST':
            self.conf.adblock_enable = json.loads(body)
            self.write(200, data=data, ctype='application/json')
            return
        if parse.path == '/api/exit' and self.command == 'GET':
            self.conf.on_exit()
            self.write(200, data='Done!', ctype='text/html')
            return
        if parse.path == '/api/log' and self.command == 'GET':
            self.write(200, data=self.conf.get_log(), ctype='text/plain; charset=utf-8')
            return
        self.logger.error('api %s not exist.' % parse.path)
        self.send_error(404)

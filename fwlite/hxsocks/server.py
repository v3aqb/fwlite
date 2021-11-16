
# server.py - hxsocks server

# Copyright (C) 2016 - 2018, v3aqb

# This file is a part of hxsocks.

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import socket
import struct
import logging
import io
import time
import traceback
import urllib.parse
import random
import hashlib

import asyncio
import asyncio.streams

from hxcrypto import BufEmptyError, InvalidTag, IVError, is_aead, Encryptor
from .hxs2_conn import Hxs2Connection
from .util import open_connection, parse_hostport


DEFAULT_METHOD = 'chacha20-ietf-poly1305'
DEFAULT_HASH = 'SHA256'
MAC_LEN = 16
CTX = b'hxsocks'


class ForwardContext:
    def __init__(self):
        self.last_active = time.time()
        # eof recieved
        self.remote_eof = False
        self.local_eof = False
        # traffic
        self.traffic_from_client = 0
        self.traffic_from_remote = 0


class Server:
    def __init__(self, handler_class, serverinfo, user_mgr, log_level, tcp_nodelay):
        self._handler_class = handler_class
        self.user_mgr = user_mgr
        self.server = None
        self.tcp_nodelay = tcp_nodelay

        self.serverinfo = serverinfo
        parse = urllib.parse.urlparse(serverinfo)
        query = urllib.parse.parse_qs(parse.query)
        if parse.scheme == 'ss':
            self.psk, self.method = parse.password, parse.username
            self.ss_enable = True
        elif 'hxs' in parse.scheme:
            self.psk = query.get('PSK', [''])[0]
            self.method = query.get('method', [DEFAULT_METHOD])[0]
            self.ss_enable = self.psk and int(query.get('ss', ['0'])[0])
        else:
            raise ValueError('bad serverinfo: {}'.format(self.serverinfo))

        self.aead = is_aead(self.method)
        if 'ss' not in query:
            self.ss_enable = self.psk and not self.aead

        # HTTP proxy only
        proxy = query.get('proxy', [''])[0]
        self.proxy = parse_hostport(proxy) if proxy else None

        self.address = (parse.hostname, parse.port)

        self.logger = logging.getLogger('hxs_%d' % self.address[1])
        self.logger.setLevel(int(query.get('log_level', [log_level])[0]))
        hdr = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s')
        hdr.setFormatter(formatter)
        self.logger.addHandler(hdr)

        self.logger.warning('starting server: %s', serverinfo)

    async def handle(self, reader, writer):
        _handler = self._handler_class(self)
        await _handler.handle(reader, writer)

    def start(self):
        asyncio.ensure_future(self._start())

    async def _start(self):
        self.server = await asyncio.start_server(self.handle,
                                                 self.address[0],
                                                 self.address[1],
                                                 limit=262144)


class HXsocksHandler:
    bufsize = 65535

    def __init__(self, server):
        self.server = server
        self.logger = server.logger
        self.user_mgr = self.server.user_mgr
        self.address = self.server.address

        self.encryptor = Encryptor(self.server.psk, self.server.method)
        self.__key = self.server.psk
        self._buf = b''

        self.client_address = None
        self.client_reader = None

    async def _read(self, size=None):
        if self.server.aead:
            _len = await self.client_reader.readexactly(18)
            if not _len:
                return b''
            _len = self.encryptor.decrypt(_len)
            _len, = struct.unpack("!H", _len)
            ct = await self.client_reader.readexactly(_len + 16)
            if not ct:
                return b''
        else:
            size = size or self.bufsize
            ct = await self.client_reader.read(size)
        return self.encryptor.decrypt(ct)

    async def read(self, size=None):
        # compatible with shadowsocks aead
        if not size:
            if self._buf:
                buf, self._buf = self._buf, b''
                return buf
            return await self._read()

        while len(self._buf) < size:
            self._buf += (await self._read(size - len(self._buf)))
        _buf, self._buf = self._buf[:size], self._buf[size:]
        return _buf

    async def handle(self, client_reader, client_writer):
        client_writer.transport.set_write_buffer_limits(262144, 131072)
        if self.server.tcp_nodelay:
            soc = client_writer.transport.get_extra_info('socket')
            soc.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        await self._handle(client_reader, client_writer)

        if not client_writer.is_closing():
            client_writer.close()
        try:
            await client_writer.wait_closed()
        except ConnectionError:
            pass

    async def _handle(self, client_reader, client_writer):
        self.client_address = client_writer.get_extra_info('peername')
        self.client_reader = client_reader
        self.logger.debug('incoming connection %s', self.client_address)

        # read iv
        try:
            fut = self.client_reader.readexactly(self.encryptor._iv_len)
            iv_ = await asyncio.wait_for(fut, timeout=10)
            self.encryptor.decrypt(iv_)
        except IVError:
            self.logger.error('iv reused, %s', self.client_address)
            await self.play_dead()
            return
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError):
            self.logger.warning('iv read failed, %s', self.client_address)
            return

        # read cmd
        try:
            fut = self.read(1)
            cmd = await asyncio.wait_for(fut, timeout=10)
        except asyncio.TimeoutError:
            self.logger.debug('read cmd timed out. %s', self.client_address)
            return
        except (ConnectionError, asyncio.IncompleteReadError):
            self.logger.debug('read cmd reset. %s', self.client_address)
            return
        except InvalidTag:
            self.logger.error('InvalidTag while read cmd. %s', self.client_address)
            await self.play_dead()
            return
        cmd = cmd[0]
        self.logger.debug('cmd: %s %s', cmd, self.client_address)

        if cmd in (1, 3, 4):
            # A shadowsocks request
            result = await self.handle_ss(client_writer, addr_type=cmd)
            if result:
                await self.play_dead()
            return
        if cmd == 20:  # hxsocks2 client key exchange
            req_len = await self.read(2)
            req_len, = struct.unpack('>H', req_len)
            data = await self.read(req_len)
            data = io.BytesIO(data)

            pklen = data.read(1)[0]
            client_pkey = data.read(pklen)
            client_auth = data.read(32)

            try:
                client, reply, shared_secret = self.user_mgr.hxs2_auth(client_pkey, client_auth)
                self.logger.info('new key exchange. client: %s %s', client, self.client_address)
            except ValueError as err:
                self.logger.error('key exchange failed. %s %s', err, self.client_address)
                await self.play_dead()
                return

            reply = reply + bytes(random.randint(64, 2048))
            reply = struct.pack('>H', len(reply)) + reply
            client_writer.write(self.encryptor.encrypt(reply))

            conn = Hxs2Connection(client_reader,
                                  client_writer,
                                  client,
                                  shared_secret,
                                  self.server.proxy,
                                  self.user_mgr,
                                  self.address[1],
                                  self.logger,
                                  self.server.tcp_nodelay)
            await conn.handle_connection()
            client_pkey = hashlib.md5(client_pkey).digest()
            self.user_mgr.del_key(client_pkey)
            return

        # TODO: security log
        self.logger.error('bad cmd: %s, %s', cmd, self.client_address)
        await self.play_dead()
        return

    async def play_dead(self, timeout=1):
        count = random.randint(6, 15)
        for _ in range(count):
            fut = self.client_reader.read(self.bufsize)
            try:
                await asyncio.wait_for(fut, timeout)
            except (asyncio.TimeoutError, ConnectionError):
                return

    async def handle_ss(self, client_writer, addr_type):
        # if error, return 1
        # get header...
        if not self.server.ss_enable:
            return True
        try:
            assert addr_type in (1, 3, 4)
            if addr_type == 1:
                addr = await self.read(4)
                addr = socket.inet_ntoa(addr)
            elif addr_type == 3:
                data = await self.read(1)
                addr = await self.read(data[0])
                addr = addr.decode('ascii')
            else:
                data = await self.read(16)
                addr = socket.inet_ntop(socket.AF_INET6, data)
            port = await self.read(2)
            port, = struct.unpack('>H', port)
        except Exception as err:
            self.logger.error('error on read ss header: %s %s', err, self.client_address)
            self.logger.error(traceback.format_exc())
            return 1

        # access control
        try:
            self.user_mgr.user_access_ctrl(self.address[1], addr, self.client_address, self.__key)
        except ValueError as err:
            self.logger.error('access denied! %s:%s, %s %s', addr, port, err)
            return

        # create connection
        self.logger.info('connect to %s:%d %r', addr, port, self.client_address)

        try:
            remote_reader, remote_writer = await open_connection(addr,
                                                                 port,
                                                                 self.server.proxy,
                                                                 self.server.tcp_nodelay)
            remote_writer.transport.set_write_buffer_limits(262144, 131072)
        except (ConnectionError, asyncio.TimeoutError, socket.gaierror) as err:
            self.logger.error('connect to %s:%s failed! %r', addr, port, err)
            return

        # forward
        context = ForwardContext()

        tasks = [asyncio.create_task(self.ss_forward_a(remote_writer, context)),
                 asyncio.create_task(self.ss_forward_b(remote_reader,
                                                       client_writer,
                                                       self.encryptor.encrypt,
                                                       context)),
                 ]
        await asyncio.wait(tasks)

        # access log
        traffic = (context.traffic_from_client, context.traffic_from_remote)
        self.user_mgr.user_access_log(self.address[1], addr, traffic, self.client_address, self.__key)
        if not remote_writer.is_closing():
            remote_writer.close()
        try:
            await remote_writer.wait_closed()
        except ConnectionError:
            pass

    async def ss_forward_a(self, write_to, context, timeout=60):
        # data from ss client, decrypt, sent to remote
        while True:
            try:
                fut = self.read()
                data = await asyncio.wait_for(fut, timeout=5)
                context.last_active = time.time()
            except asyncio.TimeoutError:
                if time.time() - context.last_active > timeout or context.remote_eof:
                    data = b''
                else:
                    continue
            except (BufEmptyError, asyncio.IncompleteReadError, InvalidTag, ConnectionError):
                data = b''

            if not data:
                break
            context.traffic_from_client += len(data)
            try:
                write_to.write(data)
                await write_to.drain()
            except ConnectionError:
                context.local_eof = True
                return
        context.local_eof = True
        try:
            write_to.write_eof()
        except ConnectionError:
            pass

    async def ss_forward_b(self, read_from, write_to, cipher, context, timeout=60):
        # data from remote, encrypt, sent to client
        while True:
            try:
                fut = read_from.read(self.bufsize)
                data = await asyncio.wait_for(fut, timeout=5)
                context.last_active = time.time()
            except asyncio.TimeoutError:
                if time.time() - context.last_active > timeout or context.local_eof:
                    data = b''
                else:
                    continue
            except ConnectionError:
                data = b''

            if not data:
                break

            context.traffic_from_remote += len(data)

            data = cipher(data)
            try:
                write_to.write(data)
                await write_to.drain()
            except ConnectionError:
                context.remote_eof = True
                return
        context.remote_eof = True
        try:
            write_to.write_eof()
        except OSError:
            pass

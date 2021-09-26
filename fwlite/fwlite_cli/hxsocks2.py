#!/usr/bin/env python
# coding:utf-8

# Copyright (C) 2017-2019 v3aqb

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


from builtins import chr

import sys
import os
import struct
import socket
import time
import hmac
import io
import hashlib
import random
import logging
import traceback
import asyncio
from asyncio import Event, Lock

from six import byte2int

from hxcrypto import InvalidTag, is_aead, Encryptor, ECC, AEncryptor, InvalidSignature

from .parent_proxy import ParentProxy


def set_logger():
    logger = logging.getLogger('hxs2')
    logger.setLevel(logging.INFO)
    hdr = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                                  datefmt='%H:%M:%S')
    hdr.setFormatter(formatter)
    logger.addHandler(hdr)


set_logger()


DEFAULT_METHOD = 'aes-128-cfb'
DEFAULT_HASH = 'sha256'
CTX = b'hxsocks2'
MAX_STREAM_ID = 65530
MAX_CONNECTION = 2

OPEN = 0
EOF_SENT = 1   # SENT END_STREAM
EOF_RECV = 2  # RECV END_STREAM
CLOSED = 3

KNOWN_HOSTS = {}
RECV = 0
SEND = 1

DATA = 0
HEADERS = 1
# PRIORITY = 2
RST_STREAM = 3
# SETTINGS = 4
# PUSH_PROMISE = 5
PING = 6
GOAWAY = 7
# WINDOW_UPDATE = 8
# CONTINUATION = 9

PONG = 1
END_STREAM_FLAG = 1

# load known certs
if not os.path.exists('./.hxs_known_hosts'):
    os.mkdir('./.hxs_known_hosts')
for fname in os.listdir('./.hxs_known_hosts'):
    if fname.endswith('.cert') and os.path.isfile(os.path.join('./.hxs_known_hosts', fname)):
        KNOWN_HOSTS[fname[:-5]] = open('./.hxs_known_hosts/' + fname, 'rb').read()

CONN_MANAGER = {}  # (server, parentproxy): manager


class ConnectionManager:
    def __init__(self, timeout):
        self.timeout = timeout
        self.connection_list = []
        self._lock = Lock()
        self.logger = logging.getLogger('hxs2')

    async def get_connection(self, proxy):
        # choose / create and return a connection
        async with self._lock:
            stream_count = sum([conn.count() for conn in self.connection_list])
            if len(self.connection_list) > 1 or stream_count > 20:
                self.logger.info('%s, %d connections, %d streams',
                                 proxy.name, len(self.connection_list), stream_count)
            if len(self.connection_list) < MAX_CONNECTION and\
                    not [conn for conn in self.connection_list if not conn.is_busy()]:
                self.connection_list.append(Hxs2Connection(proxy, self.timeout, self))
        list_ = sorted(self.connection_list, key=lambda item: item.busy())
        return list_[0]

    def remove(self, conn):
        # this connection is not accepting new streams anymore
        if conn in self.connection_list:
            self.connection_list.remove(conn)


async def hxs2_get_connection(proxy, timeout):
    if proxy.name not in CONN_MANAGER:
        CONN_MANAGER[proxy.name] = ConnectionManager(timeout)
    conn = await CONN_MANAGER[proxy.name].get_connection(proxy)
    return conn


async def hxs2_connect(proxy, timeout, addr, port):
    # Entry Point
    if not isinstance(proxy, ParentProxy):
        proxy = ParentProxy(proxy, proxy)
    assert proxy.scheme == 'hxs2'

    # get hxs2 connection
    conn = await hxs2_get_connection(proxy, timeout)

    soc = await conn.connect(addr, port, timeout)

    reader, writer = await asyncio.open_connection(sock=soc)
    writer.transport.set_write_buffer_limits(0, 0)
    return reader, writer, conn.name


class Hxs2Connection:
    bufsize = 32768

    def __init__(self, proxy, timeout, manager):
        if not isinstance(proxy, ParentProxy):
            proxy = ParentProxy(proxy, proxy)
        self.logger = logging.getLogger('hxs2')
        self.proxy = proxy
        self.name = self.proxy.name
        self.timeout = timeout
        self._manager = manager
        self._ping_test = False
        self._ping_time = 0
        self.connected = False
        self.connection_lost = False

        self._psk = self.proxy.query.get('PSK', [''])[0]
        self.method = self.proxy.query.get('method', [DEFAULT_METHOD])[0].lower()
        self.hash_algo = self.proxy.query.get('hash', [DEFAULT_HASH])[0].upper()

        self.remote_reader = None
        self.remote_writer = None

        self.__pskcipher = None
        self.__cipher = None
        self._next_stream_id = 1

        self._client_writer = {}
        self._client_status = {}
        self._stream_status = {}
        self._last_active = {}
        self._last_active_c = time.monotonic()
        self._last_ping_log = 0

        self._last_direction = SEND
        self._last_count = 0
        self.send_delay = 0
        self.recv_intv = 1
        self.recv_time = 0
        self.recv_tp = 0
        self.recv_tp_ewma = 0

        self._stat_data_recv = 0
        self._stat_total_recv = 1
        self._stat_recv_tp = 0
        self._stat_data_sent = 0
        self._stat_total_sent = 1

        self._lock = Lock()

    async def connect(self, addr, port, timeout=3):
        self.logger.debug('hxsocks2 send connect request')
        async with self._lock:
            if self.connection_lost:
                self._manager.remove(self)
                raise ConnectionResetError(0, 'hxs connection lost')
            if not self.connected:
                try:
                    await self.get_key(timeout)
                except asyncio.CancelledError:
                    raise
                except Exception as err:
                    self.logger.error('%s get_key %r', self.name, err)
                    # self.logger.error(traceback.format_exc())
                    try:
                        self.remote_writer.close()
                    except (OSError, AttributeError):
                        pass
                    raise ConnectionResetError(0, 'hxs get_key failed.')
        # send connect request
        payload = b''.join([chr(len(addr)).encode('latin1'),
                            addr.encode(),
                            struct.pack('>H', port),
                            b'\x00' * random.randint(64, 255),
                            ])
        stream_id = self._next_stream_id
        self._next_stream_id += 1
        if self._next_stream_id > MAX_STREAM_ID:
            self.logger.error('MAX_STREAM_ID reached')
            self._manager.remove(self)

        await self.send_frame(HEADERS, OPEN, stream_id, payload)

        # wait for server response
        event = Event()
        self._client_status[stream_id] = event

        # await event.wait()
        fut = event.wait()
        try:
            await asyncio.wait_for(fut, timeout=timeout)
        except asyncio.TimeoutError:
            self.logger.error('no response from %s, timeout=%.3f', self.name, timeout)
            del self._client_status[stream_id]
            self.print_status()
            await self.send_ping()
            raise

        del self._client_status[stream_id]

        if self._stream_status[stream_id] == OPEN:
            socketpair_a, socketpair_b = socket.socketpair()
            if sys.platform == 'win32':
                socketpair_a.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
                socketpair_b.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)

            reader, writer = await asyncio.open_connection(sock=socketpair_b)
            writer.transport.set_write_buffer_limits(0, 0)

            self._client_writer[stream_id] = writer
            self._last_active[stream_id] = time.monotonic()
            # start forwarding
            asyncio.ensure_future(self.read_from_client(stream_id, reader))
            return socketpair_a
        raise ConnectionResetError(0, 'remote connect to %s:%d failed.' % (addr, port))

    async def read_from_client(self, stream_id, client_reader):
        self.logger.debug('start read from client')

        while not self.connection_lost:
            try:
                intv = 5
                fut = client_reader.read(self.bufsize)
                try:
                    data = await asyncio.wait_for(fut, timeout=intv)
                    self._last_active[stream_id] = time.monotonic()
                except asyncio.TimeoutError:
                    if time.monotonic() - self._last_active[stream_id] > 60 or\
                            self._stream_status[stream_id] & EOF_RECV:
                        await self.send_frame(RST_STREAM, 0, stream_id, bytes(random.randint(8, 256)))
                        self._stream_status[stream_id] = CLOSED
                        break
                    continue
                except ConnectionResetError:
                    await self.send_frame(RST_STREAM, 0, stream_id, bytes(random.randint(8, 256)))
                    self._stream_status[stream_id] = CLOSED
                    break

                if not data:
                    # close stream(LOCAL)
                    self._stream_status[stream_id] |= EOF_SENT
                    await self.send_frame(HEADERS, END_STREAM_FLAG, stream_id, bytes(random.randint(8, 256)))
                    break

                elif self._stream_status[stream_id] & EOF_SENT:
                    self.logger.error('data recv from client, while stream is closed!')

                    await self.send_frame(RST_STREAM, 0, stream_id, bytes(random.randint(8, 256)))
                    self._stream_status[stream_id] = CLOSED
                    self._client_writer[stream_id].close()
                    return
                payload = struct.pack('>H', len(data)) + data + bytes(random.randint(8, 256))
                await self.send_frame(DATA, 0, stream_id, payload)
                self._stat_data_sent += len(data)
            except asyncio.CancelledError:
                raise
            except Exception as err:
                self.logger.error('CLIENT_SIDE BOOM! %r', err)
                self.logger.error(traceback.format_exc())
                self._stream_status[stream_id] = CLOSED
                break
        await asyncio.sleep(5)
        if self._stream_status[stream_id] != CLOSED:
            self._stream_status[stream_id] = CLOSED
            await self.send_frame(RST_STREAM, 0, stream_id, bytes(random.randint(8, 256)))
        if stream_id in self._client_writer:
            try:
                self._client_writer[stream_id].close()
            except OSError:
                pass
            del self._client_writer[stream_id]

    async def send_frame(self, type_, flags, stream_id, payload):
        self.logger.debug('send_frame type: %d, stream_id: %d', type_, stream_id)
        if self.connection_lost:
            self.logger.error('send_frame: connection closed. %s', self.name)
            return
        if type_ != 6:
            self._last_active_c = time.monotonic()

        if self._last_direction == RECV:
            self._last_direction = SEND
            self._last_count = 0

        async with self._lock:
            try:
                header = struct.pack('>BBH', type_, flags, stream_id)
                data = header + payload
                ct = self.__cipher.encrypt(data)
                self.remote_writer.write(struct.pack('>H', len(ct)) + ct)
                await self.remote_writer.drain()
                self._stat_total_sent += len(ct) + 2
                self._last_count += 1
            except ConnectionResetError:
                self.connection_lost = True
                self._manager.remove(self)
            else:
                if type_ == DATA and self._last_count > 10 and random.random() < 0.01:
                    asyncio.ensure_future(self.send_ping(False))

    async def send_ping(self, test=True):
        if self._ping_time == 0:
            self._ping_test = test
            self._ping_time = time.monotonic()
            await self.send_frame(PING, 0, 0, bytes(random.randint(64, 256)))

    async def read_from_connection(self):
        self.logger.debug('start read from connection')
        last_recv = time.monotonic()
        while not self.connection_lost:
            try:
                # read frame_len
                intv = 3 if self._ping_test else 6

                try:
                    frame_len = await self._rfile_read(2, timeout=intv)
                    frame_len, = struct.unpack('>H', frame_len)
                except asyncio.TimeoutError:
                    if self._ping_test and time.monotonic() - self._ping_time > intv:
                        self.logger.warning('server no response %s', self.proxy.name)
                        break
                    if time.monotonic() - self._last_active_c > 120:
                        # no point keeping so long
                        break
                    if time.monotonic() - self._last_active_c > 10:
                        if not self._ping_test:
                            await self.send_ping()
                    continue
                except Exception as err:
                    # destroy connection
                    self.logger.error('read from connection error: %r', err)
                    break
                finally:
                    # log recv delay
                    recv_intv = time.monotonic() - last_recv
                    last_recv = time.monotonic()
                    self.recv_intv = self.recv_intv * 0.87 + recv_intv * 0.13

                # read frame_data
                try:
                    frame_data = await self._rfile_read(frame_len, timeout=self.timeout)
                    frame_data = self.__cipher.decrypt(frame_data)
                    self._stat_total_recv += frame_len + 2
                    self._stat_recv_tp += frame_len + 2
                except (asyncio.TimeoutError, InvalidTag) as err:
                    # destroy connection
                    self.logger.error('read frame data error: %r, timeout %s', err, self.timeout)
                    break
                else:
                    recv_time = time.monotonic() - last_recv
                    self.recv_time = self.recv_time * 0.87 + recv_time * 0.13

                # parse chunk_data
                # +------+-------------------+----------+
                # | type | flags | stream_id | payload  |
                # +------+-------------------+----------+
                # |  1   |   1   |     2     | Variable |
                # +------+-------------------+----------+

                header, payload = frame_data[:4], frame_data[4:]
                frame_type, frame_flags, stream_id = struct.unpack('>BBH', header)
                payload = io.BytesIO(payload)
                self.logger.debug('recv frame_type: %s, stream_id: %s', frame_type, stream_id)

                if self._last_direction == SEND:
                    self._last_direction = RECV
                    self._last_count = 0
                self._last_count += 1

                if self._last_count > 10 and random.random() < 0.1:
                    await self.send_frame(PING, PONG, 0, bytes(random.randint(64, 256)))

                if frame_type == DATA:  # 0
                    # first 2 bytes of payload indicates data_len, the rest would be padding
                    self._last_active_c = time.monotonic()
                    data_len, = struct.unpack('>H', payload.read(2))
                    data = payload.read(data_len)
                    if len(data) != data_len:
                        # something went wrong, destory connection
                        self.logger.error('len(data) != data_len')
                        break
                    # sent data to stream
                    try:
                        self._last_active[stream_id] = time.monotonic()
                        self._client_writer[stream_id].write(data)
                        await self._client_writer[stream_id].drain()
                        self._stat_data_recv += data_len
                    except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
                        # client error, reset stream
                        self._client_writer[stream_id].close()
                        self._stream_status[stream_id] = CLOSED
                        await self.send_frame(RST_STREAM, 0, stream_id, bytes(random.randint(8, 256)))
                    except KeyError:
                        self._stream_status[stream_id] = CLOSED
                        await self.send_frame(RST_STREAM, 0, stream_id, bytes(random.randint(8, 256)))
                elif frame_type == HEADERS:  # 1
                    self._last_active_c = time.monotonic()
                    if self._next_stream_id == stream_id:
                        # server is not supposed to open a new stream
                        # send connection error?
                        break
                    if stream_id < self._next_stream_id:
                        if frame_flags == END_STREAM_FLAG:
                            self._stream_status[stream_id] |= EOF_RECV
                            try:
                                self._client_writer[stream_id].write_eof()  # KeyError?
                            except (KeyError, AttributeError, ConnectionResetError):
                                pass
                            if self._stream_status[stream_id] == CLOSED:
                                if stream_id in self._client_writer:
                                    self._client_writer[stream_id].close()
                                    del self._client_writer[stream_id]
                        else:
                            # confirm a stream is opened
                            if stream_id in self._client_status:
                                self._stream_status[stream_id] = OPEN
                                self._client_status[stream_id].set()
                            else:
                                self.logger.info('%s stream open, client closed', self.name)
                                self._stream_status[stream_id] = CLOSED
                                await self.send_frame(RST_STREAM, 0, stream_id,
                                                      bytes(random.randint(8, 256)))
                elif frame_type == RST_STREAM:  # 3
                    self._last_active_c = time.monotonic()
                    self._stream_status[stream_id] = CLOSED
                    if stream_id in self._client_status:
                        self._stream_status[stream_id] = CLOSED
                        self._client_status[stream_id].set()
                    if stream_id in self._client_writer:
                        self._client_writer[stream_id].close()
                        del self._client_writer[stream_id]

                elif frame_type == PING:  # 6
                    if frame_flags == PONG:
                        resp_time = time.monotonic() - self._ping_time
                        if time.monotonic() - self._last_ping_log > 30:
                            self.logger.info('server response time: %.3f %s', resp_time, self.proxy.name)
                            self._last_ping_log = time.monotonic()
                            if resp_time < 0.5:
                                self.proxy.log('', resp_time)
                        self._ping_test = False
                        self._ping_time = 0
                    else:
                        await self.send_frame(PING, PONG, 0, bytes(random.randint(64, 256)))
                elif frame_type == GOAWAY:  # 7
                    # no more new stream
                    max_stream_id = payload.read(2)
                    self._manager.remove(self)
                    for stream_id, client_writer in self._client_writer:
                        if stream_id > max_stream_id:
                            # reset stream
                            try:
                                client_writer.close()
                            except OSError:
                                pass
                elif frame_type == 8:
                    # WINDOW_UPDATE
                    pass
                else:
                    break
            except Exception as err:
                self.logger.error('CONNECTION BOOM! %r', err)
                self.logger.error(traceback.format_exc())
                break
        # out of loop, destroy connection
        self.connection_lost = True
        self.logger.warning('out of loop %s', self.proxy.name)
        self.logger.info('total_recv: %d, data_recv: %d %.3f',
                         self._stat_total_recv, self._stat_data_recv,
                         self._stat_data_recv / self._stat_total_recv)
        self.logger.info('total_sent: %d, data_sent: %d %.3f',
                         self._stat_total_sent, self._stat_data_sent,
                         self._stat_data_sent / self._stat_total_sent)
        self._manager.remove(self)

        for sid, status in self._client_status.items():
            if isinstance(status, Event):
                self._stream_status[sid] = CLOSED
                status.set()

        try:
            self.remote_writer.close()
        except (OSError, IOError):
            pass
        for stream_id, writer in self._client_writer.items():
            try:
                writer.close()
            except ConnectionResetError:
                pass

    async def get_key(self, timeout):
        self.logger.debug('hxsocks2 getKey')
        usn, psw = (self.proxy.username, self.proxy.password)
        self.logger.info('%s connect to server', self.name)
        from .connection import open_connection
        self.remote_reader, self.remote_writer, _ = await open_connection(
            self.proxy.hostname,
            self.proxy.port,
            proxy=self.proxy.get_via(),
            timeout=timeout,
            tunnel=True)

        # prep key exchange request
        self.__pskcipher = Encryptor(self._psk, self.method)
        ecc = ECC(self.__pskcipher._key_len)
        pubk = ecc.get_pub_key()
        ts = int(time.time()) // 30
        ts = struct.pack('>I', ts)
        padding_len = random.randint(64, 255)
        data = b''.join([chr(len(pubk)).encode('latin1'),
                         pubk,
                         hmac.new(psw.encode(), ts + pubk + usn.encode(), hashlib.sha256).digest(),
                         bytes(padding_len)])
        data = chr(20).encode() + struct.pack('>H', len(data)) + data

        ct = self.__pskcipher.encrypt(data)

        # send key exchange request
        self.remote_writer.write(ct)
        await self.remote_writer.drain()

        # read iv
        iv = await self._rfile_read(self.__pskcipher._iv_len, timeout)
        self.__pskcipher.decrypt(iv)

        # read server response
        if is_aead(self.method):
            ct_len = await self._rfile_read(18, timeout)
            ct_len = self.__pskcipher.decrypt(ct_len)
            ct_len, = struct.unpack('!H', ct_len)
            ct = await self._rfile_read(ct_len + 16)
            ct = self.__pskcipher.decrypt(ct)
            data = ct[2:]
        else:
            resp_len = await self._rfile_read(2, timeout)
            resp_len = self.__pskcipher.decrypt(resp_len)
            resp_len, = struct.unpack('>H', resp_len)
            data = await self._rfile_read(resp_len)
            data = self.__pskcipher.decrypt(data)

        data = io.BytesIO(data)

        resp_code = byte2int(data.read(1))
        if resp_code == 0:
            self.logger.debug('hxsocks read key exchange respond')
            pklen = byte2int(data.read(1))
            scertlen = byte2int(data.read(1))
            siglen = byte2int(data.read(1))

            server_key = data.read(pklen)
            auth = data.read(32)
            server_cert = data.read(scertlen)
            signature = data.read(siglen)

            # TODO: ask user if a certificate should be accepted or not.
            host, port = self.proxy._host_port
            server_id = '%s_%d' % (host, port)
            if server_id not in KNOWN_HOSTS:
                self.logger.info('hxs: server %s new cert %s saved.',
                                 server_id, hashlib.sha256(server_cert).hexdigest()[:8])
                with open('./.hxs_known_hosts/' + server_id + '.cert', 'wb') as f:
                    f.write(server_cert)
                    KNOWN_HOSTS[server_id] = server_cert
            elif KNOWN_HOSTS[server_id] != server_cert:
                self.logger.error('hxs: server %s certificate mismatch! PLEASE CHECK!', server_id)
                raise ConnectionResetError(0, 'hxs: bad certificate')

            if auth == hmac.new(psw.encode(), pubk + server_key + usn.encode(), hashlib.sha256).digest():
                try:
                    ECC.verify_with_pub_key(server_cert, auth, signature, self.hash_algo)
                    shared_secret = ecc.get_dh_key(server_key)
                    self.logger.debug('hxs key exchange success')
                    self.__cipher = AEncryptor(shared_secret, self.method, CTX)
                    # start reading from connection
                    asyncio.ensure_future(self.read_from_connection())
                    asyncio.ensure_future(self.stat())
                    self.connected = True
                    return
                except InvalidSignature:
                    self.logger.error('hxs getKey Error: server auth failed, bad signature')
            else:
                self.logger.error('hxs getKey Error: server auth failed, bad username or password')
        else:
            self.logger.error('hxs getKey Error. bad password or timestamp.')
        raise ConnectionResetError(0, 'hxs getKey Error')

    async def _rfile_read(self, size, timeout=3):
        fut = self.remote_reader.readexactly(size)
        data = await asyncio.wait_for(fut, timeout=timeout)
        return data

    def count(self):
        return len(self._client_writer)

    async def stat(self):
        while not self.connection_lost:
            await asyncio.sleep(1)
            self.recv_tp = self._stat_recv_tp
            self.recv_tp_ewma = self.recv_tp_ewma * 0.87 + self._stat_recv_tp * 0.13
            self._stat_recv_tp = 0

    def busy(self):
        return self.recv_time / self.recv_intv

    def is_busy(self):
        if self.busy() > 0.8:
            return True
        return False

    def print_status(self):
        self.logger.info('%s recv_tp: %s', self.name, self.recv_tp)
        self.logger.info('%s tp_ewma: %d', self.name, self.recv_tp_ewma)
        self.logger.info('%s recv_intv: %f', self.name, self.recv_intv)
        self.logger.info('%s recv_time: %f', self.name, self.recv_time)
        self.logger.info('%s stream: %d', self.name, self.count())

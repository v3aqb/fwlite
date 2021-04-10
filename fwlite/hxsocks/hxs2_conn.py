
# hxs2_conn.py - hxsocks2 protocol

# Copyright (C) 2018, v3aqb

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

import asyncio
import struct
import io
import time
import random
import traceback

from hxcrypto import InvalidTag, AEncryptor
from .util import open_connection


CTX = b'hxsocks2'

OPEN = 0
EOF_SENT = 1   # SENT END_STREAM
EOF_RECV = 2  # RECV END_STREAM
CLOSED = 3

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


class ForwardContext:
    def __init__(self, host):
        self.host = host
        self.last_active = time.time()
        # eof recieved
        self.stream_status = OPEN
        self.remote_status = OPEN
        # traffic
        self.traffic_from_client = 0
        self.traffic_from_remote = 0


class Hxs2Connection():
    bufsize = 32768

    def __init__(self, reader, writer, user, skey, method, proxy, user_mgr, s_port, logger):
        self.__cipher = AEncryptor(skey, method, CTX)
        self._client_reader = reader
        self._client_writer = writer
        self._client_address = writer.get_extra_info('peername')[0]
        self._client_writer.transport.set_write_buffer_limits(0, 0)
        self._proxy = proxy
        self._s_port = s_port
        self._logger = logger
        self.user = user
        self.user_mgr = user_mgr

        self._init_time = time.time()
        self._last_active = self._init_time
        self._gone = False
        self._next_stream_id = 1

        self._stream_writer = {}
        self._stream_task = {}
        self._stream_context = {}

        self._client_writer_lock = asyncio.Lock()

    async def wait_close(self):
        self._logger.debug('start recieving frames...')
        timeout_count = 0

        while True:
            try:
                if self._gone and not self._stream_writer:
                    break

                time_ = time.time()
                if time_ - self._last_active > 300:
                    break

                # read frame_len
                try:
                    fut = self._client_reader.readexactly(2)
                    frame_len = await asyncio.wait_for(fut, timeout=10)
                    frame_len, = struct.unpack('>H', frame_len)
                    timeout_count = 0
                except (asyncio.IncompleteReadError, ValueError, InvalidTag,
                        ConnectionResetError) as err:
                    self._logger.debug('read frame_len error: %r', err)
                    break
                except asyncio.TimeoutError:
                    timeout_count += 1
                    # client should sent keep_alive chunk
                    if timeout_count > 10:
                        # destroy connection
                        self._logger.debug('read frame_len timed out.')
                        break
                    continue
                except OSError as err:
                    self._logger.debug('read frame_len error: %r', err)
                    break

                # read chunk_data
                try:
                    fut = self._client_reader.readexactly(frame_len)
                    # chunk size shoule be lower than 16kB
                    frame_data = await asyncio.wait_for(fut, timeout=8)
                    frame_data = self.__cipher.decrypt(frame_data)
                except (OSError, InvalidTag, asyncio.TimeoutError,
                        asyncio.streams.IncompleteReadError) as err:
                    # something went wrong...
                    self._logger.debug('read frame error: %r', err)
                    break

                # parse chunk_data
                # +------+-------------------+----------+
                # | type | flags | stream_id | payload  |
                # +------+-------------------+----------+
                # |  1   |   1   |     2     | Variable |
                # +------+-------------------+----------+

                header, payload = frame_data[:4], frame_data[4:]
                frame_type, frame_flags, stream_id = struct.unpack('>BBH', header)
                payload = io.BytesIO(payload)

                if frame_type != PING:
                    self._last_active = time.time()

                self._logger.debug('recv frame_type: %d, stream_id: %d', frame_type, stream_id)
                if frame_type == DATA:  # 1
                    # first 2 bytes of payload indicates data_len
                    data_len, = struct.unpack('>H', payload.read(2))
                    data = payload.read(data_len)
                    if len(data) != data_len:
                        # something went wrong, destory connection
                        self._logger.debug('data_len mismatch')
                        break
                    # check if remote socket writable
                    if self._stream_context[stream_id].remote_status & EOF_SENT:
                        continue
                    # sent data to stream
                    try:
                        self._stream_writer[stream_id].write(data)
                        self._stream_context[stream_id].traffic_from_client += len(data)
                        self._stream_context[stream_id].last_active = time.time()
                        await self._stream_writer[stream_id].drain()
                    except OSError:
                        # remote closed, reset stream
                        self._stream_context[stream_id].stream_status = CLOSED
                        if stream_id in self._stream_writer:
                            self._stream_writer[stream_id].close()
                            del self._stream_writer[stream_id]
                        self._stream_context[stream_id].remote_status = CLOSED
                elif frame_type == HEADERS:  # 1
                    if self._next_stream_id == stream_id:
                        # open new stream
                        self._next_stream_id += 1

                        host_len = payload.read(1)[0]
                        host = payload.read(host_len).decode('ascii')
                        port, = struct.unpack('>H', payload.read(2))
                        # rest of the payload is discarded
                        asyncio.ensure_future(self.create_connection(stream_id, host, port))

                    elif stream_id < self._next_stream_id:
                        self._logger.debug('sid %s END_STREAM. status %s',
                                           stream_id,
                                           self._stream_context[stream_id].stream_status)
                        if frame_flags & END_STREAM_FLAG:
                            if self._stream_context[stream_id].stream_status == OPEN:
                                self._stream_context[stream_id].stream_status = EOF_RECV
                                self._stream_writer[stream_id].write_eof()
                                self._stream_context[stream_id].remote_status = EOF_SENT
                            elif self._stream_context[stream_id].stream_status == EOF_SENT:
                                self._stream_context[stream_id].stream_status = CLOSED
                                self._stream_writer[stream_id].close()
                                self._stream_context[stream_id].remote_status = CLOSED
                                del self._stream_writer[stream_id]
                                self.log_access(stream_id)
                            else:
                                self._logger.error('recv END_STREAM_FLAG, stream already closed.')
                elif frame_type == RST_STREAM:  # 3
                    self._stream_context[stream_id].stream_status = CLOSED
                    if stream_id in self._stream_writer:
                        self._stream_writer[stream_id].close()
                        del self._stream_writer[stream_id]
                    self._stream_context[stream_id].remote_status = CLOSED
                elif frame_type == PING:  # 6
                    if frame_flags == 0:
                        await self.send_frame(PING, PONG, 0, bytes(random.randint(64, 256)))
                elif frame_type == GOAWAY:  # 7
                    # GOAWAY
                    # no more new stream
                    # make no sense when client sending this...
                    self._gone = True
            except Exception as err:
                self._logger.error('read from connection error: %r', err)
                self._logger.error(traceback.format_exc())
        # exit loop, close all streams...
        self._logger.info('recv from hxs2 connect ended')
        for stream_id, writer in self._stream_writer.items():
            try:
                writer.close()
            except Exception:
                pass

    async def create_connection(self, stream_id, host, port):
        self._logger.info('connecting %s:%s %s %s', host, port, self.user, self._client_address)
        timelog = time.time()

        try:
            self.user_mgr.user_access_ctrl(self._s_port, host, self._client_address, self.user)
            reader, writer = await open_connection(host, port, self._proxy)
            writer.transport.set_write_buffer_limits(0, 0)
        except Exception as err:
            # tell client request failed.
            self._logger.error('connect %s:%s failed: %r', host, port, err)
            data = b'\x01' * random.randint(64, 256)
            await self.send_frame(RST_STREAM, 0, stream_id, data)
        else:
            # tell client request success, header frame, first byte is \x00
            timelog = time.time() - timelog
            if timelog > 1:
                self._logger.info('connect %s:%s connected, %.3fs', host, port, timelog)
            # client may reset the connection
            # TODO: maybe keep this connection for later?
            if stream_id in self._stream_context and self._stream_context[stream_id].stream_status == CLOSED:
                writer.close()
                return
            data = bytes(random.randint(64, 256))
            await self.send_frame(HEADERS, OPEN, stream_id, data)
            # registor stream
            self._stream_writer[stream_id] = writer
            self._stream_context[stream_id] = ForwardContext(host)
            # start forward from remote_reader to client_writer
            task = asyncio.ensure_future(self.read_from_remote(stream_id, reader))
            self._stream_task[stream_id] = task

    async def send_frame(self, type_, flags, stream_id, payload):
        self._logger.debug('send frame_type: %d, stream_id: %d', type_, stream_id)
        if type_ != 6:
            self._last_active = time.time()

        await self._client_writer_lock.acquire()
        try:
            header = struct.pack('>BBH', type_, flags, stream_id)
            data = header + payload
            ct = self.__cipher.encrypt(data)
            self._client_writer.write(struct.pack('>H', len(ct)) + ct)
            await self._client_writer.drain()
        except OSError as err:
            # destroy connection
            self._logger.error('send_frame error %r', err)
            raise err
        finally:
            self._client_writer_lock.release()

    async def read_from_remote(self, stream_id, remote_reader):
        self._logger.debug('start read from stream')
        timeout_count = 0
        while not self._stream_context[stream_id].remote_status & EOF_RECV:
            fut = remote_reader.read(self.bufsize)
            try:
                data = await asyncio.wait_for(fut, timeout=6)
                self._stream_context[stream_id].last_active = time.time()
            except asyncio.TimeoutError:
                timeout_count += 1
                if self._stream_context[stream_id].stream_status != OPEN:
                    data = b''
                elif time.time() - self._stream_context[stream_id].last_active < 120:
                    continue
                self._stream_context[stream_id].remote_status = CLOSED
                # TODO: reset stream
                data = b''
            except OSError:
                self._stream_context[stream_id].remote_status = CLOSED
                # TODO: reset stream
                data = b''
            if not data:
                self._stream_context[stream_id].remote_status |= EOF_RECV
                try:
                    await self.send_frame(HEADERS, END_STREAM_FLAG, stream_id,
                                          bytes(random.randint(8, 2048)))
                except ConnectionResetError:
                    pass
                self._stream_context[stream_id].stream_status |= EOF_SENT
                if self._stream_context[stream_id].stream_status & EOF_RECV:
                    if stream_id in self._stream_writer:
                        self._stream_writer[stream_id].close()
                        del self._stream_writer[stream_id]
                    self._stream_context[stream_id].remote_status = CLOSED
                    self._logger.debug('sid %s stream closed.(rfr)', stream_id)
                    self.log_access(stream_id)
                break
            if not self._stream_context[stream_id].stream_status & EOF_SENT:
                self._stream_context[stream_id].traffic_from_remote += len(data)
                payload = struct.pack('>H', len(data)) + data + bytes(random.randint(8, 255))
                await self.send_frame(DATA, 0, stream_id, payload)
        self._logger.debug('sid %s read_from_remote end. status %s',
                           stream_id,
                           self._stream_context[stream_id].stream_status)

    def log_access(self, stream_id):
        traffic = (self._stream_context[stream_id].traffic_from_client,
                   self._stream_context[stream_id].traffic_from_remote)
        self.user_mgr.user_access_log(self._s_port,
                                      self._stream_context[stream_id].host,
                                      traffic,
                                      self._client_address,
                                      self.user)

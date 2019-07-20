
# Copyright (C) 2014-2018 v3aqb

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

import email
from http.client import HTTPMessage
from http.server import BaseHTTPRequestHandler
from http import HTTPStatus
import traceback

import asyncio

__version__ = '0'


async def read_response_line(reader, timeout=1):
    # GET / HTTP/1.1\r\n
    # HTTP/1.1 200 OK\r\n
    fut = reader.readline()
    request_line = await asyncio.wait_for(fut, timeout=timeout)

    if not request_line.endswith(b'\n'):
        raise asyncio.TimeoutError()

    a, b, c = request_line.strip().split(b' ', 2)
    return request_line, a, b, c


async def read_header_data(reader, timeout=1):
    header_data = b''
    while True:
        fut = reader.readline()
        line = await asyncio.wait_for(fut, timeout=timeout)
        header_data += line
        if not line.strip():
            break
    return header_data


async def read_headers(reader, timeout=1):
    header_data = await read_header_data(reader, timeout)
    headers = email.parser.Parser(_class=HTTPMessage).parsestr(header_data.decode('iso-8859-1'))
    return header_data, headers


class BaseHandler(BaseHTTPRequestHandler):
    bufsize = 8192
    server_version = "BaseHTTPServer/" + __version__
    default_request_version = "HTTP/1.1"

    def __init__(self, server):  # pylint: disable=super-init-not-called
        # Not calling super-init, not for TCPServer
        self.server = server
        self.logger = server.logger
        self.requestline = ''
        self.request_version = ''
        self.command = ''
        self.close_connection = True
        self.req_count = 0
        self.path = ''
        self.headers = None

    async def handle(self, client_reader, client_writer):  # pylint: disable=W0221
        self.client_reader = client_reader
        self.client_writer = client_writer
        self.client_address = client_writer.get_extra_info('peername')
        self.logger.debug('incoming connection %s', self.client_address)

        self.wfile = client_writer

        self.remote_writer = None

        self.close_connection = True
        self.request_host = None

        try:
            await self._handle()
        except asyncio.CancelledError:
            raise
        except Exception as err:
            self.logger.error('base_handler')
            self.logger.error(repr(err))
            self.logger.error(traceback.format_exc())

        self.client_writer.close()

    async def _handle(self):
        await self.handle_one_request()
        while not self.close_connection:
            await self.handle_one_request()
        if self.remote_writer:
            self.remote_writer.close()

    def pre_request_init(self):
        self.req_count += 1
        self.requestline = ''
        self.request_version = ''
        self.command = ''
        self.close_connection = True

    async def handle_one_request(self):
        self.pre_request_init()

        try:
            # read request line
            self.requestline, command, path, request_version = \
                await read_response_line(self.client_reader, 60)

            # read headers
            _, self.headers = await read_headers(self.client_reader)
        except (asyncio.TimeoutError, ConnectionResetError) as err:
            self.logger.debug('base_handler read request failed! %r', err)
            self.close_connection = True
            return

        self.command = command.decode('ascii')
        self.path = path.decode('ascii')
        self.request_version = request_version.decode('ascii')

        base_version_number = self.request_version.split('/', 1)[1]
        version_number = base_version_number.split(".")
        version_number = int(version_number[0]), int(version_number[1])
        if version_number == (1, 1):
            self.close_connection = False

        # look for a Connection directive
        conntype = self.headers.get('Connection', "")
        if conntype.lower() == 'close':
            self.close_connection = True
        elif conntype.lower() == 'keep-alive':
            self.close_connection = False

        # call method function
        mname = 'do_' + self.command
        if not hasattr(self, mname):
            self.send_error(
                HTTPStatus.NOT_IMPLEMENTED,
                "Unsupported method (%r)" % self.command)
            await self.client_writer.drain()
            return
        method = getattr(self, mname)
        await method()
        try:
            await self.client_writer.drain()
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            self.close_connection = True

    def log_message(self, _format, *args):
        pass

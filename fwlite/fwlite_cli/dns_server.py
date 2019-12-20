
# Copyright (C) 2019 v3aqb

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


import asyncio
import struct
import socket
import logging

import dnslib

from .connection import open_connection

logger = logging.getLogger('dns_server')


def set_logger():
    logger.setLevel(logging.INFO)
    hdr = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                                  datefmt='%H:%M:%S')
    hdr.setFormatter(formatter)
    logger.addHandler(hdr)


set_logger()


class RequestFinishedError(Exception):
    pass


async def getaddrinfo(host, port):
    loop = asyncio.get_event_loop()
    fut = loop.getaddrinfo(host, port)
    result = await asyncio.wait_for(fut, timeout=2)
    return result


async def resolve(host, port):
    result = await getaddrinfo(host, port)
    return [(i[0], i[4][0]) for i in result]


class TcpDnsHandler:
    def __init__(self, server, proxy, conf):
        self.conf = conf      # has a GET_PROXY object, provide isgfwed function
        self.proxy = proxy    # "http://127.0.0.1:8118"
        self.server = server  # ('8.8.8.8', 53)

    async def handle(self, reader, writer):
        # read dns request
        while True:
            try:
                length = reader.readexactly(2)
                length = await asyncio.wait_for(length, timeout=10)
                length = struct.unpack("!H", length)[0]
                data = reader.readexactly(length)
                data = await asyncio.wait_for(data, timeout=2)

                request = dnslib.DNSRecord.parse(data)

                asyncio.ensure_future(self.do_resolve(request, writer))

            except (IOError, asyncio.IncompleteReadError):
                break
        try:
            writer.close()
        except IOError:
            pass

    async def do_resolve(self, request, client_writer):
        try:
            record = await self.get_record(request, client_writer)
            rdata = record.pack()

            rdata = struct.pack("!H", len(rdata)) + rdata
            client_writer.write(rdata)
        except RequestFinishedError:
            pass

    async def get_record(self, request, client_writer):
        if len(request.questions) != 1:
            logger.debug('len(request.questions) != 1, FORMERR')
            reply = request.reply()
            reply.header.rcode = getattr(dnslib.RCODE, 'FORMERR')
            return reply

        try:
            result = await self._get_record(request, client_writer)
            return result
        except IOError as e:
            reply = request.reply()
            reply.header.rcode = getattr(dnslib.RCODE, 'NXDOMAIN')
            return reply

    async def _get_record(self, request, client_writer):
        domain = str(request.questions[0].qname)[:-1]
        qtype = request.questions[0].qtype
        logger.info('dns_request: %s, %s', domain, qtype)

        if not self.conf.GET_PROXY.isgfwed_resolver(domain):
            # try resolve with getaddrinfo first
            logger.debug('not gfwed.')
            if qtype in (dnslib.QTYPE.A, dnslib.QTYPE.AAAA, dnslib.QTYPE.ANY):
                result_list = await resolve(domain, 0)
                response = request.reply()
                for result in result_list:
                    if result[0] == socket.AF_INET and qtype in (dnslib.QTYPE.A, dnslib.QTYPE.ANY):
                        response.add_answer(dnslib.RR(domain, dnslib.QTYPE.A,
                                                      rdata=dnslib.A(result[1])))

                    elif result[0] == socket.AF_INET6 and qtype in (dnslib.QTYPE.AAAA, dnslib.QTYPE.ANY):
                        response.add_answer(dnslib.RR(domain, dnslib.QTYPE.AAAA,
                                                      rdata=dnslib.AAAA(result[1])))
                return response

        await self.tcp_dns_record(request, client_writer)

    async def tcp_dns_record(self, request, client_writer):
        logger.debug('tcp_dns_record')
        try:
            addr, port = self.server
            reader, writer, _ = await open_connection(addr, port, proxy=self.proxy, tunnel=True)
            query_data = request.pack()
            data = struct.pack('>h', len(query_data)) + query_data
            logger.debug('send request')
            writer.write(data)
            await writer.drain()

            fut = reader.readexactly(2)
            reply_data_length = await asyncio.wait_for(fut, timeout=60)
            fut = reader.readexactly(struct.unpack('>h', reply_data_length)[0])
            reply_data = await asyncio.wait_for(fut, timeout=2)
            logger.debug('record recved.')
            client_writer.write(reply_data_length + reply_data)
        finally:
            try:
                writer.close()
            except IOError:
                pass
            raise RequestFinishedError

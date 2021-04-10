
# util.py - funtion used by both hxsocks and hxsocks2 protocol

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

import asyncio
import ipaddress


async def get_ip_address(host):
    try:
        return ipaddress.ip_address(host)
    except Exception:
        return ipaddress.ip_address('1.1.1.1')


async def request_is_loopback(addr):
    try:
        ip = await get_ip_address(addr)
        if ip.is_loopback:
            return ip
    except Exception:
        pass
    return None


async def open_connection(addr, port, proxy):
    # do security check here
    data = await request_is_loopback(addr)
    if data:
        raise ValueError('connect to localhost denied!')

    # create connection
    if proxy:
        fut = asyncio.open_connection(proxy[0], proxy[1])
        remote_reader, remote_writer = await asyncio.wait_for(fut, timeout=2)
        s = 'CONNECT {0}:{1} HTTP/1.1\r\nHost: {0}:{1}\r\n\r\n'.format(addr, port)
        remote_writer.write(s.encode())
        fut = remote_reader.readuntil(b'\r\n\r\n')
        data = await asyncio.wait_for(fut, timeout=2)
        if b'200' not in data:
            raise IOError(0, 'create tunnel via %s failed!' % proxy)
        return remote_reader, remote_writer

    fut = asyncio.open_connection(addr, port)
    remote_reader, remote_writer = await asyncio.wait_for(fut, timeout=6)
    return remote_reader, remote_writer

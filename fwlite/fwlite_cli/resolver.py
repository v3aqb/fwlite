
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

import asyncio
import socket
import logging
from ipaddress import ip_address

logger = logging.getLogger('resolver')


def set_logger():
    logger.setLevel(logging.INFO)
    hdr = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                                  datefmt='%H:%M:%S')
    hdr.setFormatter(formatter)
    logger.addHandler(hdr)


set_logger()


async def getaddrinfo(host, port):
    loop = asyncio.get_event_loop()
    fut = loop.getaddrinfo(host, port)
    result = await asyncio.wait_for(fut, timeout=2)
    return result


async def resolve(host, port):
    result = await getaddrinfo(host, port)
    return [(i[0], i[4][0]) for i in result]


class Resolver:
    def __init__(self, get_proxy, bad_ip):
        self.get_proxy = get_proxy
        self.bad_ip = bad_ip

    def is_poisoned(self, domain):
        if self.get_proxy and self.get_proxy.isgfwed_resolver(domain):
            return True
        return False

    async def resolve(self, host, port, dirty=False):
        ''' return
        '''
        logger.debug('entering %s.resolve(%s)', self.__class__.__name__, host)
        try:
            ip = ip_address(host)
            return [(socket.AF_INET if ip.version == 4 else socket.AF_INET6, host), ]
        except ValueError:
            pass
        if self.is_poisoned(host):
            if dirty:
                return []
            raise NotImplementedError
        try:
            # resolve
            result = await resolve(host, port)
            if result[0][1] in self.bad_ip:
                return []
            return result
        except (OSError, asyncio.TimeoutError, LookupError) as err:
            logger.warning('resolving %s failed: %r', host, err)
            return []

    async def get_ip_address(self, host):
        logger.debug('entering %s.get_ip_address(%s)', self.__class__.__name__, host)
        try:
            return ip_address(host)
        except ValueError:
            pass

        try:
            result = await self.resolve(host, 0, dirty=True)
            result = [ip for ip in result if ip[0] == socket.AF_INET]
            return ip_address(result[0][1])
        except IndexError:
            return ip_address(u'0.0.0.0')

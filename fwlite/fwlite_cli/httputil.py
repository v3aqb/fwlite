
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

import logging
import itertools
import asyncio
from asyncio import Lock
from collections import defaultdict, deque


def is_connection_dropped(conn_lst):
    """
    Returns sockets that is dropped and should be closed.

    conn_list: [(reader, writer), ...]

    """
    return [item for item in conn_lst if item[0].at_eof()]


class ConnectionPool:
    logger = logging.getLogger('httpconn_pool')
    logger.setLevel(logging.INFO)
    hdr = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                                  datefmt='%H:%M:%S')
    hdr.setFormatter(formatter)
    logger.addHandler(hdr)

    def __init__(self, timeout=60):
        self.pool = defaultdict(deque)  # {upstream_name: [(soc, ppname), ...]}
        self.socs = {}  # keep track of sock info
        self.intv = 10
        self.count = timeout // self.intv
        self.timerwheel = [set() for _ in range(self.count)]  # a list of socket object
        self.timerwheel_iter = itertools.cycle(range(self.count))
        self.timerwheel_index = next(self.timerwheel_iter)
        self.lock = Lock()

        asyncio.ensure_future(self._purge())

    def put(self, upstream_name, soc, ppname):
        # soc: (reader, writer)
        self.logger.debug('adding')
        self.logger.debug('  upstream_name: %r %r', *upstream_name)
        self.logger.debug('  soc: %r %r', *soc)
        self.logger.debug('  ppname: %r', ppname)
        self.pool[upstream_name].append((soc, ppname))
        self.socs[soc] = (self.timerwheel_index, ppname, upstream_name)
        self.timerwheel[self.timerwheel_index].add(soc)

    def get(self, upstream_name):
        self.logger.debug('get: %r %r', *upstream_name)
        lst = self.pool.get(upstream_name)
        while lst:
            sock, pproxy = lst.popleft()
            if is_connection_dropped([sock]):
                sock[1].close()
                self._remove(sock)
                continue
            self._remove(sock)
            return (sock, pproxy)

    def _remove(self, soc):
        twindex, ppn, upsname = self.socs.pop(soc)
        self.timerwheel[twindex].discard(soc)
        if (soc, ppn) in self.pool[upsname]:
            self.pool[upsname].remove((soc, ppn))

    async def _purge(self):
        while 1:
            await asyncio.sleep(self.intv)
            pcount = 0
            async with self.lock:
                remove_lst = []
                for soc in is_connection_dropped(self.socs.keys()):
                    soc[1].close()
                    remove_lst.append(soc)
                    pcount += 1
                for soc in remove_lst:
                    self._remove(soc)
                remove_lst = []
                if pcount:
                    self.logger.debug('closing %s for connection droped.', pcount)

                self.timerwheel_index = next(self.timerwheel_iter)
                for soc in list(self.timerwheel[self.timerwheel_index]):
                    soc[1].close()
                    remove_lst.append(soc)
                    pcount += 1
                for soc in remove_lst:
                    self._remove(soc)

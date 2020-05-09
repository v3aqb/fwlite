# Copyright (c) 2017-2018 v3aqb

# This file is part of hxcrypto.

# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
# 02110-1301  USA

from collections import OrderedDict, defaultdict
import time
import random


class IVError(ValueError):
    pass


class IVStore(object):

    def __init__(self, maxlen, timeout):
        self.maxlen = maxlen
        self.timeout = timeout
        self.store = OrderedDict()
        self.last_time_used = time.time()

    def add(self, item):
        self.last_time_used = time.time()
        if random.random() < 0.01:
            self._clean()
        if item in self:
            raise IVError
        self.store[item] = self.last_time_used
        while len(self.store) > self.maxlen:
            self.store.popitem()

    def __contains__(self, item):
        try:
            if self.store[item] < time.time() - self.timeout:
                while True:
                    a, _ = self.store.popitem()
                    if a == item:
                        break
                return False
            return True
        except KeyError:
            return False

    def _clean(self):
        garbage = []
        for k in self.store:
            if self.store[k] < time.time() - self.timeout:
                garbage.append(k)
            else:
                break
        for k in garbage:
            del self.store[k]

    def __str__(self):
        return str([k for k in self.store])

    def __repr__(self):
        return str([k for k in self.store])


class IVChecker(object):
    # check reused iv, removing out-dated data automatically

    def __init__(self, maxlen, timeout):
        self.timeout = timeout * 10
        # create a IVStore for each key
        self.store = defaultdict(lambda: IVStore(maxlen, timeout * 2))

    def check(self, key, iv):
        if random.random() < 0.01:
            self._clean()
        self.store[key].add(iv)

    def _clean(self):
        garbage = []
        for key, store in self.store.items():
            if store.last_time_used < time.time() - self.timeout:
                garbage.append(key)
        for key in garbage:
            del self.store[key]

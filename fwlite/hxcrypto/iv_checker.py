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

import random
import time
from collections import defaultdict
from dmfrbloom.bloomfilter import BloomFilter as _BloomFilter


class BloomFilter(_BloomFilter):
    def __init__(self, expected_items, fp_rate):
        super().__init__(expected_items, fp_rate)
        self.count = 0

    def add(self, item):
        super().add(item)
        self.count += 1

    def __contains__(self, item):
        return self.lookup(item)

    def __len__(self):
        return self.count

    def clear(self):
        self.filter.zero()
        self.count = 0


class IVError(ValueError):
    pass


class IVStore(object):

    def __init__(self, maxlen):
        self.maxlen = maxlen
        self.store_0 = BloomFilter(self.maxlen, 0.001)
        self.store_1 = BloomFilter(self.maxlen, 0.001)

    def add(self, item):
        if item in self:
            raise IVError
        if len(self.store_0) >= self.maxlen:
            self.store_0, self.store_1 = self.store_1, self.store_0
            self.store_0.clear()
        self.store_0.add(item)

    def __contains__(self, item):
        if item in self.store_0:
            return True
        if item in self.store_1:
            return True
        return False


class IVChecker(object):
    # check reused iv, removing out-dated data automatically

    def __init__(self, maxlen=50000, timeout=3600):
        # create a IVStore for each key
        self.timeout = timeout
        self.store = defaultdict(lambda: IVStore(maxlen))

    def check(self, key, iv):
        self.store[key].add(iv)


# Copyright (C) 2018 v3aqb

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

from __future__ import absolute_import, print_function, division

import os
import sys
import argparse

import asyncio

from .config import Config
from . import __version__


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', required=True, help="path to config file")
    parser.add_argument('-gui', action='store_true')
    args = parser.parse_args()

    if not os.path.exists(args.c):
        sys.stderr.write('config file {} not exist!\n'.format(args.c))
        sys.exit()

    hello = 'FWLite %s with asyncio, ' % __version__
    import platform
    hello += 'python %s %s' % (platform.python_version(), platform.architecture()[0])

    if args.gui:
        hello += ' with GUI'

    sys.stderr.write(hello + '\n')

    if sys.platform == 'win32':
        loop = asyncio.ProactorEventLoop()
        asyncio.set_event_loop(loop)

    conf = Config(args.c, args.gui)

    conf.start_server()

    conf.start_dns_server()

    conf.start()


if __name__ == '__main__':
    main()

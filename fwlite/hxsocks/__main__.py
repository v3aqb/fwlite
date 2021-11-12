
# __main__.py - start hxsocks server

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

import os
import sys
import argparse
import asyncio

from .start_server import start_hxs_server


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', required=True, help="config file")
    args = parser.parse_args()

    if not os.path.exists(args.c):
        sys.stderr.write('config file {} not exist!\n'.format(args.c))
        sys.exit()
    if sys.platform == 'win32':
        loop = asyncio.ProactorEventLoop()
        asyncio.set_event_loop(loop)

    server_list = start_hxs_server(args.c)

    loop = asyncio.get_event_loop()
    loop.run_forever()


if __name__ == '__main__':
    main()

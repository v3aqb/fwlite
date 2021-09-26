
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

import os
import time
import socket
import subprocess
import shlex
import atexit
import logging

logger = logging.getLogger('plugin_manager')


def set_logger():
    logger.setLevel(logging.INFO)
    hdr = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                                  datefmt='%H:%M:%S')
    hdr.setFormatter(formatter)
    logger.addHandler(hdr)


set_logger()

PLUGIN_PATH = {}
NON_SIP003 = ['kcptun']


def is_udp(plugin_info):
    if plugin_info[0] == 'kcptun':
        return True
    if 'ray-plugin' in plugin_info[0]:
        if 'mode=quic' in plugin_info:
            return True
    return False


def find_path(path):
    if not os.path.isabs(path):
        if not os.path.dirname(path):
            from ctypes.util import find_library
            if find_library(path):
                return path
        if os.path.exists(path):
            return path
        new_path = '../' + path
        if os.path.exists(new_path):
            return new_path
    if not os.path.exists(path):
        logger.warning('%s not exist.', path)
    return path


def plugin_register(plugin, path):
    if plugin in PLUGIN_PATH:
        logger.error('%s already registered at %s', plugin, PLUGIN_PATH[plugin])
        return
    if not os.path.exists(path):
        path = find_path(path)
    if not os.path.isabs(path):
        path = './' + path
    logger.info('register plugin: %s %s', plugin, path)
    PLUGIN_PATH[plugin] = path


def plugin_command(host_port, plugin_info, port):
    '''
    host_port: plugin server address
    port: plugin client listening port
    '''
    plugin = plugin_info[0]
    plugin_args = plugin_info[1:]

    if plugin not in PLUGIN_PATH:
        raise ValueError('plugin "%s" not registered!' % plugin)

    cmd = shlex.split(PLUGIN_PATH[plugin])
    if 'kcptun' in plugin.lower():
        cmd.extend(['--localaddr', '127.0.0.1:%d' % port])
        cmd.extend(['--remoteaddr', '%s:%d' % host_port])
        for args in plugin_args:
            if '=' in args:
                key, val = args.split('=')
                cmd.extend(['--' + key, val])
            else:
                cmd.append('--' + args)
        cmd.append('--quiet')
    return cmd


class PluginManager:

    def __init__(self, conf):
        self.conf = conf
        self.plugin_info = {}
        self.subprocess = {}
        self.plugin_port = {}
        atexit.register(self.cleanup)

    def add(self, host_port, plugin_info, proxy):
        # log plugin info
        key = '%s:%s' % host_port
        key += '-%s' % proxy.proxy
        if key in self.plugin_port:
            logger.warning('plugin registered!')
            # TODO: check if plugin is running
            #       if not, assume port used, start plugin
            return self.plugin_port[key]

        if proxy.proxy and is_udp(plugin_info):
            raise ValueError('cannot proxy UDP plugin')

        self.plugin_info[key] = plugin_info
        if proxy.proxy:
            # start tunnel
            tunnel_port = self.conf.port_forward.add(host_port, proxy)

            # adjust tunnel port
            new_host_port = ('127.0.0.1', tunnel_port)
            # assign free socket for plugin
            soc = socket.socket()
            soc.bind(('127.0.0.1', 0))
            _, port = soc.getsockname()
            soc.close()

            self.plugin_port[key] = port
            # start process
            self.start(new_host_port, key)
            return port
        # assign free socket
        soc = socket.socket()
        soc.bind(('127.0.0.1', 0))
        _, port = soc.getsockname()
        soc.close()

        self.plugin_port[key] = port
        # start process
        self.start(host_port, key)
        return port

    def start(self, host_port, key):

        # host_port: plugin server address
        # proxy: keyword need to get plugin_info

        port = self.plugin_port[key]
        plugin_info = self.plugin_info[key]
        plugin = plugin_info[0]
        plugin_args = ';'.join(plugin_info[1:])

        try:
            if plugin in NON_SIP003:
                args = plugin_command(host_port, self.plugin_info[key], self.plugin_port[key])
                process = subprocess.Popen(args)
                self.subprocess[host_port] = process
            else:
                # set environment variable
                # SS_REMOTE_HOST, SS_REMOTE_PORT, SS_LOCAL_HOST, SS_LOCAL_PORT, [SS_PLUGIN_OPTIONS]
                os.environ["SS_REMOTE_HOST"] = host_port[0]
                os.environ["SS_REMOTE_PORT"] = str(host_port[1])
                os.environ["SS_LOCAL_HOST"] = '127.0.0.1'
                os.environ["SS_LOCAL_PORT"] = str(port)
                os.environ["SS_PLUGIN_OPTIONS"] = plugin_args

                cmd = shlex.split(PLUGIN_PATH[plugin])
                process = subprocess.Popen(cmd)
                self.subprocess[key] = process

                time.sleep(0.2)
        except Exception as err:
            logger.error(repr(err))

    def restart(self, host_port, proxy):
        key = '%s:%s' % host_port
        key += '-%s' % proxy.proxy
        self.subprocess[key].kill()
        self.start(host_port, proxy)

    def cleanup(self):
        # kill all subprocess
        all_processes = [v for k, v in self.subprocess.items()]
        for process in all_processes:  # list of your processes
            process.kill()

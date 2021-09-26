
import os
import sys
import hashlib
import asyncio
from concurrent.futures import ThreadPoolExecutor

import yaml

from .server import HandlerFactory, HXsocksHandler, ECC
from .user_manager import UserManager
from .udp_relay import udp_relay_server


def start_hxs_server(confpath):
    with open(confpath, 'r') as ymlfile:
        cfg = yaml.safe_load(ymlfile)
    servers = cfg['servers']
    log_level = cfg.get('log_level', 20)

    udp_enable = cfg.get('udp_enable', False)
    # boolean, port_number, [list of ports]
    if isinstance(udp_enable, int) and udp_enable < 0:
        udp_enable = False
    if isinstance(udp_enable, int) and udp_enable > 2:
        # False == 0, True == 1
        udp_enable = [udp_enable]

    udp_timeout = cfg.get('udp_timeout', 60)
    if not isinstance(udp_timeout, int):
        udp_timeout = 60

    udp_mode = cfg.get('udp_mode', 2)
    # 0 for fullcone, 1 for restricted, 2 for port_restricted
    if not isinstance(udp_mode, int):
        udp_mode = 2

    # server cert
    cert_path = os.path.join(os.path.dirname(os.path.abspath(confpath)), 'cert.pem')

    if not os.path.exists(cert_path):
        sys.stderr.write('server cert not found, creating...\n')
        ECC(key_len=32).save(cert_path)

    user_mgr = UserManager(cert_path)
    cert = user_mgr.SERVER_CERT.get_pub_key()
    cert_hash = hashlib.sha256(cert).hexdigest()[:8]
    sys.stderr.write('load server cert %s\n' % cert_hash)

    # add user
    for user, passwd in cfg['users'].items():
        user_mgr.add_user(user, passwd)

    loop = asyncio.get_event_loop()
    loop.set_default_executor(ThreadPoolExecutor(20))

    for server in servers:
        handler = HandlerFactory(HXsocksHandler, server, user_mgr, log_level)
        coro = asyncio.start_server(handler.handle, handler.address[0], handler.address[1], loop=loop)
        asyncio.ensure_future(coro)
        if udp_enable:
            if isinstance(udp_enable, list) and handler.address[1] not in udp_enable:
                continue
            coro2 = udp_relay_server(handler.address, handler.method, handler.psk, udp_timeout, udp_mode).serve_forever()
            asyncio.ensure_future(coro2)

    # loop.run_forever()

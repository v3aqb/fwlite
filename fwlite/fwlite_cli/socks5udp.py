
import io
import ipaddress
import socket
import struct
import time
import logging

import base64

import asyncio
import asyncio_dgram

from hxcrypto import Encryptor, InvalidTag, IVError


class socks5_udp:
    def __init__(self, parent, proxy, timeout=60, mode=0):
        self.parent = parent
        self.client_addr = None
        self.client_stream = None
        self.proxy = proxy
        self.timeout = timeout
        self.mode = mode

        self.close_event = asyncio.Event()
        self.last_active = 0

        self.udp_relay = None
        self.addr_log = set()

        self.logger = logging.getLogger('socks5udp_%d' % self.parent.server_addr[1])
        self.logger.setLevel(logging.INFO)
        hdr = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                                      datefmt='%H:%M:%S')
        hdr.setFormatter(formatter)
        self.logger.addHandler(hdr)

        self._stop = False
        self.client_recv_task = asyncio.ensure_future(self.socks5_udp_client_recv())

    async def socks5_udp_client_recv(self):
        self.logger.debug('start udp forward, %s', self.proxy)
        stream = await asyncio_dgram.bind((self.parent.server_addr[0], 0))
        self.client_stream = stream
        self.parent.write_udp_reply(stream.sockname[1])
        while not self._stop:
            try:
                fut = stream.recv()
                data, client_addr = await asyncio.wait_for(fut, timeout=5)
            except asyncio.TimeoutError:
                continue
            # source check
            if not self.client_addr:
                self.client_addr = client_addr
            if client_addr != self.client_addr:
                self.logger.warning('client_addr not match, drop')
                continue

            # if FRAG, drop
            data_io = io.BytesIO(data)
            req = data_io.read(4)
            frag = req[2]
            if frag:
                continue

            addrtype = req[3]
            if addrtype == 1:  # ipv4
                addr = data_io.read(4)
                addr = socket.inet_ntoa(addr)
            elif addrtype == 3:  # hostname
                addrlen = data_io.read(1)
                addr = data_io.read(addrlen[0])
                addr = addr.decode()
            elif addrtype == 4:  # ipv6
                addr = data_io.read(16)
                addr = socket.inet_ntop(socket.AF_INET6, addr)
            port = struct.unpack(b">H", data_io.read(2))[0]
            remote_addr = (addr, port)
            dgram = data_io.read()
            self.logger.debug('on_server_recv %r', remote_addr)
            # get relay, send
            await self.udp_relay_send(dgram, remote_addr, data[3:])

    async def udp_relay_send(self, dgram, remote_addr, data):
        if not self.udp_relay:
            if not self.parent.conf.GET_PROXY.ip_in_china(None, remote_addr[0]):
                if self.proxy and self.proxy.scheme == 'ss':
                    self.udp_relay = udp_relay_ss(self, self.client_addr, self.proxy, self.timeout, self.mode)
        if not self.udp_relay:
            self.udp_relay = udp_relay_direct(self, self.client_addr, self.proxy, self.timeout, self.mode)

        await self.udp_relay.send(dgram, remote_addr, data)

    async def on_remote_recv(self, client_addr, remote_addr, dgram, data):
        self.logger.debug('on_remote_recv %r, %r', remote_addr, client_addr)
        buf = b'\x00\x00\x00'
        if data:
            buf += data
        else:
            remote_ip = ipaddress.ip_address(remote_addr[0])
            buf += b'\x01' if remote_ip.version == 4 else b'\x04'
            buf += remote_ip.packed
            buf += struct.pack(b'>H', remote_addr[1])
            buf += dgram
        await self.client_stream.send(buf, client_addr)

    def on_relay_timeout(self):
        self._stop = True
        self.udp_relay.stop()
        # tell socks5 server to close connection
        self.close_event.set()


FULL = 0
RESTRICTED = 1
PORTRESTRICTED = 2


class udp_relay_direct:
    def __init__(self, parent, client_addr, proxy, timeout=60, mode=PORTRESTRICTED):
        self.parent = parent
        self.client_addr = client_addr
        self.proxy = proxy
        self.timeout = timeout
        self.mode = mode
        self.write_lock = asyncio.Lock()
        self.remote_stream = None
        self.remote_lastactive = {}
        self._last_active = time.time()
        self._stop = False
        self.recv_from_remote_task = None

    async def send(self, dgram, remote_addr, data):
        async with self.write_lock:
            if not self.remote_stream:
                await self.udp_associate()
        await self._send(dgram, remote_addr, data)

    async def recv_from_remote(self):
        while not self._stop:
            try:
                fut = self.remote_stream.recv()
                dgram, remote_addr = await asyncio.wait_for(fut, timeout=5)

                if self.firewall(remote_addr):
                    self.parent.logger.info('udp drop %r', remote_addr)
                    continue
                self.firewall_register(remote_addr)

                dgram, remote_addr, data = self.recv_from_remote_process(dgram, remote_addr)
            except asyncio.TimeoutError:
                if time.time() - self._last_active > self.timeout:
                    break
                continue
            except (OSError, IVError, InvalidTag):
                continue

            await self.parent.on_remote_recv(self.client_addr, remote_addr, dgram, data)
        self.remote_stream.close()
        self.parent.on_relay_timeout()

    def stop(self):
        self._stop = True

    async def udp_associate(self):
        self.remote_stream = await asyncio_dgram.bind(('0.0.0.0', 0))
        self.recv_from_remote_task = asyncio.ensure_future(self.recv_from_remote())

    async def _send(self, dgram, remote_addr, data):
        self.firewall_register(remote_addr)
        await self.remote_stream.send(dgram, remote_addr)

    def recv_from_remote_process(self, dgram, remote_addr):
        self._last_active = time.time()
        return dgram, remote_addr, None

    def firewall_register(self, remote_addr):
        if self.mode:
            key = remote_addr[0] if self.mode == 1 else remote_addr
            self.remote_lastactive[key] = time.time()
            self._last_active = time.time()

    def firewall(self, remote_addr):
        '''
            dgram received from remote_addr
            return True if dgram should be droped.
        '''
        if self.mode:
            key = remote_addr[0] if self.mode == 1 else remote_addr
            if key not in self.remote_lastactive:
                return True
            if time.time() - self.remote_lastactive[key] > self.timeout:
                del self.remote_lastactive[key]
                return True
        return None


class udp_relay_ss(udp_relay_direct):
    def __init__(self, parent, client_addr, proxy, timeout=60, mode=PORTRESTRICTED):
        super().__init__(parent, client_addr, proxy, timeout, mode)
        self.remote_addr = None
        ssmethod, sspassword = self.proxy.username, self.proxy.password
        if sspassword is None:
            ssmethod, sspassword = base64.b64decode(ssmethod).decode().split(':', 1)
        self.ssmethod, self.sspassword = ssmethod, sspassword
        try:
            ipaddress.ip_address(self.proxy.hostname)
            self.firewall_register((self.proxy.hostname, self.proxy.port))
        except ValueError:
            pass

    async def udp_associate(self):
        self.remote_stream = await asyncio_dgram.connect((self.proxy.hostname, self.proxy.port))
        self.recv_from_remote_task = asyncio.ensure_future(self.recv_from_remote())

    def get_cipher(self):
        cipher = Encryptor(self.sspassword, self.ssmethod)
        return cipher

    async def _send(self, dgram, remote_addr, data):
        buf = self.get_cipher().encrypt_once(data)
        await self.remote_stream.send(buf)
        if self.remote_addr:
            self.firewall_register(None)

    def recv_from_remote_process(self, dgram, remote_addr):
        data = self.get_cipher().decrypt(dgram)
        return None, None, data

    def firewall_register(self, remote_addr):
        if not self.remote_addr:
            self.remote_addr = remote_addr
        self._last_active = time.time()

    def firewall(self, remote_addr):
        '''
            dgram received from remote_addr
            return True if dgram should be droped.
        '''
        if not self.remote_addr:
            self.firewall_register(remote_addr)
            return None
        if remote_addr != self.remote_addr:
            return True
        return None

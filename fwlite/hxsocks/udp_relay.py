
import io
import ipaddress
import socket
import struct
import time
import logging
import asyncio
import asyncio_dgram

from hxcrypto import Encryptor


FULL = 0
RESTRICTED = 1
PORTRESTRICTED = 2


class udp_relay:
    def __init__(self, parent, client_addr, timeout=60, mode=PORTRESTRICTED):
        self.parent = parent
        self.client_addr = client_addr
        self.timeout = timeout
        self.mode = mode
        self.write_lock = asyncio.Lock()
        self.remote_stream = None
        self.remote_lastactive = {}
        self._last_active = time.time()
        self._stop = False

    async def send(self, dgram, remote_addr, data):
        async with self.write_lock:
            if not self.remote_stream:
                self.remote_stream = await asyncio_dgram.bind((self.parent.server_addr[0], 0))
                asyncio.ensure_future(self.recv_from_remote())
            self._last_active = time.time()
            if self.mode:
                key = remote_addr[0] if self.mode == 1 else remote_addr
                self.remote_lastactive[key] = time.time()
            await self.remote_stream.send(dgram, remote_addr)

    async def recv_from_remote(self):
        while not self._stop:
            try:
                fut = self.remote_stream.recv()
                data, remote_addr = await asyncio.wait_for(fut, timeout=5)
            except asyncio.TimeoutError:
                if time.time() - self._last_active > self.timeout:
                    break
                continue
            except OSError:
                break

            async with self.write_lock:
                if self.firewall(remote_addr):
                    self.parent.logger.info('udp drop %r', remote_addr)
                    continue

                self._last_active = time.time()
                if self.mode:
                    key = remote_addr[0] if self.mode == 1 else remote_addr
                    self.remote_lastactive[key] = time.time()
            await self.parent.on_remote_recv(self.client_addr, remote_addr, data, None)
        self.remote_stream.close()
        self.parent.on_relay_timeout(self.client_addr)

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

    def stop(self):
        self._stop = True


class udp_relay_server:
    '''
    provide udp relay for shadowsocks
    '''
    def __init__(self, server_addr, method, key, timeout, mode):
        self.server_addr = server_addr
        self.method = method
        self.__key = key
        self.timeout = timeout
        self.mode = mode
        self.server_stream = None
        self.relay_holder = {}  # {client_addr: udp_relay}

        self.logger = logging.getLogger('ssudp_%d' % self.server_addr[1])
        self.logger.setLevel(logging.INFO)
        hdr = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                                      datefmt='%H:%M:%S')
        hdr.setFormatter(formatter)
        self.logger.addHandler(hdr)

    async def serve_forever(self):
        self.logger.info('start udp_relay server %r', self.server_addr)
        self.server_stream = await asyncio_dgram.bind(self.server_addr)
        while True:
            data, client_addr = await self.server_stream.recv()
            asyncio.ensure_future(self.handle(client_addr, data))

    async def handle(self, client_addr, data):
        try:
            remote_addr, dgram, data = self.decrypt_parse(data)
        except Exception as err:
            self.logger.error('%s %s', repr(err), repr(client_addr))
        else:
            self.logger.debug('on_server_recv, %r, %r', client_addr, remote_addr)
            relay = self.get_relay(client_addr)
            await relay.send(dgram, remote_addr, data)

    async def on_remote_recv(self, client_addr, remote_addr, dgram, data):
        '''
            create dgram, encrypt and send to client
        '''
        self.logger.debug('on_remote_recv %r, %r', remote_addr, client_addr)
        if data:
            buf = data
        else:
            remote_ip = ipaddress.ip_address(remote_addr[0])
            buf = b'\x01' if remote_ip.version == 4 else b'\x04'
            buf += remote_ip.packed
            buf += struct.pack(b'>H', remote_addr[1])
            buf += dgram
        cipher = Encryptor(self.__key, self.method)
        buf = cipher.encrypt_once(buf)
        await self.server_stream.send(buf, client_addr)

    def on_relay_timeout(self, client_addr):
        if client_addr in self.relay_holder:
            self.relay_holder[client_addr].stop()
            del self.relay_holder[client_addr]

    def decrypt_parse(self, data):
        cipher = Encryptor(self.__key, self.method)
        data = cipher.decrypt(data)

        data = io.BytesIO(data)
        addrtype = data.read(1)[0]
        if addrtype == 1:
            addr = data.read(4)
            addr = socket.inet_ntoa(addr)
        elif addrtype == 3:
            addr = data.read(1)
            addr = data.read(addr[0])
            addr = addr.decode('ascii')
        else:
            addr = data.read(16)
            addr = socket.inet_ntop(socket.AF_INET6, addr)
        port = data.read(2)
        port, = struct.unpack('>H', port)

        dgram = data.read()
        return (addr, port), dgram, data

    def get_relay(self, client_addr):
        '''
            for each client_addr, create a ctx and udp stream
            start udp recv, store udp stream in ctx
            return udp_relay object
        '''
        if client_addr not in self.relay_holder:
            self.logger.debug('start udp_relay %r', client_addr)
            relay = udp_relay(self, client_addr, self.timeout, self.mode)
            self.relay_holder[client_addr] = relay
        return self.relay_holder[client_addr]

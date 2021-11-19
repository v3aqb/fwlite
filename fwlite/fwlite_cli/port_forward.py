
import asyncio
import socket
import time
import logging

logger = logging.getLogger('tunnel')


def set_logger():
    logger.setLevel(logging.INFO)
    hdr = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                                  datefmt='%H:%M:%S')
    hdr.setFormatter(formatter)
    logger.addHandler(hdr)


set_logger()


BUFSIZE = 65536


class ForwardContext:
    def __init__(self):
        self.last_active = time.time()
        # eof recieved
        self.remote_eof = False
        self.local_eof = False
        # link status
        self.writeable = True
        self.readable = True
        # result
        self.timeout = None
        self.err = None


async def forward_from_client(read_from, write_to, context, timeout=60):
    while True:
        intv = 5
        try:
            fut = read_from.read(BUFSIZE)
            data = await asyncio.wait_for(fut, timeout=intv)
        except asyncio.TimeoutError:
            if time.time() - context.last_active > timeout or context.remote_eof:
                data = b''
            else:
                continue
        except ConnectionError:
            data = b''

        if not data:
            break
        try:
            context.last_active = time.time()
            write_to.write(data)
            await write_to.drain()
        except ConnectionError:
            context.local_eof = True
            return
    context.local_eof = True
    # client closed, tell remote
    try:
        write_to.write_eof()
    except ConnectionError:
        pass


async def forward_from_remote(read_from, write_to, context, timeout=60):
    count = 0
    while True:
        intv = 5
        try:
            fut = read_from.read(BUFSIZE)
            data = await asyncio.wait_for(fut, intv)
            count += 1
        except asyncio.TimeoutError:
            if time.time() - context.last_active > timeout or context.local_eof:
                data = b''
            else:
                continue
        except ConnectionError:
            data = b''

        if not data:
            break
        try:
            context.last_active = time.time()
            context.retryable = False
            write_to.write(data)
            await write_to.drain()
        except ConnectionError:
            # client closed
            context.remote_eof = True
            context.retryable = False
            break
    context.remote_eof = True
    context.remote_recv_count = count

    try:
        write_to.write_eof()
    except ConnectionError:
        pass


class ForwardHandler:
    def __init__(self, target, proxy, ctimeout=3, timeout=120, tcp_nodelay=False):
        self.addr, self.port = target
        self.proxy = proxy
        self.timeout = timeout
        self.ctimeout = ctimeout
        self.tcp_nodelay = tcp_nodelay

    async def handle(self, client_reader, client_writer):
        remote_writer = None
        client_writer.transport.set_write_buffer_limits(262144)
        try:
            # connect to target
            from .connection import open_connection
            remote_reader, remote_writer, _ = await open_connection(self.addr,
                                                                    self.port,
                                                                    proxy=self.proxy,
                                                                    timeout=self.ctimeout,
                                                                    tunnel=True)
        except ConnectionError:
            logger.error('open_connection failed: %s:%s, via %s', self.addr, self.port, self.proxy)
            client_writer.close()
            await client_writer.wait_closed()
            return

        if self.tcp_nodelay:
            soc = remote_writer.transport.get_extra_info('socket')
            soc.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            soc = client_writer.transport.get_extra_info('socket')
            soc.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        # forward
        context = ForwardContext()

        tasks = [asyncio.create_task(forward_from_client(client_reader,
                                                         remote_writer,
                                                         context,
                                                         self.timeout)),
                 asyncio.create_task(forward_from_remote(remote_reader,
                                                         client_writer,
                                                         context,
                                                         self.timeout)),
                 ]
        await asyncio.wait(tasks)

        for writer in (remote_writer, client_writer):
            if not writer.is_closing():
                writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass


class ForwardManager:
    def __init__(self, conf):
        self.conf = conf
        self.server = {}
        self.server_info = {}
        self.tcp_nodelay = self.conf.tcp_nodelay

    def add(self, target, proxy, port=0):
        soc = None
        if port == 0:
            soc = socket.socket()
            soc.bind(('127.0.0.1', port))
            _, port = soc.getsockname()

        logger.info('add port_forward %s %s %s', target, proxy, port)
        asyncio.ensure_future(self.add_forward(target, proxy, port, soc))
        return port

    async def add_forward(self, target, proxy, port, soc=None):
        if isinstance(proxy, str):
            proxy = self.conf.parentlist.get(proxy)
        if soc:
            soc.close()
        # start server on port
        handler = ForwardHandler(target, proxy, timeout=120, tcp_nodelay=self.tcp_nodelay)
        server = await asyncio.start_server(handler.handle, '127.0.0.1', port)
        self.server[port] = server
        self.server_info[port] = (target, proxy.name)
        self.conf.stdout('forward')

    def stop(self, port):
        asyncio.ensure_future(self.stop_w(port))

    def stop_all(self):
        for port in self.server:
            asyncio.ensure_future(self.stop_w(port))

    async def stop_w(self, port):
        import sys
        if sys.platform == 'win32':
            if sys.version_info < (3, 7):
                return

        logger.info('removing forward %s', port)
        server = self.server[port]
        server.close()
        await server.wait_closed()
        del self.server[port]
        del self.server_info[port]
        self.conf.stdout('forward')

    def list(self):
        return [(target_proxy[0], target_proxy[1], port)
                for port, target_proxy in self.server_info.items()]

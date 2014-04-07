#!/usr/bin/env python
# coding:utf-8
# Based on GAppProxy 2.0.0 by Du XiaoGang <dugang.2008@gmail.com>
# Based on WallProxy 0.4.0 by Hust Moon <www.ehust@gmail.com>
# Contributor:
#      Phus Lu           <phus.lu@gmail.com>
#      Hewig Xu          <hewigovens@gmail.com>
#      Ayanamist Yang    <ayanamist@gmail.com>
#      V.E.O             <V.E.O@tom.com>
#      Max Lv            <max.c.lv@gmail.com>
#      AlsoTang          <alsotang@gmail.com>
#      Christopher Meng  <i@cicku.me>
#      Yonsm Guo         <YonsmGuo@gmail.com>
#      Parkman           <cseparkman@gmail.com>
#      Ming Bai          <mbbill@gmail.com>
#      Bin Yu            <yubinlove1991@gmail.com>
#      lileixuan         <lileixuan@gmail.com>
#      Cong Ding         <cong@cding.org>
#      Zhang Youfu       <zhangyoufu@gmail.com>
#      Lu Wei            <luwei@barfoo>
#      Harmony Meow      <harmony.meow@gmail.com>
#      logostream        <logostream@gmail.com>
#      Rui Wang          <isnowfy@gmail.com>
#      Wang Wei Qiang    <wwqgtxx@gmail.com>
#      Felix Yan         <felixonmars@gmail.com>
#      Sui Feng          <suifeng.me@qq.com>
#      QXO               <qxodream@gmail.com>
#      Geek An           <geekan@foxmail.com>
#      Poly Rabbit       <mcx_221@foxmail.com>
#      oxnz              <yunxinyi@gmail.com>
#      Shusen Liu        <liushusen.smart@gmail.com>
#      Yad Smood         <y.s.inside@gmail.com>
#      Chen Shuang       <cs0x7f@gmail.com>
#      cnfuyu            <cnfuyu@gmail.com>
#      cuixin            <steven.cuixin@gmail.com>
#      s2marine0         <s2marine0@gmail.com>
#      Toshio Xiang      <snachx@gmail.com>
#      Bo Tian           <dxmtb@163.com>

__version__ = '3.1.7'

import sys
import os
import glob

sys.dont_write_bytecode = True
sys.path += glob.glob('%s/*.egg' % os.path.dirname(os.path.abspath(__file__)))

try:
    import gevent
    import gevent.socket
    import gevent.server
    import gevent.queue
    import gevent.monkey
    gevent.monkey.patch_all(subprocess=True)
except ImportError:
    gevent = None
except TypeError:
    gevent.monkey.patch_all()
    sys.stderr.write('\033[31m  Warning: Please update gevent to the latest 1.0 version!\033[0m\n')

import errno
import time
import struct
import collections
import zlib
import functools
import itertools
import re
import io
import fnmatch
import traceback
import random
import base64
import string
import hashlib
import threading
import thread
import socket
import ssl
import select
import Queue
import SocketServer
import ConfigParser
import BaseHTTPServer
import httplib
import urllib2
import urlparse
try:
    import dnslib
except ImportError:
    dnslib = None
try:
    import OpenSSL
except ImportError:
    OpenSSL = None
try:
    import pygeoip
except ImportError:
    pygeoip = None


HAS_PYPY = hasattr(sys, 'pypy_version_info')
NetWorkIOError = (socket.error, ssl.SSLError, OSError) if not OpenSSL else (socket.error, ssl.SSLError, OpenSSL.SSL.Error, OSError)


class Logging(type(sys)):
    CRITICAL = 50
    FATAL = CRITICAL
    ERROR = 40
    WARNING = 30
    WARN = WARNING
    INFO = 20
    DEBUG = 10
    NOTSET = 0

    def __init__(self, *args, **kwargs):
        self.level = self.__class__.INFO
        self.__set_error_color = lambda: None
        self.__set_warning_color = lambda: None
        self.__set_debug_color = lambda: None
        self.__reset_color = lambda: None
        if hasattr(sys.stderr, 'isatty') and sys.stderr.isatty():
            if os.name == 'nt':
                import ctypes
                SetConsoleTextAttribute = ctypes.windll.kernel32.SetConsoleTextAttribute
                GetStdHandle = ctypes.windll.kernel32.GetStdHandle
                self.__set_error_color = lambda: SetConsoleTextAttribute(GetStdHandle(-11), 0x04)
                self.__set_warning_color = lambda: SetConsoleTextAttribute(GetStdHandle(-11), 0x06)
                self.__set_debug_color = lambda: SetConsoleTextAttribute(GetStdHandle(-11), 0x002)
                self.__reset_color = lambda: SetConsoleTextAttribute(GetStdHandle(-11), 0x07)
            elif os.name == 'posix':
                self.__set_error_color = lambda: sys.stderr.write('\033[31m')
                self.__set_warning_color = lambda: sys.stderr.write('\033[33m')
                self.__set_debug_color = lambda: sys.stderr.write('\033[32m')
                self.__reset_color = lambda: sys.stderr.write('\033[0m')

    @classmethod
    def getLogger(cls, *args, **kwargs):
        return cls(*args, **kwargs)

    def basicConfig(self, *args, **kwargs):
        self.level = int(kwargs.get('level', self.__class__.INFO))
        if self.level > self.__class__.DEBUG:
            self.debug = self.dummy

    def log(self, level, fmt, *args, **kwargs):
        sys.stderr.write('%s - [%s] %s\n' % (level, time.ctime()[4:-5], fmt % args))

    def dummy(self, *args, **kwargs):
        pass

    def debug(self, fmt, *args, **kwargs):
        self.__set_debug_color()
        self.log('DEBUG', fmt, *args, **kwargs)
        self.__reset_color()

    def info(self, fmt, *args, **kwargs):
        self.log('INFO', fmt, *args)

    def warning(self, fmt, *args, **kwargs):
        self.__set_warning_color()
        self.log('WARNING', fmt, *args, **kwargs)
        self.__reset_color()

    def warn(self, fmt, *args, **kwargs):
        self.warning(fmt, *args, **kwargs)

    def error(self, fmt, *args, **kwargs):
        self.__set_error_color()
        self.log('ERROR', fmt, *args, **kwargs)
        self.__reset_color()

    def exception(self, fmt, *args, **kwargs):
        self.error(fmt, *args, **kwargs)
        sys.stderr.write(traceback.format_exc() + '\n')

    def critical(self, fmt, *args, **kwargs):
        self.__set_error_color()
        self.log('CRITICAL', fmt, *args, **kwargs)
        self.__reset_color()
logging = sys.modules['logging'] = Logging('logging')


class LRUCache(object):
    """http://pypi.python.org/pypi/lru/"""

    def __init__(self, max_items=100):
        self.cache = {}
        self.key_order = []
        self.max_items = max_items

    def __setitem__(self, key, value):
        self.cache[key] = value
        self._mark(key)

    def __getitem__(self, key):
        value = self.cache[key]
        self._mark(key)
        return value

    def __contains__(self, key):
        return key in self.cache

    def _mark(self, key):
        if key in self.key_order:
            self.key_order.remove(key)
        self.key_order.insert(0, key)
        if len(self.key_order) > self.max_items:
            remove = self.key_order[self.max_items]
            del self.cache[remove]
            self.key_order.pop(self.max_items)

    def clear(self):
        self.cache = {}
        self.key_order = []


class CertUtil(object):
    """CertUtil module, based on mitmproxy"""

    ca_vendor = 'GoAgent'
    ca_keyfile = 'CA.crt'
    ca_certdir = 'certs'
    ca_lock = threading.Lock()

    @staticmethod
    def create_ca():
        key = OpenSSL.crypto.PKey()
        key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
        ca = OpenSSL.crypto.X509()
        ca.set_serial_number(0)
        ca.set_version(2)
        subj = ca.get_subject()
        subj.countryName = 'CN'
        subj.stateOrProvinceName = 'Internet'
        subj.localityName = 'Cernet'
        subj.organizationName = CertUtil.ca_vendor
        subj.organizationalUnitName = '%s Root' % CertUtil.ca_vendor
        subj.commonName = '%s CA' % CertUtil.ca_vendor
        ca.gmtime_adj_notBefore(0)
        ca.gmtime_adj_notAfter(24 * 60 * 60 * 3652)
        ca.set_issuer(ca.get_subject())
        ca.set_pubkey(key)
        ca.add_extensions([
            OpenSSL.crypto.X509Extension(b'basicConstraints', True, b'CA:TRUE'),
            OpenSSL.crypto.X509Extension(b'nsCertType', True, b'sslCA'),
            OpenSSL.crypto.X509Extension(b'extendedKeyUsage', True, b'serverAuth,clientAuth,emailProtection,timeStamping,msCodeInd,msCodeCom,msCTLSign,msSGC,msEFS,nsSGC'),
            OpenSSL.crypto.X509Extension(b'keyUsage', False, b'keyCertSign, cRLSign'),
            OpenSSL.crypto.X509Extension(b'subjectKeyIdentifier', False, b'hash', subject=ca), ])
        ca.sign(key, 'sha1')
        return key, ca

    @staticmethod
    def dump_ca():
        key, ca = CertUtil.create_ca()
        with open(CertUtil.ca_keyfile, 'wb') as fp:
            fp.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, ca))
            fp.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key))

    @staticmethod
    def _get_cert(commonname, sans=()):
        with open(CertUtil.ca_keyfile, 'rb') as fp:
            content = fp.read()
            key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, content)
            ca = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, content)

        pkey = OpenSSL.crypto.PKey()
        pkey.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

        req = OpenSSL.crypto.X509Req()
        subj = req.get_subject()
        subj.countryName = 'CN'
        subj.stateOrProvinceName = 'Internet'
        subj.localityName = 'Cernet'
        subj.organizationalUnitName = '%s Branch' % CertUtil.ca_vendor
        if commonname[0] == '.':
            subj.commonName = '*' + commonname
            subj.organizationName = '*' + commonname
            sans = ['*'+commonname] + [x for x in sans if x != '*'+commonname]
        else:
            subj.commonName = commonname
            subj.organizationName = commonname
            sans = [commonname] + [x for x in sans if x != commonname]
        #req.add_extensions([OpenSSL.crypto.X509Extension(b'subjectAltName', True, ', '.join('DNS: %s' % x for x in sans)).encode()])
        req.set_pubkey(pkey)
        req.sign(pkey, 'sha1')

        cert = OpenSSL.crypto.X509()
        cert.set_version(2)
        try:
            cert.set_serial_number(int(hashlib.md5(commonname.encode('utf-8')).hexdigest(), 16))
        except OpenSSL.SSL.Error:
            cert.set_serial_number(int(time.time()*1000))
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(60 * 60 * 24 * 3652)
        cert.set_issuer(ca.get_subject())
        cert.set_subject(req.get_subject())
        cert.set_pubkey(req.get_pubkey())
        if commonname[0] == '.':
            sans = ['*'+commonname] + [s for s in sans if s != '*'+commonname]
        else:
            sans = [commonname] + [s for s in sans if s != commonname]
        #cert.add_extensions([OpenSSL.crypto.X509Extension(b'subjectAltName', True, ', '.join('DNS: %s' % x for x in sans))])
        cert.sign(key, 'sha1')

        certfile = os.path.join(CertUtil.ca_certdir, commonname + '.crt')
        with open(certfile, 'wb') as fp:
            fp.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))
            fp.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, pkey))
        return certfile

    @staticmethod
    def get_cert(commonname, sans=()):
        if commonname.count('.') >= 2 and [len(x) for x in reversed(commonname.split('.'))] > [2, 4]:
            commonname = '.'+commonname.partition('.')[-1]
        certfile = os.path.join(CertUtil.ca_certdir, commonname + '.crt')
        if os.path.exists(certfile):
            return certfile
        elif OpenSSL is None:
            return CertUtil.ca_keyfile
        else:
            with CertUtil.ca_lock:
                if os.path.exists(certfile):
                    return certfile
                return CertUtil._get_cert(commonname, sans)

    @staticmethod
    def import_ca(certfile):
        commonname = os.path.splitext(os.path.basename(certfile))[0]
        if OpenSSL:
            try:
                with open(certfile, 'rb') as fp:
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, fp.read())
                    commonname = next(v.decode() for k, v in x509.get_subject().get_components() if k == b'O')
            except Exception as e:
                logging.error('load_certificate(certfile=%r) failed:%s', certfile, e)
        if sys.platform.startswith('win'):
            import ctypes
            with open(certfile, 'rb') as fp:
                certdata = fp.read()
                if certdata.startswith(b'-----'):
                    begin = b'-----BEGIN CERTIFICATE-----'
                    end = b'-----END CERTIFICATE-----'
                    certdata = base64.b64decode(b''.join(certdata[certdata.find(begin)+len(begin):certdata.find(end)].strip().splitlines()))
                crypt32 = ctypes.WinDLL(b'crypt32.dll'.decode())
                store_handle = crypt32.CertOpenStore(10, 0, 0, 0x4000 | 0x20000, b'ROOT'.decode())
                if not store_handle:
                    return -1
                if crypt32.CertFindCertificateInStore(store_handle, 0x1, 0, 0x80007, CertUtil.ca_vendor.decode(), None):
                    return 0
                ret = crypt32.CertAddEncodedCertificateToStore(store_handle, 0x1, certdata, len(certdata), 4, None)
                crypt32.CertCloseStore(store_handle, 0)
                del crypt32
                return 0 if ret else -1
        elif sys.platform == 'darwin':
            return os.system(('security find-certificate -a -c "%s" | grep "%s" >/dev/null || security add-trusted-cert -d -r trustRoot -k "/Library/Keychains/System.keychain" "%s"' % (commonname, commonname, certfile.decode('utf-8'))).encode('utf-8'))
        elif sys.platform.startswith('linux'):
            import platform
            platform_distname = platform.dist()[0]
            if platform_distname == 'Ubuntu':
                pemfile = "/etc/ssl/certs/%s.pem" % commonname
                new_certfile = "/usr/local/share/ca-certificates/%s.crt" % commonname
                if not os.path.exists(pemfile):
                    return os.system('cp "%s" "%s" && update-ca-certificates' % (certfile, new_certfile))
            elif any(os.path.isfile('%s/certutil' % x) for x in os.environ['PATH'].split(os.pathsep)):
                return os.system('certutil -L -d sql:$HOME/.pki/nssdb | grep "%s" || certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "%s" -i "%s"' % (commonname, commonname, certfile))
            else:
                logging.warning('please install *libnss3-tools* package to import GoAgent root ca')
        return 0

    @staticmethod
    def check_ca():
        #Check CA exists
        capath = os.path.join(os.path.dirname(os.path.abspath(__file__)), CertUtil.ca_keyfile)
        certdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), CertUtil.ca_certdir)
        if not os.path.exists(capath):
            if not OpenSSL:
                logging.critical('CA.key is not exist and OpenSSL is disabled, ABORT!')
                sys.exit(-1)
            if os.path.exists(certdir):
                if os.path.isdir(certdir):
                    any(os.remove(x) for x in glob.glob(certdir+'/*.crt')+glob.glob(certdir+'/.*.crt'))
                else:
                    os.remove(certdir)
                    os.mkdir(certdir)
            CertUtil.dump_ca()
        if glob.glob('%s/*.key' % CertUtil.ca_certdir):
            for filename in glob.glob('%s/*.key' % CertUtil.ca_certdir):
                try:
                    os.remove(filename)
                    os.remove(os.path.splitext(filename)[0]+'.crt')
                except EnvironmentError:
                    pass
        #Check CA imported
        if CertUtil.import_ca(capath) != 0:
            logging.warning('install root certificate failed, Please run as administrator/root/sudo')
        #Check Certs Dir
        if not os.path.exists(certdir):
            os.makedirs(certdir)


class SSLConnection(object):

    has_gevent = socket.socket is getattr(sys.modules.get('gevent.socket'), 'socket', None)

    def __init__(self, context, sock):
        self._context = context
        self._sock = sock
        self._connection = OpenSSL.SSL.Connection(context, sock)
        self._makefile_refs = 0
        if self.has_gevent:
            self._wait_read = gevent.socket.wait_read
            self._wait_write = gevent.socket.wait_write
            self._wait_readwrite = gevent.socket.wait_readwrite
        else:
            self._wait_read = lambda fd,t: select.select([fd], [], [fd], t)
            self._wait_write = lambda fd,t: select.select([], [fd], [fd], t)
            self._wait_readwrite = lambda fd,t: select.select([fd], [fd], [fd], t)

    def __getattr__(self, attr):
        if attr not in ('_context', '_sock', '_connection', '_makefile_refs'):
            return getattr(self._connection, attr)

    def accept(self):
        sock, addr = self._sock.accept()
        client = OpenSSL.SSL.Connection(sock._context, sock)
        return client, addr

    def do_handshake(self):
        timeout = self._sock.gettimeout()
        while True:
            try:
                self._connection.do_handshake()
                break
            except (OpenSSL.SSL.WantReadError, OpenSSL.SSL.WantX509LookupError, OpenSSL.SSL.WantWriteError):
                sys.exc_clear()
                self._wait_readwrite(self._sock.fileno(), timeout)

    def connect(self, *args, **kwargs):
        timeout = self._sock.gettimeout()
        while True:
            try:
                self._connection.connect(*args, **kwargs)
                break
            except (OpenSSL.SSL.WantReadError, OpenSSL.SSL.WantX509LookupError):
                sys.exc_clear()
                self._wait_read(self._sock.fileno(), timeout)
            except OpenSSL.SSL.WantWriteError:
                sys.exc_clear()
                self._wait_write(self._sock.fileno(), timeout)

    def send(self, data, flags=0):
        timeout = self._sock.gettimeout()
        while True:
            try:
                self._connection.send(data, flags)
                break
            except (OpenSSL.SSL.WantReadError, OpenSSL.SSL.WantX509LookupError):
                sys.exc_clear()
                self._wait_read(self._sock.fileno(), timeout)
            except OpenSSL.SSL.WantWriteError:
                sys.exc_clear()
                self._wait_write(self._sock.fileno(), timeout)
            except OpenSSL.SSL.SysCallError as e:
                if e[0] == -1 and not data:
                    # errors when writing empty strings are expected and can be ignored
                    return 0
                raise

    def recv(self, bufsiz, flags=0):
        timeout = self._sock.gettimeout()
        pending = self._connection.pending()
        if pending:
            return self._connection.recv(min(pending, bufsiz))
        while True:
            try:
                return self._connection.recv(bufsiz, flags)
            except (OpenSSL.SSL.WantReadError, OpenSSL.SSL.WantX509LookupError):
                sys.exc_clear()
                self._wait_read(self._sock.fileno(), timeout)
            except OpenSSL.SSL.WantWriteError:
                sys.exc_clear()
                self._wait_write(self._sock.fileno(), timeout)
            except OpenSSL.SSL.ZeroReturnError:
                return ''

    def read(self, bufsiz, flags=0):
        return self.recv(bufsiz, flags)

    def write(self, buf, flags=0):
        return self.sendall(buf, flags)

    def close(self):
        if self._makefile_refs < 1:
            self._connection = None
            if self._sock:
                socket.socket.close(self._sock)
        else:
            self._makefile_refs -= 1

    def makefile(self, mode='r', bufsize=-1):
        self._makefile_refs += 1
        return socket._fileobject(self, mode, bufsize, close=True)



class ProxyUtil(object):
    """ProxyUtil module, based on urllib2"""

    @staticmethod
    def parse_proxy(proxy):
        return urllib2._parse_proxy(proxy)

    @staticmethod
    def get_system_proxy():
        proxies = urllib2.getproxies()
        return proxies.get('https') or proxies.get('http') or {}

    @staticmethod
    def get_listen_ip():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(('8.8.8.8', 53))
        listen_ip = sock.getsockname()[0]
        sock.close()
        return listen_ip


def dns_remote_resolve(qname, dnsservers, blacklist, timeout):
    """
    http://gfwrev.blogspot.com/2009/11/gfwdns.html
    http://zh.wikipedia.org/wiki/域名服务器缓存污染
    http://support.microsoft.com/kb/241352
    """
    query = dnslib.DNSRecord(q=dnslib.DNSQuestion(qname))
    query_data = query.pack()
    dns_v4_servers = [x for x in dnsservers if ':' not in x]
    dns_v6_servers = [x for x in dnsservers if ':' in x]
    sock_v4 = sock_v6 = None
    socks = []
    if dns_v4_servers:
        sock_v4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        socks.append(sock_v4)
    if dns_v6_servers:
        sock_v6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        socks.append(sock_v6)
    timeout_at = time.time() + timeout
    try:
        for _ in xrange(5):
            try:
                for dnsserver in dns_v4_servers:
                    sock_v4.sendto(query_data, (dnsserver, 53))
                for dnsserver in dns_v6_servers:
                    sock_v6.sendto(query_data, (dnsserver, 53))
                while time.time() < timeout_at:
                    ins, _, _ = select.select(socks, [], [], 0.1)
                    for sock in ins:
                        reply_data, _ = sock.recvfrom(512)
                        reply = dnslib.DNSRecord.parse(reply_data)
                        rtypes = (1, 28) if sock is sock_v6 else (1,)
                        iplist = [str(x.rdata) for x in reply.rr if x.rtype in rtypes]
                        if any(x in blacklist for x in iplist):
                            logging.warning('query qname=%r dnsservers=%r reply bad iplist=%r', qname, dnsservers, iplist)
                        else:
                            logging.debug('query qname=%r dnsservers=%r reply iplist=%s', qname, dnsservers, iplist)
                            return iplist
            except socket.error as e:
                logging.warning('handle dns query=%s socket: %r', query, e)
    finally:
        for sock in socks:
            sock.close()


def get_dnsserver_list():
    if os.name == 'nt':
        import ctypes, ctypes.wintypes, struct, socket
        DNS_CONFIG_DNS_SERVER_LIST = 6
        buf = ctypes.create_string_buffer(2048)
        ctypes.windll.dnsapi.DnsQueryConfig(DNS_CONFIG_DNS_SERVER_LIST, 0, None, None, ctypes.byref(buf), ctypes.byref(ctypes.wintypes.DWORD(len(buf))))
        ips = struct.unpack('I', buf[0:4])[0]
        out = []
        for i in xrange(ips):
            start = (i+1) * 4
            out.append(socket.inet_ntoa(buf[start:start+4]))
        return out
    elif os.path.isfile('/etc/resolv.conf'):
        with open('/etc/resolv.conf', 'rb') as fp:
            return re.findall(r'(?m)^nameserver\s+(\S+)', fp.read())
    else:
        logging.warning("get_dnsserver_list failed: unsupport platform '%s-%s'", sys.platform, os.name)
        return []


def spawn_later(seconds, target, *args, **kwargs):
    def wrap(*args, **kwargs):
        __import__('time').sleep(seconds)
        return target(*args, **kwargs)
    return __import__('thread').start_new_thread(wrap, args, kwargs)


class BaseProxyHandlerFilter(object):
    """base proxy handler filter"""
    def filter(self, handler):
        raise NotImplementedError


class SimpleProxyHandlerFilter(BaseProxyHandlerFilter):
    """simple proxy handler filter"""
    def filter(self, handler):
        if handler.command == 'CONNECT':
            return [handler.FORWARD, handler.host, handler.port, handler.connect_timeout]
        else:
            return [handler.DIRECT]


class SimpleProxyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    """SimpleProxyHandler for GoAgent 3.x"""

    protocol_version = 'HTTP/1.1'
    scheme = 'http'
    skip_headers = frozenset(['Vary', 'Via', 'X-Forwarded-For', 'Proxy-Authorization', 'Proxy-Connection', 'Upgrade', 'X-Chrome-Variations', 'Connection', 'Cache-Control'])
    normcookie = functools.partial(re.compile(', ([^ =]+(?:=|$))').sub, '\\r\\nSet-Cookie: \\1')
    normattachment = functools.partial(re.compile(r'filename=([^"\']+)').sub, 'filename="\\1"')
    bufsize = 256 * 1024
    max_timeout = 16
    connect_timeout = 8
    first_run_lock = threading.Lock()
    handler_filters = [SimpleProxyHandlerFilter()]

    def finish(self):
        """make python2 BaseHTTPRequestHandler happy"""
        try:
            BaseHTTPServer.BaseHTTPRequestHandler.finish(self)
        except NetWorkIOError as e:
            if e[0] not in (errno.ECONNABORTED, errno.ECONNRESET, errno.EPIPE):
                raise

    def address_string(self):
        return '%s:%s' % self.client_address[:2]

    def send_response(self, code, message=None):
        if message is None:
            if code in self.responses:
                message = self.responses[code][0]
            else:
                message = ''
        if self.request_version != 'HTTP/0.9':
            self.wfile.write("%s %d %s\r\n" %
                             (self.protocol_version, code, message))

    def setup(self):
        if isinstance(self.__class__.first_run, collections.Callable):
            try:
                with self.__class__.first_run_lock:
                    if isinstance(self.__class__.first_run, collections.Callable):
                        self.first_run()
                        self.__class__.first_run = None
            except Exception as e:
                logging.exception('%s.first_run() return %r', self.__class__, e)
        self.__class__.setup = BaseHTTPServer.BaseHTTPRequestHandler.setup
        self.__class__.do_CONNECT = self.__class__.do_METHOD
        self.__class__.do_GET = self.__class__.do_METHOD
        self.__class__.do_PUT = self.__class__.do_METHOD
        self.__class__.do_POST = self.__class__.do_METHOD
        self.__class__.do_HEAD = self.__class__.do_METHOD
        self.__class__.do_DELETE = self.__class__.do_METHOD
        self.__class__.do_OPTIONS = self.__class__.do_METHOD
        self.setup()

    def first_run(self):
        pass

    def gethostbyname2(self, hostname):
        return socket.gethostbyname_ex(hostname)[-1]

    def create_tcp_connection(self, hostname, port, timeout, **kwargs):
        return socket.create_connection((hostname, port), timeout)

    def create_ssl_connection(self, hostname, port, timeout, **kwargs):
        sock = self.create_tcp_connection(hostname, port, timeout, **kwargs)
        ssl_sock = ssl.wrap_socket(sock)
        return ssl_sock

    def create_http_request(self, method, url, headers, body, timeout, **kwargs):
        scheme, netloc, path, query, _ = urlparse.urlsplit(url)
        if netloc.rfind(':') <= netloc.rfind(']'):
            # no port number
            host = netloc
            port = 443 if scheme == 'https' else 80
        else:
            host, _, port = netloc.rpartition(':')
            port = int(port)
        if query:
            path += '?' + query
        if 'Host' not in headers:
            headers['Host'] = host
        if body and 'Content-Length' not in headers:
            headers['Content-Length'] = str(len(body))
        ConnectionType = httplib.HTTPSConnection if scheme == 'https' else httplib.HTTPConnection
        connection = ConnectionType(netloc, timeout=timeout)
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse(buffering=True)
        return response

    def create_http_request_withserver(self, fetchserver, method, url, headers, body, timeout, **kwargs):
        raise NotImplementedError

    def MOCK(self, status, headers, content):
        """mock response"""
        logging.info('%s "MOCK %s %s %s" %d %d', self.address_string(), self.command, self.path, self.protocol_version, status, len(content))
        if 'Content-Length' not in headers:
            headers['Content-Length'] = len(content)
        headers['Connection'] = 'close'
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(content)

    def STRIPSSL(self):
        """strip ssl"""
        certfile = CertUtil.get_cert(self.host)
        logging.info('%s "SSL %s %s:%d %s" - -', self.address_string(), self.command, self.host, self.port, self.protocol_version)
        self.send_response(200)
        self.end_headers()
        try:
            ssl_sock = ssl.wrap_socket(self.connection, keyfile=certfile, certfile=certfile, server_side=True)
        except Exception as e:
            if e.args[0] not in (errno.ECONNABORTED, errno.ECONNRESET):
                logging.exception('ssl.wrap_socket(self.connection=%r) failed: %s', self.connection, e)
            return
        self.connection = ssl_sock
        self.rfile = self.connection.makefile('rb', self.bufsize)
        self.wfile = self.connection.makefile('wb', 0)
        try:
            self.raw_requestline = self.rfile.readline(65537)
            if len(self.raw_requestline) > 65536:
                self.requestline = ''
                self.request_version = ''
                self.command = ''
                self.send_error(414)
                return
            if not self.raw_requestline:
                self.close_connection = 1
                return
            if not self.parse_request():
                return
        except NetWorkIOError as e:
            if e.args[0] not in (errno.ECONNABORTED, errno.ECONNRESET, errno.EPIPE):
                raise
        self.scheme = 'https'
        try:
            self.do_METHOD()
        except NetWorkIOError as e:
            if e.args[0] not in (errno.ECONNABORTED, errno.ETIMEDOUT, errno.EPIPE):
                raise

    def FORWARD(self, hostname, port, timeout, kwargs={}):
        """forward socket"""
        do_ssl_handshake = kwargs.pop('do_ssl_handshake', False)
        local = self.connection
        max_retry = int(kwargs.get('max_retry', 3))
        remote = None
        for i in xrange(max_retry):
            try:
                if do_ssl_handshake:
                    remote = self.create_ssl_connection(hostname, port, timeout, **kwargs)
                else:
                    remote = self.create_tcp_connection(hostname, port, timeout, **kwargs)
                if remote and not isinstance(remote, Exception):
                    self.send_response(200)
                    self.send_header('Connection', 'close')
                    self.end_headers()
                    break
            except Exception as e:
                logging.warning('%s "FWD %s %s:%d %s" %r', self.address_string(), self.command, hostname, port, self.protocol_version, e)
                if i == max_retry - 1:
                    raise
        logging.info('%s "FWD %s %s:%d %s" - -', self.address_string(), self.command, hostname, port, self.protocol_version)
        try:
            tick = 1
            bufsize = self.bufsize
            timecount = timeout
            while 1:
                timecount -= tick
                if timecount <= 0:
                    break
                (ins, _, errors) = select.select([local, remote], [], [local, remote], tick)
                if errors:
                    break
                if ins:
                    for sock in ins:
                        data = sock.recv(bufsize)
                        if data:
                            if sock is remote:
                                local.sendall(data)
                                timecount = timeout
                            else:
                                remote.sendall(data)
                                timecount = timeout
                        else:
                            return
        except NetWorkIOError as e:
            if e.args[0] not in (errno.ECONNABORTED, errno.ECONNRESET, errno.ENOTCONN, errno.EPIPE):
                raise
        finally:
            if local:
                local.close()
            if remote:
                remote.close()

    def DIRECT(self, kwargs):
        method = self.command
        if self.path.lower().startswith(('http://', 'https://', 'ftp://')):
            url = self.path
        else:
            url = 'http://%s%s' % (self.headers['Host'], self.path)
        headers = {k.title(): v for k, v in self.headers.items()}
        body = self.rfile.read(int(headers.get('Content-Length', 0)))
        response = self.create_http_request(method, url, headers, body, timeout=self.connect_timeout, **kwargs)
        logging.info('%s "DIRECT %s %s %s" %s %s', self.address_string(), self.command, url, self.protocol_version, response.status, response.getheader('Content-Length', '-'))
        response_headers = {k.title(): v for k, v in response.getheaders()}
        if 'Set-Cookie' in response_headers:
            response_headers['Set-Cookie'] = self.normcookie(response_headers['Set-Cookie'])
        self.send_response(response.status)
        for key, value in response.getheaders():
            key = key.title()
            self.send_header(key, value)
        self.end_headers()
        need_chunked = 'Transfer-Encoding' in response_headers
        try:
            while True:
                data = response.read(8192)
                if not data:
                    if need_chunked:
                        self.wfile.write('0\r\n\r\n')
                    break
                if need_chunked:
                    self.wfile.write('%x\r\n' % len(data))
                self.wfile.write(data)
                if need_chunked:
                    self.wfile.write('\r\n')
                del data
        finally:
            response.close()

    def URLFETCH(self, fetchservers, max_retry=2, raw_response=False, kwargs={}):
        """urlfetch from fetchserver"""
        method = self.command
        if self.path[0] == '/':
            url = '%s://%s%s' % (self.scheme, self.headers['Host'], self.path)
        elif self.path.lower().startswith(('http://', 'https://', 'ftp://')):
            url = self.path
        else:
            raise ValueError('URLFETCH %r is not a valid url' % self.path)
        headers = {k.title(): v for k, v in self.headers.items()}
        body = self.body
        response = None
        errors = []
        headers_sent = False
        fetchserver = fetchservers[0]
        for i in xrange(max_retry):
            try:
                response = self.create_http_request_withserver(fetchserver, method, url, headers, body, timeout=self.max_timeout, **kwargs)
                # appid over qouta, switch to next appid
                if response.app_status >= 500:
                    message = {503: 'Current APPID Over Quota'}.get(response.status) or 'URLFETCH retrun %s' % response.status
                    if i == max_retry - 1:
                        content = message_html('502 URLFetch failed', 'Local URLFetch %r failed' % url, message)
                        return self.MOCK(response.status, {'Content-Type': 'text/html'}, content)
                    else:
                        fetchserver = random.choice(fetchservers)
                        logging.info('%s, trying another fetchserver=%r', message, fetchserver)
                        response.close()
                        continue
                # first response, has no retry.
                if not headers_sent and not raw_response:
                    logging.info('%s "URL %s %s %s" %s %s', self.address_string(), method, url, self.protocol_version, response.status, response.getheader('Content-Length', '-'))
                    if response.status == 206:
                        return RangeFetch(self, response, fetchservers, **kwargs).fetch()
                    if response.getheader('Set-Cookie'):
                        response.msg['Set-Cookie'] = self.normcookie(response.getheader('Set-Cookie'))
                    if response.getheader('Content-Disposition') and '"' not in response.getheader('Content-Disposition'):
                        response.msg['Content-Disposition'] = self.normattachment(response.getheader('Content-Disposition'))
                    self.send_response(response.status)
                    for key, value in response.getheaders():
                        key = key.title()
                        self.send_header(key, value)
                    self.end_headers()
                    headers_sent = True
                content_length = int(response.getheader('Content-Length', 0))
                content_range = response.getheader('Content-Range', '')
                accept_ranges = response.getheader('Accept-Ranges', 'none')
                need_chunked = response.getheader('Transfer-Encoding', '') and not raw_response
                if content_range:
                    start, end = tuple(int(x) for x in re.search(r'bytes (\d+)-(\d+)/(\d+)', content_range).group(1, 2))
                else:
                    start, end = 0, content_length-1
                while True:
                    data = response.read(8192)
                    if not data:
                        if need_chunked:
                            self.wfile.write('0\r\n\r\n')
                        response.close()
                        return
                    start += len(data)
                    if need_chunked:
                        self.wfile.write('%x\r\n' % len(data))
                    self.wfile.write(data)
                    if need_chunked:
                        self.wfile.write('\r\n')
                    del data
                    if start >= end and not raw_response:
                        response.close()
                        return
            except NetWorkIOError as e:
                if e[0] in (errno.ECONNABORTED, errno.EPIPE) or 'bad write retry' in repr(e):
                    return
            except Exception as e:
                errors.append(e)
                logging.info('URLFETCH fetchserver=%r %r, retry...', fetchserver, e)
            finally:
                if response:
                    response.close()
        if len(errors) == max_retry:
            content = message_html('502 URLFetch failed', 'Local URLFetch %r failed' % url, str(errors))
            return self.MOCK(502, {'Content-Type': 'text/html'}, content)

    def do_METHOD(self):
        if self.command == 'CONNECT':
            netloc = self.path
        elif self.path[0] == '/':
            netloc = self.headers.get('Host', 'localhost')
            self.path = '%s://%s%s' % (self.scheme, netloc, self.path)
        else:
            netloc = urlparse.urlsplit(self.path).netloc
        m = re.match(r'^(.+):(\d+)$', netloc)
        if m:
            self.host = m.group(1).strip('[]')
            self.port = int(m.group(2))
        else:
            self.host = netloc
            self.port = 443 if self.scheme == 'http' else 80
        self.body = self.rfile.read(int(self.headers['Content-Length'])) if 'Content-Length' in self.headers else ''
        for handler_filter in self.handler_filters:
            action = handler_filter.filter(self)
            if action:
                return action.pop(0)(*action)


class RangeFetch(object):
    """Range Fetch Class"""

    threads = 2
    maxsize = 1024*1024*4
    bufsize = 8192
    waitsize = 1024*512

    def __init__(self, handler, response, fetchservers, **kwargs):
        self.handler = handler
        self.url = handler.path
        self.response = response
        self.fetchservers = fetchservers
        self.kwargs = kwargs
        self._stopped = None
        self._last_app_status = {}

    def fetch(self):
        response_status = self.response.status
        response_headers = dict((k.title(), v) for k, v in self.response.getheaders())
        content_range = response_headers['Content-Range']
        #content_length = response_headers['Content-Length']
        start, end, length = tuple(int(x) for x in re.search(r'bytes (\d+)-(\d+)/(\d+)', content_range).group(1, 2, 3))
        if start == 0:
            response_status = 200
            response_headers['Content-Length'] = str(length)
            del response_headers['Content-Range']
        else:
            response_headers['Content-Range'] = 'bytes %s-%s/%s' % (start, end, length)
            response_headers['Content-Length'] = str(length-start)

        logging.info('>>>>>>>>>>>>>>> RangeFetch started(%r) %d-%d', self.url, start, end)
        self.handler.send_response(response_status)
        for key, value in response_headers.items():
            self.handler.send_header(key, value)
        self.handler.end_headers()

        data_queue = Queue.PriorityQueue()
        range_queue = Queue.PriorityQueue()
        range_queue.put((start, end, self.response))
        for begin in range(end+1, length, self.maxsize):
            range_queue.put((begin, min(begin+self.maxsize-1, length-1), None))
        for i in xrange(0, self.threads):
            range_delay_size = i * self.maxsize
            spawn_later(float(range_delay_size)/self.waitsize, self.__fetchlet, range_queue, data_queue, range_delay_size)
        has_peek = hasattr(data_queue, 'peek')
        peek_timeout = 120
        self.expect_begin = start
        while self.expect_begin < length - 1:
            try:
                if has_peek:
                    begin, data = data_queue.peek(timeout=peek_timeout)
                    if self.expect_begin == begin:
                        data_queue.get()
                    elif self.expect_begin < begin:
                        time.sleep(0.1)
                        continue
                    else:
                        logging.error('RangeFetch Error: begin(%r) < expect_begin(%r), quit.', begin, self.expect_begin)
                        break
                else:
                    begin, data = data_queue.get(timeout=peek_timeout)
                    if self.expect_begin == begin:
                        pass
                    elif self.expect_begin < begin:
                        data_queue.put((begin, data))
                        time.sleep(0.1)
                        continue
                    else:
                        logging.error('RangeFetch Error: begin(%r) < expect_begin(%r), quit.', begin, self.expect_begin)
                        break
            except Queue.Empty:
                logging.error('data_queue peek timeout, break')
                break
            try:
                self.handler.wfile.write(data)
                self.expect_begin += len(data)
                del data
            except Exception as e:
                logging.info('RangeFetch client connection aborted(%s).', e)
                break
        self._stopped = True

    def __fetchlet(self, range_queue, data_queue, range_delay_size):
        headers = dict((k.title(), v) for k, v in self.handler.headers.items())
        headers['Connection'] = 'close'
        while 1:
            try:
                if self._stopped:
                    return
                try:
                    start, end, response = range_queue.get(timeout=1)
                    if self.expect_begin < start and data_queue.qsize() * self.bufsize + range_delay_size > 30*1024*1024:
                        range_queue.put((start, end, response))
                        time.sleep(10)
                        continue
                    headers['Range'] = 'bytes=%d-%d' % (start, end)
                    fetchserver = ''
                    if not response:
                        fetchserver = random.choice(self.fetchservers)
                        if self._last_app_status.get(fetchserver, 200) >= 500:
                            time.sleep(5)
                        response = self.handler.create_http_request_withserver(fetchserver, self.handler.command, self.url, headers, self.handler.body, timeout=self.handler.max_timeout, **self.kwargs)
                except Queue.Empty:
                    continue
                except Exception as e:
                    logging.warning("Response %r in __fetchlet", e)
                    range_queue.put((start, end, None))
                    continue
                if not response:
                    logging.warning('RangeFetch %s return %r', headers['Range'], response)
                    range_queue.put((start, end, None))
                    continue
                if fetchserver:
                    self._last_app_status[fetchserver] = response.app_status
                if response.app_status != 200:
                    logging.warning('Range Fetch "%s %s" %s return %s', self.handler.command, self.url, headers['Range'], response.app_status)
                    response.close()
                    range_queue.put((start, end, None))
                    continue
                if response.getheader('Location'):
                    self.url = urlparse.urljoin(self.url, response.getheader('Location'))
                    logging.info('RangeFetch Redirect(%r)', self.url)
                    response.close()
                    range_queue.put((start, end, None))
                    continue
                if 200 <= response.status < 300:
                    content_range = response.getheader('Content-Range')
                    if not content_range:
                        logging.warning('RangeFetch "%s %s" return Content-Range=%r: response headers=%r', self.handler.command, self.url, content_range, response.getheaders())
                        response.close()
                        range_queue.put((start, end, None))
                        continue
                    content_length = int(response.getheader('Content-Length', 0))
                    logging.info('>>>>>>>>>>>>>>> [thread %s] %s %s', threading.currentThread().ident, content_length, content_range)
                    while 1:
                        try:
                            if self._stopped:
                                response.close()
                                return
                            data = response.read(self.bufsize)
                            if not data:
                                break
                            data_queue.put((start, data))
                            start += len(data)
                        except Exception as e:
                            logging.warning('RangeFetch "%s %s" %s failed: %s', self.handler.command, self.url, headers['Range'], e)
                            break
                    if start < end + 1:
                        logging.warning('RangeFetch "%s %s" retry %s-%s', self.handler.command, self.url, start, end)
                        response.close()
                        range_queue.put((start, end, None))
                        continue
                    logging.info('>>>>>>>>>>>>>>> Successfully reached %d bytes.', start - 1)
                else:
                    logging.error('RangeFetch %r return %s', self.url, response.status)
                    response.close()
                    range_queue.put((start, end, None))
                    continue
            except Exception as e:
                logging.exception('RangeFetch._fetchlet error:%s', e)
                raise


class AdvancedProxyHandler(SimpleProxyHandler):
    """Advanced Proxy Handler"""
    dns_cache = LRUCache(64*1024)
    dns_servers = []
    dns_blacklist = []
    tcp_connection_time = collections.defaultdict(float)
    tcp_connection_cache = collections.defaultdict(Queue.PriorityQueue)
    ssl_connection_time = collections.defaultdict(float)
    ssl_connection_cache = collections.defaultdict(Queue.PriorityQueue)
    max_window = 4

    def gethostbyname2(self, hostname):
        try:
            iplist = self.dns_cache[hostname]
        except KeyError:
            if self.dns_servers:
                iplist = dns_remote_resolve(hostname, self.dns_servers, self.dns_blacklist, timeout=2)
            else:
                iplist = socket.gethostbyname_ex(hostname)[-1]
            self.dns_cache[hostname] = iplist
        return iplist

    def create_tcp_connection(self, hostname, port, timeout, **kwargs):
        cache_key = kwargs.get('cache_key')
        cache_key = ''
        def create_connection(ipaddr, timeout, queobj):
            sock = None
            try:
                # create a ipv4/ipv6 socket object
                sock = socket.socket(socket.AF_INET if ':' not in ipaddr[0] else socket.AF_INET6)
                # set reuseaddr option to avoid 10048 socket error
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # resize socket recv buffer 8K->32K to improve browser releated application performance
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32*1024)
                # disable nagle algorithm to send http request quickly.
                sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
                # set a short timeout to trigger timeout retry more quickly.
                sock.settimeout(timeout or self.max_timeout)
                # start connection time record
                start_time = time.time()
                # TCP connect
                sock.connect(ipaddr)
                # record TCP connection time
                self.tcp_connection_time[ipaddr] = time.time() - start_time
                # put ssl socket object to output queobj
                queobj.put(sock)
            except (socket.error, OSError) as e:
                # any socket.error, put Excpetions to output queobj.
                queobj.put(e)
                # reset a large and random timeout to the ipaddr
                self.tcp_connection_time[ipaddr] = self.max_timeout+random.random()
                # close tcp socket
                if sock:
                    sock.close()
        def close_connection(count, queobj, first_tcp_time):
            for _ in range(count):
                sock = queobj.get()
                tcp_time_threshold = min(1, 1.5 * first_tcp_time)
                if sock and not isinstance(sock, Exception):
                    ipaddr = sock.getpeername()
                    if cache_key and self.tcp_connection_time[ipaddr] < tcp_time_threshold:
                        self.ssl_connection_cache[cache_key].put((time.time(), sock))
                    else:
                        sock.close()
        try:
            while cache_key:
                ctime, sock = self.tcp_connection_cache[cache_key].get_nowait()
                if time.time() - ctime < 16:
                    return sock
                else:
                    sock.close()
        except Queue.Empty:
            pass
        result = None
        addresses = [(x, port) for x in self.gethostbyname2(hostname)]
        if port == 443:
            get_connection_time = lambda addr: self.ssl_connection_time.__getitem__(addr) or self.tcp_connection_time.__getitem__(addr)
        else:
            get_connection_time = self.tcp_connection_time.__getitem__
        errors = []
        for i in range(3):
            window = min((self.max_window+1)//2 + min(i, 1), len(addresses))
            addresses.sort(key=get_connection_time)
            addrs = addresses[:window] + random.sample(addresses, min(len(addresses), window, self.max_window-window))
            queobj = Queue.Queue()
            for addr in addrs:
                thread.start_new_thread(create_connection, (addr, timeout, queobj))
            for i in range(len(addrs)):
                result = queobj.get()
                if not isinstance(result, (socket.error, OSError)):
                    ipaddr = result.getpeername()
                    thread.start_new_thread(close_connection, (len(addrs)-i-1, queobj, self.tcp_connection_time[ipaddr]))
                    return result
                else:
                    if i == 0:
                        # only output first error
                        logging.warning('create_connection to %s return %r, try again.', addrs, result)
                    errors.append(result)
        raise errors[-1]

    def create_ssl_connection(self, hostname, port, timeout, **kwargs):
        cache_key = kwargs.get('cache_key')
        validate = kwargs.get('validate')
        def create_connection(ipaddr, timeout, queobj):
            sock = None
            ssl_sock = None
            try:
                # create a ipv4/ipv6 socket object
                sock = socket.socket(socket.AF_INET if ':' not in ipaddr[0] else socket.AF_INET6)
                # set reuseaddr option to avoid 10048 socket error
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # resize socket recv buffer 8K->32K to improve browser releated application performance
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32*1024)
                # disable negal algorithm to send http request quickly.
                sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
                # set a short timeout to trigger timeout retry more quickly.
                sock.settimeout(timeout or self.max_timeout)
                # pick up the certificate
                if not validate:
                    ssl_sock = ssl.wrap_socket(sock, do_handshake_on_connect=False)
                else:
                    ssl_sock = ssl.wrap_socket(sock, cert_reqs=ssl.CERT_REQUIRED, ca_certs=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cacert.pem'), do_handshake_on_connect=False)
                ssl_sock.settimeout(timeout or self.connect_timeout)
                # start connection time record
                start_time = time.time()
                # TCP connect
                ssl_sock.connect(ipaddr)
                connected_time = time.time()
                # SSL handshake
                ssl_sock.do_handshake()
                handshaked_time = time.time()
                # record TCP connection time
                self.tcp_connection_time[ipaddr] = ssl_sock.tcp_time = connected_time - start_time
                # record SSL connection time
                self.ssl_connection_time[ipaddr] = ssl_sock.ssl_time = handshaked_time - start_time
                ssl_sock.ssl_time = connected_time - start_time
                # sometimes, we want to use raw tcp socket directly(select/epoll), so setattr it to ssl socket.
                ssl_sock.sock = sock
                # verify SSL certificate.
                if validate and hostname.endswith('.appspot.com'):
                    cert = ssl_sock.getpeercert()
                    orgname = next((v for ((k, v),) in cert['subject'] if k == 'organizationName'))
                    if not orgname.lower().startswith('google '):
                        raise ssl.SSLError("%r certificate organizationName(%r) not startswith 'Google'" % (hostname, orgname))
                # put ssl socket object to output queobj
                queobj.put(ssl_sock)
            except (socket.error, ssl.SSLError, OSError) as e:
                # any socket.error, put Excpetions to output queobj.
                queobj.put(e)
                # reset a large and random timeout to the ipaddr
                self.ssl_connection_time[ipaddr] = self.connect_timeout + random.random()
                # close ssl socket
                if ssl_sock:
                    ssl_sock.close()
                # close tcp socket
                if sock:
                    sock.close()
        def create_connection_withopenssl(ipaddr, timeout, queobj):
            sock = None
            ssl_sock = None
            try:
                # create a ipv4/ipv6 socket object
                sock = socket.socket(socket.AF_INET if ':' not in ipaddr[0] else socket.AF_INET6)
                # set reuseaddr option to avoid 10048 socket error
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # resize socket recv buffer 8K->32K to improve browser releated application performance
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32*1024)
                # disable negal algorithm to send http request quickly.
                sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
                # set a short timeout to trigger timeout retry more quickly.
                sock.settimeout(timeout or self.max_timeout)
                # pick up the certificate
                server_hostname = b'www.google.com' if hostname.endswith('.appspot.com') else None
                ssl_sock = SSLConnection(self.openssl_context, sock)
                ssl_sock.set_connect_state()
                if server_hostname:
                    ssl_sock.set_tlsext_host_name(server_hostname)
                # start connection time record
                start_time = time.time()
                # TCP connect
                ssl_sock.connect(ipaddr)
                connected_time = time.time()
                # SSL handshake
                ssl_sock.do_handshake()
                handshaked_time = time.time()
                # record TCP connection time
                self.tcp_connection_time[ipaddr] = ssl_sock.tcp_time = connected_time - start_time
                # record SSL connection time
                self.ssl_connection_time[ipaddr] = ssl_sock.ssl_time = handshaked_time - start_time
                # sometimes, we want to use raw tcp socket directly(select/epoll), so setattr it to ssl socket.
                ssl_sock.sock = sock
                # verify SSL certificate.
                if validate and hostname.endswith('.appspot.com'):
                    cert = ssl_sock.get_peer_certificate()
                    commonname = next((v for k, v in cert.get_subject().get_components() if k == 'CN'))
                    if '.google' not in commonname and not commonname.endswith('.appspot.com'):
                        raise socket.error("Host name '%s' doesn't match certificate host '%s'" % (hostname, commonname))
                # put ssl socket object to output queobj
                queobj.put(ssl_sock)
            except (socket.error, OpenSSL.SSL.Error, OSError) as e:
                # any socket.error, put Excpetions to output queobj.
                queobj.put(e)
                # reset a large and random timeout to the ipaddr
                self.ssl_connection_time[ipaddr] = self.max_timeout + random.random()
                # close ssl socket
                if ssl_sock:
                    ssl_sock.close()
                # close tcp socket
                if sock:
                    sock.close()
        def close_connection(count, queobj, first_tcp_time, first_ssl_time):
            for _ in range(count):
                sock = queobj.get()
                ssl_time_threshold = min(1, 1.5 * first_ssl_time)
                if sock and not isinstance(sock, Exception):
                    if cache_key and sock.ssl_time < ssl_time_threshold:
                        self.ssl_connection_cache[cache_key].put((time.time(), sock))
                    else:
                        sock.close()
        try:
            while cache_key:
                ctime, sock = self.ssl_connection_cache[cache_key].get_nowait()
                if time.time() - ctime < 16:
                    return sock
                else:
                    sock.close()
        except Queue.Empty:
            pass
        result = None
        addresses = [(x, port) for x in self.gethostbyname2(hostname)]
        for i in range(3):
            window = min((self.max_window+1)//2 + min(i, 1), len(addresses))
            addresses.sort(key=self.ssl_connection_time.__getitem__)
            addrs = addresses[:window] + random.sample(addresses, min(len(addresses), window, self.max_window-window))
            queobj = Queue.Queue()
            for addr in addrs:
                thread.start_new_thread(create_connection, (addr, timeout, queobj))
            errors = []
            for i in range(len(addrs)):
                result = queobj.get()
                if not isinstance(result, Exception):
                    thread.start_new_thread(close_connection, (len(addrs)-i-1, queobj, result.tcp_time, result.ssl_time))
                    if i > 0:
                        logging.info('create_ssl_connection to %s return OK.', addrs)
                    return result
                else:
                    if i == 0:
                        # only output first error
                        logging.warning('create_ssl_connection to %s return %r, try again.', addrs, result)
                errors.append(result)
        raise errors[-1]

    def create_http_request(self, method, url, headers, body, timeout, max_retry=3, bufsize=8192, crlf=None, validate=None, cache_key=None):
        scheme, netloc, path, query, _ = urlparse.urlsplit(url)
        if netloc.rfind(':') <= netloc.rfind(']'):
            # no port number
            host = netloc
            port = 443 if scheme == 'https' else 80
        else:
            host, _, port = netloc.rpartition(':')
            port = int(port)
        if query:
            path += '?' + query
        if 'Host' not in headers:
            headers['Host'] = host
        if body and 'Content-Length' not in headers:
            headers['Content-Length'] = str(len(body))
        sock = None
        errors = []
        for _ in range(max_retry):
            try:
                create_connection = self.create_ssl_connection if scheme == 'https' else self.create_tcp_connection
                sock = create_connection(host, port, timeout, validate=validate, cache_key=cache_key)
                if sock and not isinstance(sock, Exception):
                    break
            except Exception as e:
                logging.exception('create_http_request "%s %s" failed:%s', method, url, e)
                errors.append(e)
                continue
        if not sock and errors:
            raise errors[-1]
        request_data = ''
        crlf_counter = 0
        if scheme != 'https' and crlf:
            fakeheaders = dict((k.title(), v) for k, v in headers.items())
            fakeheaders.pop('Content-Length', None)
            fakeheaders.pop('Cookie', None)
            fakeheaders.pop('Host', None)
            if 'User-Agent' not in fakeheaders:
                fakeheaders['User-Agent'] = 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1878.0 Safari/537.36'
            if 'Accept-Language' not in fakeheaders:
                fakeheaders['Accept-Language'] = 'zh-CN,zh;q=0.8,en-US;q=0.6,en;q=0.4'
            if 'Accept' not in fakeheaders:
                fakeheaders['Accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
            fakeheaders_data = ''.join('%s: %s\r\n' % (k, v) for k, v in fakeheaders.items() if k not in self.skip_headers)
            while crlf_counter < 5 or len(request_data) < 1500 * 2:
                request_data += 'GET / HTTP/1.1\r\n%s\r\n' % fakeheaders_data
                crlf_counter += 1
            request_data += '\r\n\r\n\r\n'
        request_data += '%s %s %s\r\n' % (method, path, self.protocol_version)
        request_data += ''.join('%s: %s\r\n' % (k.title(), v) for k, v in headers.items() if k.title() not in self.skip_headers)
        request_data += '\r\n'
        if isinstance(body, bytes):
            sock.sendall(request_data.encode() + body)
        elif hasattr(body, 'read'):
            sock.sendall(request_data)
            while 1:
                data = body.read(bufsize)
                if not data:
                    break
                sock.sendall(data)
        else:
            raise TypeError('create_http_request(body) must be a string or buffer, not %r' % type(body))
        try:
            while crlf_counter:
                response = httplib.HTTPResponse(sock, buffering=False)
                response.begin()
                response.read()
                response.close()
                crlf_counter -= 1
        except Exception as e:
            logging.exception('crlf skip read host=%r path=%r error: %r', headers.get('Host'), path, e)
            return None
        response = httplib.HTTPResponse(sock, buffering=True)
        try:
            response.begin()
        except httplib.BadStatusLine:
            response = None
        return response


class Common(object):
    """Global Config Object"""

    ENV_CONFIG_PREFIX = 'GOAGENT_'

    def __init__(self):
        """load config from proxy.ini"""
        ConfigParser.RawConfigParser.OPTCRE = re.compile(r'(?P<option>[^=\s][^=]*)\s*(?P<vi>[=])\s*(?P<value>.*)$')
        self.CONFIG = ConfigParser.ConfigParser()
        self.CONFIG_FILENAME = os.path.splitext(os.path.abspath(__file__))[0]+'.ini'
        self.CONFIG_USER_FILENAME = re.sub(r'\.ini$', '.user.ini', self.CONFIG_FILENAME)
        self.CONFIG.read([self.CONFIG_FILENAME, self.CONFIG_USER_FILENAME])

        for key, value in os.environ.items():
            m = re.match(r'^%s([A-Z]+)_([A-Z\_\-]+)$' % self.ENV_CONFIG_PREFIX, key)
            if m:
                self.CONFIG.set(m.group(1).lower(), m.group(2).lower(), value)

        self.LISTEN_IP = self.CONFIG.get('listen', 'ip')
        self.LISTEN_PORT = self.CONFIG.getint('listen', 'port')
        self.LISTEN_VISIBLE = self.CONFIG.getint('listen', 'visible')
        self.LISTEN_DEBUGINFO = self.CONFIG.getint('listen', 'debuginfo')

        self.GAE_APPIDS = re.findall(r'[\w\-\.]+', self.CONFIG.get('gae', 'appid').replace('.appspot.com', ''))
        self.GAE_PASSWORD = self.CONFIG.get('gae', 'password').strip()
        self.GAE_PATH = self.CONFIG.get('gae', 'path')
        self.GAE_MODE = self.CONFIG.get('gae', 'mode')
        self.GAE_PROFILE = self.CONFIG.get('gae', 'profile').strip()
        self.GAE_WINDOW = self.CONFIG.getint('gae', 'window')
        self.GAE_VALIDATE = self.CONFIG.getint('gae', 'validate')
        self.GAE_OBFUSCATE = self.CONFIG.getint('gae', 'obfuscate')
        self.GAE_OPTIONS = self.CONFIG.get('gae', 'options')
        self.GAE_REGIONS = frozenset(x.upper() for x in self.CONFIG.get('gae', 'regions').split('|') if x.strip())

        if self.GAE_PROFILE == 'auto':
            try:
                socket.create_connection(('2001:4860:4860::8888', 53), timeout=1).close()
                logging.info('Use profile ipv6')
                self.GAE_PROFILE = 'ipv6'
            except socket.error as e:
                logging.info('Fail try profile ipv6 %r, fallback ipv4', e)
                self.GAE_PROFILE = 'ipv4'
        hosts_section, http_section = '%s/hosts' % self.GAE_PROFILE, '%s/http' % self.GAE_PROFILE

        if 'USERDNSDOMAIN' in os.environ and re.match(r'^\w+\.\w+$', os.environ['USERDNSDOMAIN']):
            self.CONFIG.set(hosts_section, '.' + os.environ['USERDNSDOMAIN'], '')

        self.HOSTS_MAP = collections.OrderedDict((k, v or k) for k, v in self.CONFIG.items(hosts_section) if '\\' not in k and ':' not in k and not k.startswith('.'))
        self.HOSTS_POSTFIX_MAP = collections.OrderedDict((k, v) for k, v in self.CONFIG.items(hosts_section) if '\\' not in k and ':' not in k and k.startswith('.'))
        self.HOSTS_POSTFIX_ENDSWITH = tuple(self.HOSTS_POSTFIX_MAP)

        self.CONNECT_HOSTS_MAP = collections.OrderedDict((k, v) for k, v in self.CONFIG.items(hosts_section) if ':' in k and not k.startswith('.'))
        self.CONNECT_POSTFIX_MAP = collections.OrderedDict((k, v) for k, v in self.CONFIG.items(hosts_section) if ':' in k and k.startswith('.'))
        self.CONNECT_POSTFIX_ENDSWITH = tuple(self.CONNECT_POSTFIX_MAP)

        self.METHOD_REMATCH_MAP = collections.OrderedDict((re.compile(k).match, v) for k, v in self.CONFIG.items(hosts_section) if '\\' in k)
        self.METHOD_REMATCH_HAS_LOCALFILE = any(x.startswith('file://') for x in self.METHOD_REMATCH_MAP.values())

        self.HTTP_WITHGAE = set(self.CONFIG.get(http_section, 'withgae').split('|'))
        self.HTTP_CRLFSITES = tuple(self.CONFIG.get(http_section, 'crlfsites').split('|'))
        self.HTTP_FORCEHTTPS = set(self.CONFIG.get(http_section, 'forcehttps').split('|'))
        self.HTTP_FAKEHTTPS = set(self.CONFIG.get(http_section, 'fakehttps').split('|'))
        self.HTTP_DNS = self.CONFIG.get(http_section, 'dns').split('|') if self.CONFIG.has_option(http_section, 'dns') else []

        self.IPLIST_MAP = collections.OrderedDict((k, v.split('|')) for k, v in self.CONFIG.items('iplist'))
        self.IPLIST_MAP.update((k, [k]) for k, v in self.HOSTS_MAP.items() if k == v)

        self.PAC_ENABLE = self.CONFIG.getint('pac', 'enable')
        self.PAC_IP = self.CONFIG.get('pac', 'ip')
        self.PAC_PORT = self.CONFIG.getint('pac', 'port')
        self.PAC_FILE = self.CONFIG.get('pac', 'file').lstrip('/')
        self.PAC_GFWLIST = self.CONFIG.get('pac', 'gfwlist')
        self.PAC_ADBLOCK = self.CONFIG.get('pac', 'adblock') if self.CONFIG.has_option('pac', 'adblock') else ''
        self.PAC_EXPIRED = self.CONFIG.getint('pac', 'expired')

        self.PHP_ENABLE = self.CONFIG.getint('php', 'enable')
        self.PHP_LISTEN = self.CONFIG.get('php', 'listen')
        self.PHP_PASSWORD = self.CONFIG.get('php', 'password') if self.CONFIG.has_option('php', 'password') else ''
        self.PHP_CRLF = self.CONFIG.getint('php', 'crlf') if self.CONFIG.has_option('php', 'crlf') else 1
        self.PHP_VALIDATE = self.CONFIG.getint('php', 'validate') if self.CONFIG.has_option('php', 'validate') else 0
        self.PHP_FETCHSERVER = self.CONFIG.get('php', 'fetchserver')
        self.PHP_USEHOSTS = self.CONFIG.getint('php', 'usehosts')

        self.PROXY_ENABLE = self.CONFIG.getint('proxy', 'enable')
        self.PROXY_AUTODETECT = self.CONFIG.getint('proxy', 'autodetect') if self.CONFIG.has_option('proxy', 'autodetect') else 0
        self.PROXY_HOST = self.CONFIG.get('proxy', 'host')
        self.PROXY_PORT = self.CONFIG.getint('proxy', 'port')
        self.PROXY_USERNAME = self.CONFIG.get('proxy', 'username')
        self.PROXY_PASSWROD = self.CONFIG.get('proxy', 'password')

        if not self.PROXY_ENABLE and self.PROXY_AUTODETECT:
            system_proxy = ProxyUtil.get_system_proxy()
            if system_proxy and self.LISTEN_IP not in system_proxy:
                _, username, password, address = ProxyUtil.parse_proxy(system_proxy)
                proxyhost, _, proxyport = address.rpartition(':')
                self.PROXY_ENABLE = 1
                self.PROXY_USERNAME = username
                self.PROXY_PASSWROD = password
                self.PROXY_HOST = proxyhost
                self.PROXY_PORT = int(proxyport)
        if self.PROXY_ENABLE:
            self.GAE_MODE = 'https'

        self.AUTORANGE_HOSTS = self.CONFIG.get('autorange', 'hosts').split('|')
        self.AUTORANGE_HOSTS_MATCH = [re.compile(fnmatch.translate(h)).match for h in self.AUTORANGE_HOSTS]
        self.AUTORANGE_ENDSWITH = tuple(self.CONFIG.get('autorange', 'endswith').split('|'))
        self.AUTORANGE_NOENDSWITH = tuple(self.CONFIG.get('autorange', 'noendswith').split('|'))
        self.AUTORANGE_MAXSIZE = self.CONFIG.getint('autorange', 'maxsize')
        self.AUTORANGE_WAITSIZE = self.CONFIG.getint('autorange', 'waitsize')
        self.AUTORANGE_BUFSIZE = self.CONFIG.getint('autorange', 'bufsize')
        self.AUTORANGE_THREADS = self.CONFIG.getint('autorange', 'threads')

        self.FETCHMAX_LOCAL = self.CONFIG.getint('fetchmax', 'local') if self.CONFIG.get('fetchmax', 'local') else 3
        self.FETCHMAX_SERVER = self.CONFIG.get('fetchmax', 'server')

        self.DNS_ENABLE = self.CONFIG.getint('dns', 'enable')
        self.DNS_LISTEN = self.CONFIG.get('dns', 'listen')
        self.DNS_SERVERS = self.HTTP_DNS or self.CONFIG.get('dns', 'servers').split('|')
        self.DNS_BLACKLIST = set(self.CONFIG.get('dns', 'blacklist').split('|'))

        self.USERAGENT_ENABLE = self.CONFIG.getint('useragent', 'enable')
        self.USERAGENT_STRING = self.CONFIG.get('useragent', 'string')

        self.LOVE_ENABLE = self.CONFIG.getint('love', 'enable')
        self.LOVE_TIP = self.CONFIG.get('love', 'tip').encode('utf8').decode('unicode-escape').split('|')

    def resolve_iplist(self):
        def do_resolve(host, dnsservers, queue):
            try:
                iplist = dns_remote_resolve(host, dnsservers, self.DNS_BLACKLIST, timeout=2)
                queue.put((host, dnsservers, iplist or []))
            except (socket.error, OSError) as e:
                logging.error('resolve remote host=%r failed: %s', host, e)
                queue.put((host, dnsservers, []))
        # https://support.google.com/websearch/answer/186669?hl=zh-Hans
        google_blacklist = ['216.239.32.20', '74.125.127.102', '74.125.155.102', '74.125.39.102', '74.125.39.113', '209.85.229.138']
        for name, need_resolve_hosts in list(self.IPLIST_MAP.items()):
            if all(re.match(r'\d+\.\d+\.\d+\.\d+', x) or ':' in x for x in need_resolve_hosts):
                continue
            need_resolve_remote = [x for x in need_resolve_hosts if ':' not in x and not re.match(r'\d+\.\d+\.\d+\.\d+', x)]
            resolved_iplist = [x for x in need_resolve_hosts if x not in need_resolve_remote]
            result_queue = Queue.Queue()
            for host in need_resolve_remote:
                for dnsserver in self.DNS_SERVERS:
                    logging.debug('resolve remote host=%r from dnsserver=%r', host, dnsserver)
                    thread.start_new_thread(do_resolve, (host, [dnsserver], result_queue))
            for _ in xrange(len(self.DNS_SERVERS) * len(need_resolve_remote)):
                try:
                    host, dnsservers, iplist = result_queue.get(timeout=2)
                    resolved_iplist += iplist or []
                    logging.debug('resolve remote host=%r from dnsservers=%s return iplist=%s', host, dnsservers, iplist)
                except Queue.Empty:
                    logging.warn('resolve remote timeout, try resolve local')
                    resolved_iplist += sum([socket.gethostbyname_ex(x)[-1] for x in need_resolve_remote], [])
                    break
            if name.startswith('google_') and name not in ('google_cn', 'google_hk'):
                iplist_prefix = re.split(r'[\.:]', resolved_iplist[0])[0]
                resolved_iplist = list(set(x for x in resolved_iplist if x.startswith(iplist_prefix)))
            else:
                resolved_iplist = list(set(resolved_iplist))
            if name.startswith('google_'):
                resolved_iplist = list(set(resolved_iplist) - set(google_blacklist))
            if len(resolved_iplist) == 0:
                logging.error('resolve %s host return empty! please retry!', name)
                sys.exit(-1)
            logging.info('resolve name=%s host to iplist=%r', name, resolved_iplist)
            common.IPLIST_MAP[name] = resolved_iplist


    def info(self):
        info = ''
        info += '------------------------------------------------------\n'
        info += 'GoAgent Version    : %s (python/%s %spyopenssl/%s)\n' % (__version__, sys.version[:5], gevent and 'gevent/%s ' % gevent.__version__ or '', getattr(OpenSSL, '__version__', 'Disabled'))
        info += 'Uvent Version      : %s (pyuv/%s libuv/%s)\n' % (__import__('uvent').__version__, __import__('pyuv').__version__, __import__('pyuv').LIBUV_VERSION) if all(x in sys.modules for x in ('pyuv', 'uvent')) else ''
        info += 'Listen Address     : %s:%d\n' % (self.LISTEN_IP, self.LISTEN_PORT)
        info += 'Local Proxy        : %s:%s\n' % (self.PROXY_HOST, self.PROXY_PORT) if self.PROXY_ENABLE else ''
        info += 'Debug INFO         : %s\n' % self.LISTEN_DEBUGINFO if self.LISTEN_DEBUGINFO else ''
        info += 'GAE Mode           : %s\n' % self.GAE_MODE
        info += 'GAE Profile        : %s\n' % self.GAE_PROFILE if self.GAE_PROFILE else ''
        info += 'GAE APPID          : %s\n' % '|'.join(self.GAE_APPIDS)
        info += 'GAE Validate       : %s\n' % self.GAE_VALIDATE if self.GAE_VALIDATE else ''
        info += 'GAE Obfuscate      : %s\n' % self.GAE_OBFUSCATE if self.GAE_OBFUSCATE else ''
        if common.PAC_ENABLE:
            info += 'Pac Server         : http://%s:%d/%s\n' % (self.PAC_IP, self.PAC_PORT, self.PAC_FILE)
            info += 'Pac File           : file://%s\n' % os.path.join(os.path.dirname(os.path.abspath(__file__)), self.PAC_FILE).replace('\\', '/')
        if common.PHP_ENABLE:
            info += 'PHP Listen         : %s\n' % common.PHP_LISTEN
            info += 'PHP FetchServer    : %s\n' % common.PHP_FETCHSERVER
        if common.DNS_ENABLE:
            info += 'DNS Listen         : %s\n' % common.DNS_LISTEN
            info += 'DNS Servers        : %s\n' % '|'.join(common.DNS_SERVERS)
        info += '------------------------------------------------------\n'
        return info

common = Common()


def message_html(title, banner, detail=''):
    MESSAGE_TEMPLATE = '''
    <html><head>
    <meta http-equiv="content-type" content="text/html;charset=utf-8">
    <title>$title</title>
    <style><!--
    body {font-family: arial,sans-serif}
    div.nav {margin-top: 1ex}
    div.nav A {font-size: 10pt; font-family: arial,sans-serif}
    span.nav {font-size: 10pt; font-family: arial,sans-serif; font-weight: bold}
    div.nav A,span.big {font-size: 12pt; color: #0000cc}
    div.nav A {font-size: 10pt; color: black}
    A.l:link {color: #6f6f6f}
    A.u:link {color: green}
    //--></style>
    </head>
    <body text=#000000 bgcolor=#ffffff>
    <table border=0 cellpadding=2 cellspacing=0 width=100%>
    <tr><td bgcolor=#3366cc><font face=arial,sans-serif color=#ffffff><b>Message</b></td></tr>
    <tr><td> </td></tr></table>
    <blockquote>
    <H1>$banner</H1>
    $detail
    <p>
    </blockquote>
    <table width=100% cellpadding=0 cellspacing=0><tr><td bgcolor=#3366cc><img alt="" width=1 height=4></td></tr></table>
    </body></html>
    '''
    return string.Template(MESSAGE_TEMPLATE).substitute(title=title, banner=banner, detail=detail)


try:
    from Crypto.Cipher.ARC4 import new as RC4Cipher
except ImportError:
    logging.warn('Load Crypto.Cipher.ARC4 Failed, Use Pure Python Instead.')
    class RC4Cipher(object):
        def __init__(self, key):
            x = 0
            box = range(256)
            for i, y in enumerate(box):
                x = (x + y + ord(key[i % len(key)])) & 0xff
                box[i], box[x] = box[x], y
            self.__box = box
            self.__x = 0
            self.__y = 0
        def encrypt(self, data):
            out = []
            out_append = out.append
            x = self.__x
            y = self.__y
            box = self.__box
            for char in data:
                x = (x + 1) & 0xff
                y = (y + box[x]) & 0xff
                box[x], box[y] = box[y], box[x]
                out_append(chr(ord(char) ^ box[(box[x] + box[y]) & 0xff]))
            self.__x = x
            self.__y = y
            return ''.join(out)


class XORCipher(object):
    """XOR Cipher Class"""
    def __init__(self, key):
        self.__key_gen = itertools.cycle([ord(x) for x in key]).next
        self.__key_xor = lambda s: ''.join(chr(ord(x) ^ self.__key_gen()) for x in s)
        if len(key) == 1:
            try:
                from Crypto.Util.strxor import strxor_c
                c = ord(key)
                self.__key_xor = lambda s: strxor_c(s, c)
            except ImportError:
                sys.stderr.write('Load Crypto.Util.strxor Failed, Use Pure Python Instead.\n')

    def encrypt(self, data):
        return self.__key_xor(data)


class CipherFileObject(object):
    """fileobj wrapper for cipher"""
    def __init__(self, fileobj, cipher):
        self.__fileobj = fileobj
        self.__cipher = cipher
    def __getattr__(self, attr):
        if attr not in ('__fileobj', '__cipher'):
            return getattr(self.__fileobj, attr)
    def read(self, size=-1):
        return self.__cipher.encrypt(self.__fileobj.read(size))


class LocalProxyServer(SocketServer.ThreadingTCPServer):
    """Local Proxy Server"""
    allow_reuse_address = True
    daemon_threads = True

    def close_request(self, request):
        try:
            request.close()
        except Exception:
            pass

    def finish_request(self, request, client_address):
        try:
            self.RequestHandlerClass(request, client_address, self)
        except NetWorkIOError as e:
            if e[0] not in (errno.ECONNABORTED, errno.ECONNRESET, errno.EPIPE):
                raise

    def handle_error(self, *args):
        """make ThreadingTCPServer happy"""
        exc_info = sys.exc_info()
        error = exc_info and len(exc_info) and exc_info[1]
        if isinstance(error, NetWorkIOError) and len(error.args) > 1 and 'bad write retry' in error.args[1]:
            exc_info = error = None
        else:
            del exc_info, error
            SocketServer.ThreadingTCPServer.handle_error(self, *args)


class WithGAEFilter(BaseProxyHandlerFilter):
    """with gae filter"""
    def filter(self, handler):
        if handler.host in common.HTTP_WITHGAE:
            logging.debug('WithGAEFilter metched %r %r', handler.path, handler.headers)
            if handler.command == 'CONNECT':
                return [handler.STRIPSSL]
            kwargs = {}
            if common.GAE_PASSWORD:
                kwargs['password'] = common.GAE_PASSWORD
            if common.GAE_VALIDATE:
                kwargs['validate'] = 1
            fetchservers = ['%s://%s.appspot.com%s' % (common.GAE_MODE, x, common.GAE_PATH) for x in common.GAE_APPIDS]
            return [handler.URLFETCH, fetchservers, common.FETCHMAX_LOCAL, False, kwargs]


class ForceHttpsFilter(BaseProxyHandlerFilter):
    """force https filter"""
    def filter(self, handler):
        if handler.command != 'CONNECT' and handler.host in common.HTTP_FORCEHTTPS and not handler.headers.get('Referer', '').startswith('https://') and not handler.path.startswith('https://'):
            logging.debug('ForceHttpsFilter metched %r %r', handler.path, handler.headers)
            headers = {'Location': handler.path.replace('http://', 'https://', 1), 'Connection': 'close'}
            return [handler.MOCK, 301, headers, '']


class FakeHttpsFilter(BaseProxyHandlerFilter):
    """fake https filter"""
    def filter(self, handler):
        if handler.command == 'CONNECT' and handler.host in common.HTTP_FAKEHTTPS:
            return [handler.STRIPSSL]


class HostsFilter(BaseProxyHandlerFilter):
    """force https filter"""
    def filter_localfile(self, handler, filename):
        content_type = None
        try:
            import mimetypes
            content_type = mimetypes.types_map.get(os.path.splitext(filename)[1])
        except Exception as e:
            logging.error('import mimetypes failed: %r', e)
        try:
            with open(filename, 'rb') as fp:
                data = fp.read()
                headers = {'Connection': 'close', 'Content-Length': str(len(data))}
                if content_type:
                    headers['Content-Type'] = content_type
                return [handler.MOCK, 200, headers, data]
        except Exception as e:
            return [handler.MOCK, 403, {'Connection': 'close'}, 'read %r %r' % (filename, e)]

    def filter(self, handler):
        host, port = handler.host, handler.port
        if handler.command == 'CONNECT':
            if handler.path in common.CONNECT_HOSTS_MAP or handler.path.endswith(common.CONNECT_POSTFIX_ENDSWITH) or host in common.HOSTS_MAP or host.endswith(common.HOSTS_POSTFIX_ENDSWITH):
                if handler.path in common.CONNECT_HOSTS_MAP:
                    hostname = common.CONNECT_HOSTS_MAP[handler.path]
                elif handler.path.endswith(common.CONNECT_POSTFIX_ENDSWITH):
                    hostname = next(common.CONNECT_POSTFIX_MAP[x] for x in common.CONNECT_POSTFIX_MAP if handler.path.endswith(x))
                    common.CONNECT_HOSTS_MAP[handler.path] = hostname
                elif host in common.HOSTS_MAP:
                    hostname = common.HOSTS_MAP[host]
                elif host.endswith(common.HOSTS_POSTFIX_ENDSWITH):
                    hostname = next(common.HOSTS_POSTFIX_MAP[x] for x in common.HOSTS_POSTFIX_MAP if host.endswith(x))
                    common.HOSTS_MAP[host] = hostname
                else:
                    hostname = host
                hostname = hostname or host
                if hostname in common.IPLIST_MAP:
                    handler.dns_cache[host] = common.IPLIST_MAP[hostname]
                cache_key = '%s:%s' % (hostname, port)
                return [handler.FORWARD, host, port, handler.connect_timeout, {'cache_key': cache_key}]
        else:
            if any(x(handler.path) for x in common.METHOD_REMATCH_MAP) or host in common.HOSTS_MAP or host.endswith(common.HOSTS_POSTFIX_ENDSWITH):
                if any(x(handler.path) for x in common.METHOD_REMATCH_MAP):
                    hostname = next(common.METHOD_REMATCH_MAP[x] for x in common.METHOD_REMATCH_MAP if x(handler.path))
                elif host in common.HOSTS_MAP:
                    hostname = common.HOSTS_MAP[host]
                elif host.endswith(common.HOSTS_POSTFIX_ENDSWITH):
                    hostname = next(common.HOSTS_POSTFIX_MAP[x] for x in common.HOSTS_POSTFIX_MAP if host.endswith(x))
                    common.HOSTS_MAP[host] = hostname
                else:
                    hostname = host
                if common.METHOD_REMATCH_HAS_LOCALFILE and hostname.startswith('file://'):
                    filename = hostname.lstrip('file://')
                    if os.name == 'nt':
                        filename = filename.lstrip('/')
                    return self.filter_localfile(handler, filename)
                else:
                    if hostname in common.IPLIST_MAP:
                        handler.dns_cache[host] = common.IPLIST_MAP[hostname]
                    cache_key = '%s:%s' % (hostname, port)
                    crlf = host.endswith(common.HTTP_CRLFSITES)
                    return [handler.DIRECT, {'cache_key': hostname, 'crlf': crlf}]


class DirectRegionFilter(BaseProxyHandlerFilter):
    """direct region filter"""
    geoip = pygeoip.GeoIP(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'GeoIP.dat')) if pygeoip and common.GAE_REGIONS else None
    region_cache = LRUCache(16*1024)

    def get_country_code(self, hostname):
        """http://dev.maxmind.com/geoip/legacy/codes/iso3166/"""
        try:
            return self.region_cache[hostname]
        except KeyError:
            pass
        try:
            country_code = self.geoip.country_code_by_addr(socket.gethostbyname(hostname))
        except Exception:
            country_code = ''
        self.region_cache[hostname] = country_code
        return country_code

    def filter(self, handler):
        if self.geoip:
            country_code = self.get_country_code(handler.host)
            if country_code in common.GAE_REGIONS:
                if handler.command == 'CONNECT':
                    return [handler.FORWARD, handler.host, handler.port, handler.connect_timeout]
                else:
                    return [handler.DIRECT, {}]


class AutoRangeFilter(BaseProxyHandlerFilter):
    """force https filter"""
    def filter(self, handler):
        need_autorange = any(x(handler.host) for x in common.AUTORANGE_HOSTS_MATCH) or handler.path.endswith(common.AUTORANGE_ENDSWITH)
        if handler.path.endswith(common.AUTORANGE_NOENDSWITH) or 'range=' in urlparse.urlsplit(handler.path).query or handler.command == 'HEAD':
            need_autorange = False
        if handler.command != 'HEAD' and handler.headers.get('Range'):
            m = re.search(r'bytes=(\d+)-', handler.headers['Range'])
            start = int(m.group(1) if m else 0)
            handler.headers['Range'] = 'bytes=%d-%d' % (start, start+common.AUTORANGE_MAXSIZE-1)
            logging.info('autorange range=%r match url=%r', handler.headers['Range'], handler.path)
        elif need_autorange:
            logging.info('Found [autorange]endswith match url=%r', handler.path)
            m = re.search(r'bytes=(\d+)-', handler.headers.get('Range', ''))
            start = int(m.group(1) if m else 0)
            handler.headers['Range'] = 'bytes=%d-%d' % (start, start+common.AUTORANGE_MAXSIZE-1)


class GAEFetchFilter(BaseProxyHandlerFilter):
    """force https filter"""
    def filter(self, handler):
        if handler.command == 'CONNECT':
            return [handler.STRIPSSL]
        else:
            kwargs = {}
            if common.GAE_PASSWORD:
                kwargs['password'] = common.GAE_PASSWORD
            if common.GAE_VALIDATE:
                kwargs['validate'] = 1
            fetchservers = ['%s://%s.appspot.com%s' % (common.GAE_MODE, x, common.GAE_PATH) for x in common.GAE_APPIDS]
            return [handler.URLFETCH, fetchservers, common.FETCHMAX_LOCAL, False, kwargs]


class GAEProxyHandler(AdvancedProxyHandler):
    """GAE Proxy Handler 2"""
    handler_filters = [WithGAEFilter(), FakeHttpsFilter(), ForceHttpsFilter(), HostsFilter(), DirectRegionFilter(), AutoRangeFilter(), GAEFetchFilter()]

    def first_run(self):
        """GAEProxyHandler setup, init domain/iplist map"""
        if not common.PROXY_ENABLE:
            logging.info('resolve common.IPLIST_MAP names=%s to iplist', list(common.IPLIST_MAP))
            common.resolve_iplist()
        random.shuffle(common.GAE_APPIDS)
        for appid in common.GAE_APPIDS:
            host = '%s.appspot.com' % appid
            if host not in common.HOSTS_MAP:
                common.HOSTS_MAP[host] = common.HOSTS_POSTFIX_MAP['.appspot.com']
            if host not in self.dns_cache:
                self.dns_cache[host] = common.IPLIST_MAP[common.HOSTS_MAP[host]]

    def create_http_request_withserver(self, fetchserver, method, url, headers, body, timeout, **kwargs):
        # deflate = lambda x:zlib.compress(x)[2:-4]
        rc4crypt = lambda s, k: RC4Cipher(k).encrypt(s) if k else s
        if body:
            if len(body) < 10 * 1024 * 1024 and 'Content-Encoding' not in headers:
                zbody = zlib.compress(body)[2:-4]
                if len(zbody) < len(body):
                    body = zbody
                    headers['Content-Encoding'] = 'deflate'
            headers['Content-Length'] = str(len(body))
        # GAE donot allow set `Host` header
        if 'Host' in headers:
            del headers['Host']
        metadata = 'G-Method:%s\nG-Url:%s\n%s' % (method, url, ''.join('G-%s:%s\n' % (k, v) for k, v in kwargs.items() if v))
        skip_headers = self.skip_headers
        metadata += ''.join('%s:%s\n' % (k.title(), v) for k, v in headers.items() if k not in skip_headers)
        # prepare GAE request
        request_method = 'POST'
        request_headers = {}
        if common.GAE_OBFUSCATE:
            if 'rc4' in common.GAE_OPTIONS:
                request_headers['X-GOA-Options'] = 'rc4'
                cookie = base64.b64encode(rc4crypt(zlib.compress(metadata)[2:-4], kwargs.get('password'))).strip()
                body = rc4crypt(body, kwargs.get('password'))
            else:
                cookie = base64.b64encode(zlib.compress(metadata)[2:-4]).strip()
            request_headers['Cookie'] = cookie
            if body:
                request_headers['Content-Length'] = str(len(body))
            else:
                request_method = 'GET'
        else:
            metadata = zlib.compress(metadata)[2:-4]
            body = '%s%s%s' % (struct.pack('!h', len(metadata)), metadata, body)
            if 'rc4' in common.GAE_OPTIONS:
                request_headers['X-GOA-Options'] = 'rc4'
                body = rc4crypt(body, kwargs.get('password'))
            request_headers['Content-Length'] = str(len(body))
        # post data
        need_crlf = 0 if common.GAE_MODE == 'https' else 1
        need_validate = common.GAE_VALIDATE
        cache_key = '%s:%d' % (common.HOSTS_POSTFIX_MAP['.appspot.com'], 443 if common.GAE_MODE == 'https' else 80)
        response = self.create_http_request(request_method, fetchserver, request_headers, body, self.connect_timeout, crlf=need_crlf, validate=need_validate, cache_key=cache_key)
        response.app_status = response.status
        response.app_options = response.getheader('X-GOA-Options', '')
        if response.status != 200:
            return response
        data = response.read(4)
        if len(data) < 4:
            response.status = 502
            response.fp = io.BytesIO(b'connection aborted. too short leadtype data=' + data)
            response.read = response.fp.read
            return response
        response.status, headers_length = struct.unpack('!hh', data)
        data = response.read(headers_length)
        if len(data) < headers_length:
            response.status = 502
            response.fp = io.BytesIO(b'connection aborted. too short headers data=' + data)
            response.read = response.fp.read
            return response
        if 'rc4' not in response.app_options:
            response.msg = httplib.HTTPMessage(io.BytesIO(zlib.decompress(data, -zlib.MAX_WBITS)))
        else:
            response.msg = httplib.HTTPMessage(io.BytesIO(zlib.decompress(rc4crypt(data, kwargs.get('password')), -zlib.MAX_WBITS)))
            if kwargs.get('password') and response.fp:
                response.fp = CipherFileObject(response.fp, RC4Cipher(kwargs['password']))
        return response


class PHPFetchFilter(BaseProxyHandlerFilter):
    """force https filter"""
    def filter(self, handler):
        if handler.command == 'CONNECT':
            return [handler.STRIPSSL]
        else:
            kwargs = {}
            if common.PHP_PASSWORD:
                kwargs['password'] = common.PHP_PASSWORD
            if common.PHP_VALIDATE:
                kwargs['validate'] = 1
            return [handler.URLFETCH, [common.PHP_FETCHSERVER], 1, True, kwargs]


class PHPProxyHandler(AdvancedProxyHandler):
    """PHP Proxy Handler 2"""
    first_run_lock = threading.Lock()
    handler_filters = [FakeHttpsFilter(), ForceHttpsFilter(), PHPFetchFilter()]

    def first_run(self):
        if common.PHP_USEHOSTS:
            self.handler_filters.insert(-1, HostsFilter())
        if not common.PROXY_ENABLE:
            common.resolve_iplist()
            fetchhost = re.sub(r':\d+$', '', urlparse.urlsplit(common.PHP_FETCHSERVER).netloc)
            logging.info('resolve common.PHP_FETCHSERVER domain=%r to iplist', fetchhost)
            if common.PHP_USEHOSTS and fetchhost in common.HOSTS_MAP:
                hostname = common.HOSTS_MAP[fetchhost]
                fetchhost_iplist = sum([socket.gethostbyname_ex(x)[-1] for x in common.IPLIST_MAP.get(hostname) or hostname.split('|')], [])
            else:
                fetchhost_iplist = self.gethostbyname2(fetchhost)
            if len(fetchhost_iplist) == 0:
                logging.error('resolve %r domain return empty! please use ip list to replace domain list!', fetchhost)
                sys.exit(-1)
            self.dns_cache[fetchhost] = list(set(fetchhost_iplist))
            logging.info('resolve common.PHP_FETCHSERVER domain to iplist=%r', fetchhost_iplist)
        return True

    def create_http_request_withserver(self, fetchserver, method, url, headers, body, timeout, **kwargs):
        if body:
            if len(body) < 10 * 1024 * 1024 and 'Content-Encoding' not in headers:
                zbody = zlib.compress(body)[2:-4]
                if len(zbody) < len(body):
                    body = zbody
                    headers['Content-Encoding'] = 'deflate'
            headers['Content-Length'] = str(len(body))
        skip_headers = self.skip_headers
        metadata = 'G-Method:%s\nG-Url:%s\n%s%s' % (method, url, ''.join('G-%s:%s\n' % (k, v) for k, v in kwargs.items() if v), ''.join('%s:%s\n' % (k, v) for k, v in headers.items() if k not in skip_headers))
        metadata = zlib.compress(metadata)[2:-4]
        app_body = b''.join((struct.pack('!h', len(metadata)), metadata, body))
        app_headers = {'Content-Length': len(app_body), 'Content-Type': 'application/octet-stream'}
        fetchserver += '?%s' % random.random()
        crlf = 0
        cache_key = '%s//:%s' % urlparse.urlsplit(fetchserver)[:2]
        response = self.create_http_request('POST', fetchserver, app_headers, app_body, self.connect_timeout, crlf=crlf, cache_key=cache_key)
        if not response:
            raise socket.error(errno.ECONNRESET, 'urlfetch %r return None' % url)
        if response.status >= 400:
            return response
        response.app_status = response.status
        need_decrypt = kwargs.get('password') and response.app_status == 200 and response.getheader('Content-Type', '') == 'image/gif' and response.fp
        transfer_encoding = response.getheader('Transfer-Encoding', '')
        if need_decrypt:
            response.fp = CipherFileObject(response.fp, XORCipher(kwargs['password'][0]))
        self.close_connection = 1
        return response


class ProxyChainMixin:
    """proxy chain mixin"""

    def gethostbyname2(self, hostname):
        try:
            return socket.gethostbyname_ex(hostname)[-1]
        except socket.error:
            return [hostname]

    def create_tcp_connection(self, hostname, port, timeout, **kwargs):
        sock = socket.create_connection((common.PROXY_HOST, int(common.PROXY_PORT)))
        if hostname.endswith('.appspot.com'):
            hostname = 'www.google.com'
        request_data = 'CONNECT %s:%s HTTP/1.1\r\n' % (hostname, port)
        if common.PROXY_USERNAME and common.PROXY_PASSWROD:
            request_data += 'Proxy-authorization: Basic %s\r\n' % base64.b64encode(('%s:%s' % (common.PROXY_USERNAME, common.PROXY_PASSWROD)).encode()).decode().strip()
        request_data += '\r\n'
        sock.sendall(request_data)
        response = httplib.HTTPResponse(sock, buffering=False)
        response.begin()
        if response.status >= 400:
            raise httplib.BadStatusLine('%s %s %s' % (response.version, response.status, response.reason))
        return sock

    def create_ssl_connection(self, hostname, port, timeout, **kwargs):
        sock = self.create_tcp_connection(hostname, port, timeout, **kwargs)
        ssl_sock = ssl.wrap_socket(sock)
        return ssl_sock


class GreenForwardMixin:
    """green forward mixin"""

    @staticmethod
    def io_copy(dest, source, timeout, bufsize):
        try:
            dest.settimeout(timeout)
            source.settimeout(timeout)
            while 1:
                data = source.recv(bufsize)
                if not data:
                    break
                dest.sendall(data)
        except NetWorkIOError as e:
            if e.args[0] not in ('timed out', errno.ECONNABORTED, errno.ECONNRESET, errno.EBADF, errno.EPIPE, errno.ENOTCONN, errno.ETIMEDOUT):
                raise
        finally:
            if dest:
                dest.close()
            if source:
                source.close()

    def FORWARD(self, hostname, port, timeout, kwargs={}):
        """forward socket"""
        bufsize = kwargs.pop('bufsize', 8192)
        do_ssl_handshake = kwargs.pop('do_ssl_handshake', False)
        local = self.connection
        if do_ssl_handshake:
            remote = self.create_ssl_connection(hostname, port, timeout, **kwargs)
        else:
            remote = self.create_tcp_connection(hostname, port, timeout, **kwargs)
        if remote and not isinstance(remote, Exception):
            self.wfile.write(b'HTTP/1.1 200 OK\r\n\r\n')
        logging.info('%s "GREEN FORWARD %s %s:%d %s" - -', self.address_string(), self.command, hostname, port, self.protocol_version)
        thread.start_new_thread(GreenForwardMixin.io_copy, (remote.dup(), local.dup(), timeout, bufsize))
        GreenForwardMixin.io_copy(local, remote, timeout, bufsize)


class ProxyChainGAEProxyHandler(ProxyChainMixin, GAEProxyHandler):
    pass


class ProxyChainPHPProxyHandler(ProxyChainMixin, PHPProxyHandler):
    pass


class GreenForwardGAEProxyHandler(GreenForwardMixin, GAEProxyHandler):
    pass


class GreenForwardPHPProxyHandler(GreenForwardMixin, PHPProxyHandler):
    pass


class ProxyChainGreenForwardGAEProxyHandler(ProxyChainMixin, GreenForwardGAEProxyHandler):
    pass


class ProxyChainGreenForwardPHPProxyHandler(ProxyChainMixin, GreenForwardPHPProxyHandler):
    pass


def get_uptime():
    if os.name == 'nt':
        import ctypes
        try:
            tick = ctypes.windll.kernel32.GetTickCount64()
        except AttributeError:
            tick = ctypes.windll.kernel32.GetTickCount()
        return tick / 1000.0
    elif os.path.isfile('/proc/uptime'):
        with open('/proc/uptime', 'rb') as fp:
            uptime = fp.readline().strip().split()[0].strip()
            return float(uptime)
    elif any(os.path.isfile(os.path.join(x, 'uptime')) for x in os.environ['PATH'].split(os.pathsep)):
        # http://www.opensource.apple.com/source/lldb/lldb-69/test/pexpect-2.4/examples/uptime.py
        pattern = r'up\s+(.*?),\s+([0-9]+) users?,\s+load averages?: ([0-9]+\.[0-9][0-9]),?\s+([0-9]+\.[0-9][0-9]),?\s+([0-9]+\.[0-9][0-9])'
        output = os.popen('uptime').read()
        duration, _, _, _, _ = re.search(pattern, output).groups()
        days, hours, mins = 0, 0, 0
        if 'day' in duration:
            m = re.search(r'([0-9]+)\s+day', duration)
            days = int(m.group(1))
        if ':' in duration:
            m = re.search(r'([0-9]+):([0-9]+)', duration)
            hours = int(m.group(1))
            mins = int(m.group(2))
        if 'min' in duration:
            m = re.search(r'([0-9]+)\s+min', duration)
            mins = int(m.group(1))
        return days * 86400 + hours * 3600 + mins * 60
    else:
        #TODO: support other platforms
        return None


class PacUtil(object):
    """GoAgent Pac Util"""

    @staticmethod
    def update_pacfile(filename):
        listen_ip = ProxyUtil.get_listen_ip() if common.LISTEN_IP in ('', '::', '0.0.0.0') else common.LISTEN_IP
        autoproxy = '%s:%s' % (listen_ip, common.LISTEN_PORT)
        blackhole = '%s:%s' % (listen_ip, common.PAC_PORT)
        default = 'PROXY %s:%s' % (common.PROXY_HOST, common.PROXY_PORT) if common.PROXY_ENABLE else 'DIRECT'
        opener = urllib2.build_opener(urllib2.ProxyHandler({'http': autoproxy, 'https': autoproxy}))
        content = ''
        need_update = True
        with open(filename, 'rb') as fp:
            content = fp.read()
        try:
            placeholder = '// AUTO-GENERATED RULES, DO NOT MODIFY!'
            content = content[:content.index(placeholder)+len(placeholder)]
            content = re.sub(r'''blackhole\s*=\s*['"]PROXY [\.\w:]+['"]''', 'blackhole = \'PROXY %s\'' % blackhole, content)
            content = re.sub(r'''autoproxy\s*=\s*['"]PROXY [\.\w:]+['"]''', 'autoproxy = \'PROXY %s\'' % autoproxy, content)
            content = re.sub(r'''defaultproxy\s*=\s*['"](DIRECT|PROXY [\.\w:]+)['"]''', 'defaultproxy = \'%s\'' % default, content)
            content = re.sub(r'''host\s*==\s*['"][\.\w:]+['"]\s*\|\|\s*isPlainHostName''', 'host == \'%s\' || isPlainHostName' % listen_ip, content)
            if content.startswith('//'):
                line = '// Proxy Auto-Config file generated by autoproxy2pac, %s\r\n' % time.strftime('%Y-%m-%d %H:%M:%S')
                content = line + '\r\n'.join(content.splitlines()[1:])
        except ValueError:
            need_update = False
        try:
            if common.PAC_ADBLOCK:
                logging.info('try download %r to update_pacfile(%r)', common.PAC_ADBLOCK, filename)
                adblock_content = opener.open(common.PAC_ADBLOCK).read()
                logging.info('%r downloaded, try convert it with adblock2pac', common.PAC_ADBLOCK)
                if 'gevent' in sys.modules and time.sleep is getattr(sys.modules['gevent'], 'sleep', None) and hasattr(gevent.get_hub(), 'threadpool'):
                    jsrule = gevent.get_hub().threadpool.apply_e(Exception, PacUtil.adblock2pac, (adblock_content, 'FindProxyForURLByAdblock', blackhole, default))
                else:
                    jsrule = PacUtil.adblock2pac(adblock_content, 'FindProxyForURLByAdblock', blackhole, default)
                content += '\r\n' + jsrule + '\r\n'
                logging.info('%r downloaded and parsed', common.PAC_ADBLOCK)
            else:
                content += '\r\nfunction FindProxyForURLByAdblock(url, host) {return "DIRECT";}\r\n'
        except Exception as e:
            need_update = False
            logging.exception('update_pacfile failed: %r', e)
        try:
            logging.info('try download %r to update_pacfile(%r)', common.PAC_GFWLIST, filename)
            autoproxy_content = base64.b64decode(opener.open(common.PAC_GFWLIST).read())
            logging.info('%r downloaded, try convert it with autoproxy2pac_lite', common.PAC_GFWLIST)
            if 'gevent' in sys.modules and time.sleep is getattr(sys.modules['gevent'], 'sleep', None) and hasattr(gevent.get_hub(), 'threadpool'):
                jsrule = gevent.get_hub().threadpool.apply_e(Exception, PacUtil.autoproxy2pac_lite, (autoproxy_content, 'FindProxyForURLByAutoProxy', autoproxy, default))
            else:
                jsrule = PacUtil.autoproxy2pac_lite(autoproxy_content, 'FindProxyForURLByAutoProxy', autoproxy, default)
            content += '\r\n' + jsrule + '\r\n'
            logging.info('%r downloaded and parsed', common.PAC_GFWLIST)
        except Exception as e:
            need_update = False
            logging.exception('update_pacfile failed: %r', e)
        if need_update:
            with open(filename, 'wb') as fp:
                fp.write(content)
            logging.info('%r successfully updated', filename)

    @staticmethod
    def autoproxy2pac(content, func_name='FindProxyForURLByAutoProxy', proxy='127.0.0.1:8087', default='DIRECT', indent=4):
        """Autoproxy to Pac, based on https://github.com/iamamac/autoproxy2pac"""
        jsLines = []
        for line in content.splitlines()[1:]:
            if line and not line.startswith("!"):
                use_proxy = True
                if line.startswith("@@"):
                    line = line[2:]
                    use_proxy = False
                return_proxy = 'PROXY %s' % proxy if use_proxy else default
                if line.startswith('/') and line.endswith('/'):
                    jsLine = 'if (/%s/i.test(url)) return "%s";' % (line[1:-1], return_proxy)
                elif line.startswith('||'):
                    domain = line[2:].lstrip('.')
                    if len(jsLines) > 0 and ('host.indexOf(".%s") >= 0' % domain in jsLines[-1] or 'host.indexOf("%s") >= 0' % domain in jsLines[-1]):
                        jsLines.pop()
                    jsLine = 'if (dnsDomainIs(host, ".%s") || host == "%s") return "%s";' % (domain, domain, return_proxy)
                elif line.startswith('|'):
                    jsLine = 'if (url.indexOf("%s") == 0) return "%s";' % (line[1:], return_proxy)
                elif '*' in line:
                    jsLine = 'if (shExpMatch(url, "*%s*")) return "%s";' % (line.strip('*'), return_proxy)
                elif '/' not in line:
                    jsLine = 'if (host.indexOf("%s") >= 0) return "%s";' % (line, return_proxy)
                else:
                    jsLine = 'if (url.indexOf("%s") >= 0) return "%s";' % (line, return_proxy)
                jsLine = ' ' * indent + jsLine
                if use_proxy:
                    jsLines.append(jsLine)
                else:
                    jsLines.insert(0, jsLine)
        function = 'function %s(url, host) {\r\n%s\r\n%sreturn "%s";\r\n}' % (func_name, '\n'.join(jsLines), ' '*indent, default)
        return function

    @staticmethod
    def autoproxy2pac_lite(content, func_name='FindProxyForURLByAutoProxy', proxy='127.0.0.1:8087', default='DIRECT', indent=4):
        """Autoproxy to Pac, based on https://github.com/iamamac/autoproxy2pac"""
        direct_domain_set = set([])
        proxy_domain_set = set([])
        for line in content.splitlines()[1:]:
            if line and not line.startswith(('!', '|!', '||!')):
                use_proxy = True
                if line.startswith("@@"):
                    line = line[2:]
                    use_proxy = False
                domain = ''
                if line.startswith('/') and line.endswith('/'):
                    line = line[1:-1]
                    if line.startswith('^https?:\\/\\/[^\\/]+') and re.match(r'^(\w|\\\-|\\\.)+$', line[18:]):
                        domain = line[18:].replace(r'\.', '.')
                    else:
                        logging.warning('unsupport gfwlist regex: %r', line)
                elif line.startswith('||'):
                    domain = line[2:].lstrip('*').rstrip('/')
                elif line.startswith('|'):
                    domain = urlparse.urlsplit(line[1:]).netloc.lstrip('*')
                elif line.startswith(('http://', 'https://')):
                    domain = urlparse.urlsplit(line).netloc.lstrip('*')
                elif re.search(r'^([\w\-\_\.]+)([\*\/]|$)', line):
                    domain = re.split(r'[\*\/]', line)[0]
                else:
                    pass
                if '*' in domain:
                    domain = domain.split('*')[-1]
                if not domain or re.match(r'^\w+$', domain):
                    logging.debug('unsupport gfwlist rule: %r', line)
                    continue
                if use_proxy:
                    proxy_domain_set.add(domain)
                else:
                    direct_domain_set.add(domain)
        proxy_domain_set = set(x.lstrip('.') for x in proxy_domain_set)
        jsLines = ',\n'.join('%s"%s": 1' % (' '*indent, x) for x in proxy_domain_set)
        template = '''\
                    var domainsFor%s = {
                    %s
                    };
                    function %s(url, host) {
                        var lastPos;
                        do {
                            if (domainsFor%s.hasOwnProperty(host)) {
                                return 'PROXY %s';
                            }
                            lastPos = host.indexOf('.') + 1;
                            host = host.slice(lastPos);
                        } while (lastPos >= 1);
                        return '%s';
                    }'''
        template = re.sub(r'(?m)^\s{%d}' % min(len(re.search(r' +', x).group()) for x in template.splitlines()), '', template)
        return template % (func_name, jsLines, func_name, func_name, proxy, default)

    @staticmethod
    def urlfilter2pac(content, func_name='FindProxyForURLByUrlfilter', proxy='127.0.0.1:8086', default='DIRECT', indent=4):
        """urlfilter.ini to Pac, based on https://github.com/iamamac/autoproxy2pac"""
        jsLines = []
        for line in content[content.index('[exclude]'):].splitlines()[1:]:
            if line and not line.startswith(';'):
                use_proxy = True
                if line.startswith("@@"):
                    line = line[2:]
                    use_proxy = False
                return_proxy = 'PROXY %s' % proxy if use_proxy else default
                if '*' in line:
                    jsLine = 'if (shExpMatch(url, "%s")) return "%s";' % (line, return_proxy)
                else:
                    jsLine = 'if (url == "%s") return "%s";' % (line, return_proxy)
                jsLine = ' ' * indent + jsLine
                if use_proxy:
                    jsLines.append(jsLine)
                else:
                    jsLines.insert(0, jsLine)
        function = 'function %s(url, host) {\r\n%s\r\n%sreturn "%s";\r\n}' % (func_name, '\n'.join(jsLines), ' '*indent, default)
        return function

    @staticmethod
    def adblock2pac(content, func_name='FindProxyForURLByAdblock', proxy='127.0.0.1:8086', default='DIRECT', indent=4):
        """adblock list to Pac, based on https://github.com/iamamac/autoproxy2pac"""
        white_conditions = []
        black_conditions = []
        for line in content.splitlines()[1:]:
            if not line or line.startswith('!') or '##' in line or '#@#' in line:
                continue
            use_proxy = True
            use_start = False
            use_end = False
            use_domain = False
            use_postfix = []
            if '$' in line:
                posfixs = line.split('$')[-1].split(',')
                if any('domain' in x for x in posfixs):
                    continue
                if 'image' in posfixs:
                    use_postfix += ['.jpg', '.gif']
                elif 'script' in posfixs:
                    use_postfix += ['.js']
                else:
                    continue
            line = line.split('$')[0]
            if line.startswith("@@"):
                line = line[2:]
                use_proxy = False
            if '||' == line[:2]:
                line = line[2:]
                if '/' not in line:
                    use_domain = True
                else:
                    use_start = True
            elif '|' == line[0]:
                line = line[1:]
                use_start = True
            if line[-1] in ('^', '|'):
                line = line[:-1]
                if not use_postfix:
                    use_end = True
            line = line.replace('^', '*').strip('*')
            if use_start and use_end:
                jsCondition = ['shExpMatch(url, "*%s*")' % line]
            elif use_start:
                if '*' in line:
                    if use_postfix:
                        jsCondition = ['shExpMatch(url, "*%s*%s")' % (line, x) for x in use_postfix]
                    else:
                        jsCondition = ['shExpMatch(url, "*%s*")' % line]
                else:
                    jsCondition = ['url.indexOf("%s") >= 0' % line]
            elif use_domain and use_end:
                if '*' in line:
                    jsCondition = ['shExpMatch(host, "%s*")' % line]
                else:
                    jsCondition = ['host == "%s"' % line]
            elif use_domain:
                if line.split('/')[0].count('.') <= 1:
                    if use_postfix:
                        jsCondition = ['shExpMatch(url, "*.%s*%s")' % (line, x) for x in use_postfix]
                    else:
                        jsCondition = ['shExpMatch(url, "*.%s*")' % line]
                else:
                    if '*' in line:
                        if use_postfix:
                            jsCondition = ['shExpMatch(url, "*%s*%s")' % (line, x) for x in use_postfix]
                        else:
                            jsCondition = ['shExpMatch(url, "*%s*")' % line]
                    else:
                        if use_postfix:
                            jsCondition = ['shExpMatch(url, "*%s*%s")' % (line, x) for x in use_postfix]
                        else:
                            jsCondition = ['url.indexOf("http://%s") == 0' % line]
            else:
                if use_postfix:
                    jsCondition = ['shExpMatch(url, "*%s*%s")' % (line, x) for x in use_postfix]
                else:
                    jsCondition = ['shExpMatch(url, "*%s*")' % line]
            if use_proxy:
                black_conditions += jsCondition
            else:
                white_conditions += jsCondition
        black_lines = ' ||\r\n'.join('%s%s' % (' '*(4+indent), x.replace('**', '*')) for x in black_conditions).strip()
        # white_lines = ' ||\r\n'.join('%s%s' % (' '*(4+indent), x.replace('**', '*')) for x in white_conditions).strip()
        white_lines = 'false'
        template = '''\
                    function %s(url, host) {
                        // untrusted ablock plus list, disable whitelist until chinalist come back.
                        // if (%s) {
                        //    return "%s";
                        // }
                        if (%s) {
                            return "PROXY %s";
                        }
                        return "%s";
                    }'''
        template = re.sub(r'(?m)^\s{%d}' % min(len(re.search(r' +', x).group()) for x in template.splitlines()), '', template)
        return template % (func_name, white_lines, default, black_lines, proxy, default)


class PacFileFilter(BaseProxyHandlerFilter):
    """pac file filter"""

    def filter(self, handler):
        pacfile = os.path.join(os.path.dirname(os.path.abspath(__file__)), common.PAC_FILE)
        urlparts = urlparse.urlsplit(handler.path)
        if handler.command == 'GET' and urlparts.path.lstrip('/') == common.PAC_FILE:
            if urlparts.query == 'flush':
                thread.start_new_thread(PacUtil.update_pacfile, (pacfile,))
            if time.time() - os.path.getmtime(pacfile) > common.PAC_EXPIRED:
                # check system uptime > 30 minutes
                uptime = get_uptime()
                if uptime and uptime > 1800:
                    thread.start_new_thread(lambda: os.utime(pacfile, (time.time(), time.time())) or PacUtil.update_pacfile(pacfile), tuple())


class StaticFileFilter(BaseProxyHandlerFilter):
    """static file filter"""
    def filter(self, handler):
        path = urlparse.urlsplit(handler.path).path
        if handler.command == 'GET' and path.startswith('/'):
            filename = '.' + path
            if os.path.isfile(filename):
                with open(filename, 'rb') as fp:
                    content = fp.read()
                    headers = {'Content-Type': 'application/octet-stream', 'Connection': 'close'}
                    return [handler.MOCK, 200, headers, content]


class BlackholeFilter(BaseProxyHandlerFilter):
    """blackhole filter"""
    one_pixel_gif = 'GIF89a\x01\x00\x01\x00\x80\xff\x00\xc0\xc0\xc0\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;'

    def filter(self, handler):
        urlparts = urlparse.urlsplit(handler.path)
        if handler.command == 'CONNECT':
            return [handler.STRIPSSL]
        elif handler.path.startswith(('http', 'https')):
            headers = {'Cache-Control': 'max-age=86400',
                       'Expires': 'Oct, 01 Aug 2100 00:00:00 GMT',
                       'Connection': 'close'}
            content = ''
            if urlparts.path.endswith(('.jpg', '.gif', '.jpeg', '.bmp')):
                headers['Content-Type'] = 'image/gif'
                content = self.one_pixel_gif
            return [handler.MOCK, 200, headers, content]
        else:
            return [handler.MOCK, 404, {'Connection': 'close'}, '']


class PACProxyHandler(SimpleProxyHandler):
    """pac proxy handler"""
    handler_filters = [PacFileFilter(), StaticFileFilter(), BlackholeFilter()]


def get_process_list():
    import os
    import glob
    import ctypes
    import collections
    Process = collections.namedtuple('Process', 'pid name exe')
    process_list = []
    if os.name == 'nt':
        PROCESS_QUERY_INFORMATION = 0x0400
        PROCESS_VM_READ = 0x0010
        lpidProcess= (ctypes.c_ulong * 1024)()
        cb = ctypes.sizeof(lpidProcess)
        cbNeeded = ctypes.c_ulong()
        ctypes.windll.psapi.EnumProcesses(ctypes.byref(lpidProcess), cb, ctypes.byref(cbNeeded))
        nReturned = cbNeeded.value/ctypes.sizeof(ctypes.c_ulong())
        pidProcess = [i for i in lpidProcess][:nReturned]
        has_queryimage = hasattr(ctypes.windll.kernel32, 'QueryFullProcessImageNameA')
        for pid in pidProcess:
            hProcess = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid)
            if hProcess:
                modname = ctypes.create_string_buffer(2048)
                count = ctypes.c_ulong(ctypes.sizeof(modname))
                if has_queryimage:
                    ctypes.windll.kernel32.QueryFullProcessImageNameA(hProcess, 0, ctypes.byref(modname), ctypes.byref(count))
                else:
                    ctypes.windll.psapi.GetModuleFileNameExA(hProcess, 0, ctypes.byref(modname), ctypes.byref(count))
                exe = modname.value
                name = os.path.basename(exe)
                process_list.append(Process(pid=pid, name=name, exe=exe))
                ctypes.windll.kernel32.CloseHandle(hProcess)
    elif sys.platform.startswith('linux'):
        for filename in glob.glob('/proc/[0-9]*/cmdline'):
            pid = int(filename.split('/')[2])
            exe_link = '/proc/%d/exe' % pid
            if os.path.exists(exe_link):
                exe = os.readlink(exe_link)
                name = os.path.basename(exe)
                process_list.append(Process(pid=pid, name=name, exe=exe))
    else:
        try:
            import psutil
            process_list = psutil.get_process_list()
        except Exception as e:
            logging.exception('psutil.get_process_list() failed: %r', e)
    return process_list

def pre_start():
    if sys.platform == 'cygwin':
        logging.info('cygwin is not officially supported, please continue at your own risk :)')
        #sys.exit(-1)
    elif os.name == 'posix':
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_NOFILE, (8192, -1))
        except ValueError:
            pass
    elif os.name == 'nt':
        import ctypes
        ctypes.windll.kernel32.SetConsoleTitleW(u'GoAgent v%s' % __version__)
        if not common.LISTEN_VISIBLE:
            ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
        else:
            ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 1)
        if common.LOVE_ENABLE and random.randint(1, 100) <= 5:
            title = ctypes.create_unicode_buffer(1024)
            ctypes.windll.kernel32.GetConsoleTitleW(ctypes.byref(title), len(title)-1)
            ctypes.windll.kernel32.SetConsoleTitleW('%s %s' % (title.value, random.choice(common.LOVE_TIP)))
        blacklist = {'360safe': False,
                     'QQProtect': False, }
        softwares = [k for k, v in blacklist.items() if v]
        if softwares:
            tasklist = '\n'.join(x.name for x in get_process_list()).lower()
            softwares = [x for x in softwares if x.lower() in tasklist]
            if softwares:
                title = u'GoAgent 建议'
                error = u'某些安全软件(如 %s)可能和本软件存在冲突，造成 CPU 占用过高。\n如有此现象建议暂时退出此安全软件来继续运行GoAgent' % ','.join(softwares)
                ctypes.windll.user32.MessageBoxW(None, error, title, 0)
                #sys.exit(0)
    if os.path.isfile('/proc/cpuinfo'):
        with open('/proc/cpuinfo', 'rb') as fp:
            m = re.search(r'(?im)(BogoMIPS|cpu MHz)\s+:\s+([\d\.]+)', fp.read())
            if m and float(m.group(2)) < 1000:
                logging.warning("*NOTE*, Please set [gae]window=2")
    if GAEProxyHandler.max_window != common.GAE_WINDOW:
        GAEProxyHandler.max_window = common.GAE_WINDOW
    if common.GAE_APPIDS[0] == 'goagent':
        logging.critical('please edit %s to add your appid to [gae] !', common.CONFIG_FILENAME)
        sys.exit(-1)
    if common.GAE_MODE == 'http' and common.GAE_PASSWORD == '':
        logging.critical('to enable http mode, you should set %r [gae]password = <your_pass> and [gae]options = rc4', common.CONFIG_FILENAME)
        sys.exit(-1)
    if common.GAE_REGIONS and not pygeoip:
        logging.critical('to enable [gae]regions mode, you should install pygeoip')
        sys.exit(-1)
    if common.PAC_ENABLE:
        pac_ip = ProxyUtil.get_listen_ip() if common.PAC_IP in ('', '::', '0.0.0.0') else common.PAC_IP
        url = 'http://%s:%d/%s' % (pac_ip, common.PAC_PORT, common.PAC_FILE)
        spawn_later(600, urllib2.build_opener(urllib2.ProxyHandler({})).open, url)
    if not dnslib:
        logging.error('dnslib not found, please put dnslib-0.8.3.egg to %r!', os.path.dirname(os.path.abspath(__file__)))
        sys.exit(-1)
    if not common.DNS_ENABLE:
        for dnsservers_ref in (common.HTTP_DNS, common.DNS_SERVERS):
            any(common.DNS_SERVERS.insert(0, x) for x in [y for y in get_dnsserver_list() if y not in common.DNS_SERVERS])
        AdvancedProxyHandler.dns_servers = common.HTTP_DNS
        AdvancedProxyHandler.dns_blacklist = common.DNS_BLACKLIST
    if not OpenSSL:
        logging.warning('python-openssl not found, please install it!')
    RangeFetch.threads = common.AUTORANGE_THREADS
    RangeFetch.maxsize = common.AUTORANGE_MAXSIZE
    RangeFetch.bufsize = common.AUTORANGE_BUFSIZE
    RangeFetch.waitsize = common.AUTORANGE_WAITSIZE


def main():
    global __file__
    __file__ = os.path.abspath(__file__)
    if os.path.islink(__file__):
        __file__ = getattr(os, 'readlink', lambda x: x)(__file__)
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    logging.basicConfig(level=logging.DEBUG if common.LISTEN_DEBUGINFO else logging.INFO, format='%(levelname)s - %(asctime)s %(message)s', datefmt='[%b %d %H:%M:%S]')
    pre_start()
    CertUtil.check_ca()
    sys.stdout.write(common.info())

    uvent_enabled = 'uvent.loop' in sys.modules and isinstance(gevent.get_hub().loop, __import__('uvent').loop.UVLoop)

    if common.PHP_ENABLE:
        host, port = common.PHP_LISTEN.split(':')
        HandlerClass = ((PHPProxyHandler, GreenForwardPHPProxyHandler) if not common.PROXY_ENABLE else (ProxyChainPHPProxyHandler, ProxyChainGreenForwardPHPProxyHandler))[uvent_enabled]
        server = LocalProxyServer((host, int(port)), HandlerClass)
        thread.start_new_thread(server.serve_forever, tuple())

    if common.PAC_ENABLE:
        server = LocalProxyServer((common.PAC_IP, common.PAC_PORT), PACProxyHandler)
        thread.start_new_thread(server.serve_forever, tuple())

    if common.DNS_ENABLE:
        try:
            sys.path += ['.']
            from dnsproxy import DNSServer
            host, port = common.DNS_LISTEN.split(':')
            server = DNSServer((host, int(port)), dns_servers=common.DNS_SERVERS, dns_blacklist=common.DNS_BLACKLIST)
            thread.start_new_thread(server.serve_forever, tuple())
        except ImportError:
            logging.exception('GoAgent DNSServer requires dnslib and gevent 1.0')
            sys.exit(-1)

    HandlerClass = ((GAEProxyHandler, GreenForwardGAEProxyHandler) if not common.PROXY_ENABLE else (ProxyChainGAEProxyHandler, ProxyChainGreenForwardGAEProxyHandler))[uvent_enabled]
    server = LocalProxyServer((common.LISTEN_IP, common.LISTEN_PORT), HandlerClass)
    try:
        server.serve_forever()
    except SystemError as e:
        if '(libev) select: ' in repr(e):
            logging.error('PLEASE START GOAGENT BY uvent.bat')
            sys.exit(-1)

if __name__ == '__main__':
    main()

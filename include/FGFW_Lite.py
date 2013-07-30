#!/usr/bin/env python
#-*- coding: UTF-8 -*-
#-------------------------------------------------------------------------------
# Name:        FGFW_Lite.py
# Purpose:     Fuck the Great Firewall of China
#
# Contributer: Jiang Chao <sgzz.cj@gmail.com>
#
# License:     The GPLv2 License
#-------------------------------------------------------------------------------
from __future__ import print_function
from __future__ import unicode_literals

__version__ = '0.3.2.1'

import sys
import os
import io
from subprocess import Popen
import shlex
import time
import re
from threading import Thread, RLock, Timer
import atexit
import base64
import socket
import struct
import random
import tornado.ioloop
import tornado.iostream
import tornado.web
from tornado.httputil import HTTPHeaders
try:
    import configparser
except ImportError:
    import ConfigParser as configparser
finally:
    configparser.RawConfigParser.OPTCRE = re.compile(r'(?P<option>[^=\s][^=]*)\s*(?P<vi>[=])\s*(?P<value>.*)$')
try:
    import ipaddress
    ip_address = ipaddress.ip_address
    ip_network = ipaddress.ip_network
except ImportError:
    import ipaddr
    ip_address = ipaddr.IPAddress
    ip_network = ipaddr.IPNetwork

WORKINGDIR = '/'.join(os.path.dirname(os.path.abspath(__file__).replace('\\', '/')).split('/')[:-1])
if ' ' in WORKINGDIR:
    print('no spacebar allowed in path')
    sys.exit()
os.chdir(WORKINGDIR)

if sys.platform.startswith('win'):
    PYTHON2 = 'c:/python27/python.exe'
    PYTHON3 = 'd:/FGFW_Lite/include/Python33/python33.exe'
else:
    PYTHON2 = '/usr/bin/env python2'
    PYTHON3 = '/usr/bin/env python3'

if not os.path.isfile('./userconf.ini'):
    import shutil
    shutil.copy2('./userconf.sample.ini', './userconf.ini')

import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('FGFW-Lite')

REDIRECTOR = '''\
|http://www.google.com/reader forcehttps
|http://www.google.com/search forcehttps
|http://www.google.com/url forcehttps
|http://news.google.com forcehttps
|http://appengine.google.com forcehttps
|http://www.google.com.hk/url forcehttps
|http://www.google.com.hk/search forcehttps
/^http://www\.google\.com/?$/ forcehttps
|http://*.googlecode.com forcehttps
|http://*.wikipedia.org forcehttps
'''
if not os.path.isfile('./include/redirector.txt'):
    with open('./include/redirector.txt', 'w') as f:
        f.write(REDIRECTOR)

UPSTREAM_POOL = {}


class ProxyHandler(tornado.web.RequestHandler):
    SUPPORTED_METHODS = ['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'TRACE', 'CONNECT']

    def getparent(self, uri, host):
        self.ppname, pp = fgfwproxy.parentproxy(uri, host)
        self.pptype, self.pphost, self.ppport, self.ppusername,\
            self.pppassword = pp

    def prepare(self):
        uri = self.request.uri
        if '//' not in uri:
            uri = 'https://' + uri
        host = self.request.host.split(':')[0]
        # redirector
        new_url = REDIRECTOR.get(uri, host)
        if new_url:
            if new_url.startswith('401'):
                self.send_error(status_code=401)
            else:
                self.redirect(new_url)
            return

        urisplit = uri.split('/')
        self.requestpath = '/'.join(urisplit[3:])

        if ':' in urisplit[2]:
            self.requestport = int(urisplit[2].split(':')[1])
        else:
            self.requestport = 443 if uri.startswith('https://') else 80
        self.getparent(uri, host)

        if self.pptype == 'socks5':
            self.upstream_name = '%s-%s-%s' % (self.ppname, self.request.host, str(self.requestport))
        else:
            self.upstream_name = self.ppname if self.pphost else self.request.host
        s = '%s %s' % (self.request.method, self.request.uri.split('?')[0])
        if self.pphost:
            s += ' via %s://%s:%s' % (self.pptype, self.pphost, self.ppport)
        else:
            s += ' via direct'
        logger.info(s)

    @tornado.web.asynchronous
    def get(self):
        if self.pphost is None or self.pptype == 'socks5':
            return self.connect()

        client = self.request.connection.stream

        def _get_upstream():
            def _create_upstream():
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
                self.upstream = tornado.iostream.IOStream(s)
                if self.pptype == 'http':
                    self.upstream.connect((self.pphost, int(self.ppport)))
                elif self.pptype == 'https':
                    self.upstream = tornado.iostream.SSLIOStream(s)
                    self.upstream.connect((self.pphost, int(self.ppport)))
                else:
                    client.write(b'HTTP/1.1 501 %s proxy not supported.\r\n\r\n' % self.pptype)
                    client.close()

            lst = UPSTREAM_POOL.get(self.upstream_name)
            self.upstream = None
            if isinstance(lst, list):
                for item in lst:
                    lst.remove(item)
                    if not item.closed():
                        self.upstream = item
                        break
            if self.upstream is None:
                _create_upstream()

        def read_from_upstream(data):
            if not client.closed():
                client.write(data)

        def _sent_request():
            if self.pptype == 'http' or self.pptype == 'https':
                s = '%s %s %s\r\n' % (self.request.method, self.request.uri, self.request.version)
                if self.ppusername and 'Proxy-Authorization' not in self.request.headers:
                    a = '%s:%s' % (self.ppusername, self.pppassword)
                    self.request.headers['Proxy-Authorization'] = 'Basic %s\r\n' % base64.b64encode(a.encode())
            else:
                s = '%s /%s %s\r\n' % (self.request.method, self.requestpath, self.request.version)
            for key, value in self.request.headers.items():
                s += '%s: %s\r\n' % (key, value)
            s += '\r\n'
            s = s.encode()
            if self.request.body:
                s += self.request.body + b'\r\n\r\n'
            _on_connect(s)

        def _on_connect(data=None):
            self.upstream.read_until_regex(b"\r?\n\r?\n", _on_headers)
            self.upstream.write(data)

        def _on_headers(data=None):
            client.write(data.replace(b'Connection: keep-alive', b'Connection: close'))
            data = data.decode()
            first_line, _, header_data = data.partition("\n")
            status_code = int(first_line.split()[1])
            headers = HTTPHeaders.parse(header_data)
            self.close_flag = True if headers.get('Connection') == 'close' else False

            if "Content-Length" in headers:
                if "," in headers["Content-Length"]:
                    # Proxies sometimes cause Content-Length headers to get
                    # duplicated.  If all the values are identical then we can
                    # use them but if they differ it's an error.
                    pieces = re.split(r',\s*', headers["Content-Length"])
                    if any(i != pieces[0] for i in pieces):
                        raise ValueError("Multiple unequal Content-Lengths: %r" %
                                         headers["Content-Length"])
                    headers["Content-Length"] = pieces[0]
                content_length = int(headers["Content-Length"])
            else:
                content_length = None

            if self.request.method == "HEAD" or status_code == 304:
                _finish()
            elif headers.get("Transfer-Encoding") == "chunked":
                self.upstream.read_until(b"\r\n", _on_chunk_lenth)
            elif content_length is not None:
                self.upstream.read_bytes(content_length, _finish, streaming_callback=read_from_upstream)
            elif headers.get("Connection") == "close":
                self.upstream.read_until_close(_finish)
            else:
                _finish()

        def _on_chunk_lenth(data):
            read_from_upstream(data)
            length = int(data.strip(), 16)
            self.upstream.read_bytes(length + 2,  # chunk ends with \r\n
                                     _on_chunk_data)

        def _on_chunk_data(data):
            read_from_upstream(data)
            if len(data) != 2:
                self.upstream.read_until(b"\r\n", _on_chunk_lenth)
            else:
                _finish()

        def _finish(data=None):
            if self.upstream_name not in UPSTREAM_POOL:
                UPSTREAM_POOL[self.upstream_name] = []
            lst = UPSTREAM_POOL.get(self.upstream_name)
            for item in lst:
                if item.closed():
                    lst.remove(item)
            if not self.upstream.closed():
                if self.close_flag:
                    self.upstream.close()
                else:
                    lst.append(self.upstream)
            if data is not None:
                read_from_upstream(data)
            if not client.closed():
                client.close()

        _get_upstream()
        try:
            _sent_request()
        except Exception as e:
            logger.info(str(e))
            if not self.upstream.closed():
                self.upstream.close()
            if not client.closed():
                client.close()

    @tornado.web.asynchronous
    def post(self):
        return self.get()

    @tornado.web.asynchronous
    def delete(self):
        return self.get()

    @tornado.web.asynchronous
    def trace(self):
        return self.get()

    @tornado.web.asynchronous
    def put(self):
        return self.get()

    @tornado.web.asynchronous
    def head(self):
        return self.get()

    @tornado.web.asynchronous
    def connect(self):
        client = self.request.connection.stream

        def read_from_client(data):
            upstream.write(data)

        def read_from_upstream(data):
            client.write(data)

        def client_close(data=None):
            if upstream.closed():
                return
            if data:
                upstream.write(data)
            upstream.close()

        def upstream_close(data=None):
            if client.closed():
                return
            if data:
                client.write(data)
            client.close()

        def start_tunnel(data=None):
            client.read_until_close(client_close, read_from_client)
            upstream.read_until_close(upstream_close, read_from_upstream)
            if data:
                upstream.write(data)

        def start_ssltunnel(data=None):
            client.read_until_close(client_close, read_from_client)
            upstream.read_until_close(upstream_close, read_from_upstream)
            client.write(b'HTTP/1.1 200 Connection established\r\n\r\n')

        def http_conntgt(data=None):
            if self.pptype == 'http' or self.pptype == 'https':
                s = '%s %s %s\r\n' % (self.request.method, self.request.uri, self.request.version)
                if 'Proxy-Authorization' not in self.request.headers and self.ppusername:
                    a = '%s:%s' % (self.ppusername, self.pppassword)
                    self.request.headers['Proxy-Authorization'] = 'Basic %s\r\n' % base64.b64encode(a.encode())
            else:
                s = '%s /%s %s\r\n' % (self.request.method, self.requestpath, self.request.version)
            if self.request.method != 'CONNECT':
                self.request.headers['Connection'] = 'close'
            for key, value in self.request.headers.items():
                s += '%s: %s\r\n' % (key, value)
            s += '\r\n'
            s = s.encode()
            if self.request.body:
                s += self.request.body + b'\r\n\r\n'
            start_tunnel(s)

        def socks5_handshake(data=None):
            def get_server_auth_method(data=None):
                upstream.read_bytes(2, socks5_auth)

            def socks5_auth(data=None):
                if data == b'\x05\00':  # no auth needed
                    conn_upstream()
                elif data == b'\x05\02':  # basic auth
                    upstream.write(b"\x01" +
                                   chr(len(self.ppusername)).encode() + self.ppusername.encode() +
                                   chr(len(self.pppassword)).encode() + self.pppassword.encode())
                    upstream.read_bytes(2, socks5_auth_finish)
                else:  # bad day, something is wrong
                    fail()

            def socks5_auth_finish(data=None):
                if data == b'\x01\x00':  # auth passed
                    conn_upstream()
                else:
                    fail()

            def conn_upstream(data=None):
                # try:
                #     ip = socket.inet_aton(self.request.host)  # guess ipv4
                # except Exception:
                #     try:  # guess ipv6
                #         ip = socket.inet_pton(socket.AF_INET6, self.request.host)
                #     except Exception:  # got to be domain name
                #         req = b"\x05\x01\x00\x03" + chr(len(self.request.host)).encode() + self.request.host.encode()
                #     else:
                #         req = b"\x05\x01\x00\x04" + ip
                # else:
                #     req = b"\x05\x01\x00\x01" + ip
                req = b"\x05\x01\x00\x03" + chr(len(self.request.host)).encode() + self.request.host.encode()
                req += struct.pack(">H", self.requestport)
                upstream.write(req, post_conn_upstream)

            def post_conn_upstream(data=None):
                upstream.read_bytes(4, read_upstream_data)

            def read_upstream_data(data=None):
                if data.startswith(b'\x05\x00\x00\x01'):
                    upstream.read_bytes(6, conn)
                elif data.startswith(b'\x05\x00\x00\x03'):
                    upstream.read_bytes(3, readhost)
                else:
                    fail()

            def readhost(data=None):
                upstream.read_bytes(data[0], conn)

            def conn(data=None):
                if self.request.method == 'CONNECT':
                    start_ssltunnel()
                else:
                    http_conntgt()

            def fail():
                client.write(b'HTTP/1.1 500 socks5 proxy Connection Failed.\r\n\r\n')
                upstream.close()
                client.close()

            if self.ppusername:
                authmethod = b"\x05\x02\x00\x02"
            else:
                authmethod = b"\x05\x01\x00"
            upstream.write(authmethod, get_server_auth_method)

        if self.pphost is None:
            if self.request.method == 'CONNECT':
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
                upstream = tornado.iostream.IOStream(s)
                upstream.connect((self.request.host.split(':')[0], int(self.requestport)), start_ssltunnel)
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
                upstream = tornado.iostream.IOStream(s)
                upstream.connect((self.request.host.split(':')[0], int(self.requestport)), http_conntgt)
        elif self.pptype == 'http':
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
            upstream = tornado.iostream.IOStream(s)
            upstream.connect((self.pphost, int(self.ppport)), http_conntgt)
        elif self.pptype == 'https':
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
            upstream = tornado.iostream.SSLIOStream(s)
            upstream.connect((self.pphost, int(self.ppport)), http_conntgt)
        elif self.pptype == 'socks5':
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
            upstream = tornado.iostream.IOStream(s)
            upstream.connect((self.pphost, int(self.ppport)), socks5_handshake)
        else:
            client.write(b'HTTP/1.1 501 %s proxy not supported.\r\n\r\n' % self.pptype)
            client.close()


class PProxyHandler(ProxyHandler):
    def getparent(self, uri, host):
        self.ppname, pp = fgfwproxy.parentproxy(uri, host, forceproxy=True)
        self.pptype, self.pphost, self.ppport, self.ppusername,\
            self.pppassword = pp


class autoproxy_rule(object):
    """docstring for autoproxy_rule
        (type,pattern)
        type:
            int
            DOMAIN = 0
            URI = 1
            KEYWORD = 2
            OVERRIDE_DOMAIN = 3
            OVERRIDE_URI =4
            OVERRIDE_KEYWORD = 5

        pattern:
            list
            [string, string, .....]
    """
    DOMAIN = 0
    URI = 1
    KEYWORD = 2
    REGEX = 3
    OVERRIDE_DOMAIN = 4
    OVERRIDE_URI = 5
    OVERRIDE_KEYWORD = 6
    OVERRIDE_REGEX = 7

    def __init__(self, arg):
        super(autoproxy_rule, self).__init__()
        if not isinstance(arg, str):
            if isinstance(arg, bytes):
                arg = arg.decode()
            else:
                raise TypeError("invalid type: must be a string(or bytes)")
        self.rule = arg.strip()
        if self.rule == '' or len(self.rule) < 3 or\
                self.rule.startswith('!') or\
                self.rule.startswith('['):
            raise ValueError("invalid autoproxy_rule")
        self.__type, self.__ptrnlst = self.__autopxy_rule_parse(self.rule)
        if self.__type >= self.OVERRIDE_DOMAIN:
            self.override = True
        else:
            self.override = False

    def __autopxy_rule_parse(self, rule):
        def parse(rule):
            if rule.startswith('||'):
                result = rule.replace('||', '').replace('/', '')
                return (self.DOMAIN, result.split('*'))

            elif rule.startswith('|'):
                result = rule.replace('|', '')
                return (self.URI, result.split('*'))

            elif rule.startswith('/') and rule.endswith('/'):
                return (self.REGEX, [re.compile(rule[1:-1]), ])

            else:
                return (self.KEYWORD, rule.split('*'))

        if rule.startswith('@@||'):
            return (self.OVERRIDE_DOMAIN, parse(rule.replace('@@', ''))[1])
        elif rule.startswith('@@|'):
            return (self.OVERRIDE_URI, parse(rule.replace('@@', ''))[1])
        elif rule.startswith('@@/') and rule.endswith('/'):
            return (self.OVERRIDE_REGEX, parse(rule.replace('@@', ''))[1])
        elif rule.startswith('@@'):
            return (self.OVERRIDE_KEYWORD, parse(rule.replace('@@', ''))[1])
        else:
            return parse(rule)

    def match(self, url, domain=None):
        # url must be something like https://www.google.com
        ptrnlst = self.__ptrnlst[:]

        def _match_domain():
            if domain.endswith(ptrnlst.pop()):
                if ptrnlst:
                    return _match_keyword(uri=domain)
                return True
            return False

        def _match_uri():
            s = ptrnlst.pop(0)
            if url.startswith(s):
                if ptrnlst:
                    return _match_keyword(index=len(s))
                return True
            return False

        def _match_keyword(uri=url, index=0):
            i = index
            while ptrnlst:
                s = ptrnlst.pop(0)
                if s in url:
                    i = uri.find(s, i) + len(s)
                else:
                    return False
            return True

        def _match_regex(uri=url, index=0):
            if ptrnlst[0].match(uri):
                return True
            return False

        if domain is None:
            domain = url.split('/')[2].split(':')[0]

        if self.__type is self.DOMAIN:
            return _match_domain()
        elif self.__type is self.URI:
            if url.startswith('https://'):
                if self.rule.startswith('|https://'):
                    return _match_uri()
                return False
            return _match_uri()
        elif self.__type is self.KEYWORD:
            if url.startswith('https://'):
                return False
            return _match_keyword()
        elif self.__type is self.REGEX:
            return _match_regex()

        elif self.__type is self.OVERRIDE_DOMAIN:
            return _match_domain()
        elif self.__type is self.OVERRIDE_URI:
            return _match_uri()
        elif self.__type is self.OVERRIDE_KEYWORD:
            return _match_keyword()
        elif self.__type is self.OVERRIDE_REGEX:
            return _match_regex()


class redirector(object):
    """docstring for redirector"""
    def __init__(self, arg=None):
        super(redirector, self).__init__()
        self.arg = arg
        self.config()

    def get(self, uri, host=None):
        for rule, result in self.list:
            if rule.match(uri, host):
                logger.info('Match redirect rule %s, %s' % (rule.rule, result))
                if result == 'forcehttps':
                    return uri.replace('http://', 'https://', 1)
                return result
        return False

    def config(self):
        self.list = []

        with open('./include/redirector.txt') as f:
            for line in f:
                line = line.strip()
                if len(line.split()) == 2:
                    try:
                        o = autoproxy_rule(line.split()[0])
                        if o.override:
                            raise Exception
                    except Exception:
                        pass
                    else:
                        self.list.append((o, line.split()[1]))

REDIRECTOR = redirector()


def run_proxy(port, start_ioloop=True):
    """
    Run proxy on the specified port. If start_ioloop is True (default),
    the tornado IOLoop will be started immediately.
    """
    print ("Starting HTTP proxy on port %s and %s" % (port, str(int(port)+1)))
    app = tornado.web.Application([(r'.*', ProxyHandler), ])
    app.listen(port)
    app2 = tornado.web.Application([(r'.*', PProxyHandler), ])
    app2.listen(int(port)+1)
    ioloop = tornado.ioloop.IOLoop.instance()
    if start_ioloop:
        ioloop.start()


def updateNbackup():
    while True:
        time.sleep(90)
        chkproxy()
        ifupdate()
        if conf.getconfbool('AutoBackupConf', 'enable', False):
            ifbackup()


def chkproxy():
    dit = fgfwproxy.parentdict.copy()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    for k, v in dit.items():
        if v[1] is None:
            continue
        try:
            s.connect((v[1], v[2]))
        except Exception:
            del dit[k]
        else:
            s.close()
    fgfwproxy.parentdictalive = dit


def ifupdate():
    if conf.getconfbool('FGFW_Lite', 'autoupdate'):
        lastupdate = conf.presets.dgetfloat('Update', 'LastUpdate', 0)
        if time.time() - lastupdate > conf.UPDATE_INTV * 60 * 60:
            fgfw2Liteupdate()


def ifbackup():
    lastbackup = conf.userconf.dgetfloat('AutoBackupConf', 'LastBackup', 0)
    if time.time() - lastbackup > conf.BACKUP_INTV * 60 * 60:
        Thread(target=backup).start()


def fgfw2Liteupdate(auto=True):
    if auto:
        open("./include/dummy", 'w').close()
    conf.presets.set('Update', 'LastUpdate', str(time.time()))
    for item in FGFWProxyAbs.ITEMS:
        if item.enableupdate:
            item.update()
    Timer(4, fgfw2Literestart).start()


def fgfw2Literestart():
    conf.confsave()
    REDIRECTOR.config()
    for item in FGFWProxyAbs.ITEMS:
        item.config()
        item.restart()


def backup():
    import tarfile
    with conf.iolock:
        conf.userconf.set('AutoBackupConf', 'LastBackup', str(time.time()))
        conf.confsave()
    try:
        backuplist = conf.userconf.items('AutoBackup', raw=True)
        backupPath = conf.userconf.get('AutoBackupConf', 'BackupPath', raw=True)
    except:
        logger.error("read userconf.ini failed!")
    else:
        if not os.path.isdir(backupPath):
            try:
                os.makedirs(backupPath)
            except:
                logger.error('create dir ' + backupPath + ' failed!')
        if len(backuplist) > 0:
            logger.info("start packing")
            for i in range(len(backuplist)):
                if os.path.exists(backuplist[i][1]):
                    filepath = '%s/%s-%s.tar.bz2' % (backupPath, backuplist[i][0], time.strftime('%Y%m%d%H%M%S'))
                    logger.info('packing %s to %s' % (backuplist[i][1], filepath))
                    pack = tarfile.open(filepath, "w:bz2")
                    try:
                        pack.add(backuplist[i][1])
                    except Exception:
                        pack.close()
                        os.remove(filepath)
                        logger.info('Packing %s failed.' % filepath)
                    else:
                        pack.close()
                        logger.info('Done.')
        #remove old backup file
        rotation = conf.userconf.dgetint('AutoBackupConf', 'rotation', 10)
        filelist = os.listdir(str(backupPath))
        filelist.sort()
        surname = ''
        group = []
        for filename in filelist:
            if re.search(r'\d{14}\.tar\.bz2$', filename):
                if filename.split('-')[0] == surname:
                    group.append(filename)
                    if len(group) > rotation:
                        os.remove(backupPath + '/' + group.pop(0))
                else:
                    group = []
                    group.append(filename)
                    surname = filename.split('-')[0]


class FGFWProxyAbs(object):
    """docstring for FGFWProxyAbs"""
    ITEMS = []

    def __init__(self):
        FGFWProxyAbs.ITEMS.append(self)
        self.subpobj = None
        self.config()
        self.daemon = Thread(target=self.start)
        self.daemon.daemon = True
        self.daemon.start()

    def config(self):
        self._config()

    def _config(self):
        self.cmd = ''
        self.cwd = ''
        self.filelist = []
        self.enable = True
        self.enableupdate = True

    def start(self):
        while True:
            if self.enable:
                if self.cwd:
                    os.chdir(self.cwd.replace('d:/FGFW_Lite', WORKINGDIR))
                self.subpobj = Popen(shlex.split(self.cmd.replace('d:/FGFW_Lite', WORKINGDIR)))
                os.chdir(WORKINGDIR)
                self.subpobj.wait()
            time.sleep(3)

    def restart(self):
        try:
            self.subpobj.terminate()
        except Exception:
            pass

    def __update(self):
        self._listfileupdate()

    def update(self):
        if self.enable and self.enableupdate:
            self.__update()

    def _listfileupdate(self):
        if len(self.filelist) > 0:
            for i in range(len(self.filelist)):
                url, path = self.filelist[i]
                etag = conf.presets.dget('Update', path.replace('./', '').replace('/', '-'), '')
                self.updateViaHTTP(url, etag, path)

    def updateViaHTTP(self, url, etag, path):
        import requests

        proxy = {'http': 'http://127.0.0.1:8118',
                 }
        header = {'If-None-Match': etag,
                  }
        cafile = './goagent/cacert.pem'
        try:
            r = requests.get(url, proxies=proxy, headers=header, timeout=5, verify=cafile)
        except Exception as e:
            logger.info(path + ' Not modified ' + str(e))
        else:
            if r.status_code == 200:
                with open(path, 'wb') as localfile:
                    localfile.write(r.content)
                with conf.iolock:
                    conf.presets.set('Update', path.replace('./', '').replace('/', '-'), str(r.headers.get('etag')))
                with consoleLock:
                    logger.info(path + ' Updated.')
            else:
                logger.info(path + ' Not modified ' + str(r.status_code))


class goagentabs(FGFWProxyAbs):
    """docstring for ClassName"""
    def __init__(self):
        FGFWProxyAbs.__init__(self)

    def _config(self):
        self.filelist = [['https://github.com/goagent/goagent/raw/3.0/local/proxy.py', './goagent/proxy.py'],
                         ['https://github.com/goagent/goagent/raw/3.0/local/proxy.ini', './goagent/proxy.ini'],
                         ['https://github.com/goagent/goagent/raw/3.0/local/cacert.pem', './goagent/cacert.pem'],
                         ['https://wwqgtxx-goagent.googlecode.com/git/Appid.txt', './include/Appid.txt'],
                         ]
        self.cwd = 'd:/FGFW_Lite/goagent'
        self.cmd = PYTHON3 + ' d:/FGFW_Lite/goagent/proxy.py'
        self.enable = conf.getconfbool('goagent', 'enable', True)

        self.enableupdate = conf.getconfbool('goagent', 'update', True)
        listen = conf.getconf('goagent', 'listen', '127.0.0.1:8087')
        if ':' in listen:
            listen_ip, listen_port = listen.split(':')
        else:
            listen_ip = '127.0.0.1'
            listen_port = listen

        proxy = SConfigParser()
        proxy.read('./goagent/proxy.ini')
        proxy.set('listen', 'ip', listen_ip)
        proxy.set('listen', 'port', listen_port)

        if self.enable:
            fgfwproxy.addparentproxy('goagnet', ('http', '127.0.0.1', int(listen_port), None, None))

        proxy.set('gae', 'profile', conf.getconf('goagent', 'profile', 'google_cn'))

        appid = 'ippotsukobeta|smartladderchina'
        if os.path.isfile('./include/Appid.txt'):
            with open('./include/Appid.txt') as f:
                appid = f.read().strip()
        proxy.set('gae', 'appid', conf.getconf('goagent', 'goagentGAEAppid', appid))

        proxy.set("gae", "password", conf.getconf('goagent', 'goagentGAEpassword', ''))
        proxy.set('gae', 'obfuscate', conf.getconf('goagent', 'obfuscate', '0'))
        proxy.set('gae', 'validate', conf.getconf('goagent', 'validate', '1'))
        proxy.set("google_hk", "hosts", conf.getconf('goagent', 'gaehkhosts', 'www.google.com|mail.google.com'))
        proxy.set('pac', 'enable', '0')
        proxy.set('paas', 'fetchserver', conf.getconf('goagent', 'paasfetchserver', ''))
        if conf.getconf('goagent', 'paasfetchserver'):
            proxy.set('paas', 'enable', '1')
            if self.enable:
                fgfwproxy.addparentproxy('goagnet-paas', ('http', '127.0.0.1', 8088, None, None))

        if os.path.isfile("./include/dummy"):
            proxy.set('listen', 'visible', '0')
            os.remove("./include/dummy")
        else:
            proxy.set('listen', 'visible', '1')

        with open('./goagent/proxy.ini', 'w') as configfile:
            proxy.write(configfile)

        if not os.path.isfile('./goagent/CA.crt'):
            self.createCert()

    def createCert(self):
        '''
        ripped from goagent 2.1.14
        '''
        import OpenSSL
        ca_vendor = 'FGFW_Lite'
        keyfile = './goagent/CA.crt'
        key = OpenSSL.crypto.PKey()
        key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
        ca = OpenSSL.crypto.X509()
        ca.set_serial_number(0)
        ca.set_version(2)
        subj = ca.get_subject()
        subj.countryName = 'CN'
        subj.stateOrProvinceName = 'Internet'
        subj.localityName = 'Cernet'
        subj.organizationName = ca_vendor
        subj.organizationalUnitName = '%s Root' % ca_vendor
        subj.commonName = '%s CA' % ca_vendor
        ca.gmtime_adj_notBefore(0)
        ca.gmtime_adj_notAfter(24 * 60 * 60 * 3652)
        ca.set_issuer(ca.get_subject())
        ca.set_pubkey(key)
        ca.add_extensions([
            OpenSSL.crypto.X509Extension(b'basicConstraints', True, b'CA:TRUE'),
            OpenSSL.crypto.X509Extension(b'keyUsage', False, b'keyCertSign, cRLSign'),
            OpenSSL.crypto.X509Extension(b'subjectKeyIdentifier', False, b'hash', subject=ca), ])
        ca.sign(key, 'sha1')
        with open(keyfile, 'wb') as fp:
            fp.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, ca))
            fp.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key))
        import shutil
        if os.path.isdir('./goagent/certs'):
            shutil.rmtree('./goagent/certs')
        self.import_ca()

    def import_ca(self):
        '''
        ripped from goagent 3.0.0
        '''
        certfile = os.path.abspath('./goagent/CA.crt')
        dirname, basename = os.path.split(certfile)
        commonname = 'FGFW_Lite CA'
        if sys.platform.startswith('win'):
            with open(certfile, 'rb') as fp:
                certdata = fp.read()
                if certdata.startswith(b'-----'):
                    begin = b'-----BEGIN CERTIFICATE-----'
                    end = b'-----END CERTIFICATE-----'
                    certdata = base64.b64decode(b''.join(certdata[certdata.find(begin)+len(begin):certdata.find(end)].strip().splitlines()))
                import ctypes
                crypt32_handle = ctypes.windll.kernel32.LoadLibraryW('crypt32.dll')
                crypt32 = ctypes.WinDLL(None, handle=crypt32_handle)
                store_handle = crypt32.CertOpenStore(10, 0, 0, 0x4000 | 0x10000, 'ROOT')
                if not store_handle:
                    return -1
                ret = crypt32.CertAddEncodedCertificateToStore(store_handle, 0x1, certdata, len(certdata), 4, None)
                crypt32.CertCloseStore(store_handle, 0)
                del crypt32
                ctypes.windll.kernel32.FreeLibrary(crypt32_handle)
                return 0 if ret else -1
        elif sys.platform == 'darwin':
            return os.system('security find-certificate -a -c "%s" | grep "%s" >/dev/null || security add-trusted-cert -d -r trustRoot -k "/Library/Keychains/System.keychain" "%s"' % (commonname, commonname, certfile))
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


class shadowsocksabs(FGFWProxyAbs):
    """docstring for ClassName"""
    def __init__(self):
        FGFWProxyAbs.__init__(self)

    def _config(self):
        self.filelist = [['https://github.com/clowwindy/shadowsocks/raw/master/shadowsocks/local.py', './shadowsocks/local.py'],
                         ['https://github.com/clowwindy/shadowsocks/raw/master/shadowsocks/encrypt.py', './shadowsocks/encrypt.py'],
                         ['https://github.com/clowwindy/shadowsocks/raw/master/shadowsocks/utils.py', './shadowsocks/utils.py'],
                         ]
        self.cmd = PYTHON2 + ' -B d:/FGFW_Lite/shadowsocks/local.py'
        self.cwd = 'd:/FGFW_Lite/shadowsocks'
        if sys.platform.startswith('win') and os.path.isfile('./shadowsocks/shadowsocks-local.exe'):
            self.cmd = 'd:/FGFW_Lite/shadowsocks/shadowsocks-local.exe'
        self.enable = conf.getconfbool('shadowsocks', 'enable', False)
        if self.enable:
            fgfwproxy.addparentproxy('shadowsocks', ('socks5', '127.0.0.1', 1080, None, None))
        self.enableupdate = conf.getconfbool('shadowsocks', 'update', False)
        server = conf.getconf('shadowsocks', 'server', '')
        server_port = conf.getconf('shadowsocks', 'server_port', '')
        password = conf.getconf('shadowsocks', 'password', 'barfoo!')
        method = conf.getconf('shadowsocks', 'method', 'table')
        self.cmd += ' -s %s -p %s -l 1080 -k %s -m %s'\
            % (server, server_port, password, method.strip('"'))


class fgfwproxy(FGFWProxyAbs):
    """docstring for ClassName"""
    def __init__(self, arg=''):
        FGFWProxyAbs.__init__(self)
        self.arg = arg

    def _config(self):
        self.filelist = [['https://autoproxy-gfwlist.googlecode.com/svn/trunk/gfwlist.txt', './include/gfwlist.txt'],
                         ['http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest', './include/delegated-apnic-latest'],
                         ['https://github.com/v3aqb/fgfw-lite/raw/master/include/FGFW_Lite.py', './include/FGFW_Lite.py'],
                         ['https://github.com/v3aqb/fgfw-lite/raw/master/include/cloud.txt', './include/cloud.txt'],
                         ]
        self.enable = conf.getconfbool('fgfwproxy', 'enable', True)
        self.enableupdate = conf.getconfbool('fgfwproxy', 'update', True)
        self.listen = conf.getconf('fgfwproxy', 'listen', '8118')
        self.chinaroute()
        self.conf()

    def start(self):
        if self.enable:
            if ':' in self.listen:
                run_proxy(self.listen.split(':')[1], address=self.listen.split(':')[0])
            else:
                run_proxy(self.listen)

    @classmethod
    def conf(cls):
        cls.parentdict = {}
        cls.addparentproxy('direct', (None, None, None, None, None))

        cls.gfwlist = []

        if os.path.isfile('./include/local.txt'):
            with open('./include/local.txt') as f:
                for line in f:
                    try:
                        o = autoproxy_rule(line)
                    except Exception:
                        pass
                    else:
                        cls.gfwlist.append(o)
        else:
            with open('./include/local.txt', 'w') as f:
                f.write('! local gfwlist config\n! rules: http://t.cn/zTeBinu\n')

        with open('./include/cloud.txt') as f:
            for line in f:
                try:
                    o = autoproxy_rule(line)
                except Exception:
                    pass
                else:
                    cls.gfwlist.append(o)

        with open('./include/gfwlist.txt') as f:
            data = f.read()
        data = base64.b64decode(data)
        for line in io.BytesIO(data):
            try:
                o = autoproxy_rule(line)
            except Exception:
                pass
            else:
                cls.gfwlist.append(o)

    @classmethod
    def addparentproxy(cls, name, proxy):
        '''
        {
            'direct': (None, None, None, None, None),
            'goagent': ('http', '127.0.0.1', 8087, None, None)
        }  # type, host, port, username, password
        '''
        cls.parentdict[name] = proxy

    @classmethod
    def parentproxy(cls, uri, domain=None, forceproxy=False):
        '''
            decide which parentproxy to use.
            url:  'https://www.google.com'
            domain: 'www.google.com'
        '''
        # return cls.parentdict.get('https')

        if uri is not None and domain is None:
            domain = uri.split('/')[2].split(':')[0]

        cls.inchinadict = {}

        def ifhost_in_china():
            if domain is None:
                return False
            result = cls.inchinadict.get('domain')
            if result is None:
                try:
                    ipo = ip_address(socket.gethostbyname(domain))
                except Exception:
                    return False
                result = False
                for net in cls.chinanet:
                    if ipo in net:
                        result = True
                        break
                cls.inchinadict[domain] = result
            return result

        def ifgfwlist():
            for rule in cls.gfwlist:
                if rule.match(uri, domain):
                    logger.info('Autoproxy Rule match %s' % rule.rule)
                    return not rule.override
            return False

        # select parent via uri
        parentlist = list(cls.parentdictalive.keys())
        if ifhost_in_china():
            return ('direct', cls.parentdictalive.get('direct'))
        if forceproxy or ifgfwlist():
            parentlist.remove('direct')
            if uri.startswith('ftp://'):
                if 'goagent' in parentlist:
                    parentlist.remove('goagent')
            if parentlist:
                ppname = random.choice(parentlist)
                return (ppname, cls.parentdictalive.get(ppname))
        return ('direct', cls.parentdictalive.get('direct'))

    @classmethod
    def chinaroute(cls):

        cls.chinanet = []
        cls.chinanet.append(ip_network('192.168.0.0/16'))
        cls.chinanet.append(ip_network('172.16.0.0/12'))
        cls.chinanet.append(ip_network('10.0.0.0/8'))
        cls.chinanet.append(ip_network('127.0.0.0/8'))
        # ripped from https://github.com/fivesheep/chnroutes
        import math
        with open('./include/delegated-apnic-latest') as remotefile:
            data = remotefile.read()

        cnregex = re.compile(r'apnic\|cn\|ipv4\|[0-9\.]+\|[0-9]+\|[0-9]+\|a.*', re.IGNORECASE)
        cndata = cnregex.findall(data)

        for item in cndata:
            unit_items = item.split('|')
            starting_ip = unit_items[3]
            num_ip = int(unit_items[4])

            #mask in *nix format
            mask2 = 32 - int(math.log(num_ip, 2))

            cls.chinanet.append(ip_network('%s/%s' % (starting_ip, mask2)))


class SConfigParser(configparser.ConfigParser):
    """docstring for SSafeConfigParser"""
    def __init__(self):
        super(SConfigParser, self).__init__()

    def dget(self, section, option, default=None):
        value = self.get(section, option)
        if value is None:
            value = default
        return value

    def dgetfloat(self, section, option, default=None):
        return float(self.dget(section, option, default))

    def dgetint(self, section, option, default=None):
        return int(self.dget(section, option, default))

    def get(self, section, option, raw=False, vars=None):
        try:
            value = configparser.ConfigParser.get(self, section, option, raw=False, vars=None)
            if value == '' or value is None:
                raise Exception
        except Exception:
            return None
        else:
            return value


class Config(object):
    def __init__(self):
        self.iolock = RLock()
        self.presets = SConfigParser()
        self.userconf = SConfigParser()
        self.reload()
        self.UPDATE_INTV = 6
        self.BACKUP_INTV = 24

    def reload(self):
        self.presets.read('presets.ini')
        self.userconf.read('userconf.ini')

    def getconf(self, section, option=None, default=None):
        if option is None:
            try:
                value = self.userconf.items(section)
                if value == [] or value is None:
                    raise Exception
            except Exception:
                try:
                    value = self.presets.items(section)
                except Exception:
                    value = []
        else:
            value = self.userconf.get(section, option)
            if value is None:
                value = self.presets.dget(section, option, default)
        return value

    def getconfbool(self, section, option, default=True):
        try:
            value = self.userconf.getboolean(section, option)
        except Exception:
            try:
                value = self.presets.getboolean(section, option)
            except Exception:
                value = default
        return value

    def confsave(self):
        self.presets.write(open('presets.ini', 'w'))
        self.userconf.write(open('userconf.ini', 'w'))

conf = Config()
consoleLock = RLock()


@atexit.register
def function():
    for item in FGFWProxyAbs.ITEMS:
        item.enable = False
        item.restart()
    conf.confsave()


def main():
    if conf.getconfbool('fgfwproxy', 'enable', True):
        fgfwproxy()
    if conf.getconfbool('goagent', 'enable', True):
        goagentabs()
    if conf.getconfbool('shadowsocks', 'enable', False):
        shadowsocksabs()
    if conf.getconfbool('https', 'enable', False):
        host = conf.getconf('https', 'host', '')
        port = conf.getconf('https', 'port', '443')
        user = conf.getconf('https', 'user', None)
        passwd = conf.getconf('https', 'passwd', None)
        fgfwproxy.addparentproxy('https', ('https', host, int(port), user, passwd))
    fgfwproxy.parentdictalive = fgfwproxy.parentdict.copy()
    updatedaemon = Thread(target=updateNbackup)
    updatedaemon.daemon = True
    updatedaemon.start()
    while True:
        line = input()
        if 'update' in line:
            fgfw2Liteupdate(auto=False)
        elif 'backup'in line:
            backup()
        elif 'restart'in line:
            fgfw2Literestart()
        else:
            print(line)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        logger.error(str(e))

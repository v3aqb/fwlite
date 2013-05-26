#!/usr/bin/env python
#-*- coding: UTF-8 -*-
#-------------------------------------------------------------------------------
# Name:        FGFW_Lite.py
# Purpose:     Fuck the Great Firewall of China
#
# Author:      Jiang Chao
#
# Created:     08/03/2013
# Copyright:   (c) 2013 Jiang Chao <sgzz.cj@gmail.com>
# License:     The GPLv2 License
#-------------------------------------------------------------------------------
from __future__ import print_function
from __future__ import unicode_literals

__version__ = '0.3.1.0'

import sys
import os
from subprocess import Popen
import shlex
import time
import requests
if sys.version[0] == '2':
    from ConfigParser import SafeConfigParser
    import _winreg as winreg
    import ipaddr
    ip_address = ipaddr.IPAddress
    ip_network = ipaddr.IPNetwork
    PYTHON = 'd:/FGFW_Lite/include/Python27/python27.exe'
else:
    from configparser import SafeConfigParser
    import winreg
    import ipaddress
    ip_address = ipaddress.ip_address
    ip_network = ipaddress.ip_network
    PYTHON = 'd:/FGFW_Lite/include/Python33/python33.exe'
from threading import Thread, RLock, Timer
import atexit
import base64
import socket
import struct
import random
import re
import tornado.ioloop
import tornado.iostream
import tornado.httpserver
import tornado.web
WORKINGDIR = os.getcwd().replace('\\', '/')
if ' ' in WORKINGDIR:
    print('no spacebar allowed in path')
    sys.exit()
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
try:
    from PySide import QtGui
except Exception:
    QtGui = None
GUI = False


class ProxyHandler(tornado.web.RequestHandler):
    SUPPORTED_METHODS = ['GET', 'POST', 'HEAD', 'PUT', 'DELETE',
                         'TRACE', 'CONNECT']

    @tornado.web.asynchronous
    def prepare(self):
        # redirector
        new_url = fgfwproxy.url_rewriter(self.request.uri)
        if new_url:
            self.redirect(new_url)
            return

        uri = self.request.uri
        if not ('//' in uri):
            uri = 'https://' + uri

        urisplit = uri.split('/')
        self.requestpath = '/'.join(urisplit[3:])

        if ':' in urisplit[2]:
            self.requestport = int(urisplit[2].split(':')[1])
        elif uri.startswith('https://'):
            self.requestport = 443
        else:
            self.requestport = 80
        #self.request.host = self.request.host.split(':')[0]
        self.pptype, self.pphost, self.ppport, self.ppusername,\
            self.pppassword = fgfwproxy.parentproxy(uri, self.request.host)
        s = '%s %s' % (self.request.method, self.request.uri.split('?')[0])
        if self.pphost:
            s += ' via %s://%s:%s' % (self.pptype, self.pphost, self.ppport)
        else:
            s += ' via direct'
        logger.info(s)

    @tornado.web.asynchronous
    def get(self):
        return self.connect()

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
            s = '%s %s %s\r\n' % (self.request.method, self.request.uri, self.request.version)
            if self.ppusername:
                a = '%s:%s' % (self.ppusername, self.pppassword)
                self.request.headers['Authorization'] = 'Basic %s\r\n' % base64.b64encode(a)
            self.request.headers['Connection'] = 'close'
            for key, value in self.request.headers.items():
                s += '%s: %s\r\n' % (key, value)
            s += '\r\n'
            s = s.encode()
            if self.request.body:
                s += self.request.body + b'\r\n\r\n'
            start_tunnel(s)

        def http_conntgt_d(data=None):
            s = '%s /%s %s\r\n' % (self.request.method, self.requestpath, self.request.version)
            self.request.headers['Connection'] = 'close'
            for key, value in self.request.headers.items():
                s += '%s: %s\r\n' % (key, value)
            s += '\r\n'
            s = s.encode()
            if self.request.body:
                s += self.request.body + b'\r\n\r\n'
            start_tunnel(s)

        def socks5_handshake(data=None):
            def socks5_auth(data=None):
                if data == b'\x05\00':  # no auth needed
                    conn_upstream()
                elif data == b'\x05\02':  # basic auth
                    upstream.write(b"\x01" +
                                   chr(len(self.ppusername)).encode() + self.ppusername.encode() +
                                   chr(len(self.pppassword)).encode() + self.pppassword).encode()
                    upstream.read_bytes(2, socks5_auth_finish)
                else:  # bad day, no auth supported
                    fail()

            def socks5_auth_finish(data=None):
                if data == b'\x01\x00':  # auth pass
                    conn_upstream()
                else:
                    fail()

            def conn_upstream(data=None):
                # try:
                #     ip = socket.aton(self.request.host)  # guess ipv4
                # except socket.error:
                #     try:  # guess ipv6
                #         ip = socket.inet_pton(socket.AF_INET6, self.request.host)
                #     except Exception:  # got to be domain name
                #         req = b"\x05\x01\x00\x03" + chr(len(self.request.host)) + self.request.host
                #     else:
                #         req = b"\x05\x01\x00\x04" + ip
                # else:
                #     req = b"\x05\x01\x00\x01" + ip
                req = b"\x05\x01\x00\x03" + chr(len(self.request.host)).encode() + self.request.host.encode()
                req += struct.pack(">H", self.requestport)
                upstream.write(req)
                upstream.read_bytes(4, upstream_verify)

            def upstream_verify(data=None):
                if data[0:1] == b'\x05\x00':
                    if data[3] == b'\x01':
                        upstream.read_bytes(6, conn)
                    elif data[3] == b'\x03':
                        upstream.read_bytes(3, readaddr)
                else:
                    fail()

            def readaddr(data=None):
                upstream.read_bytes(data[0], conn)

            def conn(data=None):
                if self.request.method == 'CONNECT':
                    start_ssltunnel()
                else:
                    http_conntgt_d()

            def fail():
                client.write(b'HTTP/1.1 500 socks5 proxy Connection Failed.\r\n\r\n')
                upstream.close()
                client.close()

            if self.ppusername:
                authmethod = b"\x05\x02\x00\x02"
            else:
                authmethod = b"\x05\x01\x00"
            upstream.write(authmethod)
            upstream.read_bytes(2, socks5_auth)

        if self.pphost is None:
            if self.request.method == 'CONNECT':
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
                upstream = tornado.iostream.IOStream(s)
                upstream.connect((self.request.host.split(':')[0], int(self.requestport)), start_ssltunnel)
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
                upstream = tornado.iostream.IOStream(s)
                upstream.connect((self.request.host.split(':')[0], int(self.requestport)), http_conntgt_d)
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
    OVERRIDE_DOMAIN = 3
    OVERRIDE_URI = 4
    OVERRIDE_KEYWORD = 5

    def __init__(self, arg):
        super(autoproxy_rule, self).__init__()
        if isinstance(arg, bytes):
            arg = arg.decode()
        elif not isinstance(arg, str):
            raise TypeError("invalid type: must be a string(or bytes)")
        self.rule = arg.strip()
        if self.rule == '' or\
                self.rule.startswith('!') or\
                self.rule.startswith('[') or\
                self.rule.startswith('/'):
            raise ValueError("invalid autoproxy_rule")
        self.__type, self.__ptrnlst = self.__autopxy_rule_parse(self.rule)
        if self.__type >= autoproxy_rule.OVERRIDE_DOMAIN:
            self.override = True
        else:
            self.override = False

    def __autopxy_rule_parse(self, rule):
        def parse(rule):
            if rule.startswith('||'):
                result = rule.replace('||', '').replace('/', '')
                return (autoproxy_rule.DOMAIN, result.split('*'))

            elif rule.startswith('|'):
                result = rule.replace('|', '')
                return (autoproxy_rule.URI, result.split('*'))

            else:
                return (autoproxy_rule.KEYWORD, rule.split('*'))

        if rule.startswith('@@||'):
            return (autoproxy_rule.OVERRIDE_DOMAIN, parse(rule.replace('@@', ''))[1])
        elif rule.startswith('@@|'):
            return (autoproxy_rule.OVERRIDE_URI, parse(rule.replace('@@', ''))[1])
        elif rule.startswith('@@'):
            return (autoproxy_rule.OVERRIDE_KEYWORD, parse(rule.replace('@@', ''))[1])
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
                    i += uri.find(s, i) + len(s)
                else:
                    return False
            return True

        if domain is None:
            domain = url.split('/')[2].split(':')[0]
        if self.__type is autoproxy_rule.DOMAIN:
            return _match_domain()
        elif self.__type is autoproxy_rule.URI:
            if url.startswith('https://'):
                if self.rule.startswith('|https://'):
                    return _match_uri()
                return False
            return _match_uri()
        elif self.__type is autoproxy_rule.KEYWORD:
            if url.startswith('https://'):
                return False
            return _match_keyword()

        elif self.__type is autoproxy_rule.OVERRIDE_DOMAIN:
            return _match_domain()
        elif self.__type is autoproxy_rule.OVERRIDE_URI:
            return _match_uri()
        elif self.__type is autoproxy_rule.OVERRIDE_KEYWORD:
            return _match_keyword()


def run_proxy(port, start_ioloop=True):
    """
    Run proxy on the specified port. If start_ioloop is True (default),
    the tornado IOLoop will be started immediately.
    """
    print ("Starting HTTP proxy on port %d" % port)
    app = tornado.web.Application([(r'.*', ProxyHandler), ])
    app.listen(port)
    ioloop = tornado.ioloop.IOLoop.instance()
    if start_ioloop:
        ioloop.start()


def updateNbackup():
    while True:
        time.sleep(90)
        chkproxy()
        ifupdate()
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


def fgfw2Liteupdate(m=False):
    open("./include/dummy", 'w').close()
    for item in FGFWProxyAbs.ITEMS:
        if item.enableupdate:
            item.update()
    conf.presets.set('Update', 'LastUpdate', str(time.time()))
    Timer(40, fgfw2Literestart).start()


def fgfw2Literestart():
    conf.confsave()
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
        self.filelist = []
        self.enable = True
        self.enableupdate = True

    def start(self):
        while True:
            if self.enable:
                self.subpobj = Popen(shlex.split(self.cmd.replace('d:/FGFW_Lite', WORKINGDIR)))
                self.subpobj .wait()
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
                etag = conf.presets.dget('Update', path.split('/')[-1] + '.ver', '')
                Thread(target=self.updateViaHTTP, args=(url, etag, path)).start()

    def updateViaHTTP(self, url, etag, path):
        with consoleLock:
            logger.info('updating ' + path)
            proxy = {'http': 'http://127.0.0.1:8118',
                     'https': 'http://127.0.0.1:8118'
                     }
            headers = {'If-None-Match': etag,
                       }
        try:
            r = requests.get(url, proxies=proxy, headers=headers)
        except Exception as e:
            logger.info(path + ' Not modified ' + str(e))
        else:
            if r.status_code == 200:
                with open(path, 'wb') as localfile:
                    localfile.write(r.content)
                with conf.iolock:
                    conf.presets.set('Update', path.split('/')[-1] + '.ver', str(r.headers.get('etag')))
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
                        ['https://github.com/goagent/goagent/raw/3.0/local/cacert.pem', './goagent/cacert.pem']
                         ]
        self.cmd = PYTHON + ' d:/FGFW_Lite/goagent/proxy.py'
        self.enable = conf.getconfbool('goagent', 'enable', True)

        if self.enable:
            fgfwproxy.addparentproxy('goagnet', ('http', '127.0.0.1', 8087, None, None))

        self.enableupdate = conf.getconfbool('goagent', 'update', True)
        proxy = SSafeConfigParser()
        proxy.read('./goagent/proxy.ini')

        proxy.set('gae', 'profile', conf.getconf('goagent', 'profile', 'google_cn'))
        proxy.set('gae', 'appid', conf.getconf('goagent', 'goagentGAEAppid', 'ippotsukobeta|smartladderchina'))
        proxy.set("gae", "password", conf.getconf('goagent', 'goagentGAEpassword', ''))
        proxy.set('gae', 'obfuscate', conf.getconf('goagent', 'obfuscate', '0'))
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
        self.cert()

    def cert(self):
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
        self.cmd = PYTHON + ' d:/FGFW_Lite/shadowsocks/local.py'
        self.enable = conf.getconfbool('shadowsocks', 'enable', False)
        if self.enable:
            fgfwproxy.addparentproxy('shadowsocks', ('socks5', '127.0.0.1', 1080, None, None))
        self.enableupdate = conf.getconfbool('shadowsocks', 'update', False)
        server = conf.getconf('shadowsocks', 'server', '')
        server_port = conf.getconf('shadowsocks', 'server_port', '')
        password = conf.getconf('shadowsocks', 'password', 'barfoo!')
        method = conf.getconf('shadowsocks', 'method', 'null')
        with open('./shadowsocks/config.json', 'w') as f:
            f.write('''\
{
    "server":"%s",
    "server_port":%s,
    "local_port":1080,
    "password":"%s",
    "timeout":600,
    "method":%s
}
''' % (server, server_port, password, method))


class gsnovaabs(FGFWProxyAbs):  # Need more work on this
    """docstring for ClassName"""
    def __init__(self, arg=''):
        FGFWProxyAbs.__init__(self)
        self.arg = arg

    def _config(self):
        self.cmd = 'd:/FGFW_Lite/gsnova/gsnova.exe'
        self.filelist = []
        self.enable = conf.getconfbool('gsnova', 'enable', False)
        if self.enable:
            fgfwproxy.addparentproxy('gsnova-gae', ('http', '127.0.0.1', 48101, None, None))
        self.enableupdate = conf.getconfbool('gsnova', 'update', False)
        proxy = SSafeConfigParser()
        proxy.optionxform = str
        proxy.read('./gsnova/gsnova.conf')

        worknodes = conf.getconf('gsnova', 'GAEworknodes')
        if worknodes:
            worknodes = worknodes.split('|')
            for i in range(len(worknodes)):
                proxy.set('GAE', 'WorkerNode[' + str(i) + ']', worknodes[i])
            proxy.set('GAE', 'Enable', '1')

        worknodes = conf.getconf('gsnova', 'C4worknodes')
        if worknodes:
            worknodes = worknodes.split('|')
            for i in range(len(worknodes)):
                proxy.set('C4', 'WorkerNode[' + str(i) + ']', worknodes[i])
            proxy.set('C4', 'Enable', '1')
            if self.enable:
                fgfwproxy.addparentproxy('gsnova-c4', ('http', '127.0.0.1', 48102, None, None))
        else:
            proxy.set('C4', 'Enable', '0')

        proxy.set('SPAC', 'Enable', '0')
        proxy.set('Misc', 'AutoOpenWebUI', 'false')
        proxy.set('Misc', 'RC4Key', conf.getconf('gsnova', 'RC4Key', '8976501f8451f03c5c4067b47882f2e5'))
        with open('./gsnova/gsnova.conf', 'w') as configfile:
            proxy.write(configfile)

        cert = open('./goagent/CA.crt').read()
        with open('./gsnova/cert/Fake-ACRoot-Certificate.cer', 'wb') as certfile:
            certfile.write(cert[:cert.find('-----BEGIN RSA PRIVATE KEY-----')])
        with open('./gsnova/cert/Fake-ACRoot-Key.pem', 'wb') as certfile:
            certfile.write(cert[cert.find('-----BEGIN RSA PRIVATE KEY-----'):])
        import shutil
        if os.path.isdir('./gsnova/cert/host'):
            shutil.rmtree('./gsnova/cert/host')


class fgfwproxy(FGFWProxyAbs):
    """docstring for ClassName"""
    def __init__(self, arg=''):
        FGFWProxyAbs.__init__(self)
        self.arg = arg

    def _config(self):
        self.filelist = [['https://autoproxy-gfwlist.googlecode.com/svn/trunk/gfwlist.txt', './include/gfwlist.txt'],
                         ['http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest', './include/delegated-apnic-latest'],
                         ['https://fgfw-lite.googlecode.com/git/include/FGFW_Lite.py', './include/FGFW_Lite.py'],
                         ['https://fgfw-lite.googlecode.com/git/include/cloud.txt', './include/cloud.txt'],
                         ]
        #self.cmd = 'd:/FGFW_Lite/include/Python33/python33.exe d:/FGFW_Lite/include/fgfwproxy.py'
        self.enable = conf.getconfbool('fgfwproxy', 'enable', True)
        self.enableupdate = conf.getconfbool('fgfwproxy', 'update', True)
        self.chinaroute()
        self.conf()

    def start(self):
        if self.enable:
            run_proxy(8118)

    @classmethod
    def conf(cls):
        cls.parentdict = {}
        cls.addparentproxy('direct', (None, None, None, None, None))
        cls.chinanet = []
        cls.chinanet.append(ip_network('192.168.0.0/16'))
        cls.chinanet.append(ip_network('172.16.0.0/12'))
        cls.chinanet.append(ip_network('10.0.0.0/8'))
        cls.chinanet.append(ip_network('127.0.0.0/8'))
        with open('./include/chinaroutes') as f:
            for line in f:
                if line:
                    cls.chinanet.append(ip_network(line.strip()))

        cls.gfwlist = []

        if os.path.isfile('./include/local.txt'):
            with open('./include/local.txt') as f:
                for line in f:
                    try:
                        o = autoproxy_rule(line)
                    except Exception:
                        pass
                    else:
                        if o.override:
                            cls.gfwlist.insert(0, o)
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
                    if o.override:
                        cls.gfwlist.insert(0, o)
                    else:
                        cls.gfwlist.append(o)

        with open('./include/gfwlist.txt') as f:
            data = f.read()
        data = base64.b64decode(data).split()
        for line in data:
            try:
                o = autoproxy_rule(line)
            except Exception:
                pass
            else:
                if o.override:
                    cls.gfwlist.insert(0, o)
                else:
                    cls.gfwlist.append(o)

    @classmethod
    def url_rewriter(cls, uri):
        forcehttps = ['http://www.google.com/reader',
                      'http://www.google.com/search'
                      'http://www.google.com/url',
                      'http://news.google.com',
                      'http://appengine.google.com',
                      'http://www.google.com.hk/url',
                      'http://www.google.com.hk/search',
                      r're^http://www\.google\.com/?$',
                      r're^http://[^/]+\.googlecode\.com',
                      r're^http://[^/]+\.wikipedia\.org']
        for string in forcehttps:
            if re.match(string[2:], uri) if string.startswith('re')\
                    else uri.startswith(string):
                return uri.replace('http://', 'https://', 1)

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
    def parentproxy(cls, uri, domain=''):
        '''
            decide which parentproxy to use.
            url:  'https://www.google.com'
            domain: 'www.google.com'
        '''
        # return cls.parentdict.get('https')

        if not domain:
            domain = uri.split('/')[2].split(':')[0]

        cls.inchinadict = {}

        def ifhost_in_china():
            result = cls.inchinadict.get('domain')
            if result is None:
                try:
                    ip = socket.gethostbyname(domain)
                except Exception:
                    return False
                ipo = ip_address(ip)
                result = False
                for net in cls.chinanet:
                    if ipo in net:
                        result = True
                        break
                cls.inchinadict[domain] = result
            return result

        def ifgsnova():
            return False

        def ifgoagent():
            return False

        def ifgfwlist():
            for rule in cls.gfwlist:
                if rule.match(uri, domain):
                    return not rule.override
            return False

        # select parent via uri
        parentlist = list(cls.parentdictalive.keys())
        if ifhost_in_china():
            return cls.parentdictalive.get('direct')
        if ifgfwlist():
            parentlist.remove('direct')
            if uri.startswith('ftp://'):
                try:
                    parentlist.remove('goagent')
                    parentlist.remove('gsnova-gae')
                except Exception:
                    pass
            if 'twitter.com' in uri:
                try:
                    parentlist.remove('gsnova-gae')
                except Exception:
                    pass
            if parentlist:
                return cls.parentdictalive.get(random.choice(parentlist))
        return cls.parentdictalive.get('direct')

    def chinaroute(self):
        # ripped from https://github.com/fivesheep/chnroutes
        import math
        with open('./include/delegated-apnic-latest') as remotefile:
            data = remotefile.read()

        cnregex = re.compile(r'apnic\|cn\|ipv4\|[0-9\.]+\|[0-9]+\|[0-9]+\|a.*', re.IGNORECASE)
        cndata = cnregex.findall(data)

        results = []

        for item in cndata:
            unit_items = item.split('|')
            starting_ip = unit_items[3]
            num_ip = int(unit_items[4])

            #mask in *nix format
            mask2 = 32 - int(math.log(num_ip, 2))

            results.append((starting_ip, mask2))

        with open('./include/chinaroutes', 'w') as rfile:
            for ip, mask2 in results:
                rfile.write('%s/%s\n' % (ip, mask2))


class SSafeConfigParser(SafeConfigParser):
    """docstring for SSafeConfigParser"""
    def __init__(self, arg=''):
        SafeConfigParser.__init__(self)
        self.arg = arg

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
            value = SafeConfigParser.get(self, section, option, raw=False, vars=None)
            if value == '' or value is None:
                raise Exception
        except Exception:
            return None
        else:
            return value


class Config(object):
    def __init__(self):
        self.iolock = RLock()
        self.presets = SSafeConfigParser()
        self.userconf = SSafeConfigParser()
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


class Window(QtGui.QSystemTrayIcon):
    def __init__(self):
        super(Window, self).__init__()

        icon = QtGui.QIcon("./include/logo.png")
        self.setIcon(icon)
        self.show()

        self.activated.connect(self.trayClick)  # 点击托盘
        self.setToolTip("托盘小程序")  # 托盘信息
        self.Menu()  # 右键菜单

    def Menu(self):
        showToggleAction = QtGui.QAction("显示/隐藏", self, triggered=self.Message)
        reloadAction = QtGui.QAction("重新载入", self, triggered=self.Message)
        proxyOverallAction = QtGui.QAction("全局代理", self, triggered=self.Message)
        proxyAutoAction = QtGui.QAction("自动代理", self, triggered=self.Message)
        proxyDirectAction = QtGui.QAction("直接连接", self, triggered=self.Message)

        trayIconMenu = QtGui.QMenu()

        trayIconMenu.addAction(showToggleAction)
        trayIconMenu.addAction(reloadAction)

        setproxyMenu = trayIconMenu.addMenu('设置代理')
        setproxyMenu.addAction(proxyOverallAction)
        setproxyMenu.addAction(proxyAutoAction)
        setproxyMenu.addAction(proxyDirectAction)

        advancedMenu = trayIconMenu.addMenu('高级')
        advancedMenu.addAction(QtGui.QAction("软件升级", self, triggered=self.Message))
        advancedMenu.addAction(QtGui.QAction("开机启动", self, triggered=self.Message))
        advancedMenu.addAction(QtGui.QAction("本地规则", self, triggered=self.Message))
        trayIconMenu.addSeparator()  # 间隔线
        trayIconMenu.addAction(QtGui.QAction("退出", self, triggered=QtGui.qApp.quit))

        self.setContextMenu(trayIconMenu)  # 右击托盘

    def trayClick(self, reason):
        if reason == QtGui.QSystemTrayIcon.DoubleClick:  # 双击
            self.Message()
        elif reason == QtGui.QSystemTrayIcon.MiddleClick:  # 中击
            self.Message()
        else:
            pass

    def Message(self):
        icon = QtGui.QSystemTrayIcon.Information
        self.showMessage("提示信息", "点我干嘛？", icon)


def gui():
    app = QtGui.QApplication(sys.argv)
    Window()
    sys.exit(app.exec_())


def main():
    if conf.getconfbool('fgfwproxy', 'enable', True):
        fgfwproxy()
    if conf.getconfbool('goagent', 'enable', True):
        goagentabs()
    if conf.getconfbool('gsnova', 'enable', False):
        gsnovaabs()
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
    if QtGui and GUI is True:
        gui()
    else:
        while True:
            line = sys.stdin.readline().strip()
            if 'update' in line:
                fgfw2Liteupdate()
            elif 'backup'in line:
                backup()
            else:
                print(line)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        logger.error(str(e))


import sys
import time
import struct
import hashlib
import hmac
from urllib.request import urlopen
from collections import defaultdict, deque
from hxcrypto import ECC, compare_digest
from .apfilter import ap_filter


class porn_filter:
    def __init__(self):
        self.porn_filter = None
        self.last_load = 0
        self.loaded = False

    def load(self):
        self.porn_filter = ap_filter()
        hosts = urlopen('https://raw.githubusercontent.com/4skinSkywalker/Anti-Porn-HOSTS-File/master/HOSTS.txt').readlines()
        for line in hosts:
            try:
                self.porn_filter.add('||' + line.decode().strip().split()[1])
            except Exception:
                pass
        self.loaded = True

    def is_porn(self, addr):
        if not self.loaded and time.time() - self.last_load > 3600:
            self.last_load = time.time()
            try:
                self.load()
            except Exception as err:
                sys.stderr.write('load porn_filter failed.\n')
        if self.loaded:
            return self.porn_filter.match(addr)


class UserManager:
    def __init__(self, server_cert, limit=20):
        '''server_cert: path to server_cert'''
        self.SERVER_CERT = ECC(from_file=server_cert)
        self._limit = limit
        self.user_pass = {}
        self.user_tag = {}
        self.userpkeys = defaultdict(deque)  # user name: client key
        self.pkeyuser = {}  # user pubkey: user name
        self.porn_filter = porn_filter()

    def add_user(self, user, password):
        password, _, tags = password.partition(' ')
        tags = tags.split()
        self.user_pass[user] = password
        self.user_tag[user] = tags

    def remove_user(self, user):
        del self.user_pass[user]
        del self.user_tag[user]

    def hxs2_auth(self, client_pkey, client_auth):
        ts_ = int(time.time()) // 30
        user = None
        password = None
        for _ts in [ts_, ts_ - 1, ts_ + 1]:
            for username, password_ in self.user_pass.items():
                hash_ = hmac.new(password_.encode(),
                                 struct.pack('>I', _ts) + client_pkey + username.encode(),
                                 hashlib.sha256).digest()
                if compare_digest(hash_, client_auth):
                    user = username
                    password = password_
                    break
            if user:
                break
        else:
            raise ValueError('user not found')

        # return public_key, username, password
        if hashlib.md5(client_pkey).digest() in self.pkeyuser:
            raise ValueError('public key already registered. user: %s' % user)
        if len(self.userpkeys[user]) > self._limit:
            raise ValueError('connection limit exceeded. user: %s' % user)
        for key_len in (32, 24, 16):
            try:
                ecc = ECC(key_len)
                shared_secret = ecc.get_dh_key(client_pkey)
                break
            except ValueError:
                continue
        user_pkey_md5 = hashlib.md5(client_pkey).digest()
        self.userpkeys[user].append(user_pkey_md5)
        self.pkeyuser[user_pkey_md5] = user
        xpubkey = ecc.get_pub_key()

        hash_ = hmac.new(password.encode(), client_pkey + xpubkey + user.encode(), hashlib.sha256).digest()
        scert = self.SERVER_CERT.get_pub_key()
        signature = self.SERVER_CERT.sign(hash_, 'SHA256')
        reply = b''.join([
            bytes((0, len(xpubkey), len(scert), len(signature))),
            xpubkey,
            hash_,
            scert,
            signature])
        return user, reply, shared_secret

    def del_key(self, pkey):
        user = self.pkeyuser[pkey]
        del self.pkeyuser[pkey]
        self.userpkeys[user].remove(pkey)

    def user_access_ctrl(self, server_port, host, ipaddr, user):
        # access control, called before each request
        # int server_port
        # str host: requested hostname
        # str ipaddr: client ipaddress
        # raise ValueError if denied
        if user not in self.user_tag:
            return
        if 'noporn' in self.user_tag[user]:
            if self.porn_filter.is_porn(host):
                raise ValueError('porn block')

    def user_access_log(self, server_port, host, traffic, ipaddr, user):
        # log user access, called after each request
        # traffic: (upload, download) in bytes
        pass

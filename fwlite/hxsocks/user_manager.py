
import struct
import hashlib
import hmac
from collections import defaultdict, deque
from hxcrypto import ECC, compare_digest


class UserManager:
    def __init__(self, server_cert, limit=10):
        '''server_cert: path to server_cert'''
        self.SERVER_CERT = ECC(from_file=server_cert)
        self._limit = limit
        self.user_pass = {}
        self.userpkeys = defaultdict(deque)  # user name: client key
        self.pkeyuser = {}  # user pubkey: user name
        self.pkeykey = {}   # user pubkey: shared secret

    def add_user(self, user, password):
        self.user_pass[user] = password

    def remove_user(self, user):
        del self.user_pass[user]

    def hxs2_auth(self, ts, client_pkey, client_auth):
        for _ts in [ts, ts - 1, ts + 1]:
            for user, passwd in self.user_pass.items():
                hash_ = hmac.new(passwd.encode(),
                                 struct.pack('>I', _ts) + client_pkey + user.encode(),
                                 hashlib.sha256).digest()
                if compare_digest(hash_, client_auth):
                    return user
        return None

    def key_xchange(self, user, user_pkey, key_len):
        # return public_key, passwd_of_user
        if hashlib.md5(user_pkey).digest() in self.pkeyuser:
            raise ValueError('public key already registered. user: %s' % user)
        if len(self.userpkeys[user]) > self._limit:
            raise ValueError('connection limit exceeded. user: %s' % user)
        ecc = ECC(key_len)
        shared_secret = ecc.get_dh_key(user_pkey)
        user_pkey_md5 = hashlib.md5(user_pkey).digest()
        self.userpkeys[user].append(user_pkey_md5)
        self.pkeyuser[user_pkey_md5] = user
        self.pkeykey[user_pkey_md5] = shared_secret
        return ecc.get_pub_key(), self.user_pass[user]

    def del_key(self, pkey):
        user = self.pkeyuser[pkey]
        del self.pkeyuser[pkey]
        del self.pkeykey[pkey]
        self.userpkeys[user].remove(pkey)

    def get_skey_by_pubkey(self, pubkey):
        return self.pkeykey[pubkey]

    def user_access_ctrl(self, server_port, host, ipaddr, user):
        # access control, called before each request
        # int server_port
        # str host: requested hostname
        # str ipaddr: client ipaddress
        # raise ValueError if denied
        pass

    def user_access_log(self, server_port, host, traffic, ipaddr, user):
        # log user access, called after each request
        # traffic: (upload, download) in bytes
        pass

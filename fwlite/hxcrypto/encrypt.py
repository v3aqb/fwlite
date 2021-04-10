#!/usr/bin/env python
# coding: UTF-8
#

# Copyright (c) 2013-2019 v3aqb

# This file is part of hxcrypto.

# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
# 02110-1301  USA

#
# Copyright (c) 2012 clowwindy
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


import os
import sys
import hashlib
import struct
import hmac

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes, aead

from .iv_checker import IVChecker, IVError

SS_SUBKEY = b"ss-subkey"


class BufEmptyError(ValueError):
    '''BufEmptyError'''


def random_string(size):
    '''random_string'''
    return os.urandom(size)


def EVP_BytesToKey(password, key_len):
    ''' equivalent to OpenSSL's EVP_BytesToKey() with count 1
        so that we make the same key and iv as nodejs version'''
    m_list = []
    _len = 0

    while _len < key_len:
        md5 = hashlib.md5()
        data = password
        if m_list:
            data = m_list[len(m_list) - 1] + password
        md5.update(data)
        m_list.append(md5.digest())
        _len += 16
    key = b''.join(m_list)
    return key[:key_len]


def check(key, method_):
    '''check if method_ is supported'''
    Encryptor(key, method_)  # test if the settings if OK


METHOD_SUPPORTED = {
    # 'id': (key_len, ivlen, is_aead)
    'aes-128-cfb': (16, 16, False),
    'aes-192-cfb': (24, 16, False),
    'aes-256-cfb': (32, 16, False),
    'aes-128-ofb': (16, 16, False),
    'aes-192-ofb': (24, 16, False),
    'aes-256-ofb': (32, 16, False),
    'aes-128-ctr': (16, 16, False),
    'aes-192-ctr': (24, 16, False),
    'aes-256-ctr': (32, 16, False),
    'camellia-128-cfb': (16, 16, False),
    'camellia-192-cfb': (24, 16, False),
    'camellia-256-cfb': (32, 16, False),
    'camellia-128-ofb': (16, 16, False),
    'camellia-192-ofb': (24, 16, False),
    'camellia-256-ofb': (32, 16, False),
    'camellia-128-ctr': (16, 16, False),
    'camellia-192-ctr': (24, 16, False),
    'camellia-256-ctr': (32, 16, False),
    'rc4-md5': (16, 16, False),
    'chacha20-ietf': (32, 12, False),
    # 'bypass': (16, 16, False),  # for testing only
    'aes-128-gcm': (16, 16, True),
    'aes-192-gcm': (24, 24, True),
    'aes-256-gcm': (32, 32, True),
    'chacha20-ietf-poly1305': (32, 32, True),
}


def is_aead(method_):
    '''return if method_ is AEAD'''
    return METHOD_SUPPORTED.get(method_)[2]


# class bypass(object):
#     '''dummy stream cipher'''
#     def __init__(self):
#         pass

#     def update(self, buf):
#         '''fake encrypt / decrypt'''
#         return buf


IV_CHECKER = IVChecker()


class Chacha20IETF(object):
    '''chacha20-ietf with python-cryptography'''
    def __init__(self, cipher_name, key, iv):
        self._key = key
        self._iv = iv
        assert cipher_name == 'chacha20-ietf'

        # byte counter, not block counter
        self.counter = 0

    def update(self, data):
        '''encrypt / decrypt'''
        data_len = len(data)

        # we can only prepend some padding to make the encryption align to
        # blocks
        padding = self.counter % 64
        if padding:
            data = (b'\0' * padding) + data

        nonce = struct.pack("<i", self.counter // 64) + self._iv

        algorithm = algorithms.ChaCha20(self._key, nonce)
        cipher = Cipher(algorithm, mode=None, backend=default_backend())
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(data)

        self.counter += data_len

        return cipher_text[padding:]


def get_cipher(key, method, op_, iv_):
    '''get stream cipher'''
    # if method == 'bypass':
    #     return bypass()
    if method == 'rc4-md5':
        md5 = hashlib.md5()
        md5.update(key)
        md5.update(iv_)
        key = md5.digest()
        method = 'rc4'
    cipher = None

    if method in ('rc4', 'chacha20-ietf'):
        pass
    elif method.endswith('ctr'):
        mode = modes.CTR(iv_)
    elif method.endswith('cfb'):
        mode = modes.CFB(iv_)
    elif method.endswith('ofb'):
        mode = modes.OFB(iv_)
    else:
        raise ValueError('operation mode "%s" not supported!' % method.upper())

    if method == 'rc4':
        cipher = Cipher(algorithms.ARC4(key), None, default_backend())
    elif method == 'chacha20-ietf':
        try:
            return Chacha20IETF(method, key, iv_)
        except OSError:
            from .ctypes_libsodium import SodiumCrypto
            return SodiumCrypto(method, key, iv_)
    elif method.startswith('aes'):
        cipher = Cipher(algorithms.AES(key), mode, default_backend())
    elif method.startswith('camellia'):
        cipher = Cipher(algorithms.Camellia(key), mode, default_backend())
    else:
        raise ValueError('crypto algorithm "%s" not supported!' % method.upper())

    return cipher.encryptor() if op_ else cipher.decryptor()


class EncryptorStream(object):
    def __init__(self, password, method):
        if method not in METHOD_SUPPORTED:
            raise ValueError('encryption method not supported')
        if not isinstance(password, bytes):
            password = password.encode('utf8')

        self.method = method
        self._key_len, self._iv_len, _aead = METHOD_SUPPORTED.get(method)
        if _aead:
            raise ValueError('AEAD method is not supported by Encryptor class!')

        self.__key = EVP_BytesToKey(password, self._key_len)

        self._encryptor = None
        self._decryptor = None
        self.encrypt_once = self.encrypt

    def encrypt(self, data):
        if not data:
            raise BufEmptyError
        if not self._encryptor:
            for _ in range(5):
                _len = len(data) + self._iv_len - 2
                iv_ = struct.pack(">H", _len) + random_string(self._iv_len - 2)
                try:
                    IV_CHECKER.check(self.__key, iv_)
                except IVError:
                    continue
                break
            else:
                raise IVError("unable to create iv")
            self._encryptor = get_cipher(self.__key, self.method, 1, iv_)
            return iv_ + self._encryptor.update(data)
        return self._encryptor.update(data)

    def decrypt(self, data):
        if not data:
            raise BufEmptyError
        if self._decryptor is None:
            iv_ = data[:self._iv_len]
            IV_CHECKER.check(self.__key, iv_)
            self._decryptor = get_cipher(self.__key, self.method, 0, iv_)
            data = data[self._iv_len:]
            if not data:
                return b''
        return self._decryptor.update(data)


def Encryptor(password, method):
    '''return shadowsocks Encryptor'''
    if is_aead(method):
        return AEncryptorAEAD(password, method, SS_SUBKEY)
    return EncryptorStream(password, method)


def AEncryptor(key, method, ctx):
    if not is_aead(method):
        method = 'chacha20-ietf-poly1305'
    return AEncryptorAEAD(key, method, ctx)


if sys.version_info[0] == 3:
    def buffer(buf):
        return buf


def get_aead_cipher(key, method):
    '''get_aead_cipher
       method should be AEAD method'''
    if method.startswith('aes'):
        return aead.AESGCM(key)
    try:
        return aead.ChaCha20Poly1305(key)
    except Exception:
        from .ctypes_libsodium import SodiumAeadCrypto
        return SodiumAeadCrypto(method, key)


class AEncryptorAEAD(object):
    '''
    Provide Authenticated Encryption, compatible with shadowsocks AEAD mode.
    '''
    NONCE_LEN = 12
    TAG_LEN = 16

    def __init__(self, key, method, ctx):
        if method not in METHOD_SUPPORTED:
            raise ValueError('encryption method not supported')

        self._key_len, self._iv_len, _aead = METHOD_SUPPORTED.get(method)
        if not _aead:
            raise ValueError('non-AEAD method is not supported by AEncryptor_AEAD class!')

        self.method = method

        self._ctx = ctx  # SUBKEY_INFO
        self.__key = key

        if self._ctx == b"ss-subkey":
            self.encrypt = self.encrypt_ss
            if not isinstance(key, bytes):
                key = key.encode('utf8')
            self.__key = EVP_BytesToKey(key, self._key_len)
        else:
            self.encrypt = self._encrypt
        self.encrypt_once = self._encrypt

        self._encryptor = None
        self._encryptor_nonce = 0

        self._decryptor = None
        self._decryptor_nonce = 0

    def key_expand(self, key, iv):
        algo = hashlib.sha1 if self._ctx == b"ss-subkey" else hashlib.sha256
        prk = hmac.new(iv, key, algo).digest()

        hash_len = algo().digest_size
        blocks_needed = self._key_len // hash_len + (1 if self._key_len % hash_len else 0)  # ceil
        okm = b""
        output_block = b""
        for counter in range(blocks_needed):
            output_block = hmac.new(prk,
                                    buffer(output_block + self._ctx + bytearray((counter + 1,))),
                                    algo
                                    ).digest()
            okm += output_block
        return okm[:self._key_len]

    def _encrypt(self, data, associated_data=None, data_len=0):
        '''
        TCP Chunk (after encryption, *ciphertext*)
        +--------------+------------+
        |    *Data*    |  Data_TAG  |
        +--------------+------------+
        |   Variable   |   Fixed    |
        +--------------+------------+
        for shadowsocks AEAD, this method must be called twice:
        first encrypt Data_Len, then encrypt Data

        '''
        if not data:
            raise BufEmptyError
        nonce = struct.pack('<Q', self._encryptor_nonce) + b'\x00\x00\x00\x00'
        self._encryptor_nonce += 1

        if not self._encryptor:
            _len = len(data) + self._iv_len + self.TAG_LEN - 2
            if self._ctx == b"ss-subkey":
                _len += self.TAG_LEN + data_len

            for _ in range(5):
                if self._ctx == b"ss-subkey":
                    iv_ = struct.pack(">H", _len) + random_string(self._iv_len - 2)
                else:
                    iv_ = random_string(self._iv_len)
                try:
                    IV_CHECKER.check(self.__key, iv_)
                except IVError:
                    continue
                break
            else:
                raise IVError("unable to create iv")
            _encryptor_skey = self.key_expand(self.__key, iv_)
            self._encryptor = get_aead_cipher(_encryptor_skey, self.method)
            cipher_text = self._encryptor.encrypt(nonce, data, associated_data)
            cipher_text = iv_ + cipher_text
        else:
            cipher_text = self._encryptor.encrypt(nonce, data, associated_data)

        return cipher_text

    def encrypt_ss(self, data):
        ct1 = self._encrypt(struct.pack("!H", len(data)), data_len=len(data))
        ct2 = self._encrypt(data)
        return ct1 + ct2

    def decrypt(self, data, associated_data=None):
        if not data:
            raise BufEmptyError

        if self._decryptor is None:
            iv_, data = data[:self._iv_len], data[self._iv_len:]
            IV_CHECKER.check(self.__key, iv_)
            _decryptor_skey = self.key_expand(self.__key, iv_)
            self._decryptor = get_aead_cipher(_decryptor_skey, self.method)

        if not data:
            return b''
        nonce = struct.pack('<Q', self._decryptor_nonce) + b'\x00\x00\x00\x00'
        self._decryptor_nonce += 1
        return self._decryptor.decrypt(nonce, data, associated_data)

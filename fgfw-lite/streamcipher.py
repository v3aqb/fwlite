#!/usr/bin/env python
#-*- coding: UTF-8 -*-

# Copyright (c) 2014 v3aqb
# License: GPLv2+

import os
from Crypto.Util.strxor import strxor


class StreamCipher(object):
    def __init__(self, method, key, iv, mode):
        if method.lower().startswith('rc4'):
            self._encrypt, self._decrypt = self._rc4_encrypt, self._rc4_decrypt
        self.method = method
        self.key = key
        self.iv = iv
        self.iv_len = len(iv)
        self.cipher = self.get_cipher()
        self.__ivecb = self.cipher.encrypt(iv)
        self.__lase_cipher = b''
        self.update = self._encrypt if mode else self._decrypt

    def _encrypt(self, data):
        result = []
        while data:
            this_plaintext, data = data[:len(self.__ivecb)], data[len(self.__ivecb):]
            ivecb, self.__ivecb = self.__ivecb[:len(this_plaintext)], self.__ivecb[len(this_plaintext):]
            cipher = strxor(ivecb, this_plaintext)
            result.append(cipher)
            self.__lase_cipher += cipher
            if not self.__ivecb:
                self.__ivecb, self.__lase_cipher = self.cipher.encrypt(self.__lase_cipher), b''
        return b''.join(result)

    def _decrypt(self, data):
        result = []
        while data:
            this_ciphertext, data = data[:len(self.__ivecb)], data[len(self.__ivecb):]
            ivecb, self.__ivecb = self.__ivecb[:len(this_ciphertext)], self.__ivecb[len(this_ciphertext):]
            self.__lase_cipher += this_ciphertext
            result.append(strxor(ivecb, this_ciphertext))
            if not self.__ivecb:
                self.__ivecb, self.__lase_cipher = self.cipher.encrypt(self.__lase_cipher), b''
        return b''.join(result)

    def _rc4_encrypt(self, data):
        return self.cipher.encrypt(data)

    def _rc4_decrypt(self, data):
        return self.cipher.decrypt(data)

    def get_cipher(self):
        if self.method.lower().startswith('aes'):
            from Crypto.Cipher import AES
            return AES.new(self.key)
        if self.method.lower().startswith('bf'):
            from Crypto.Cipher import Blowfish
            return Blowfish.new(self.key)
        if self.method.lower().startswith('cast'):
            from Crypto.Cipher import CAST
            return CAST.new(self.key)
        if self.method.lower().startswith('rc4'):
            from Crypto.Cipher import ARC4
            return ARC4.new(self.key)
        raise ValueError('crypto method %s not supported!' % self.method)


def main():
    key = b"_M\xcc;Z\xa7e\xd6\x1d\x83'\xde\xb8\x82\xcf\x99+\x95\x99\n\x91Q7J\xbd\x8f\xf8\xc5\xa7\xa0\xfe\x08"
    iv = b'\xb7\xb47,\xdf\xbc\xb3\xd1j&1\xb5\x9bP\x9e\x94'
    method = 'aes_256_cfb'
    cipher = StreamCipher(method, key, iv, 1)
    decipher = StreamCipher(method, key, iv, 0)
    a = cipher.update(b'a long test string')
    b = cipher.update(b'a long test string')
    c = decipher.update(a)
    d = decipher.update(b)
    print(b == '\xc9\xc1h\xe4u\x9b\xa7\x94\x0c\xa6 \xbf\xc7au\xb10\x8a')
    print(repr(a))
    print(repr(b))
    print(repr(c))
    print(repr(d))
    print('encrypt and decrypt 2MB data')
    s = os.urandom(1024)
    import time
    t = time.time()
    for _ in range(1024):
        a = cipher.update(s)
        b = cipher.update(s)
        c = decipher.update(a)
        d = decipher.update(b)
    print('StreamCipher %ss' % (time.time() - t))
    import M2Crypto.EVP
    cipher = M2Crypto.EVP.Cipher(method, key, iv, 1)
    decipher = M2Crypto.EVP.Cipher(method, key, iv, 0)
    t = time.time()
    for _ in range(1024):
        a = cipher.update(s)
        b = cipher.update(s)
        c = decipher.update(a)
        d = decipher.update(b)
    print('M2Crypto %ss' % (time.time() - t))

if __name__ == "__main__":
    main()

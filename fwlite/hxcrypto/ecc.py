'''
ecc.py

This file is part of hxcrypto.

'''

# Copyright (c) 2017-2019 v3aqb

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

import base64
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key,\
    load_der_private_key, load_der_public_key, Encoding, PublicFormat, PrivateFormat, NoEncryption


class Ecc(object):
    curve = {256: ec.SECP521R1,
             192: ec.SECP384R1,
             128: ec.SECP256R1,
             32: ec.SECP521R1,
             24: ec.SECP384R1,
             16: ec.SECP256R1,
             }

    def __init__(self, key_len=128, from_file=None):
        if from_file:
            with open(from_file, 'rb') as key_file:
                data = key_file.read()
            if data.startswith(b'-----'):
                self.ec_private = load_pem_private_key(data, None, backend=default_backend())
            else:
                self.ec_private = load_der_private_key(data, None, backend=default_backend())
        else:
            self.ec_private = ec.generate_private_key(self.curve[key_len](), default_backend())
        self.ec_public = self.ec_private.public_key()

    def get_pub_key(self):
        '''get public key'''
        return self.ec_public.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    def get_pub_key_b64u(self):
        return base64.urlsafe_b64encode(self.get_pub_key()).decode()

    def get_dh_key(self, other):
        '''ECDH exchange'''
        peer_public_key = load_der_public_key(other, backend=default_backend())
        return self.ec_private.exchange(ec.ECDH(), peer_public_key)

    def get_dh_key_b64u(self, other):
        return self.get_dh_key(base64.urlsafe_b64decode(other))

    def save(self, path):
        '''save private key to file'''
        data = self.ec_private.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        with open(path, 'wb') as write_to:
            write_to.write(data)

    def sign(self, data, hash_algo):
        '''Sign the given digest using ECDSA. Returns a signature.'''
        signature = self.ec_private.sign(data, ec.ECDSA(getattr(hashes, hash_algo)()))
        return signature

    def verify(self, data, signature, hash_algo):
        '''Verify the given digest using ECDSA.
           raise Exception if NOT verified.
        '''
        self.ec_public.verify(signature, data, ec.ECDSA(getattr(hashes, hash_algo)()))

    @staticmethod
    def b64u_to_hash(data):
        data = base64.urlsafe_b64decode(data)
        hash_ = hashlib.md5(data).digest()
        return base64.urlsafe_b64encode(hash_).decode()[:8]

    @staticmethod
    def verify_with_pub_key(pubkey, data, signature, hash_algo):
        '''Verify the given digest using ECDSA.
           raise Exception if NOT verified.
        '''
        pubkey = load_der_public_key(pubkey, backend=default_backend())
        pubkey.verify(signature, data, ec.ECDSA(getattr(hashes, hash_algo)()))

    @staticmethod
    def save_pub_key(pubkey, path):
        '''save public key to path'''
        pubk = load_der_public_key(pubkey, backend=default_backend())
        data = pubk.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        with open(path, 'wb') as write_to:
            write_to.write(data)

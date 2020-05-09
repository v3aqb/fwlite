
import hashlib
import base64
import zlib
from hxcrypto import AEncryptor
from hxcrypto import encrypt as _encrypt

CTX = b'v3aqb.hxcrypto'
SUPPORTED_METHOD = ('aes-256-gcm', 'chacha20-ietf-poly1305')
DEFAULT_METHOD = 'aes-256-gcm'


# disable ivchecker
class DummyIVChecker:
    '''DummyIVChecker'''
    def __init__(self, size, timeout):
        pass

    def check(self, key, iv):
        pass


_encrypt.IV_CHECKER = DummyIVChecker(1, 1)


def key_to_bytes(key):
    return hashlib.sha256(key.encode('utf-8')).digest()


def encrypt(key: bytes, plain_text: str, method=DEFAULT_METHOD) -> str:
    if not plain_text:
        return None
    zip_flag = 0
    plain_text = plain_text.encode('utf-8')
    plain_text_zip = zlib.compress(plain_text)
    if len(plain_text_zip) < len(plain_text):
        plain_text = plain_text_zip
        zip_flag = 1
    plain_text = chr(zip_flag).encode('latin1') + plain_text
    crypto = AEncryptor(key, method, CTX)
    cipher_text = crypto.encrypt(plain_text)
    return base64.urlsafe_b64encode(cipher_text).decode()


def decrypt(key: bytes, cipher_text: str) -> str:
    if not cipher_text:
        return None

    method = DEFAULT_METHOD
    cipher_text = base64.urlsafe_b64decode(cipher_text.encode())
    crypto = AEncryptor(key, method, CTX)
    plain_text = crypto.decrypt(cipher_text)
    if plain_text[0] == 1:
        plain_text = zlib.decompress(plain_text[1:])
    else:
        plain_text = plain_text[1:]
    return plain_text.decode('utf-8')

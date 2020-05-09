"""
cryptography module for shadowsocks and hxsocks
"""
# Copyright (c) 2017-2018 v3aqb

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


__version__ = '0.0.3'
from hmac import compare_digest

from cryptography.exceptions import InvalidSignature, InvalidTag

from .encrypt import BufEmptyError, is_aead, Encryptor, AEncryptor, IVError
from .encrypt import METHOD_SUPPORTED as method_supported
from .ecc import ECC

__all__ = ['BufEmptyError',
           'InvalidSignature',
           'InvalidTag',
           'is_aead',
           'Encryptor',
           'AEncryptor',
           'IVError',
           'ECC',
           'compare_digest',
           'method_supported',
           ]

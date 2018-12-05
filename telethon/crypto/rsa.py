"""
This module holds several utilities regarding RSA and server fingerprints.
"""
import os
import struct
from hashlib import sha1

try:
    import rsa
    import rsa.core
except ImportError:
    rsa = None
    raise ImportError('Missing module "rsa", please install via pip.')

from ..tl import TLObject

# {fingerprint: Crypto.PublicKey.RSA._RSAobj} dictionary
_server_keys = {}


def get_byte_array(integer):
    """Return the variable length bytes corresponding to the given int"""
    # Operate in big endian (unlike most of Telegram API) since:
    # > "...pq is a representation of a natural number
    #    (in binary *big endian* format)..."
    # > "...current value of dh_prime equals
    #    (in *big-endian* byte order)..."
    # Reference: https://core.telegram.org/mtproto/auth_key
    return int.to_bytes(
        integer,
        (integer.bit_length() + 8 - 1) // 8,  # 8 bits per byte,
        byteorder='big',
        signed=False
    )


def _compute_fingerprint(key):
    """
    Given a RSA key, computes its fingerprint like Telegram does.

    :param key: the Crypto.RSA key.
    :return: its 8-bytes-long fingerprint.
    """
    n = TLObject.serialize_bytes(get_byte_array(key.n))
    e = TLObject.serialize_bytes(get_byte_array(key.e))
    # Telegram uses the last 8 bytes as the fingerprint
    print(struct.unpack('<q', sha1(n + e).digest()[-8:])[0])
    return struct.unpack('<q', sha1(n + e).digest()[-8:])[0]


def add_key(pub):
    """Adds a new public key to be used when encrypting new data is needed"""
    global _server_keys
    key = rsa.PublicKey.load_pkcs1(pub)
    _server_keys[_compute_fingerprint(key)] = key


def encrypt(fingerprint, data):
    """
    Encrypts the given data known the fingerprint to be used
    in the way Telegram requires us to do so (sha1(data) + data + padding)

    :param fingerprint: the fingerprint of the RSA key.
    :param data: the data to be encrypted.
    :return:
        the cipher text, or None if no key matching this fingerprint is found.
    """
    global _server_keys
    key = _server_keys.get(fingerprint, None)
    if not key:
        return None

    # len(sha1.digest) is always 20, so we're left with 255 - 20 - x padding
    to_encrypt = sha1(data).digest() + data + os.urandom(235 - len(data))

    # rsa module rsa.encrypt adds 11 bits for padding which we don't want
    # rsa module uses rsa.transform.bytes2int(to_encrypt), easier way:
    payload = int.from_bytes(to_encrypt, 'big')
    encrypted = rsa.core.encrypt_int(payload, key.e, key.n)
    # rsa module uses transform.int2bytes(encrypted, keylength), easier:
    block = encrypted.to_bytes(256, 'big')
    return block


# Add default keys
for pub in (
        '''-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAhxVEhBA/UCt4wJ3KDDnyfGdVjt7aiabt2VqubvF+qVfqN3z9u2QZ
uy9llpahF+h1buZlkx/pNWPULmTn/hv5OH08OJFkxvbCCMHAMrFxcZoW02b+YlB/
99blgMuBLvDsFuR0inHB8yZcRAK6nbJKwMyqos4welUA/zJgNLSIkZ2C5zOKZ9qM
GbhAlQ3IDtlGe8qcdQ1lkWXRckws4CyI8RbgEWPThcbocyzk8sQki8l2xMlUUvPv
nOs7Yb6jEfSsNZqwr2+83bh5vSuYl7PUVn9b07N3eEJhjgGKUL4HdTk7j55vPRAy
Uh4CDJezpUKogf2joj8JUSPfMuC6cYenQwIDAQAB
-----END RSA PUBLIC KEY-----''',

        '''-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAxq7aeLAqJR20tkQQMfRn+ocfrtMlJsQ2Uksfs7Xcoo77jAid0bRt
ksiVmT2HEIJUlRxfABoPBV8wY9zRTUMaMA654pUX41mhyVN+XoerGxFvrs9dF1Ru
vCHbI02dM2ppPvyytvvMoefRoL5BTcpAihFgm5xCaakgsJ/tH5oVl74CdhQw8J5L
xI/K++KJBUyZ26Uba1632cOiq05JBUW0Z2vWIOk4BLysk7+U9z+SxynKiZR3/xdi
XvFKk01R3BHV+GUKM2RYazpS/P8v7eyKhAbKxOdRcFpHLlVwfjyM1VlDQrEZxsMp
NTLYXb6Sce1Uov0YtNx5wEowlREH1WOTlwIDAQAB
-----END RSA PUBLIC KEY-----''',

        '''-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAsQZnSWVZNfClk29RcDTJQ76n8zZaiTGuUsi8sUhW8AS4PSbPKDm+
DyJgdHDWdIF3HBzl7DHeFrILuqTs0vfS7Pa2NW8nUBwiaYQmPtwEa4n7bTmBVGsB
1700/tz8wQWOLUlL2nMv+BPlDhxq4kmJCyJfgrIrHlX8sGPcPA4Y6Rwo0MSqYn3s
g1Pu5gOKlaT9HKmE6wn5Sut6IiBjWozrRQ6n5h2RXNtO7O2qCDqjgB2vBxhV7B+z
hRbLbCmW0tYMDsvPpX5M8fsO05svN+lKtCAuz1leFns8piZpptpSCFn7bWxiA9/f
x5x17D7pfah3Sy2pA+NDXyzSlGcKdaUmwQIDAQAB
-----END RSA PUBLIC KEY-----''',

        '''-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAwqjFW0pi4reKGbkc9pK83Eunwj/k0G8ZTioMMPbZmW99GivMibwa
xDM9RDWabEMyUtGoQC2ZcDeLWRK3W8jMP6dnEKAlvLkDLfC4fXYHzFO5KHEqF06i
qAqBdmI1iBGdQv/OQCBcbXIWCGDY2AsiqLhlGQfPOI7/vvKc188rTriocgUtoTUc
/n/sIUzkgwTqRyvWYynWARWzQg0I9olLBBC2q5RQJJlnYXZwyTL3y9tdb7zOHkks
WV9IMQmZmyZh/N7sMbGWQpt4NMchGpPGeJ2e5gHBjDnlIf2p1yZOYeUYrdbwcS0t
UiggS4UeE8TzIuXFQxw7fzEIlmhIaq3FnwIDAQAB
-----END RSA PUBLIC KEY-----'''
):
    add_key(pub)

# for pub in (
#         '''-----BEGIN RSA PUBLIC KEY-----
# MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhxVEhBA/UCt4wJ3KDDny
# fGdVjt7aiabt2VqubvF+qVfqN3z9u2QZuy9llpahF+h1buZlkx/pNWPULmTn/hv5
# OH08OJFkxvbCCMHAMrFxcZoW02b+YlB/99blgMuBLvDsFuR0inHB8yZcRAK6nbJK
# wMyqos4welUA/zJgNLSIkZ2C5zOKZ9qMGbhAlQ3IDtlGe8qcdQ1lkWXRckws4CyI
# 8RbgEWPThcbocyzk8sQki8l2xMlUUvPvnOs7Yb6jEfSsNZqwr2+83bh5vSuYl7PU
# Vn9b07N3eEJhjgGKUL4HdTk7j55vPRAyUh4CDJezpUKogf2joj8JUSPfMuC6cYen
# QwIDAQAB
# -----END RSA PUBLIC KEY-----''',
# ):
#     add_key(pub)

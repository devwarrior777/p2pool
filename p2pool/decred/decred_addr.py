from __future__ import division

import sys
import hashlib
import binascii

#import p2pool
from p2pool.util import pack
from p2pool.decred.blake import BLAKE


def hash160(data):
    # hack for people who don't have openssl - from original p2pool
    if data == '04ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1b3d8090496b53256786bf5c82932ec23c3b74d9f05a6f95a8b5529352656664b'.decode('hex'):
        return "384f570ccc88ac2e7e00b026d1690a3fca63dd0"
    #
    # Decred uses ripemd(blake256(buffer)) for addresses
    #
    return pack.IntType(160).unpack(hashlib.new( 'ripemd160', BLAKE(256).digest(data) ).digest())


#
# Base 58
#

b58_digits = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def base58_encode(b):
    """Encode bytes to a base58-encoded string"""

    # Convert big-endian bytes to integer
    n = int('0x0' + binascii.hexlify(b).decode('utf8'), 16)

    # Divide that integer into bas58
    res = []
    while n > 0:
        n, r = divmod(n, 58)
        res.append(b58_digits[r])
    res = ''.join(res[::-1])

    # Encode leading zeros as base58 zeros
    czero = b'\x00'
    if sys.version > '3':
        # In Python3 indexing a bytes returns numbers, not characters.
        czero = 0
    pad = 0
    for c in b:
        if c == czero:
            pad += 1
        else:
            break
    return b58_digits[0] * pad + res


class InvalidBase58Error(Exception):
    pass

def base58_decode(s):
    """Decode a base58-encoding string, returning bytes"""
    if not s:
        return b''

    # Convert the string to an integer
    n = 0
    for c in s:
        n *= 58
        if c not in b58_digits:
            raise InvalidBase58Error('Character %r is not a valid base58 character' % c)
        digit = b58_digits.index(c)
        n += digit

    # Convert the integer to bytes
    h = '%x' % n
    if len(h) % 2:
        h = '0' + h
    res = binascii.unhexlify(h.encode('utf8'))

    # Add padding back.
    pad = 0
    for c in s[:-1]:
        if c == b58_digits[0]: pad += 1
        else: break
    return b'\x00' * pad + res


#
# Address decode
#

def checksum_decred_decoded(data):
    #
    # Decred a uses double Blake256 ...
    #
    ret = BLAKE(256).digest(BLAKE(256).digest(data))[:4]
    return ret


class ChecksummedType(pack.Type):
    def __init__(self, inner, checksum_func=checksum_decred_decoded):
        self.inner = inner
        self.checksum_func = checksum_func
    
    def read(self, file):
        obj, file = self.inner.read(file)
        data = self.inner.pack(obj)
        #
        calculated_checksum = self.checksum_func(data)
        checksum, file = pack.read(file, len(calculated_checksum))
        if checksum != calculated_checksum:
            raise InvalidBase58Error('invalid checksum {0:x}'.format(checksum))
        return obj, file
    
    def write(self, file, item):
        data = self.inner.pack(item)
        return (file, data), self.checksum_func(data)

#
# decoded_address_type
#
# Holds address bytes after base58 decode
#
#      net         algo                 pubkeyhash
# [net 1-byte][algo 1-byte] [[hash 20-bytes]+[checksum 4-bytes]]
#
# - ChecksummedType also calculates blake256(blake256(checksum)) over 20-byte hash
#
decoded_address_type = ChecksummedType(pack.ComposedType([
    ('net', pack.IntType(8)),
    ('algo', pack.IntType(8)),
    ('pubkey_hash', pack.IntType(160)),
]))


#
# Address functions
#

def pubkey_hash_to_address(pubkey_hash, net):
    packed_addr = decoded_address_type.pack(
        {'net': net.ADDRESS_VERSION_NET, 'algo': net.ADDRESS_VERSION_ALGO, 'pubkey_hash': pubkey_hash})
    encoded_addr = base58_encode(packed_addr)
    return encoded_addr


def pubkey_to_pubkey_hash(pubkey):
    return hash160(pubkey)


def pubkey_to_address(pubkey, net):
    pubkey_hash = pubkey_to_pubkey_hash(pubkey)
    return pubkey_hash_to_address(pubkey_hash, net)


def address_to_pubkey_hash(address, net):
    decoded_address = base58_decode(address)
    dat = decoded_address_type.unpack(decoded_address, ignore_trailing=False)
    if dat.net != net.ADDRESS_VERSION_NET:
        raise ValueError('wrong encoded network {0:x}'.format(dat.net))  
    if dat.algo != net.ADDRESS_VERSION_ALGO:
        raise ValueError('wrong encoded algo {0:x}'.format(dat.algo))
    return dat.pubkey_hash


#
# Script funcs
#

def pubkey_to_script2(pubkey):
    assert len(pubkey) <= 75
    return (chr(len(pubkey)) + pubkey) + '\xac'

def pubkey_hash_to_script2(pubkey_hash):
    return '\x76\xa9' + ('\x14' + pack.IntType(160).pack(pubkey_hash)) + '\x88\xac'

def script2_to_address(script2, net):
    try:
        pubkey = script2[1:-1]
        script2_test = pubkey_to_script2(pubkey)
    except:
        pass
    else:
        if script2_test == script2:
            return pubkey_to_address(pubkey, net)
    
    try:
        pubkey_hash = pack.IntType(160).unpack(script2[3:-2])
        script2_test2 = pubkey_hash_to_script2(pubkey_hash)
    except:
        pass
    else:
        if script2_test2 == script2:
            return pubkey_hash_to_address(pubkey_hash, net)

def script2_to_human(script2, net):
    try:
        pubkey = script2[1:-1]
        script2_test = pubkey_to_script2(pubkey)
    except:
        pass
    else:
        if script2_test == script2:
            return 'Pubkey. Address: %s' % (pubkey_to_address(pubkey, net), )
    
    try:
        pubkey_hash = pack.IntType(160).unpack(script2[3:-2])
        script2_test2 = pubkey_hash_to_script2(pubkey_hash)
    except:
        pass
    else:
        if script2_test2 == script2:
            return 'Address. Address: %s' % (pubkey_hash_to_address(pubkey_hash, net), )
    
    return 'Unknown. Script: %s'  % (script2.encode('hex'), )

if __name__=="__main__":
    #     
    # Test data for mainnet - ripemd(Blake256) - TODO:
    #
    class MainnetSec:
        ADDRESS_VERSION_NET  = 7    # Mainnet
        ADDRESS_VERSION_ALGO = 63   # Secp256k1

    class Testnet2Sec:
        ADDRESS_VERSION_NET  = 15   # TestNet2
        ADDRESS_VERSION_ALGO = 33   # Secp256k1
        

    #
    # MAINNET
    #
    # Test pubkey -> pubkey_hash -> address -> pubkey_hash
    #
    #   "isvalid": true,
    #   "address": "DsaZa37gEchYWc9rhfxFyf3E43yDxwA9cxV",
    #   "ismine": true,
    #   "pubkeyaddr": "DkM4GitLmfHSdxJtSWnwjbftW2FU828E5xsoku5bPCtK3FNaxBSw8",
    #   "pubkey": "02ec6e0865eeffc2fc9e9ece2c3ccdce1be760c713e15484abe0ac6646b1aec49b",
    #   "iscompressed": true,
    #   "account": "default"
    #
    compressed_pubkey = "02ec6e0865eeffc2fc9e9ece2c3ccdce1be760c713e15484abe0ac6646b1aec49b"
    print('compressed_pubkey', compressed_pubkey)
    #
    # pubkey -> pubkey_hash
    #
    pubkey_hash = pubkey_to_pubkey_hash(compressed_pubkey.decode('hex'))
    print('pubkey_hash', pubkey_hash, type(pubkey_hash))
    #
    addr = pubkey_hash_to_address(pubkey_hash, MainnetSec)
    print('address',addr)
    #
    # address -> pub key hash
    #  
    pkh  = address_to_pubkey_hash(addr, MainnetSec)
    print('pubkey_hash', pkh)
    #
    # pub key hash -> address
    #
    addr = pubkey_hash_to_address(pkh, MainnetSec)
    print('address',addr)
    assert addr == "DsaZa37gEchYWc9rhfxFyf3E43yDxwA9cxV"
    print("Mainnet test 1 - PASS\n")
    
    #
    # TESTNET2
    #
    # Test pubkey -> pubkey_hash -> address -> pubkey_hash
    #
    #   "address": "TscoEFWZjuWEqVPNGGzM9X3Pa8iXHk6jgYg",
    #   "ismine": true,
    #   "pubkeyaddr": "TkQ4652aFF6wocnxbkuTK3bCVAqJci4jTQZRbB6kcaisub8WnPi5U",
    #   "pubkey": "035f0d8f932330d3847f9f6cf30201c6292b3b5698981ebb411a3456009300e5ff",
    #   "iscompressed": true,
    #   "account": "default"
    #
    compressed_pubkey = "035f0d8f932330d3847f9f6cf30201c6292b3b5698981ebb411a3456009300e5ff"
    print('compressed_pubkey', compressed_pubkey)
    #
    # pubkey -> pubkey_hash
    #
    pubkey_hash = pubkey_to_pubkey_hash(compressed_pubkey.decode('hex'))
    print('pubkey_hash', pubkey_hash, type(pubkey_hash))
    #
    addr = pubkey_hash_to_address(pubkey_hash, Testnet2Sec)
    print('address',addr)
    #
    # address -> pub key hash
    #  
    pkh, net, algo  = address_to_pubkey_hash(addr, Testnet2Sec)
    print('pubkey_hash', pkh)
    #
    # pub key hash -> address
    #
    addr = pubkey_hash_to_address(pkh, Testnet2Sec)
    print('address',addr)
    assert addr == "TscoEFWZjuWEqVPNGGzM9X3Pa8iXHk6jgYg"
    print("Testnet test 1 - PASS")

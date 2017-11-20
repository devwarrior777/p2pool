from __future__ import division

import hashlib
import random
import warnings

import p2pool
from p2pool.util import math, pack
from p2pool.decred.blake import BLAKE
import struct


def hash256(data):
    return pack.IntType(256).unpack(BLAKE(256).digest(data))


def hash256_sha(data):
    return pack.IntType(256).unpack(hashlib.sha256(hashlib.sha256(data).digest()).digest())


#gf: blake or sha256d here?
def hash160(data):
    if data == '04ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1b3d8090496b53256786bf5c82932ec23c3b74d9f05a6f95a8b5529352656664b'.decode('hex'):
        return 0x384f570ccc88ac2e7e00b026d1690a3fca63dd0 # hack for people who don't have openssl - this is the only value that p2pool ever hashes
    return pack.IntType(160).unpack(hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest())

class ChecksummedType(pack.Type):
    def __init__(self, inner, checksum_func=lambda data: BLAKE(256).digest(data)[:4]):
        self.inner = inner
        self.checksum_func = checksum_func
    
    def read(self, file):
        obj, file = self.inner.read(file)
        data = self.inner.pack(obj)
        
        calculated_checksum = self.checksum_func(data)
        checksum, file = pack.read(file, len(calculated_checksum))
        if checksum != calculated_checksum:
            raise ValueError('invalid checksum')
        
        return obj, file
    
    def write(self, file, item):
        data = self.inner.pack(item)
        return (file, data), self.checksum_func(data)

class FloatingInteger(object):
    __slots__ = ['bits', '_target']
    
    @classmethod
    def from_target_upper_bound(cls, target):
        n = math.natural_to_string(target)
        if n and ord(n[0]) >= 128:
            n = '\x00' + n
        bits2 = (chr(len(n)) + (n + 3*chr(0))[:3])[::-1]
        bits = pack.IntType(32).unpack(bits2)
        return cls(bits)
    
    def __init__(self, bits, target=None):
        self.bits = bits
        self._target = None
        if target is not None and self.target != target:
            raise ValueError('target does not match')
    
    @property
    def target(self):
        res = self._target
        if res is None:
            res = self._target = math.shift_left(self.bits & 0x00ffffff, 8 * ((self.bits >> 24) - 3))
        return res
    
    def __hash__(self):
        return hash(self.bits)
    
    def __eq__(self, other):
        return self.bits == other.bits
    
    def __ne__(self, other):
        return not (self == other)
    
    def __cmp__(self, other):
        assert False
    
    def __repr__(self):
        return 'FloatingInteger(bits=%s, target=%s)' % (hex(self.bits), hex(self.target))

class FloatingIntegerType(pack.Type):
    _inner = pack.IntType(32)
    
    def read(self, file):
        bits, file = self._inner.read(file)
        return FloatingInteger(bits), file
    
    def write(self, file, item):
        return self._inner.write(file, item.bits)

address_type = pack.ComposedType([
    ('services', pack.IntType(64)),
    ('address', pack.IPV6AddressType()),
    ('port', pack.IntType(16, 'big')),
])

#gf->
# tx_type = pack.ComposedType([
#     ('version', pack.IntType(32)),
#     ('tx_ins', pack.ListType(pack.ComposedType([
#         ('previous_output', pack.PossiblyNoneType(dict(hash=0, index=2**32 - 1), pack.ComposedType([
#             ('hash', pack.IntType(256)),
#             ('index', pack.IntType(32)),
#         ]))),
#         ('script', pack.VarStrType()),
#         ('sequence', pack.PossiblyNoneType(2**32 - 1, pack.IntType(32))),
#     ]))),
#     ('tx_outs', pack.ListType(pack.ComposedType([
#         ('value', pack.IntType(64)),
#         ('script', pack.VarStrType()),
#     ]))),
#     ('lock_time', pack.IntType(32)),
# ])


###############################################################################
# https://docs.decred.org/advanced/transaction-details/
###############################################################################

#
# 0 (Full Serialization) - The transaction's prefix is located immediately before it's witness data
#
tx_type_0 = pack.ComposedType([
    ('version', pack.IntType(32)),
    ('tx_ins', pack.ListType(pack.ComposedType([
        ('previous_output', pack.PossiblyNoneType(dict(hash=0, index=2**32 - 1), pack.ComposedType([
            ('hash', pack.IntType(256)),
            ('index', pack.IntType(32)),
            ('tree', pack.IntType(8)),
        ]))),
        ('sequence', pack.IntType(32)),
    ]))),
    ('tx_outs', pack.ListType(pack.ComposedType([
        ('value', pack.IntType(64)),
        ('version', pack.IntType(16)),
        ('script_pk', pack.VarStrType()),
    ]))),
    ('lock_time', pack.IntType(32)),
    ('expiry', pack.IntType(32)),
    #
    # Witness Inputs
    #
    ('wtx_ins', pack.ListType(pack.ComposedType([
        ('value', pack.IntType(64)),
        ('block_height', pack.IntType(32)),
        ('block_index', pack.IntType(32)),
        ('script_sig', pack.VarStrType()),
    ]))),
])

#
# 1 (No witness) - The transaction's prefix is the only data present
#
tx_type_1 = pack.ComposedType([
    ('version', pack.IntType(32)),
    ('tx_ins', pack.ListType(pack.ComposedType([
        ('previous_output', pack.PossiblyNoneType(dict(hash=0, index=2**32 - 1), pack.ComposedType([
            ('hash', pack.IntType(256)),
            ('index', pack.IntType(32)),
            ('tree', pack.IntType(8)),
        ]))),
        ('sequence', pack.IntType(32)),
    ]))),
    ('tx_outs', pack.ListType(pack.ComposedType([
        ('value', pack.IntType(64)),
        ('version', pack.IntType(16)),
        ('script', pack.VarStrType()),
    ]))),
    ('lock_time', pack.IntType(32)),
    ('expiry', pack.IntType(32)),
])

#
# 2 (Only witness) - The transaction's witness data is the only data present. 
#   For each input, this includes its value, block height, block index, and signature script.
#
tx_type_2 = pack.ComposedType([
    # Witness Inputs
    ('wtx_ins', pack.ListType(pack.ComposedType([
        ('value', pack.IntType(64)),
        ('block_height', pack.IntType(32)),
        ('block_index', pack.IntType(32)),
        ('script_sig', pack.VarStrType()),
    ]))),
])


#
# 3 (Witness signing) - The transaction's witness data is the only data present, and is serialized
#   for signing purposes. For each input, this includes only its signature script.
#
tx_type_3 = pack.ComposedType([
    # Witness Inputs
    ('wtx_ins', pack.ListType(pack.ComposedType([
        ('script_sig', pack.VarStrType()),
    ]))),
])

#
# 4 (Witness signing with value) - The transaction's witness data is the only data present, and is
#   serialized for signing purposes. Unlike the Witness signing format, this format includes the 
#   value of each input before its signature script.
#
tx_type_4 = pack.ComposedType([
    # Witness Inputs
    ('wtx_ins', pack.ListType(pack.ComposedType([
        ('value', pack.IntType(64)),
        ('script_sig', pack.VarStrType()),
    ]))),
])


class SerializedTx(object):
    def __init__(self, type_0, type_1, type_2, type_3, type_4):
        self._type_0 = type_0
        self._type_1 = type_1
        self._type_2 = type_2
        self._type_3 = type_3
        self._type_4 = type_4
        self.sertype = 0
    
    def unpack(self, packed_tx, ignore_trailing=False):
        '''
        Deserialize a raw transaction into a Record struct - depending on serialization type
        
        We assume the data is packed 'bytes'. Serialization type is the second little endian word.
        '''
        s = (packed_tx[3] + packed_tx[2]).encode('hex')
        sertype = int(s,16)
        self.sertype = sertype
        if sertype == 0:
            return self._type_0.unpack(packed_tx)
        elif sertype == 1:
            return self._type_1.unpack(packed_tx)
        elif sertype == 2:
            return self._type_2.unpack(packed_tx)
        elif sertype == 3:
            return self._type_3.unpack(packed_tx)
        elif sertype == 4:
            return self._type_4.unpack(packed_tx)
        else:
            raise AssertionError('Unknown serializaation type {}'.format(sertype))
        
    def pack(self,obj):
        sertype = self.sertype
        if sertype == 0:
            return self._type_0.pack(obj)
        elif sertype == 1:
            return self._type_1.pack(obj)
        elif sertype == 2:
            return self._type_2.pack(obj)
        elif sertype == 3:
            return self._type_3.pack(obj)
        elif sertype == 4:
            return self._type_4.pack(obj)
        else:
            raise AssertionError('Unknown serializaation type {}'.format(sertype))
        
    #dummy read/write
    def read(self,file):
        return file
    def write(self, file, item):
        return file, item
#
# General tx_type. Actual type specified by bytes 2, 3 of the initial 4-byte version
#
tx_type = SerializedTx(tx_type_0, tx_type_1, tx_type_2, tx_type_3, tx_type_4)

#<-gf:


merkle_link_type = pack.ComposedType([
    ('branch', pack.ListType(pack.IntType(256))),
    ('index', pack.IntType(32)),
])

merkle_tx_type = pack.ComposedType([
    ('tx', tx_type),
    ('block_hash', pack.IntType(256)),
    ('merkle_link', merkle_link_type),
])

#gf->
#
# Decred block header
#
# Extra data: redefined for pool worker unique id
# Extra data: redefined for extra nonce space (asics) 
# Extra data: undefined
#  
block_header_type = pack.ComposedType([
    ('version', pack.IntType(32)),
    ('previous_block', pack.IntType(256)),
    ('merkle_root', pack.IntType(256)),
    ('stake_root', pack.IntType(256)),
    ('vote_bits', pack.IntType(16)),
    ('final_state', pack.IntType(48, endianness='big')),
    ('voters', pack.IntType(16)),
    ('fresh_stake', pack.IntType(8)),
    ('revocations', pack.IntType(8)),
    ('pool_size', pack.IntType(32)),
    ('bits', pack.IntType(32)),
    ('sbits', pack.IntType(64)),
    ('height', pack.IntType(32)),
    ('size', pack.IntType(32)),
    ('timestamp', pack.IntType(32)),
    ('nonce', pack.IntType(32)),
    ('extra_nonce1', pack.IntType(32)),
    ('extra_nonce2', pack.IntType(32)),
    ('extra', pack.IntType(256 - 64)),
    ('stake_version', pack.IntType(32)),
])
#<-gf

block_type = pack.ComposedType([
    ('header', block_header_type),
    ('txs', pack.ListType(tx_type)),
])

# merged mining

aux_pow_type = pack.ComposedType([
    ('merkle_tx', merkle_tx_type),
    ('merkle_link', merkle_link_type),
    ('parent_block_header', block_header_type),
])

aux_pow_coinbase_type = pack.ComposedType([
    ('merkle_root', pack.IntType(256, 'big')),
    ('size', pack.IntType(32)),
    ('nonce', pack.IntType(32)),
])

def make_auxpow_tree(chain_ids):
    for size in (2**i for i in xrange(31)):
        if size < len(chain_ids):
            continue
        res = {}
        for chain_id in chain_ids:
            pos = (1103515245 * chain_id + 1103515245 * 12345 + 12345) % size
            if pos in res:
                break
            res[pos] = chain_id
        else:
            return res, size
    raise AssertionError()

# merkle trees

merkle_record_type = pack.ComposedType([
    ('left', pack.IntType(256)),
    ('right', pack.IntType(256)),
])

def merkle_hash(hashes): # TODO: Blake256
    if not hashes:
        return 0
    hash_list = list(hashes)
    while len(hash_list) > 1:
        hash_list = [hash256(merkle_record_type.pack(dict(left=left, right=right)))
            for left, right in zip(hash_list[::2], hash_list[1::2] + [hash_list[::2][-1]])]
    return hash_list[0]

def calculate_merkle_link(hashes, index):
    # XXX optimize this
    
    hash_list = [(lambda _h=h: _h, i == index, []) for i, h in enumerate(hashes)]
    
    while len(hash_list) > 1:
        hash_list = [
            (
                lambda _left=left, _right=right: hash256(merkle_record_type.pack(dict(left=_left(), right=_right()))),
                left_f or right_f,
                (left_l if left_f else right_l) + [dict(side=1, hash=right) if left_f else dict(side=0, hash=left)],
            )
            for (left, left_f, left_l), (right, right_f, right_l) in
                zip(hash_list[::2], hash_list[1::2] + [hash_list[::2][-1]])
        ]
    
    res = [x['hash']() for x in hash_list[0][2]]
    
    assert hash_list[0][1]
    if p2pool.DEBUG:
        new_hashes = [random.randrange(2**256) if x is None else x
            for x in hashes]
        assert check_merkle_link(new_hashes[index], dict(branch=res, index=index)) == merkle_hash(new_hashes)
    assert index == sum(k*2**i for i, k in enumerate([1-x['side'] for x in hash_list[0][2]]))
    
    return dict(branch=res, index=index)

def check_merkle_link(tip_hash, link):
    if link['index'] >= 2**len(link['branch']):
        raise ValueError('index too large')
    return reduce(lambda c, (i, h): hash256(merkle_record_type.pack(
        dict(left=h, right=c) if (link['index'] >> i) & 1 else
        dict(left=c, right=h)
    )), enumerate(link['branch']), tip_hash)

# targets

def target_to_average_attempts(target):
    assert 0 <= target and isinstance(target, (int, long)), target
    if target >= 2**256: warnings.warn('target >= 2**256!')
    return 2**256//(target + 1)

def average_attempts_to_target(average_attempts):
    assert average_attempts > 0
    return min(int(2**256/average_attempts - 1 + 0.5), 2**256-1)

def target_to_difficulty(target):
    assert 0 <= target and isinstance(target, (int, long)), target
    if target >= 2**256: warnings.warn('target >= 2**256!')
    return (0xffff0000 * 2**(256-64) + 1)/(target + 1)

def difficulty_to_target(difficulty):
    assert difficulty >= 0
    if difficulty == 0: return 2**256-1
    return min(int((0xffff0000 * 2**(256-64) + 1)/difficulty - 1 + 0.5), 2**256-1)

# human addresses

base58_alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def base58_encode(bindata):
    bindata2 = bindata.lstrip(chr(0))
    return base58_alphabet[0]*(len(bindata) - len(bindata2)) + math.natural_to_string(math.string_to_natural(bindata2), base58_alphabet)

def base58_decode(b58data):
    b58data2 = b58data.lstrip(base58_alphabet[0])
    return chr(0)*(len(b58data) - len(b58data2)) + math.natural_to_string(math.string_to_natural(b58data2, base58_alphabet))

human_address_type = ChecksummedType(pack.ComposedType([
    ('version', pack.IntType(8)),
    ('pubkey_hash', pack.IntType(160)),
]))

def pubkey_hash_to_address(pubkey_hash, net):
#     return base58_encode(human_address_type.pack(dict(version=net.ADDRESS_VERSION, pubkey_hash=pubkey_hash)))
    human = dict(version=0, pubkey_hash=pubkey_hash)
    hat = human_address_type.pack(human)
    return base58_encode(hat)

def pubkey_to_address(pubkey, net):
    return pubkey_hash_to_address(hash160(pubkey), net)

def address_to_pubkey_hash(address, net):
    x = human_address_type.unpack(base58_decode(address))
    if x['version'] != net.ADDRESS_VERSION:
        raise ValueError('address not for this net!')
    return x['pubkey_hash']

# transactions - FIXME: for decred

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
            return 'Pubkey. Address: %s' % (pubkey_to_address(pubkey, net),)
    
    try:
        pubkey_hash = pack.IntType(160).unpack(script2[3:-2])
        script2_test2 = pubkey_hash_to_script2(pubkey_hash)
    except:
        pass
    else:
        if script2_test2 == script2:
            return 'Address. Address: %s' % (pubkey_hash_to_address(pubkey_hash, net),)
    
    return 'Unknown. Script: %s'  % (script2.encode('hex'),)

if __name__=="__main__":
    #     
    # Test - Blake256
    #     
    d = b'\x00'
    h = BLAKE(256).digest(d)
    print("hash of '{0}' is \n'{1}' \nstr {2}\n".format(d.encode('hex'),h,h.encode('hex')))
    # Expected: 0ce8d4ef4dd7cd8d62dfded9d4edb0a774ae6a41929a74da23109e8f11139c87
    
    d = b'\x00'*72
    h = BLAKE(256).digest(d)
    print("hash of '{0}' is \n'{1}' \nstr {2}\n".format(d.encode('hex'),h,h.encode('hex')))
    # Expected: 0ce8d4ef4dd7cd8d62dfded9d4edb0a774ae6a41929a74da23109e8f11139c87
   
    l = long(0x00000000000000000000000000000000000000000000000000000000000)
    h = hash256(l)
    print("hash of '{0}' is \n{1} \nhex: {2}'\n".format(l,h,hex(h)))
    
    #     
    # Test - Parse Transaction
    #     
    data = "01000000020e5551a794baacdc45c453d8ce3d511058dc6618977884f685bc3cc878bbb3bf0100000000ffffffffe14810a5123cdddc98e2a1040cd584ac2a172a2c2cda36d98a94e34bf12985ba0200000001ffffffff02c347dac00100000000001976a9145ed0b86ae903b337a58203b84c98aa004473d61e88ac7cb097570100000000001976a9140459aa94d72597122586c011c5e29d3a7a9db3e388ac0000000000000000021f74a71a01000000b1dc0200030000006a47304402201b12b4f88d172ea24b94ef71b68c25d83072239c37aa70205f56a8c83adeb21c0220151851dc0a2ed80f86bc96dab3c2d190a81296be8ca83dd8578db1ce56a405b7012102a3f6cf568ed663348118f7dfd412253b61a3e93d4eb6cf3ce9046b3c18e4e393cc27cbfd01000000b4db0200020000006b483045022100d194f05a7a2a5c54744cf305b5e3d6a925f4ed300c924eff135b8719bd0048c8022074da56a7d7035393fce62ccd238a972a3f332b15f588bed62156ea5082dc4d8a012102c074fe37ac06734bfd2b8aeedc23e38c0487418d0aa885af285b31ccebed9fec"
    hash = "fa7003848826f8fec2041d05b26f90ff9447fa14eb8fde66079074b3a5005332"
    packed_tx = data.decode('hex')
    packed_hash = hash.decode('hex')
    print(packed_hash.encode('hex'))
    transaction = tx_type.unpack(packed_tx, ignore_trailing=False)
    print(transaction)
    # Test re-pack
    pkdtx = tx_type.pack(transaction)
    assert pkdtx == packed_tx
    
    #     
    # Test - Parse Block Header
    #
    block_header = "0500000068c69fa348fa573e026a019023e8dd68bfd1015d83e3787a6900000000000000a6007c15b73f3c7cdb213bf21507590c8b20ce35d01a87f2c4193659419ca4910da437a68c2ad4097dfd361f6a677004edf2b2443895e119d98286c4f873aef80100089e4f047cc705001400da9f00000cca001a90e814bf01000000dcdd02005b3400006c99125a06df158dc79d268ec36218fc00000000000000000000000000000000000000000000000005000000"
    packed_header = block_header.decode('hex')
    header_fields = block_header_type.unpack(packed_header, ignore_trailing=False)  
    print("\nBlock Header:")
    for k in header_fields.keys():
        print(k, hex(header_fields[k]))
    
    #
    # bits -> floating integer
    #
    bits = header_fields.bits
    print(bits,type(bits))
    fib = FloatingInteger(bits)
    print(fib,(type(fib)))
    print
    
    #
    # pub key hash -> address
    #
    # 
    # TscoEFWZjuWEqVPNGGzM9X3Pa8iXHk6jgYg
    #
    # TkQ4652aFF6wocnxbkuTK3bCVAqJci4jTQZRbB6kcaisub8WnPi5U
    #
    # 035f0d8f932330d3847f9f6cf30201c6292b3b5698981ebb411a3456009300e5ff
    # 
    class net:
        ADDRESS_VERSION = 1
    pubkey_hash = 'TkQ4652aFF6wocnxbkuTK3bCVAqJci4jTQZRbB6kcaisub8WnPi5U'
    res = pubkey_hash_to_address(pubkey_hash, net)
    print res
    
    
    
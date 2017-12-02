from __future__ import division

import hashlib
import random
import warnings

import p2pool
from p2pool.util import math, pack
from p2pool.decred.blake import BLAKE
from copy import copy as _copy
from p2pool.util.pack import IntType

def blake256(data):
    return BLAKE(256).digest(data)
    
def hash256(data):
    return pack.IntType(256).unpack(blake256(data))

def hash256d(data):
    return pack.IntType(256).unpack(blake256(blake256(data)))

def hash256_sha(data):
    return pack.IntType(256).unpack(hashlib.sha256(hashlib.sha256(data).digest()).digest())

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


###############################################################################
# https://docs.decred.org/advanced/transaction-details/
###############################################################################

#
# 0 (Full Serialization) - The transaction's prefix is located immediately before it's witness data
#
tx_type_0 = pack.ComposedType([
    ('version', pack.IntType(16)),
    ('sertype', pack.IntType(16)),
    ('tx_ins', pack.ListType(pack.ComposedType([
        ('outpoint', pack.PossiblyNoneType(dict(hash=0, index=2**32 - 1), pack.ComposedType([
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
    ('version', pack.IntType(16)),
    ('sertype', pack.IntType(16)),
    ('tx_ins', pack.ListType(pack.ComposedType([
        ('outpoint', pack.PossiblyNoneType(dict(hash=0, index=2**32 - 1), pack.ComposedType([
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


#
# Helper to quickly assess if the transaction is SerTypeFull - version 1, sertype 0
#
tx_type_version_sertype = pack.ComposedType([
    ('version', pack.IntType(16)),
    ('sertype', pack.IntType(16)),
])

#
# SerializedTx
# 

class SerializedTxException(Exception): pass

class SerializedTx(object):
    '''  
    https://docs.decred.org/advanced/transaction-details/
    
    This is a wrapper for 'tx_type' which is a struct that decodes prefix and witness data
    
    For mining we ignore everything on the wire except SerTypeFull - 0 ... for now!
    '''
    def __init__(self):
        self.type_0 = tx_type_0
    
    def get_all(self, raw_tx_pkd):
        '''
        new code can use this to get a full decode of the whole wire tx message
        '''
        version_sertype = tx_type_version_sertype.unpack(raw_tx_pkd, ignore_trailing=True)
        if version_sertype.sertype != 0:
            raise SerializedTxException('Only SerTypeFull wire transactions supported')
        tx_full = self.type_0.unpack(raw_tx_pkd, ignore_trailing=False)             # prefix + witness
        #
        # Prefix
        #
        prefix = tx_type_1.unpack(raw_tx_pkd, ignore_trailing=True)
        prefix_len = tx_type_1.packed_size(prefix)
        #
        # Prefix hash: Must set to sertype 1 before hashing: msgtx.go
        #
        prefix_ser_1 = _copy(prefix)
        prefix_ser_1.sertype = 1
        prefix_ser_1_pkd = tx_type_1.pack(prefix_ser_1)
        prefix_hash = hash256(prefix_ser_1_pkd)                                     # H1(prefix) 
        #
        # Witness
        #
        wit_pkd = raw_tx_pkd[prefix_len:]
        witness = tx_type_2.unpack(wit_pkd, ignore_trailing=False)
        #
        # Witness hash: Must prepend version sertype (uint32) and set to sertype 2 before hashing: msgtx.go
        #
        ver_ser_2 = _copy(version_sertype)
        ver_ser_2.sertype = 2
        ver_ser_2_pkd = tx_type_version_sertype.pack(ver_ser_2)
        witness_ser_2_pkd = ver_ser_2_pkd + wit_pkd
        witness_hash = hash256(witness_ser_2_pkd)                                   # H2(witness)
        #
        # FullTx hash: Hash ( H1(prefix) concat H2(witness) )
        #
        prefix_hash_pkd = IntType(256).pack(prefix_hash)
        witness_hash_pkd = IntType(256).pack(witness_hash)
        concat_pkd = prefix_hash_pkd + witness_hash_pkd
        tx_full_hash = hash256(concat_pkd)
        
        return dict(
            tx_full=tx_full,
            tx_full_hash=tx_full_hash,
            prefix=prefix,
            prefix_hash=prefix_hash,
            witness=witness,
            witness_hash=witness_hash
            )


#     def get_all(self, raw_tx_pkd):
#         '''
#         new code can use this to get a full decode of the whole wire tx message
#         '''
#         version_sertype = tx_type_version_sertype.unpack(raw_tx_pkd, ignore_trailing=True)
#         if version_sertype.sertype != 0:
#             raise SerializedTxException('Only SerTypeFull wire transactions supported')
#         full_tx = self.type_0.unpack(raw_tx_pkd, ignore_trailing=False)                 # prefix + witness
#         
#         prefix = tx_type_1.unpack(raw_tx_pkd, ignore_trailing=True)                     # prefix
#         prefix_len = tx_type_1.packed_size(prefix)
#         
#         wit_pkd = raw_tx_pkd[prefix_len:]                                               # witness
#         witness = tx_type_2.unpack(wit_pkd, ignore_trailing=False)
#         #
#         # Must set to sertype 1 before hashing: msgtx.go
#         #
#         prefix_ser_1 = _copy(prefix)                                                     # H(prefix)
#         prefix_ser_1.sertype = 1
#         prefix_ser_1_pkd = tx_type_1.pack(prefix_ser_1)
#         tx_hash = hash256(prefix_ser_1_pkd)
#         #
#         return full_tx, prefix, witness, tx_hash
          
    def unpack(self, raw_tx_pkd, ignore_trailing=False):
        '''
        Deserialize a raw transaction into a tx_type_0 Record struct
        
        @param raw_tx_:               packed str containing raw tx data 'bytes'
        @raise SerializedTxException: if sertype is not 0

        old code can comtinue to use this to get a full decode of the whole wire 
        tx message by calling ts_type.update(<packed tx sertype 0>)
        '''
        version_sertype = tx_type_version_sertype.unpack(raw_tx_pkd, ignore_trailing=True)
        if version_sertype.sertype != 0:
            raise SerializedTxException('Only SerTypeFull wire transactions supported')
        return self.type_0.unpack(raw_tx_pkd, ignore_trailing=False)    # prefix + witness
        
    def pack(self, obj):
        '''
        Re-serialize the tx_type_0 Record struct into the unpacked raw transaction
        '''
        return self.type_0.pack(obj)
    
    def packed_size(self, obj):
        '''
        Get the packed size of the underlying object
        '''
        return self.type_0.packed_size(obj)
                    
    def read(self, f):
        return self.type_0.read(f)

    def write(self, f, item):
        return self.type_0.write(f, item)
#
# wrapper    
#
tx_type = SerializedTx()

###############################################################################
# https://docs.decred.org/advanced/block-header-specifications/
###############################################################################

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

block_type = pack.ComposedType([
    ('header', block_header_type),
    ('txs', pack.ListType(SerializedTx)),
])


###############################################################################
# merkle tree manipulation
###############################################################################

merkle_link_type = pack.ComposedType([
    ('branch', pack.ListType(pack.IntType(256))),
    ('index', pack.IntType(32)),
])

merkle_tx_type = pack.ComposedType([
    ('tx', SerializedTx),
    ('block_hash', pack.IntType(256)),
    ('merkle_link', merkle_link_type),
])

merkle_record_type = pack.ComposedType([
    ('left', pack.IntType(256)),
    ('right', pack.IntType(256)),
])

# def merkle_hash(hashes): # TODO: Blake256
#     if not hashes:
#         return 0
#     hash_list = list(hashes)
#     while len(hash_list) > 1:
#         hash_list = [hash256(merkle_record_type.pack(dict(left=left, right=right)))
#             for left, right in zip(hash_list[::2], hash_list[1::2] + [hash_list[::2][-1]])]
#     return hash_list[0]
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



if __name__=="__main__":
    def _rev(hexb):
        '''
        In:     Hex encoded 'byte' str  '414243' or '4142433'
        Out:    The byte string with the order reversed. '434241' or '30434241'
                Zero padded before reverse if input ends with an odd number of encoded hex 'bytes'
        '''
        rev = []
        ln = len(hexb)
        if ln%2:
            return ''
        lastpos = ln -1
        firstpos = 0
        step = -2
        for i in range(lastpos,firstpos,step):
            rev.append(hexb[i-1])
            rev.append(hexb[i])
        return ''.join(rev)
            
    def dumptx(tx):
        print '-----------------'
        print 'TX'
        print '-----------------'
        for k in tx.keys():
            v = tx[k]
            if k == 'version':
                print k,hex(v)
            if k == 'sertype':
                print k,hex(v)
            elif k == 'expiry':
                print k,hex(v)
            elif k == 'lock_time':
                print k,hex(v)
            elif k == 'tx_ins':
                print 'tx_ins'
                for o in v:
                    print'  outpoint'
                    print'    index', hex(o.outpoint.index)
                    print'    hash', hex(o.outpoint.hash)
                    print'    tree', o.outpoint.tree
                    print'  sequence', hex(o.sequence)
            elif k == 'tx_outs':
                print 'tx_outs'
                for o in v:
                    print'  version', hex(o.version)
                    print'  value', o.value
                    print'  script_pk', o.script_pk.encode('hex')
        print '-----------------'

    def dumpwtx(tx):
        print '-----------------'
        print 'WTX'
        print '-----------------'
        for k in tx.keys():
            v = tx[k]
            if k == 'wtx_ins':
                print 'wtx_ins'
                for o in v:
                    print'  block_index', hex(o.block_index)
                    print'  script_sig', o.script_sig.encode('hex')
                    print'  block_height', o.block_height
        print '-----------------'

    #     
    # Test - Parse Block Header
    #
    block_header = "0500000068c69fa348fa573e026a019023e8dd68bfd1015d83e3787a6900000000000000a6007c15b73f3c7cdb213bf21507590c8b20ce35d01a87f2c4193659419ca4910da437a68c2ad4097dfd361f6a677004edf2b2443895e119d98286c4f873aef80100089e4f047cc705001400da9f00000cca001a90e814bf01000000dcdd02005b3400006c99125a06df158dc79d268ec36218fc00000000000000000000000000000000000000000000000005000000"
    packed_header = block_header.decode('hex')
    header_fields = block_header_type.unpack(packed_header, ignore_trailing=False)  
    print(header_fields)
    print("\nBlock Header:")
    for k in header_fields.keys():
        print(k, hex(header_fields[k]))
    # Test packed size
    pkd_size = block_header_type.packed_size(header_fields)
    print
    print('packed size', pkd_size, type(pkd_size))
    # Test re-pack
    pkdhdr = block_header_type.pack(header_fields)
    assert pkdhdr == packed_header
    print
    
    #     
    # Parse the 2 Regular Transactions from testnet2 block 100,000
    #
    
    #
    # 0. Coinbase - 49a89e0e84bbb3e2671a9b990ea7f824028ac46b7df9fffbdfd1e16c603aa425
    #
    tx0_raw = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff030b1b3e09000000000000144fa6cbd0dbe5ec407fe4c8ad374e667771fa0d4400000000000000000000266a24a0860100000000000000000000000000000000000000000000000000fa550bdded3592f50a8e79370000000000001976a9149d8e8bdc618035be32a14ab752af2e331f9abf3688ac00000000000000000150bdb2400000000000000000ffffffff0800002f646372642f"
    packed_tx0 = tx0_raw.decode('hex')
    tx0 = tx_type.unpack(packed_tx0)
    
    alldata = tx_type.get_all(packed_tx0)
    print alldata['tx_full']
    print alldata['prefix']
    print hex(alldata['prefix_hash'])
    print alldata['witness']
    print hex(alldata['witness_hash'])
    assert alldata['prefix_hash'] == 0x49a89e0e84bbb3e2671a9b990ea7f824028ac46b7df9fffbdfd1e16c603aa425L
    print


    #
    # 1. b0c5d12a01b636ab044c3f709dbfb26fedaf3b07f0e4f4b0f91479b73388b871
    #
    tx1_raw = "010000000930072588364d4085b2facea8d7a33a54c91236af73c5bab99fb12292a69e4ec70500000000ffffffff466d95994b5268f175b80e17e129e747cd49a13be6ad2f6e2cdf22aa574352d20200000000ffffffff80480d01223f44545fb8226b14d91599a54d3ac2c3647f37af95528409835efe0200000001ffffffff804b9f56f55ce0026ca815fe1b6e2b78a25cde305097401dd762a0a4c1592e090200000001ffffffff809d67ad85582cb64f880aa1012e5279f05ee9ccec2168177000474d70d483b50200000001ffffffff81279ef649967b5a4a56bc0c036db40c8547b72660f3877d6635619fcef01e3e0200000001ffffffff81353ccadb539d37803d937130683c26ff6e88f6f62c38e55b8e3ef69c791a3c0200000001ffffffff8148ae90db48f90092d79998763605c9091635d99475c986c29cfe0a8562ce3a0200000000ffffffff81c695d5dfa3e06377065cb44378ce5fe1fff48b3c44fa730092339c19c6b8f80200000001ffffffff06977df9520100000000001976a91465a8be1de0e0af4b7d4429aa2b5032af9711c64388ac977df9520100000000001976a91465a8be1de0e0af4b7d4429aa2b5032af9711c64388ac977df9520100000000001976a91465a8be1de0e0af4b7d4429aa2b5032af9711c64388ac977df9520100000000001976a91465a8be1de0e0af4b7d4429aa2b5032af9711c64388ac977df9520100000000001976a91465a8be1de0e0af4b7d4429aa2b5032af9711c64388ac19a25d030100000000001976a91497a93b29fe5454b4080534b6d595a6121c18080188ac000000000000000009e405e06a000000009f860100010000006a473044022018fa18347aaf9534431111797f71771d337f4fde7870551a5a4bf76f7e64ba2f02201ba1db79983f07114b3f7227905928bc25550822c21b4385c4468b6c3bdf78c5012103ecdea47d34b6ce060fd23c70b3758f5fbcd5e18820d80d8cfa007817b99e107083cb78370000000090860100000000006b4830450221009b7107e3d2cdf46f2d55985026a501ab40f207c8537d0013dd5cf33de293575902207477c79de3b897b7b385349ba6434d89ee0e0c0c5c853b11e4844d50f1afaaf50121024d9134e6176f99dbe95b155f3638a55530e3776c2b6c8bd2234dbfbdbcae732a28efb93501000000d3850100030000006b483045022100855de5ba1b482e555d5380138fa314583b39af6032f32bd78c125afa1502bd490220382aaa933ce6151a257dae4081f4438b2cd5688c48e273f5e0f349e26807242b0121024d9134e6176f99dbe95b155f3638a55530e3776c2b6c8bd2234dbfbdbcae732aff4a2a1101000000a3850100040000006a47304402202caf9b32aa076cd39634094e8ec2f58087c47823b808dba1afde296d9fa390ce0220373eb2f2a2bacab5d00cef64b2d2f3c331ec632f611f070c0ef73dc6e127a7560121024d9134e6176f99dbe95b155f3638a55530e3776c2b6c8bd2234dbfbdbcae732aa6f733ff0000000098850100040000006a473044022077405f353442c6bc8c0e9c4e5dc3f90affec08555ffa8abee4017c1150d6c4d502204a589cebbe3ddda2c5ee2f17eddbd5776f92a5078ff5ce0969ec85a953d854870121024d9134e6176f99dbe95b155f3638a55530e3776c2b6c8bd2234dbfbdbcae732af27ecc500100000010860100040000006a473044022055e7630bf8d2b3036baf634201c0dd050fef7735d1b0b690e1f1161fad64e310022000cabc2c84af220c57f71fc407160d8d3de9ef0c9b6800ddaed79e323ac7b2f10121024d9134e6176f99dbe95b155f3638a55530e3776c2b6c8bd2234dbfbdbcae732a1d9c7a2b0100000045850100020000006a47304402203d7f1dbbc137be8aa6523489c95081981302ea9610829dc72850dc23be5de9e1022074b7ef769ec5df0d77c5c886241c7ca3df9df2bb5c7d918403d3e532329211fe0121024d9134e6176f99dbe95b155f3638a55530e3776c2b6c8bd2234dbfbdbcae732a9e4e5d2c00000000d4850100000000006a47304402204a3a38560480df5e7ffd0a14464ee34a06695e23754c2abbfd9a30b1f7d40227022059b6128ef5ececc42479d5084cc57f0e6eb36815f20faa9fc98e9f25278e728d0121024d9134e6176f99dbe95b155f3638a55530e3776c2b6c8bd2234dbfbdbcae732aff4a2a1101000000c3850100020000006b483045022100b178e715bc61c80a06e3b522e21d51af81598acf9b2f05dfaf88341288e2388d02204f7511749e6b4ab89b2c46f4e7057324396887df5b088da93b7918f93b634ef30121024d9134e6176f99dbe95b155f3638a55530e3776c2b6c8bd2234dbfbdbcae732a"
    packed_tx1 = tx1_raw.decode('hex')
    tx1 = tx_type.unpack(packed_tx1)
    print tx1
    
#     tx1 = tx_type.unpack(packed_tx1, ignore_trailing=False)
#     dumptx(tx1)
#     dumpwtx(tx1)
#     
#     tx1_sertype1_raw = "010001000930072588364d4085b2facea8d7a33a54c91236af73c5bab99fb12292a69e4ec70500000000ffffffff466d95994b5268f175b80e17e129e747cd49a13be6ad2f6e2cdf22aa574352d20200000000ffffffff80480d01223f44545fb8226b14d91599a54d3ac2c3647f37af95528409835efe0200000001ffffffff804b9f56f55ce0026ca815fe1b6e2b78a25cde305097401dd762a0a4c1592e090200000001ffffffff809d67ad85582cb64f880aa1012e5279f05ee9ccec2168177000474d70d483b50200000001ffffffff81279ef649967b5a4a56bc0c036db40c8547b72660f3877d6635619fcef01e3e0200000001ffffffff81353ccadb539d37803d937130683c26ff6e88f6f62c38e55b8e3ef69c791a3c0200000001ffffffff8148ae90db48f90092d79998763605c9091635d99475c986c29cfe0a8562ce3a0200000000ffffffff81c695d5dfa3e06377065cb44378ce5fe1fff48b3c44fa730092339c19c6b8f80200000001ffffffff06977df9520100000000001976a91465a8be1de0e0af4b7d4429aa2b5032af9711c64388ac977df9520100000000001976a91465a8be1de0e0af4b7d4429aa2b5032af9711c64388ac977df9520100000000001976a91465a8be1de0e0af4b7d4429aa2b5032af9711c64388ac977df9520100000000001976a91465a8be1de0e0af4b7d4429aa2b5032af9711c64388ac977df9520100000000001976a91465a8be1de0e0af4b7d4429aa2b5032af9711c64388ac19a25d030100000000001976a91497a93b29fe5454b4080534b6d595a6121c18080188ac000000000000000009e405e06a000000009f860100010000006a473044022018fa18347aaf9534431111797f71771d337f4fde7870551a5a4bf76f7e64ba2f02201ba1db79983f07114b3f7227905928bc25550822c21b4385c4468b6c3bdf78c5012103ecdea47d34b6ce060fd23c70b3758f5fbcd5e18820d80d8cfa007817b99e107083cb78370000000090860100000000006b4830450221009b7107e3d2cdf46f2d55985026a501ab40f207c8537d0013dd5cf33de293575902207477c79de3b897b7b385349ba6434d89ee0e0c0c5c853b11e4844d50f1afaaf50121024d9134e6176f99dbe95b155f3638a55530e3776c2b6c8bd2234dbfbdbcae732a28efb93501000000d3850100030000006b483045022100855de5ba1b482e555d5380138fa314583b39af6032f32bd78c125afa1502bd490220382aaa933ce6151a257dae4081f4438b2cd5688c48e273f5e0f349e26807242b0121024d9134e6176f99dbe95b155f3638a55530e3776c2b6c8bd2234dbfbdbcae732aff4a2a1101000000a3850100040000006a47304402202caf9b32aa076cd39634094e8ec2f58087c47823b808dba1afde296d9fa390ce0220373eb2f2a2bacab5d00cef64b2d2f3c331ec632f611f070c0ef73dc6e127a7560121024d9134e6176f99dbe95b155f3638a55530e3776c2b6c8bd2234dbfbdbcae732aa6f733ff0000000098850100040000006a473044022077405f353442c6bc8c0e9c4e5dc3f90affec08555ffa8abee4017c1150d6c4d502204a589cebbe3ddda2c5ee2f17eddbd5776f92a5078ff5ce0969ec85a953d854870121024d9134e6176f99dbe95b155f3638a55530e3776c2b6c8bd2234dbfbdbcae732af27ecc500100000010860100040000006a473044022055e7630bf8d2b3036baf634201c0dd050fef7735d1b0b690e1f1161fad64e310022000cabc2c84af220c57f71fc407160d8d3de9ef0c9b6800ddaed79e323ac7b2f10121024d9134e6176f99dbe95b155f3638a55530e3776c2b6c8bd2234dbfbdbcae732a1d9c7a2b0100000045850100020000006a47304402203d7f1dbbc137be8aa6523489c95081981302ea9610829dc72850dc23be5de9e1022074b7ef769ec5df0d77c5c886241c7ca3df9df2bb5c7d918403d3e532329211fe0121024d9134e6176f99dbe95b155f3638a55530e3776c2b6c8bd2234dbfbdbcae732a9e4e5d2c00000000d4850100000000006a47304402204a3a38560480df5e7ffd0a14464ee34a06695e23754c2abbfd9a30b1f7d40227022059b6128ef5ececc42479d5084cc57f0e6eb36815f20faa9fc98e9f25278e728d0121024d9134e6176f99dbe95b155f3638a55530e3776c2b6c8bd2234dbfbdbcae732aff4a2a1101000000c3850100020000006b483045022100b178e715bc61c80a06e3b522e21d51af81598acf9b2f05dfaf88341288e2388d02204f7511749e6b4ab89b2c46f4e7057324396887df5b088da93b7918f93b634ef30121024d9134e6176f99dbe95b155f3638a55530e3776c2b6c8bd2234dbfbdbcae732a"
#     packed_tx1_sertype1 = tx1_sertype1_raw.decode('hex')
#     non_witness_tx1 = tx_type_1.unpack(packed_tx1_sertype1, ignore_trailing=True)
#     dumptx(non_witness_tx1)
#     dumpwtx(non_witness_tx1)
#     
#     
#     non_witness_tx1_packed = tx_type_1.pack(non_witness_tx1)
#     h1 = hash256(non_witness_tx1_packed)
#     print 'Tx Hash', hex(h1)
#     assert h1 == 0xb0c5d12a01b636ab044c3f709dbfb26fedaf3b07f0e4f4b0f91479b73388b871L
# 
#     b1 = blake256(non_witness_tx1_packed)
#     print b1.encode('hex')
#     
#     print '---'
#     
#     
#     #
#     # witness only .. test
#     #
#     non_witness_tx1_packed_size = tx_type_1.packed_size(non_witness_tx1)
#     witness_tx1_raw = tx1_raw[non_witness_tx1_packed_size:]
#     if len(witness_tx1_raw)%2:
#         witness_tx1_raw += '0'
#     witness_tx1_packed = witness_tx1_raw.decode('hex')
#     witness_tx1 = tx_type_2.unpack(witness_tx1_packed, ignore_trailing=True)
#     print
    
    
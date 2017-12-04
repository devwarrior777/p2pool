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
        Deserialize a raw transaction into all component parts
        
        @param raw_tx_pkd:            packed str containing raw tx data 'bytes'
        @raise SerializedTxException: if sertype is not 0
        
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


    def unpack(self, raw_tx_pkd, ignore_trailing=False):
        '''
        Deserialize a raw transaction into a tx_type_0 Record struct
        
        @param raw_tx_pkd:            packed str containing raw tx data 'bytes'
        @param ignore_trailing        ignore extra bytes after unpacked into records complete
        @raise SerializedTxException: if sertype is not 0

        old code can comtinue to use this to get a full decode of the whole wire 
        tx message by calling tx_type.update(<packed tx sertype 0>)
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

def merkle_hash(hashes):
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



if __name__=="__main__":
    #
    # Test Utils - TODO: move into their own file
    #
    def _rev(hexb):
        '''
        In:     Hex encoded 'byte' str  '414243' or '4142433'
        Out:    The byte string with the order reversed. '434241' or '30434241'
                Zero padded before reverse if input ends with an odd number of encoded hex 'bytes'
        '''
        rev = []
        ln = len(hexb)
        if ln%2:
            hexb += '0'
            ln += 1
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


    ##############################
    # Use Block 100,000 Testnet2 #
    ##############################

    #     
    # Test - Parse Block Header - from testnet2 block 100,000
    #
    block_header = "05000000d8261d81d5e0cfc886de2edde0c08cd89281c96a13408a25a9f18a0400000000d9c36121bf9a904100ef5c21eb7e07f46ce24e7f8ea6697dbc235d1b899215e8bab09bce3618e97d56ce0902920b91c1436ce8ce53b50bec41f7744cfc737c9b0100593215bc8ae805000500d7110000c80a071c6708f95201000000a0860100f71400007d738059f9000afef8a133008bd9b60000000000000000000000000000000000000000000000000005000000"
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
    #print alldata['tx_full']
    tx_full_hash_0 = alldata['tx_full_hash']
    print hex(alldata['tx_full_hash']), 'tx_full_hash'
    print hex(alldata['prefix_hash']), 'prefix_hash'
    print hex(alldata['witness_hash']), 'witness_hash'
    prefix_hash_0 = alldata['prefix_hash']
    assert prefix_hash_0 == 0x49a89e0e84bbb3e2671a9b990ea7f824028ac46b7df9fffbdfd1e16c603aa425L
    print


    #
    # 1. b0c5d12a01b636ab044c3f709dbfb26fedaf3b07f0e4f4b0f91479b73388b871
    #
    tx1_raw = "010000000930072588364d4085b2facea8d7a33a54c91236af73c5bab99fb12292a69e4ec70500000000ffffffff466d95994b5268f175b80e17e129e747cd49a13be6ad2f6e2cdf22aa574352d20200000000ffffffff80480d01223f44545fb8226b14d91599a54d3ac2c3647f37af95528409835efe0200000001ffffffff804b9f56f55ce0026ca815fe1b6e2b78a25cde305097401dd762a0a4c1592e090200000001ffffffff809d67ad85582cb64f880aa1012e5279f05ee9ccec2168177000474d70d483b50200000001ffffffff81279ef649967b5a4a56bc0c036db40c8547b72660f3877d6635619fcef01e3e0200000001ffffffff81353ccadb539d37803d937130683c26ff6e88f6f62c38e55b8e3ef69c791a3c0200000001ffffffff8148ae90db48f90092d79998763605c9091635d99475c986c29cfe0a8562ce3a0200000000ffffffff81c695d5dfa3e06377065cb44378ce5fe1fff48b3c44fa730092339c19c6b8f80200000001ffffffff06977df9520100000000001976a91465a8be1de0e0af4b7d4429aa2b5032af9711c64388ac977df9520100000000001976a91465a8be1de0e0af4b7d4429aa2b5032af9711c64388ac977df9520100000000001976a91465a8be1de0e0af4b7d4429aa2b5032af9711c64388ac977df9520100000000001976a91465a8be1de0e0af4b7d4429aa2b5032af9711c64388ac977df9520100000000001976a91465a8be1de0e0af4b7d4429aa2b5032af9711c64388ac19a25d030100000000001976a91497a93b29fe5454b4080534b6d595a6121c18080188ac000000000000000009e405e06a000000009f860100010000006a473044022018fa18347aaf9534431111797f71771d337f4fde7870551a5a4bf76f7e64ba2f02201ba1db79983f07114b3f7227905928bc25550822c21b4385c4468b6c3bdf78c5012103ecdea47d34b6ce060fd23c70b3758f5fbcd5e18820d80d8cfa007817b99e107083cb78370000000090860100000000006b4830450221009b7107e3d2cdf46f2d55985026a501ab40f207c8537d0013dd5cf33de293575902207477c79de3b897b7b385349ba6434d89ee0e0c0c5c853b11e4844d50f1afaaf50121024d9134e6176f99dbe95b155f3638a55530e3776c2b6c8bd2234dbfbdbcae732a28efb93501000000d3850100030000006b483045022100855de5ba1b482e555d5380138fa314583b39af6032f32bd78c125afa1502bd490220382aaa933ce6151a257dae4081f4438b2cd5688c48e273f5e0f349e26807242b0121024d9134e6176f99dbe95b155f3638a55530e3776c2b6c8bd2234dbfbdbcae732aff4a2a1101000000a3850100040000006a47304402202caf9b32aa076cd39634094e8ec2f58087c47823b808dba1afde296d9fa390ce0220373eb2f2a2bacab5d00cef64b2d2f3c331ec632f611f070c0ef73dc6e127a7560121024d9134e6176f99dbe95b155f3638a55530e3776c2b6c8bd2234dbfbdbcae732aa6f733ff0000000098850100040000006a473044022077405f353442c6bc8c0e9c4e5dc3f90affec08555ffa8abee4017c1150d6c4d502204a589cebbe3ddda2c5ee2f17eddbd5776f92a5078ff5ce0969ec85a953d854870121024d9134e6176f99dbe95b155f3638a55530e3776c2b6c8bd2234dbfbdbcae732af27ecc500100000010860100040000006a473044022055e7630bf8d2b3036baf634201c0dd050fef7735d1b0b690e1f1161fad64e310022000cabc2c84af220c57f71fc407160d8d3de9ef0c9b6800ddaed79e323ac7b2f10121024d9134e6176f99dbe95b155f3638a55530e3776c2b6c8bd2234dbfbdbcae732a1d9c7a2b0100000045850100020000006a47304402203d7f1dbbc137be8aa6523489c95081981302ea9610829dc72850dc23be5de9e1022074b7ef769ec5df0d77c5c886241c7ca3df9df2bb5c7d918403d3e532329211fe0121024d9134e6176f99dbe95b155f3638a55530e3776c2b6c8bd2234dbfbdbcae732a9e4e5d2c00000000d4850100000000006a47304402204a3a38560480df5e7ffd0a14464ee34a06695e23754c2abbfd9a30b1f7d40227022059b6128ef5ececc42479d5084cc57f0e6eb36815f20faa9fc98e9f25278e728d0121024d9134e6176f99dbe95b155f3638a55530e3776c2b6c8bd2234dbfbdbcae732aff4a2a1101000000c3850100020000006b483045022100b178e715bc61c80a06e3b522e21d51af81598acf9b2f05dfaf88341288e2388d02204f7511749e6b4ab89b2c46f4e7057324396887df5b088da93b7918f93b634ef30121024d9134e6176f99dbe95b155f3638a55530e3776c2b6c8bd2234dbfbdbcae732a"
    packed_tx1 = tx1_raw.decode('hex')
    tx1 = tx_type.unpack(packed_tx1)
    
    alldata = tx_type.get_all(packed_tx1)
    #print alldata['tx_full']
    tx_full_hash_1 = alldata['tx_full_hash']
    print hex(alldata['tx_full_hash']), 'tx_full_hash'
    print hex(alldata['prefix_hash']), 'prefix_hash'
    print hex(alldata['witness_hash']), 'witness_hash'
    prefix_hash_1 = alldata['prefix_hash']
    assert prefix_hash_1 == 0xb0c5d12a01b636ab044c3f709dbfb26fedaf3b07f0e4f4b0f91479b73388b871L
    print


    #
    # check merkleroot: 0xe81592891b5d23bc7d69a68e7f4ee26cf4077eeb215cef0041909abf2161c3d9L
    #
    hashes = [tx_full_hash_0, tx_full_hash_1]
    
    merkle_root = merkle_hash(hashes)
    assert merkle_root == 0xe81592891b5d23bc7d69a68e7f4ee26cf4077eeb215cef0041909abf2161c3d9L

    #     
    # Parse the 10 Stake Transactions from testnet2 block 100,000
    #
    stx0_raw = "01000000020000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffffeabf91567776cbe7c7596ee6b7e93ac0aee276c5198807c0bf00af497e66f9c20000000001ffffffff0400000000000000000000266a24d8261d81d5e0cfc886de2edde0c08cd89281c96a13408a25a9f18a04000000009f86010000000000000000000000086a0601000500000089796a000000000000001abb76a9147f686bc0e548bbb92f487db6da070e43a341172888ac75d1bf100100000000001abb76a9149d8e8bdc618035be32a14ab752af2e331f9abf3688ac000000000000000002d3a98b050000000000000000ffffffff0200002ca19e0b01000000c17f01000b0000009047304402201f9879fb85cb5dc9d5570842c7766242f36e690b6c88925f3307b422e4d03428022058c3bfed6728e9b6cc89964976d58618420f51a553a8a28d7439e714590c41840147512102fe82f22f2e5bc1be0b67d85afef87329fc1c4512f30a47ce459c78bd7502ba9821022cf2f038dbb85f0a35fed9ac147e58d9ee85a80f8827085f51ef4129a02d458652ae"
    stx1_raw = "01000000020000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff3f609f6dcec5ab8f021e84af763b5530e7586b4617b77e9b8042a2217cc5a2480000000001ffffffff0300000000000000000000266a24d8261d81d5e0cfc886de2edde0c08cd89281c96a13408a25a9f18a04000000009f86010000000000000000000000086a060100050000001d9c7a2b0100000000001abb76a914a7e94ff7a271bf40718be28a4f622fa678d18f6388ac000000000000000002d3a98b050000000000000000ffffffff0200004af2ee250100000011850100090000006b483045022100b48ac3ce05a9ac5553b2f3dad21009e5bfc204205ced9b6b98f3580f7ab06ee102205c50af58deadcc8bc5f42f8b7031a5b861b52bb71abbcbfbb4ab3e8d1548a1670121036c7b1826c3da739ca07390fe673fdb9ea8430938cb18f331e457a1c444cf5f25"
    stx2_raw = "01000000020000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffffe13df4d1404cb78ccf2d23665389279551d5b8ac7f463b16fa1fd1f0505ce2080000000001ffffffff0300000000000000000000266a24d8261d81d5e0cfc886de2edde0c08cd89281c96a13408a25a9f18a04000000009f86010000000000000000000000086a060100050000001d9c7a2b0100000000001abb76a914a7e94ff7a271bf40718be28a4f622fa678d18f6388ac000000000000000002d3a98b050000000000000000ffffffff0200004af2ee250100000003850100060000006a4730440220548fd54ff98bd3344b275ebd59917ff91821c80a1ec9e16c31a2cb43c576146b02202bd75cc42a12fe8a5be748a542212eb0d8260c72eb79cac142883d9137830f9f012102196c3175e462b4e4f5ed10319a011960845235668f466b919c106e83731f6715"
    stx3_raw = "01000000020000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff1b6f4256f7d1da14519a237dfd8d043dce5199b04365a543d43f3358d958da980000000001ffffffff0300000000000000000000266a24d8261d81d5e0cfc886de2edde0c08cd89281c96a13408a25a9f18a04000000009f86010000000000000000000000086a06010005000000f27ecc500100000000001abb76a914a7e94ff7a271bf40718be28a4f622fa678d18f6388ac000000000000000002d3a98b050000000000000000ffffffff0200001fd5404b0100000056810100080000006b483045022100915c25fcac29f4d1c587da7a26b39daaa85b4db7ceb13cd3e3712ffa0a996d4c0220268e3496edc52b27968b63b04d4a1e6664b03cd31805e59cafe555384080d7230121036ef530ea582588c151a3b684fe1ab291a46f8deadbd69a4db30192c15f046481"
    stx4_raw = "01000000020000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff9ef2a8e86b2c764423df242efee96d728bd872f5cb8492d4b87cc00f085f61820000000001ffffffff0300000000000000000000266a24d8261d81d5e0cfc886de2edde0c08cd89281c96a13408a25a9f18a04000000009f86010000000000000000000000086a060100050000001d9c7a2b0100000000001abb76a914a7e94ff7a271bf40718be28a4f622fa678d18f6388ac000000000000000002d3a98b050000000000000000ffffffff0200004af2ee2501000000df840100130000006a47304402206b755156d9aebc12b7ff7a80e26c979ebc68a36da0a9b0d0436aa3b75968466f02204697d52c2b13a9e1a5ff8d4f798a620c3a80752ae57afad0230a93404fea780e012102004dccc58350e0058e78c440c69a1531d0296775ce39c91655ab643cd8cd9f4a"
    stx5_raw = "010000000130072588364d4085b2facea8d7a33a54c91236af73c5bab99fb12292a69e4ec70400000000ffffffff036708f9520100000000001aba76a91438d4eea12c6701e59c755429078d1fd5f6d98bf888ac00000000000000000000206a1ea7e94ff7a271bf40718be28a4f622fa678d18f63977df952010000000058000000000000000000001abd76a914000000000000000000000000000000000000000088ac00000000b086010001977df952010000009f860100010000006a47304402207a7b62a37794fbf347311e7d3c816de528bc57754bc73b1c6841da6983cc2eb502207cf8e9d4e200d58406cc4c387ad534047e2f4a93f5de0c2d2c7a36cbdeb0f4f0012103553b24e54b1382947b5afa84115b10c30eebe4144e14fa33f58082f28dcb0420"
    stx6_raw = "010000000130072588364d4085b2facea8d7a33a54c91236af73c5bab99fb12292a69e4ec70100000000ffffffff036708f9520100000000001aba76a91438d4eea12c6701e59c755429078d1fd5f6d98bf888ac00000000000000000000206a1ea7e94ff7a271bf40718be28a4f622fa678d18f63977df952010000000058000000000000000000001abd76a914000000000000000000000000000000000000000088ac00000000b086010001977df952010000009f860100010000006a47304402206d2be8fdf5692d03e576a777e81a82b3d78cc1811d3d4a1316df91b3ca83d9d20220749cea01d56ee88eae20da1dd868b5c35fb05011eb1f28b0646a10c372aa0630012103553b24e54b1382947b5afa84115b10c30eebe4144e14fa33f58082f28dcb0420"
    stx7_raw = "010000000130072588364d4085b2facea8d7a33a54c91236af73c5bab99fb12292a69e4ec70000000000ffffffff036708f9520100000000001aba76a91438d4eea12c6701e59c755429078d1fd5f6d98bf888ac00000000000000000000206a1ea7e94ff7a271bf40718be28a4f622fa678d18f63977df952010000000058000000000000000000001abd76a914000000000000000000000000000000000000000088ac00000000b086010001977df952010000009f860100010000006a4730440220060568490637a100a045182bc6b16c16dc9cf06ae22ba411a6fdcf41ddd171c102206287538bd579aa42b93b8cef8a34b6f0c1ae9395fd5e66168346bdfa7e80ab0f012103553b24e54b1382947b5afa84115b10c30eebe4144e14fa33f58082f28dcb0420"
    stx8_raw = "010000000130072588364d4085b2facea8d7a33a54c91236af73c5bab99fb12292a69e4ec70200000000ffffffff036708f9520100000000001aba76a91438d4eea12c6701e59c755429078d1fd5f6d98bf888ac00000000000000000000206a1ea7e94ff7a271bf40718be28a4f622fa678d18f63977df952010000000058000000000000000000001abd76a914000000000000000000000000000000000000000088ac00000000b086010001977df952010000009f860100010000006a47304402207f50f973f38cb2525d982b03900e6f0af25a2d9314de474df32d653837936efc02203f9db5c069596a77d07f18fc04cc25f03d234dbf577e84d6f29955d33373c9ea012103553b24e54b1382947b5afa84115b10c30eebe4144e14fa33f58082f28dcb0420"
    stx9_raw = "010000000130072588364d4085b2facea8d7a33a54c91236af73c5bab99fb12292a69e4ec70300000000ffffffff036708f9520100000000001aba76a91438d4eea12c6701e59c755429078d1fd5f6d98bf888ac00000000000000000000206a1ea7e94ff7a271bf40718be28a4f622fa678d18f63977df952010000000058000000000000000000001abd76a914000000000000000000000000000000000000000088ac00000000b086010001977df952010000009f860100010000006b483045022100c094d1ecc64be6fae4dd33d483c34fdab0ae071a010457bc2fce340a6466721d02201a30d2fafb4664bd276503d2466bc8534a866ce9cd0aed659b2f620d849b8023012103553b24e54b1382947b5afa84115b10c30eebe4144e14fa33f58082f28dcb0420"

    packed_stx0 = stx0_raw.decode('hex')
    stx0 = tx_type.unpack(packed_stx0)
    #
    alldata = tx_type.get_all(packed_stx0)
    stx_full_hash_0 = alldata['tx_full_hash']
    prefix_hash_0 = alldata['prefix_hash']
    assert prefix_hash_0 == 0x2f013d5dc9089ac37c003a332041ea0b5c2ec27303deee475fec773673244ba3L
    print
    
    packed_stx1 = stx1_raw.decode('hex')
    stx1 = tx_type.unpack(packed_stx1)
    #
    alldata = tx_type.get_all(packed_stx1)
    stx_full_hash_1 = alldata['tx_full_hash']
    prefix_hash_1 = alldata['prefix_hash']
    assert prefix_hash_1 == 0x40b2ab4642fd4f3f3419e3897c9fa82d882dc0e750e34c0fff20cde7b42fbef8L
    print
    
    packed_stx2 = stx2_raw.decode('hex')
    stx2 = tx_type.unpack(packed_stx2)
    #
    alldata = tx_type.get_all(packed_stx2)
    stx_full_hash_2 = alldata['tx_full_hash']
    prefix_hash_2 = alldata['prefix_hash']
    assert prefix_hash_2 == 0x2cdc94f5e7bd8596ec172b1fe3624df3715a2bc62058a4af0fca7be762371379L
    print
    
    packed_stx3 = stx3_raw.decode('hex')
    stx3 = tx_type.unpack(packed_stx3)
    #
    alldata = tx_type.get_all(packed_stx3)
    stx_full_hash_3 = alldata['tx_full_hash']
    prefix_hash_3 = alldata['prefix_hash']
    assert prefix_hash_3 == 0xfcdf85ddd9a230c5e8542fe0f3dd642e5b777876838425afb61654582ccef607L
    print
    
    packed_stx4 = stx4_raw.decode('hex')
    stx4 = tx_type.unpack(packed_stx4)
    #
    alldata = tx_type.get_all(packed_stx4)
    stx_full_hash_4 = alldata['tx_full_hash']
    prefix_hash_4 = alldata['prefix_hash']
    assert prefix_hash_4 == 0x8ea9b4713f5c9590d0c5ff91a5cf31c2d498d0bd951cf1020d191331a7c11ccdL
    print
    
    packed_stx5 = stx5_raw.decode('hex')
    stx5 = tx_type.unpack(packed_stx5)
    #
    alldata = tx_type.get_all(packed_stx5)
    stx_full_hash_5 = alldata['tx_full_hash']
    prefix_hash_5 = alldata['prefix_hash']
    assert prefix_hash_5 == 0xf68a14d528a34f51f7f2bb5253e5bd2999eb0f8317a0fccc314a615dbd25481cL
    print
    
    packed_stx6 = stx6_raw.decode('hex')
    stx6 = tx_type.unpack(packed_stx6)
    #
    alldata = tx_type.get_all(packed_stx6)
    stx_full_hash_6 = alldata['tx_full_hash']
    prefix_hash_6 = alldata['prefix_hash']
    assert prefix_hash_6 == 0xd721d203ccaac6e3b58dcc0d90db4e53478c2603a10f19ab81e7367dba44a4a3L
    print
    
    packed_stx7 = stx7_raw.decode('hex')
    stx7 = tx_type.unpack(packed_stx7)
    #
    alldata = tx_type.get_all(packed_stx7)
    stx_full_hash_7 = alldata['tx_full_hash']
    prefix_hash_7 = alldata['prefix_hash']
    assert prefix_hash_7 == 0x5d90393b5e5db763d87ce31cca614d75cf12eebeab04dfaae5084767df0ebe5fL
    print
    
    packed_stx8 = stx8_raw.decode('hex')
    stx8 = tx_type.unpack(packed_stx8)
    #
    alldata = tx_type.get_all(packed_stx8)
    stx_full_hash_8 = alldata['tx_full_hash']
    prefix_hash_8 = alldata['prefix_hash']
    assert prefix_hash_8 == 0x77da688b6d1a388aec30ec4436537ac3138231febe1074bfd5acd8fb260373c6L
    print
    
    packed_stx9 = stx9_raw.decode('hex')
    stx9 = tx_type.unpack(packed_stx9)
    #
    alldata = tx_type.get_all(packed_stx9)
    stx_full_hash_9 = alldata['tx_full_hash']
    prefix_hash_9 = alldata['prefix_hash']
    assert prefix_hash_9 == 0x50be003b7cc52fc7697541ef98c93cd1eae7cab30deeae63715540dfd4d8e563L
    print
    
    
    #
    # check stakeroot: 0x9b7c73fc4c74f741ec0bb553cee86c43c1910b920209ce567de91836ce9bb0baL
    #
    
    stx_hashes = [stx_full_hash_0, stx_full_hash_1, stx_full_hash_2, stx_full_hash_3, 
                  stx_full_hash_4, stx_full_hash_5, stx_full_hash_6, stx_full_hash_7, 
                  stx_full_hash_8, stx_full_hash_9 ]
    
    stake_root = merkle_hash(stx_hashes)
    assert stake_root == 0x9b7c73fc4c74f741ec0bb553cee86c43c1910b920209ce567de91836ce9bb0baL
    print
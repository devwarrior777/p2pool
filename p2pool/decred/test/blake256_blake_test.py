'''
Created on 6 Nov 2017

@author: devwarrior
'''

# import p2pool
from p2pool.util import math, pack
from p2pool.decred.blake import BLAKE
from binascii import hexlify, unhexlify
from p2pool.decred.data import hash256_sha

#
# bitcoin double sha256 hashing as a model
#
# def hash256_sha(data):
#     return pack.IntType(256).unpack(hashlib.sha256(hashlib.sha256(data).digest()).digest())

def hash256(data):
    return pack.IntType(256).unpack(BLAKE(256).digest(data))

def getChecksumForPayload(payload):
    hashed_payload = BLAKE(256).digest(payload)
    print(hexlify(hashed_payload))
    checksum = hashed_payload[:4]
    return checksum

if __name__ == '__main__':
    payload = b'\x00'
    print payload, len(payload)
    checksum = getChecksumForPayload(payload)
    print "checksum raw: '{}' hexstr: {}".format(checksum, hexlify(checksum))    
    # Expected: [0ce8d4ef]..4dd7cd8d62dfded9d4edb0a774ae6a41929a74da23109e8f11139c87
    print
    payload = 'Kilroy was here!'
    print payload, len(payload)
    checksum = getChecksumForPayload(payload)
    print "checksum raw: '{}' hexstr: {}".format(checksum, hexlify(checksum))    
    # Expected: [b25c02cc]..fa1f664d25a15d999b56a4be1ad84a029a96be5d654387a2def99916
     
#     print '-------'
#     print 'sha256d'
#     print '-------'
#      
#     rawtx = "0100000001a23fbfc21a19afa187826326da191f2d9f92e8b4ca5516004d1e6b578088537e010000006b483045022100ae364851313e1d690c898b2ae86441906d73a98b87f08e78f8836d3514e7e784022050f8bd560e8123c448a4075fdb8af9ea80b7db5d82e027f02b6f09c341e68267012103dde4f4c1be0f0331335c599ad47981e7a662eb000fff7a947fef2981abed7b6dfeffffff02f45a0f00000000001976a914db34e5c559265f0513e883f547937da21944022a88ac08436923000000001976a9147e65189f60382c42fc987916d1a2e1713056cc0c88acceee0000"
#     print rawtx
#     rawtx_decoded = rawtx.decode('hex')
#     hash = hash256_sha(rawtx_decoded)
#     print "hash", hex(hash)    
#     # Expected: 0xb483b9e5142c2ff82c4157fab714bec38987e45c15fc56449a6950dfce41dc75L
#  
#     rawtx = "01000000011df529c1068fa32591bc072d1f8dfbb731085034e653774f43a864c30f93e0e1000000006b483045022100fcde6b2df82e17f7454e571916636ec1d875bc03261a773c3aea6705852f84be022075060c117b385cf73d188c1e25ac39b9bfc7970f14985eda6879bef412c5e659012103c892a5dacdc82e2b04bfb12284da078105cc6256301a54e7a0c6407a5545e4e2feffffff025aeeb6e7000000001976a9147a887ded58fc52735d490d1105d6f81c0237b13388ac85298f00000000001976a914a3f9a29630b6f1afa09cad634c6300e4ec0e132f88acceee0000"
#     print rawtx
#     rawtx_decoded = rawtx.decode('hex')
#     hash = hash256_sha(rawtx_decoded)
#     print "hash", hex(hash)    
#     # Expected: 0x73dc87f378cc36ccbd00048cebf85a95c86a9e481b4c7920808e819b02ad6132L
 
    print '--------'
    print 'blake256'
    print '--------'
 
    raw = "01000000020000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff59693b8cd215ee8b5b9d2e4c6126a4e0de13f577f797a6c72845ea65de11e1d10000000001ffffffff0400000000000000000000266a24d9111648fa784ecf8d40f154e6c3341d08b63fe18bb28c6ef85009000000000043b3020000000000000000000000086a06050006000000583d48000000000000001abb76a9147f686bc0e548bbb92f487db6da070e43a341172888ac51b934050100000000001abb76a9149d8e8bdc618035be32a14ab752af2e331f9abf3688ac000000000000000002e8afcc030000000000000000ffffffff020000ffffffffffffffff00000000ffffffff9047304402202220ff995b67ae77700b7df0a38597ed9930a3181adad2cd35ef9e784539bade02201eeeb54b0d21962958f75bf7dfe1ee176bcd5a011a7cc1a9edc7476f4f07c0250147512102fe82f22f2e5bc1be0b67d85afef87329fc1c4512f30a47ce459c78bd7502ba9821022cf2f038dbb85f0a35fed9ac147e58d9ee85a80f8827085f51ef4129a02d458652ae"

    raw2 = ""
    print raw2[:128], '...'
    tx = raw2.decode('hex')
    hsh = hash256(tx)
    print hsh
        
    print 'done', len(raw)

    
    

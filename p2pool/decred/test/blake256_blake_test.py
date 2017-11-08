'''
Created on 6 Nov 2017

@author: devwarrior
'''

from p2pool.decred.blake import BLAKE
from binascii import hexlify

def getChecksumForPayload(payload):
    blake256 = BLAKE(256)
    hashed_payload = blake256.digest(payload)
    print(hexlify(hashed_payload))
    checksum = hashed_payload[:4]
    return checksum

if __name__ == '__main__':
    payload = b'\x00'
    print payload, len(payload)
    checksum = getChecksumForPayload(payload)
    print "checksum", checksum, hexlify(checksum)    
    # Expected: 0ce8d4ef 4dd7cd8d62dfded9d4edb0a774ae6a41929a74da23109e8f11139c87
    print
    payload = 'Kilroy was here!'
    print payload, len(payload)
    checksum = getChecksumForPayload(payload)
    print "checksum", checksum, hexlify(checksum)
    # Expected: b25c02cc fa1f664d25a15d999b56a4be1ad84a029a96be5d654387a2def99916
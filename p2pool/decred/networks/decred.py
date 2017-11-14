''' 
 Currently copied from p2pool orig decred/networks/decred.py 

'''

import os
import platform

from twisted.internet import defer
from .. import helper
from p2pool.util import pack


P2P_PREFIX = 'F900B4D9'.decode('hex')   # MsgVersion 1..5 #
P2P_PORT = 9108
ADDRESS_VERSION = 76
RPC_PORT = 9109
# FIXME Genesis Block hash for Decred
RPC_CHECK = defer.inlineCallbacks(lambda dcrd: defer.returnValue(
            (yield helper.check_genesis_block(dcrd, '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f')) and
            not (yield dcrd.rpc_getinfo())['testnet']
        ))
SUBSIDY_FUNC = lambda height: 50*100000000 >> (height + 1)//210000
###POW_FUNC = POW_FUNC = lambda data: pack.IntType(256).unpack(__import__('blake_hash').getPoWHash(data))  <-- FIXME
POW_FUNC = POW_FUNC = lambda data: pack.IntType(256).unpack(__import__('blake_hash').getPoWHash(data))
BLOCK_PERIOD = 300 # s
SYMBOL = 'DCR'
CONF_FILE_FUNC = lambda: os.path.join(os.path.join(os.environ['LOCALAPPDATA'], 'dcrd') if platform.system() == 'Windows' else os.path.expanduser('~/Library/Application Support/dcrd/') if platform.system() == 'Darwin' else os.path.expanduser('~/.dcrd'), 'dcrd.conf')
BLOCK_EXPLORER_URL_PREFIX = 'https://mainnet.decred.org/block/'
ADDRESS_EXPLORER_URL_PREFIX = 'https://mainnet.decred.org/address/'
TX_EXPLORER_URL_PREFIX = 'https://mainnet.decred.org/tx/'
SANE_TARGET_RANGE = (2**256//2**32//1000000 - 1, 2**256//2**32 - 1)
DUMB_SCRYPT_DIFF = 1
DUST_THRESHOLD = 0.001e8

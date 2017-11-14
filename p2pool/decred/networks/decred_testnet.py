import os
import platform

from twisted.internet import defer
from .. import helper
from p2pool.util import pack


P2P_PREFIX = '65A0E748'.decode('hex')
P2P_PORT = 19108
ADDRESS_VERSION = 0 #111
RPC_PORT = 19109
# RPC_CHECK = defer.inlineCallbacks(lambda dcrd: defer.returnValue(
#             'decredaddress' in (yield dcrd.rpc_help()) and
#             (yield dcrd.rpc_getinfo())['testnet']
#         ))
#
# Check genesis block of testnet2
#
RPC_CHECK = defer.inlineCallbacks(lambda dcrd: defer.returnValue(
            (yield helper.check_genesis_block(dcrd, '4261602a9d07d80ad47621a64ba6a07754902e496777edc4ff581946bd7bc29c')) and
            (yield dcrd.rpc_getinfo())['testnet']
        ))

SUBSIDY_FUNC = lambda height: 50*100000000 >> (height + 1)//210000
###POW_FUNC = lambda data: pack.IntType(256).unpack(__import__('blake_hash').getPoWHash(data))  <-- FIXME
POW_FUNC = lambda data: pack.IntType(256).unpack(__import__('blake_hash').getPoWHash(data))
BLOCK_PERIOD = 300 # s
SYMBOL = 'DCR'
CONF_FILE_FUNC = lambda: os.path.join(os.path.join(os.environ['LOCALAPPDATA'], 'dcrd') if platform.system() == 'Windows' else os.path.expanduser('~/Library/Application Support/Dcrd/') if platform.system() == 'Darwin' else os.path.expanduser('~/.dcrd'), 'dcrd.conf')
BLOCK_EXPLORER_URL_PREFIX = 'https://testnet.decred.org/block/'
ADDRESS_EXPLORER_URL_PREFIX = 'https://testnet.decred.org/address/'
TX_EXPLORER_URL_PREFIX = 'https://testnet.decred.org/tx/'
SANE_TARGET_RANGE = (2**256//2**32//1000 - 1, 2**256//2**32 - 1)
DUMB_SCRYPT_DIFF = 1
DUST_THRESHOLD = 1e8
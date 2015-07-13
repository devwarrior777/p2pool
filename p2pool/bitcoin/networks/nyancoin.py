import os
import platform

from twisted.internet import defer

from .. import data, helper
from p2pool.util import pack


P2P_PREFIX = 'fcd9b7dd'.decode('hex')
P2P_PORT = 33701
ADDRESS_VERSION = 45
RPC_PORT = 33700
RPC_CHECK = defer.inlineCallbacks(lambda bitcoind: defer.returnValue(
            'nyancoin address' in (yield bitcoind.rpc_help()) and
            not (yield bitcoind.rpc_getinfo())['testnet']
        ))
SUBSIDY_FUNC = lambda height: 337*100000000 >> (height + 1)//500000
POW_FUNC = lambda data: pack.IntType(256).unpack(__import__('ltc_scrypt').getPoWHash(data))
BLOCK_PERIOD = 60 # s
SYMBOL = 'NYAN'
CONF_FILE_FUNC = lambda: os.path.join(os.path.join(os.environ['APPDATA'], 'nyancoin') if platform.system() == 'Windows' else os.path.expanduser('~/Library/Application Support/nyancoin/') if platform.system() == 'Darwin' else os.path.expanduser('~/.nyancoin'), 'nyancoin.conf')
BLOCK_EXPLORER_URL_PREFIX = 'https://nyan.space/chain/Nyancoin/block/'
ADDRESS_EXPLORER_URL_PREFIX = 'https://nyan.space/chain/Nyancoin/address/'
TX_EXPLORER_URL_PREFIX = 'https://nyan.space/chain/Nyancoin/tx/'
SANE_TARGET_RANGE = (2**256//1000000000 - 1, 2**256//1000 - 1)
DUMB_SCRYPT_DIFF = 2**16
DUST_THRESHOLD = 0.03e8

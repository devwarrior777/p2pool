import os
import platform

from twisted.internet import defer

from .. import data, helper
from p2pool.util import pack


P2P_PREFIX = 'fcd9b7dd'.decode('hex')
P2P_PORT = 55789
ADDRESS_VERSION = 15
RPC_PORT = 55788
RPC_CHECK = defer.inlineCallbacks(lambda bitcoind: defer.returnValue(
            'globalcoin address' in (yield bitcoind.rpc_help()) and
            not (yield bitcoind.rpc_getinfo())['testnet']
        ))
SUBSIDY_FUNC = lambda height: 100*100000000 >> (height + 1)//288400
POW_FUNC = lambda data: pack.IntType(256).unpack(__import__('ltc_scrypt').getPoWHash(data))
BLOCK_PERIOD = 40 # s
SYMBOL = 'GLC'
CONF_FILE_FUNC = lambda: os.path.join(os.path.join(os.environ['APPDATA'], 'globalcoin') if platform.system() == 'Windows' else os.path.expanduser('~/Library/Application Support/globalcoin/') if platform.system() == 'Darwin' else os.path.expanduser('~/.globalcoin'), 'globalcoin.conf')
BLOCK_EXPLORER_URL_PREFIX = 'http://chainz.cryptoid.info/glc/block.dws?'
ADDRESS_EXPLORER_URL_PREFIX = 'http://chainz.cryptoid.info/glc/address.dws?'
TX_EXPLORER_URL_PREFIX = 'http://chainz.cryptoid.info/glc/tx.dws?'
SANE_TARGET_RANGE = (2**256//1000000000 - 1, 2**256//1000 - 1)
DUMB_SCRYPT_DIFF = 2**16
DUST_THRESHOLD = 0.03e8

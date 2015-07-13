import os
import platform

from twisted.internet import defer

from .. import data, helper
from p2pool.util import pack


P2P_PREFIX = 'facabada'.decode('hex')
P2P_PORT = 9377
ADDRESS_VERSION = 23
RPC_PORT = 9376
RPC_CHECK = defer.inlineCallbacks(lambda bitcoind: defer.returnValue(
            'anoncoinaddress' in (yield bitcoind.rpc_help()) and
            not (yield bitcoind.rpc_getinfo())['testnet']
        ))
SUBSIDY_FUNC = lambda height: 5*100000000 >> (height + 1)//306600
POW_FUNC = lambda data: pack.IntType(256).unpack(__import__('ltc_scrypt').getPoWHash(data))
BLOCK_PERIOD = 205 # s
SYMBOL = 'ANC'
CONF_FILE_FUNC = lambda: os.path.join(os.path.join(os.environ['APPDATA'], 'anoncoin') if platform.system() == 'Windows' else os.path.expanduser('~/Library/Application Support/anoncoin/') if platform.system() == 'Darwin' else os.path.expanduser('~/.anoncoin'), 'anoncoin.conf')
BLOCK_EXPLORER_URL_PREFIX = 'https://coinplorer.com/ANC/Blocks/'
ADDRESS_EXPLORER_URL_PREFIX = 'https://coinplorer.com/ANC/Addresses/'
TX_EXPLORER_URL_PREFIX = 'https://coinplorer.com/ANC/Transactions/'
SANE_TARGET_RANGE = (2**256//1000000000 - 1, 2**256//1000 - 1)
DUMB_SCRYPT_DIFF = 2**16
DUST_THRESHOLD = 0.03e8

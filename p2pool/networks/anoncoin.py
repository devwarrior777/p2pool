from p2pool.bitcoin import networks

PARENT = networks.nets['anoncoin']
SHARE_PERIOD = 10 # seconds
CHAIN_LENGTH = 24*60*60//10 # shares
REAL_CHAIN_LENGTH = 24*60*60//10 # shares
TARGET_LOOKBEHIND = 20 # shares
SPREAD = 10 # blocks
IDENTIFIER = '4C29103E81D10083'.decode('hex')
PREFIX = '5A0866A5CAE422C3'.decode('hex')
P2P_PORT = 23650
MIN_TARGET = 0
MAX_TARGET = 2**256//2**20 - 1
PERSIST = False
WORKER_PORT = 8850
BOOTSTRAP_ADDRS = 'xpool.net'.split(' ')
ANNOUNCE_CHANNEL = '#p2pool-anc'
VERSION_CHECK = lambda v: True
VERSION_WARNING = lambda v: None

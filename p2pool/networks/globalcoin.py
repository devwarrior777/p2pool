from p2pool.bitcoin import networks

PARENT = networks.nets['globalcoin']
SHARE_PERIOD = 10 # seconds
CHAIN_LENGTH = 24*60*60//10 # shares
REAL_CHAIN_LENGTH = 24*60*60//10 # shares
TARGET_LOOKBEHIND = 200 # shares
SPREAD = 45 # blocks
IDENTIFIER = '5F0183D62F698832'.decode('hex')
PREFIX = '52F8CF5955E02234'.decode('hex')
P2P_PORT = 23660
MIN_TARGET = 0
MAX_TARGET = 2**256//2**20 - 1
PERSIST = False
WORKER_PORT = 8860
BOOTSTRAP_ADDRS = 'xpool.net'.split(' ')
ANNOUNCE_CHANNEL = '#p2pool-glc'
VERSION_CHECK = lambda v: True
VERSION_WARNING = lambda v: None

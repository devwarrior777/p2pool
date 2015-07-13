from p2pool.bitcoin import networks

PARENT = networks.nets['nyancoin']
SHARE_PERIOD = 10 # seconds
CHAIN_LENGTH = 24*60*60//10 # shares
REAL_CHAIN_LENGTH = 24*60*60//10 # shares
TARGET_LOOKBEHIND = 200 # shares
SPREAD = 30 # blocks
IDENTIFIER = '5D4D5622297EE0E4'.decode('hex')
PREFIX = '4DD804B010424A99'.decode('hex')
P2P_PORT = 23670
MIN_TARGET = 0
MAX_TARGET = 2**256//2**20 - 1
PERSIST = False
WORKER_PORT = 8870
BOOTSTRAP_ADDRS = 'xpool.net'.split(' ')
ANNOUNCE_CHANNEL = '#p2pool-nyan'
VERSION_CHECK = lambda v: True
VERSION_WARNING = lambda v: None

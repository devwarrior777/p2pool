from p2pool.bitcoin import networks

PARENT = networks.nets['potcoin']
SHARE_PERIOD = 10 # seconds
CHAIN_LENGTH = 24*60*60//10 # shares
REAL_CHAIN_LENGTH = 24*60*60//10 # shares
TARGET_LOOKBEHIND = 200 # shares
SPREAD = 10 # blocks
IDENTIFIER = 'DDA1A1D3B2F68CDD'.decode('hex')
PREFIX = 'A2C3D4D541C11DDD'.decode('hex')
P2P_PORT = 8420
MIN_TARGET = 0
MAX_TARGET = 2**256//2**20 - 1
PERSIST = False
WORKER_PORT = 9420
BOOTSTRAP_ADDRS = 'xpool.net'.split(' ')
ANNOUNCE_CHANNEL = '#p2pool-pot'
VERSION_CHECK = lambda v: True
VERSION_WARNING = lambda v: None
